package engine_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/lechandonga/signature-detection-engine-go/engine"
)

func logResultFull(t *testing.T, res *engine.Result) {
	t.Helper()
	hits, _ := json.Marshal(res.Hits)
	t.Logf("rule_set_version=%s file_id=%s status=%s mode=%s progress=%s cached=%v "+
		"bytes_read=%d bytes_processed=%d bytes_reused=%d bytes_verified=%d "+
		"cache_entries=%d cache_cost=%d cache_limit=%d cache_evictions=%d hits=%s",
		res.RuleVersion, res.FileID, res.Status, res.Mode, res.Progress, res.Cached,
		res.Work.BytesRead, res.Work.BytesProcessed, res.Work.BytesReused, res.Work.BytesVerified,
		res.Work.CacheEntries, res.Work.CacheCostBytes, res.Work.CacheLimitBytes,
		res.Work.CacheEvictions, string(hits))
}

func newEngineBounded(t *testing.T, dir, body string, chunk int, limit int64) *engine.Engine {
	t.Helper()
	rp := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{
		RulePaths: []string{rp}, ChunkSize: chunk, CacheLimitBytes: limit,
	})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func bumpMTime() { time.Sleep(12 * time.Millisecond) }

func appendFile(t *testing.T, path string, b []byte) {
	t.Helper()
	bumpMTime()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		t.Fatal(err)
	}
}

func rewriteFile(t *testing.T, path string, b []byte) {
	t.Helper()
	bumpMTime()
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestIncrementalResumeMatchesFullScan: append-only rescans produce exactly
// the full-scan hit set, including matches crossing the old/new boundary.
func TestIncrementalResumeMatchesFullScan(t *testing.T) {
	dir := t.TempDir()
	eng := newEngine(t, dir, testRules, 32)

	// Prefix: PNG at 0, aa bb at 64, and the final old bytes are 50 4b 03
	// so appending one 0x04 completes a zip match across the boundary.
	base := make([]byte, 128)
	copy(base[0:8], []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a})
	copy(base[64:66], []byte{0xaa, 0xbb})
	copy(base[125:128], []byte{0x50, 0x4b, 0x03})
	target := writeTarget(t, dir, "grow.bin", base)

	first := eng.Scan(target)
	logResultFull(t, first)
	if first.Status != engine.StatusOK || first.Mode != engine.ModeFull ||
		first.Progress != engine.ProgressNew {
		t.Fatalf("first scan: %s/%s/%s", first.Status, first.Mode, first.Progress)
	}

	// Appended tail: 04 closes the crossing zip; cc dd completes the "pair"
	// rule across the boundary (aa bb in old, cc dd in new); 11 22 and 33 44
	// are wholly new; another PK zip sits fully inside the new tail.
	tail := []byte{
		0x04,       // 128: zip match started at 125 crosses boundary
		0xcc, 0xdd, // 129: pair rule completed across boundary
		0x11, 0x22, // 131: either
		0x33, 0x44, // 133: either
		0x50, 0x4b, 0x03, 0x04, // 135: zip fully in tail
	}
	appendFile(t, target, tail)

	inc := eng.Scan(target)
	logResultFull(t, inc)
	if inc.Status != engine.StatusOK {
		t.Fatalf("incremental status=%s err=%s", inc.Status, inc.Error)
	}
	if inc.Mode != engine.ModeIncremental || inc.Progress != engine.ProgressResumed {
		t.Fatalf("want incremental/resumed, got %s/%s", inc.Mode, inc.Progress)
	}

	full := newEngine(t, dir, testRules, 4096).Scan(target)
	logResultFull(t, full)
	if !hitsEqual(inc.Hits, full.Hits) {
		t.Fatalf("incremental hits differ from full:\ninc =%+v\nfull=%+v", inc.Hits, full.Hits)
	}
	if inc.ContentHash != full.ContentHash {
		t.Fatalf("content hash mismatch %s vs %s", inc.ContentHash, full.ContentHash)
	}

	wantReused := int64(len(base))
	if inc.Work.BytesReused != wantReused || inc.Work.BytesRead != int64(len(tail)) {
		t.Fatalf("work accounting: read=%d reused=%d, want read=%d reused=%d",
			inc.Work.BytesRead, inc.Work.BytesReused, len(tail), wantReused)
	}
	if inc.Work.BytesProcessed >= wantReused {
		t.Fatalf("processed %d should be far below full size %d",
			inc.Work.BytesProcessed, wantReused)
	}

	// No-change rescan: zero content bytes read, identical hits.
	again := eng.Scan(target)
	logResultFull(t, again)
	if again.Mode != engine.ModeCached || !again.Cached || again.Work.BytesRead != 0 {
		t.Fatalf("unchanged rescan must be zero-work cached, got %s/%s read=%d",
			again.Mode, again.Progress, again.Work.BytesRead)
	}
	if !hitsEqual(again.Hits, full.Hits) {
		t.Fatal("unchanged rescan hit set changed")
	}
}

// TestProgressInvalidatedByRewriteTruncateReplace: every non-append change
// discards progress, forces a full rescan, and reports a reaction distinct
// from a normal completed scan.
func TestProgressInvalidatedByRewriteTruncateReplace(t *testing.T) {
	dir := t.TempDir()
	eng := newEngine(t, dir, testRules, 64)

	t.Run("rewrite_same_size", func(t *testing.T) {
		target := writeTarget(t, dir, "rw.bin", sampleData())
		first := eng.Scan(target)
		changed := sampleData()
		changed[10] = 0x00 // kill the zip at offset 10; same length
		rewriteFile(t, target, changed)
		res := eng.Scan(target)
		logResultFull(t, res)
		if res.Status != engine.StatusOK || res.Mode != engine.ModeFull {
			t.Fatalf("want OK/full, got %s/%s (%s)", res.Status, res.Mode, res.Error)
		}
		if res.Progress != engine.ProgressInvalidatedRewritten {
			t.Fatalf("want invalidated_rewritten, got %s", res.Progress)
		}
		if hitsEqual(res.Hits, first.Hits) {
			t.Fatal("rewritten content must change the hit set")
		}
	})

	t.Run("truncate", func(t *testing.T) {
		target := writeTarget(t, dir, "tr.bin", sampleData())
		eng.Scan(target)
		rewriteFile(t, target, sampleData()[:40])
		res := eng.Scan(target)
		logResultFull(t, res)
		if res.Mode != engine.ModeFull ||
			res.Progress != engine.ProgressInvalidatedTruncated {
			t.Fatalf("want full/invalidated_truncated, got %s/%s", res.Mode, res.Progress)
		}
		want := []engine.Hit{
			{RuleID: "png-head", Offset: 0},
			{RuleID: "wild-window", Offset: 14},
			{RuleID: "zip", Offset: 10},
		}
		if !hitsEqual(res.Hits, want) {
			t.Fatalf("unexpected hits after shrink: %+v", res.Hits)
		}
	})

	t.Run("replace", func(t *testing.T) {
		target := writeTarget(t, dir, "rp.bin", sampleData())
		eng.Scan(target)
		replacement := make([]byte, 200)
		copy(replacement[0:4], []byte{0x50, 0x4b, 0x03, 0x04})
		tmp := filepath.Join(dir, "rp-new.bin")
		if err := os.WriteFile(tmp, replacement, 0o644); err != nil {
			t.Fatal(err)
		}
		bumpMTime()
		if err := os.Rename(tmp, target); err != nil {
			t.Fatal(err)
		}
		res := eng.Scan(target)
		logResultFull(t, res)
		if res.Status != engine.StatusOK || res.Mode != engine.ModeFull {
			t.Fatalf("replaced file: %s %s/%s", res.Status, res.Mode, res.Progress)
		}
		if res.Progress != engine.ProgressInvalidatedReplaced {
			t.Fatalf("want invalidated_replaced, got %s", res.Progress)
		}
		if !hitsEqual(res.Hits, []engine.Hit{{RuleID: "zip", Offset: 0}}) {
			t.Fatalf("replaced-content hits wrong: %+v", res.Hits)
		}
	})

	t.Run("rewrite_then_append", func(t *testing.T) {
		target := writeTarget(t, dir, "ra.bin", sampleData())
		eng.Scan(target)
		changed := sampleData()
		changed[0] = 0x00 // destroy PNG header in old prefix
		bumpMTime()
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(changed); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte{0x50, 0x4b, 0x03, 0x04}); err != nil {
			t.Fatal(err)
		}
		f.Close()
		res := eng.Scan(target)
		logResultFull(t, res)
		if res.Mode != engine.ModeFull ||
			(res.Progress != engine.ProgressInvalidatedPrefix &&
				res.Progress != engine.ProgressInvalidatedTruncated) {
			t.Fatalf("rewritten prefix must invalidate resume, got %s/%s",
				res.Mode, res.Progress)
		}
		for _, h := range res.Hits {
			if h.RuleID == "png-head" {
				t.Fatalf("destroyed png header must not hit: %+v", res.Hits)
			}
		}
	})
}

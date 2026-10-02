package engine_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/lechandonga/signature-detection-engine-go/engine"
)

func logStats(t *testing.T, res *engine.Result) {
	t.Helper()
	out, _ := json.Marshal(res.Hits)
	t.Logf("rule_set_version=%s file_id=%s status=%s mode=%s basis=%s/%s cached=%v read=%d processed=%d reused=%d size=%d hits=%s",
		res.RuleVersion, res.FileID, res.Status, res.Mode, res.Basis, res.BasisReason, res.Cached,
		res.Stats.BytesRead, res.Stats.BytesProcessed, res.Stats.BytesReused, res.Stats.FileSize, string(out))
}

func appendFile(t *testing.T, path string, extra []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.Write(extra); err != nil {
		t.Fatal(err)
	}
}

// TestIncrementalAppendMatchesFullScan is the core acceptance case: a tail
// append triggers an incremental scan whose hits equal a from-zero full
// scan, including a rule whose terms straddle the splice point.
func TestIncrementalAppendMatchesFullScan(t *testing.T) {
	dir := t.TempDir()
	eng := newEngine(t, dir, testRules, 16)
	target := writeTarget(t, dir, "grow.bin", sampleData())

	first := eng.Scan(target)
	logStats(t, first)
	if first.Mode != engine.ModeFull || first.Basis != engine.BasisValid {
		t.Fatalf("first scan: mode=%s basis=%s", first.Mode, first.Basis)
	}

	// "aa bb" near the old tail and "cc dd" in the appended block, so rule
	// "pair" can only complete across the splice point.
	prefix := sampleData()
	extra := make([]byte, 32)
	copy(extra[0:2], []byte{0xaa, 0xbb})
	copy(extra[2:4], []byte{0xcc, 0xdd})
	copy(extra[8:12], []byte{0x50, 0x4b, 0x03, 0x04})

	appendFile(t, target, extra)
	second := eng.Scan(target)
	logStats(t, second)
	if second.Status != engine.StatusOK {
		t.Fatalf("incremental status=%s err=%s", second.Status, second.Error)
	}
	if second.Mode != engine.ModeIncremental || second.Basis != engine.BasisReused {
		t.Fatalf("want INCREMENTAL/REUSED, got %s/%s", second.Mode, second.Basis)
	}
	if second.Stats.BytesProcessed != int64(len(extra)) {
		t.Fatalf("processed=%d, want only the %d appended bytes",
			second.Stats.BytesProcessed, len(extra))
	}
	if second.Stats.BytesReused != int64(len(prefix)) {
		t.Fatalf("reused=%d, want prefix %d", second.Stats.BytesReused, len(prefix))
	}

	// Reference: a fresh engine scanning the whole content from zero.
	refData := append(append([]byte(nil), prefix...), extra...)
	refPath := writeTarget(t, dir, "ref.bin", refData)
	ref := newEngine(t, dir, testRules, 4096).Scan(refPath)
	logStats(t, ref)
	if !hitsEqual(ref.Hits, second.Hits) {
		t.Fatalf("incremental vs full hits differ:\nfull=%+v\ninc =%+v",
			ref.Hits, second.Hits)
	}

	// Unchanged rescan: REUSE with zero read and zero processing.
	third := eng.Scan(target)
	logStats(t, third)
	if third.Mode != engine.ModeReuse || third.Stats.BytesProcessed != 0 ||
		third.Stats.BytesRead != 0 || !third.Cached {
		t.Fatalf("unchanged rescan: mode=%s cached=%v stats=%+v",
			third.Mode, third.Cached, third.Stats)
	}
	if !hitsEqual(third.Hits, ref.Hits) {
		t.Fatalf("reuse hits differ: %+v", third.Hits)
	}
}

// TestBasisInvalidatedOnMutation covers rewrite-in-place, truncation and
// whole-path replacement: the basis must be discarded, a full scan done, and
// the outcome distinguished from a clean first scan.
func TestBasisInvalidatedOnMutation(t *testing.T) {
	dir := t.TempDir()

	t.Run("rewritten-in-place", func(t *testing.T) {
		eng := newEngine(t, dir, testRules, 32)
		p := writeTarget(t, dir, "rw.bin", sampleData())
		if r := eng.Scan(p); r.Status != engine.StatusOK {
			t.Fatal(r.Error)
		}
		changed := sampleData()
		changed[64] = 0xff // destroy "aa bb" inside the old prefix
		if err := os.WriteFile(p, changed, 0o644); err != nil {
			t.Fatal(err)
		}
		r := eng.Scan(p)
		logStats(t, r)
		if r.Mode != engine.ModeFull || r.Basis != engine.BasisInvalidated ||
			r.BasisReason != engine.ReasonRewritten {
			t.Fatalf("mode=%s basis=%s reason=%s", r.Mode, r.Basis, r.BasisReason)
		}
		for _, h := range r.Hits {
			if h.RuleID == "pair" {
				t.Fatalf("rewritten content still reported pair hit: %+v", r.Hits)
			}
		}
	})

	t.Run("truncated", func(t *testing.T) {
		eng := newEngine(t, dir, testRules, 32)
		p := writeTarget(t, dir, "tr.bin", sampleData())
		if r := eng.Scan(p); r.Status != engine.StatusOK {
			t.Fatal(r.Error)
		}
		// Smaller than every signature in the rule file.
		if err := os.Truncate(p, 3); err != nil {
			t.Fatal(err)
		}
		r := eng.Scan(p)
		logStats(t, r)
		if r.Mode != engine.ModeFull || r.Basis != engine.BasisInvalidated ||
			r.BasisReason != engine.ReasonTruncated {
			t.Fatalf("mode=%s basis=%s reason=%s", r.Mode, r.Basis, r.BasisReason)
		}
		if len(r.Hits) != 0 {
			t.Fatalf("3-byte file must have no hits, got %+v", r.Hits)
		}
	})

	t.Run("replaced-at-path", func(t *testing.T) {
		eng := newEngine(t, dir, testRules, 32)
		p := filepath.Join(dir, "rot.bin")
		if err := os.WriteFile(p, sampleData(), 0o644); err != nil {
			t.Fatal(err)
		}
		if r := eng.Scan(p); r.Status != engine.StatusOK {
			t.Fatal(r.Error)
		}
		other := make([]byte, 128)
		copy(other, sampleData())
		copy(other[0:4], []byte{0x50, 0x4b, 0x03, 0x04})
		tmp := filepath.Join(dir, "rot.tmp")
		if err := os.WriteFile(tmp, other, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, p); err != nil {
			t.Fatal(err)
		}
		r := eng.Scan(p)
		logStats(t, r)
		if r.Mode != engine.ModeFull || r.Basis != engine.BasisInvalidated ||
			r.BasisReason != engine.ReasonTruncated {
			t.Fatalf("mode=%s basis=%s reason=%s", r.Mode, r.Basis, r.BasisReason)
		}
		fresh := newEngine(t, t.TempDir(), testRules, 4096)
		freshPath := writeTarget(t, dir, "rot-fresh.bin", other)
		if !hitsEqual(r.Hits, fresh.Scan(freshPath).Hits) {
			t.Fatalf("replacement scan hits must equal a plain fresh scan: %+v", r.Hits)
		}
	})
}

// TestAppendDuringScanIsNotDirty appends bytes mid incremental scan: the
// result must equal the current full content or be explicitly marked
// incomplete, never silently miss the new bytes. It must converge later.
func TestAppendDuringScanIsNotDirty(t *testing.T) {
	dir := t.TempDir()
	eng := newEngine(t, dir, testRules, 32)
	target := writeTarget(t, dir, "race.bin", sampleData())
	if r := eng.Scan(target); r.Status != engine.StatusOK {
		t.Fatal(r.Error)
	}

	extra := make([]byte, 64)
	copy(extra[10:14], []byte{0x50, 0x4b, 0x03, 0x04})
	eng.SetOnChunk(func(path string, n int) {
		if path == target && n == 1 {
			appendFile(t, path, extra)
		}
	})

	r := eng.Scan(target)
	logStats(t, r)
	eng.SetOnChunk(nil)

	current, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	refDir := t.TempDir()
	refPath := writeTarget(t, refDir, "race-ref.bin", current)
	full := newEngine(t, refDir, testRules, 4096).Scan(refPath)

	switch r.Status {
	case engine.StatusOK:
		if !hitsEqual(r.Hits, full.Hits) {
			t.Fatalf("OK result hid an append:\ngot =%+v\nwant=%+v", r.Hits, full.Hits)
		}
	case engine.StatusModified, engine.StatusTruncated:
		if len(r.Hits) != 0 {
			t.Fatal("incomplete scan must not return hits")
		}
		t.Logf("incomplete content correctly reported as %s: %s", r.Status, r.Error)
	default:
		t.Fatalf("unexpected status %s: %s", r.Status, r.Error)
	}

	again := eng.Scan(target)
	logStats(t, again)
	if again.Status != engine.StatusOK || !hitsEqual(again.Hits, full.Hits) {
		t.Fatalf("follow-up scan did not converge: status=%s hits=%+v want=%+v",
			again.Status, again.Hits, full.Hits)
	}
}

// TestCacheCapacityEviction checks LRU behavior in represented-bytes terms
// and proves eviction never changes hits.
func TestCacheCapacityEviction(t *testing.T) {
	dir := t.TempDir()
	eng := newEngine(t, dir, testRules, 64)
	// Budget strictly below two 128-byte entries: after both are scanned,
	// LRU must have evicted the first one.
	eng.SetCacheMaxBytes(128)

	a := writeTarget(t, dir, "a.bin", sampleData())
	b := writeTarget(t, dir, "b.bin", sampleData())

	ra := eng.Scan(a)
	rb := eng.Scan(b)
	logStats(t, ra)
	logStats(t, rb)
	if n, sz := eng.CacheStats(); n != 1 || sz != 128 {
		t.Fatalf("cache=%d entries, %d bytes; want 1/128", n, sz)
	}

	ra2 := eng.Scan(a)
	logStats(t, ra2)
	if ra2.Mode != engine.ModeFull || ra2.Basis != engine.BasisInvalidated ||
		ra2.BasisReason != engine.ReasonEvicted {
		t.Fatalf("evicted-then-rescan: mode=%s basis=%s reason=%s",
			ra2.Mode, ra2.Basis, ra2.BasisReason)
	}
	if !hitsEqual(ra.Hits, ra2.Hits) {
		t.Fatalf("eviction changed hits:\nbefore=%+v\nafter =%+v", ra.Hits, ra2.Hits)
	}
	if n, _ := eng.CacheStats(); n != 1 {
		t.Fatalf("rescanning a must evict b again, entries=%d", n)
	}

	// a is now the LRU survivor; rescanning it again must reuse.
	if ra3 := eng.Scan(a); ra3.Mode != engine.ModeReuse {
		t.Fatalf("surviving entry should reuse, mode=%s", ra3.Mode)
	}
	// b was evicted: it rescans as a clean full scan with unchanged hits.
	rb2 := eng.Scan(b)
	logStats(t, rb2)
	if rb2.Mode != engine.ModeFull || rb2.BasisReason != engine.ReasonEvicted ||
		!hitsEqual(rb.Hits, rb2.Hits) {
		t.Fatalf("evicted b: mode=%s reason=%s hitsEqual=%v",
			rb2.Mode, rb2.BasisReason, hitsEqual(rb.Hits, rb2.Hits))
	}
}

// TestReloadInvalidatesIncrementalBasis: after a rule change an incremental
// continuation under the old rules is forbidden; the whole file is rescanned
// under the new version.
func TestReloadInvalidatesIncrementalBasis(t *testing.T) {
	dir := t.TempDir()
	rp := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rp, []byte(testRules), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{RulePaths: []string{rp}, ChunkSize: 32})
	if err != nil {
		t.Fatal(err)
	}
	target := writeTarget(t, dir, "f.bin", sampleData())

	first := eng.Scan(target)
	logStats(t, first)
	appendFile(t, target, make([]byte, 16))

	if err := os.WriteFile(rp, []byte(zipOnlyRules), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := eng.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := eng.CacheStats(); n != 0 {
		t.Fatalf("reload must evict old-version bases, entries=%d", n)
	}

	r := eng.Scan(target)
	logStats(t, r)
	if r.RuleVersion != set.Version {
		t.Fatalf("result version=%s, want %s", r.RuleVersion, set.Version)
	}
	if r.Mode != engine.ModeFull || r.Basis != engine.BasisInvalidated ||
		r.BasisReason != engine.ReasonRuleVer {
		t.Fatalf("after reload must be FULL/INVALIDATED/RULE_VERSION_CHANGED, got %s/%s/%s",
			r.Mode, r.Basis, r.BasisReason)
	}
	for _, h := range r.Hits {
		if h.RuleID != "zip" {
			t.Fatalf("old rule leaked after reload: %+v", r.Hits)
		}
	}

	// Append again: now incremental continuation works under the new rules.
	extra := make([]byte, 16)
	copy(extra[4:8], []byte{0x50, 0x4b, 0x03, 0x04})
	appendFile(t, target, extra)
	r2 := eng.Scan(target)
	logStats(t, r2)
	if r2.Mode != engine.ModeIncremental || r2.RuleVersion != set.Version {
		t.Fatalf("post-reload append: mode=%s version=%s", r2.Mode, r2.RuleVersion)
	}
	current, _ := os.ReadFile(target)
	full := scanFileFresh(t, dir, rp, current)
	if !hitsEqual(r2.Hits, full) {
		t.Fatalf("post-reload incremental hits differ:\ninc=%+v\nfull=%+v", r2.Hits, full)
	}
}

// scanFileFresh writes data to a new temp file and scans it with a fresh
// engine loading the given rule file, returning the full-scan hits.
func scanFileFresh(t *testing.T, dir, rulesPath string, data []byte) []engine.Hit {
	t.Helper()
	eng, err := engine.New(engine.Config{RulePaths: []string{rulesPath}, ChunkSize: 4096})
	if err != nil {
		t.Fatal(err)
	}
	p := writeTarget(t, dir, filepath.Base(rulesPath)+".target", data)
	r := eng.Scan(p)
	if r.Status != engine.StatusOK {
		t.Fatalf("fresh scan: %s: %s", r.Status, r.Error)
	}
	return r.Hits
}

// TestConcurrentAppendAndReload mixes same-file concurrent scans, tail
// appends and rule hot reloads against a bounded cache: nothing may crash or
// race, and every result's counters must stay self-consistent.
func TestConcurrentAppendAndReload(t *testing.T) {
	dir := t.TempDir()
	rp := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rp, []byte(testRules), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{
		RulePaths: []string{rp}, ChunkSize: 29, CacheMaxBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}

	files := make([]string, 3)
	for i := range files {
		files[i] = writeTarget(t, dir, fmt.Sprintf("c%d.bin", i), sampleData())
	}

	var mu sync.Mutex
	var failures []string
	record := func(format string, args ...any) {
		mu.Lock()
		failures = append(failures, fmt.Sprintf(format, args...))
		mu.Unlock()
	}

	var wg sync.WaitGroup

	block := make([]byte, 40)
	copy(block[2:6], []byte{0x50, 0x4b, 0x03, 0x04})

	// Appender.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			appendFile(t, files[i%len(files)], block)
		}
	}()

	// Reloader.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, body := range []string{zipOnlyRules, testRules, zipOnlyRules, testRules} {
			if err := os.WriteFile(rp, []byte(body), 0o644); err != nil {
				record("write rules: %v", err)
				return
			}
			if _, err := eng.Reload(); err != nil {
				record("reload: %v", err)
				return
			}
		}
	}()

	// Scanners, several per file to exercise same-file singleflight.
	for worker := 0; worker < 6; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				f := files[i%len(files)]
				r := eng.Scan(f)
				switch r.Status {
				case engine.StatusOK:
					if r.Stats.BytesProcessed+r.Stats.BytesReused != r.Stats.FileSize {
						record("stats inconsistent: processed=%d reused=%d size=%d",
							r.Stats.BytesProcessed, r.Stats.BytesReused, r.Stats.FileSize)
					}
					for _, h := range r.Hits {
						if h.Offset < 0 || h.Offset >= r.Stats.FileSize {
							record("hit offset %d outside file size %d",
								h.Offset, r.Stats.FileSize)
						}
					}
					if r.Mode == engine.ModeIncremental &&
						r.Stats.BytesProcessed >= r.Stats.FileSize {
						record("incremental processed the whole file: %+v", r.Stats)
					}
					logStats(t, r)
				case engine.StatusModified, engine.StatusTruncated:
					// allowed: raced with the appender
				default:
					record("unexpected status %s: %s", r.Status, r.Error)
				}
			}
		}()
	}
	wg.Wait()

	for _, msg := range failures {
		t.Error(msg)
	}

	if err := os.WriteFile(rp, []byte(testRules), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Reload(); err != nil {
		t.Fatal(err)
	}
	for i, f := range files {
		r := eng.Scan(f)
		current, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		want := scanFileFresh(t, t.TempDir(), rp, current)
		if !hitsEqual(r.Hits, want) {
			t.Fatalf("file %d final hits mismatch:\ngot =%+v\nwant=%+v",
				i, r.Hits, want)
		}
		logStats(t, r)
	}
}

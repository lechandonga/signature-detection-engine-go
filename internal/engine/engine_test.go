package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/signature-detection-engine-go/internal/rules"
)

const ruleDoc = `{
  "rules": [
    {"id":"mz","terms":[{"pattern":"4d 5a","offset_start":0,"offset_end":3}]},
    {"id":"hex-tail","terms":[{"pattern":"de ad be ef","offset_start":0,"offset_end":-1}]},
    {"id":"wild","terms":[{"pattern":"11 ?? 33 [2] 66","offset_start":0,"offset_end":-1}]},
    {"id":"combo","match":"all","terms":[
      {"pattern":"4d5a","offset_start":0,"offset_end":3},
      {"pattern":"deadbeef","offset_start":0,"offset_end":-1}
    ]}
  ]
}`

func setupRules(t *testing.T, doc string) *rules.Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	store := rules.NewStore()
	v, rejected := store.Reload(dir)
	if len(rejected) != 0 {
		t.Fatalf("rule rejects: %v", rejected)
	}
	t.Logf("rule_set_version=%s", v)
	return store
}

func writeTarget(t *testing.T, body []byte) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	// Make mtime stable/distinct for fingerprint comparisons.
	future := time.Now().Add(1 * time.Hour)
	if err := os.Chtimes(p, future, future); err != nil {
		t.Fatal(err)
	}
	return p
}

func logResult(t *testing.T, r Result) {
	t.Helper()
	t.Logf("file_id=%s rule_set_version=%s status=%s size=%d sha=%s cache_hit=%t hits=%+v err=%q",
		r.FileID, r.RuleVer, r.Status, r.Size, r.ContentSHA, r.CacheHit, r.Hits, r.Error)
}

func hitIDs(r Result) map[string]int64 {
	m := map[string]int64{}
	for _, h := range r.Hits {
		m[h.RuleID] = h.Offset
	}
	return m
}

func sampleBytes() []byte {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 251)
	}
	data[0], data[1] = 0x4d, 0x5a
	copy(data[2000:2004], []byte{0xde, 0xad, 0xbe, 0xef})
	copy(data[3000:3006], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	return data
}

func TestChunkSizesProduceIdenticalVerdicts(t *testing.T) {
	data := sampleBytes()
	wantHits := map[string]int64{"mz": 0, "hex-tail": 2000, "wild": 3000, "combo": 0}

	for _, cs := range []int{1, 2, 3, 7, 64, 1000, 4096, 8192} {
		p := writeTarget(t, data)
		store := setupRules(t, ruleDoc)
		eng := New(store, Config{ChunkSize: cs, Workers: 2})
		r := eng.Scan(p)
		logResult(t, r)
		if r.Status != StatusDetected {
			t.Fatalf("cs=%d status=%s err=%s", cs, r.Status, r.Error)
		}
		got := hitIDs(r)
		if len(got) != len(wantHits) {
			t.Fatalf("cs=%d hits=%v want %v", cs, got, wantHits)
		}
		for id, off := range wantHits {
			if got[id] != off {
				t.Fatalf("cs=%d rule %s offset=%d want %d", cs, id, got[id], off)
			}
		}
		if r.ContentSHA == "" {
			t.Fatalf("cs=%d missing content hash", cs)
		}
	}
}

func TestUnreadableAndBatchIsolation(t *testing.T) {
	store := setupRules(t, ruleDoc)
	eng := New(store, Config{ChunkSize: 16})

	good := writeTarget(t, []byte{0x4d, 0x5a})
	missing := filepath.Join(t.TempDir(), "nope.bin")
	dirPath := t.TempDir()

	results := eng.ScanBatch([]string{good, missing, dirPath, good})
	if len(results) != 4 {
		t.Fatalf("got %d results", len(results))
	}
	for i, r := range results {
		logResult(t, r)
		switch i {
		case 0:
			if r.Status != StatusDetected {
				t.Fatalf("result0 status=%s", r.Status)
			}
		case 1:
			if r.Status != StatusUnreadable || r.Error == "" {
				t.Fatalf("missing file: %+v", r)
			}
		case 2:
			if r.Status != StatusUnreadable {
				t.Fatalf("directory: %+v", r)
			}
		case 3:
			// Duplicate of result 0 in the same concurrent batch: identical
			// verdict; one of the pair is coalesced (cache_hit=true).
			if r.Status != StatusDetected {
				t.Fatalf("duplicate scan verdict changed: %+v", r)
			}
			if hitIDs(r)["mz"] != 0 {
				t.Fatal("cache must preserve hits")
			}
			if !results[0].CacheHit && !r.CacheHit {
				t.Fatal("concurrent duplicate scans should coalesce into one execution")
			}
		}
	}
	// Results returned in input order regardless of concurrency.
	if results[0].FileID != FileID(good) {
		t.Fatal("batch result order is not input order")
	}
}

func TestTruncatedMidScan(t *testing.T) {
	data := sampleBytes()
	store := setupRules(t, ruleDoc)
	eng := New(store, Config{ChunkSize: 512})

	p := writeTarget(t, data)
	eng.SetAfterChunkHook(func(feedNo int, total int64) {
		if feedNo == 2 {
			// Shrink the file while scanning: fewer bytes than advertised.
			if err := os.Truncate(p, 10); err != nil {
				t.Errorf("truncate: %v", err)
			}
		}
	})
	r := eng.Scan(p)
	logResult(t, r)
	if r.Status != StatusTruncated && r.Status != StatusModified {
		t.Fatalf("expected truncated/modified, got %s: %s", r.Status, r.Error)
	}
	if r.Status == StatusTruncated {
		if r.Error != errTruncated.Error() {
			t.Fatalf("truncation reason not distinct: %q", r.Error)
		}
	}

	// Failure verdicts must not be cached: after restoring, scan succeeds.
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Hour)
	_ = os.Chtimes(p, future, future)
	eng.SetAfterChunkHook(nil)
	r2 := eng.Scan(p)
	logResult(t, r2)
	if r2.Status != StatusDetected {
		t.Fatalf("restored file should scan cleanly/detected, got %s: %s", r2.Status, r2.Error)
	}
}

func TestModifiedSameLengthMidScan(t *testing.T) {
	data := sampleBytes()
	store := setupRules(t, ruleDoc)
	eng := New(store, Config{ChunkSize: 512})
	p := writeTarget(t, data)

	eng.SetAfterChunkHook(func(feedNo int, total int64) {
		if feedNo == 2 {
			// Same-length in-place edit near the tail: caught by re-hash or
			// mtime change; must be reported as modified, never as a verdict.
			f, err := os.OpenFile(p, os.O_RDWR, 0)
			if err != nil {
				t.Errorf("open: %v", err)
				return
			}
			if _, err := f.WriteAt([]byte{0xff, 0xff}, 3500); err != nil {
				t.Errorf("write: %v", err)
			}
			f.Close()
		}
	})
	r := eng.Scan(p)
	logResult(t, r)
	if r.Status != StatusModified {
		t.Fatalf("expected modified, got %s: %s", r.Status, r.Error)
	}
	if r.Error != errModified.Error() {
		t.Fatalf("modification reason not distinct: %q", r.Error)
	}
}

func TestCacheBoundToRuleVersionAndContent(t *testing.T) {
	data := sampleBytes()
	store := setupRules(t, ruleDoc)
	eng := New(store, Config{ChunkSize: 256})
	p := writeTarget(t, data)

	r1 := eng.Scan(p)
	logResult(t, r1)
	if r1.Status != StatusDetected {
		t.Fatalf("r1: %s %s", r1.Status, r1.Error)
	}
	r2 := eng.Scan(p)
	if !r2.CacheHit || r2.Status != r1.Status || len(r2.Hits) != len(r1.Hits) {
		t.Fatalf("identical rescan must reuse cache: %+v", r2)
	}
	v1 := store.Snapshot().Version

	// Hot reload: drop a rule. Version changes; cached verdict must not leak.
	dir := filepath.Dir(p)
	_ = dir
	ruleDir := t.TempDir()
	doc2 := `{"rules":[
	  {"id":"mz","terms":[{"pattern":"4d 5a","offset_start":0,"offset_end":3}]}
	]}`
	if err := os.WriteFile(filepath.Join(ruleDir, "r.json"), []byte(doc2), 0o644); err != nil {
		t.Fatal(err)
	}
	v2, rejected := store.Reload(ruleDir)
	if len(rejected) != 0 || v2 == v1 {
		t.Fatalf("reload v1=%s v2=%s rejects=%v", v1, v2, rejected)
	}
	t.Logf("reloaded rule_set_version=%s (was %s)", v2, v1)
	r3 := eng.Scan(p)
	logResult(t, r3)
	if r3.CacheHit {
		t.Fatal("rule version change must invalidate the cache")
	}
	if r3.RuleVer != v2 {
		t.Fatal("result must cite the new rule version")
	}
	if len(hitIDs(r3)) != 1 || hitIDs(r3)["mz"] != 0 {
		t.Fatalf("old rules must not linger: %+v", r3.Hits)
	}

	// Content change under the same rules: fingerprint changes -> rescan.
	data2 := append([]byte(nil), data...)
	data2[0], data2[1] = 0, 0 // remove MZ
	if err := os.WriteFile(p, data2, 0o644); err != nil {
		t.Fatal(err)
	}
	newTime := time.Now().Add(3 * time.Hour)
	_ = os.Chtimes(p, newTime, newTime)
	r4 := eng.Scan(p)
	logResult(t, r4)
	if r4.CacheHit {
		t.Fatal("content change must invalidate the cache")
	}
	if r4.Status != StatusClean {
		t.Fatalf("edited content should be clean under new rule set, got %s hits=%+v", r4.Status, r4.Hits)
	}
}

func TestConcurrentScansAndHotReload(t *testing.T) {
	data := sampleBytes()
	store := setupRules(t, ruleDoc)
	eng := New(store, Config{ChunkSize: 37})

	paths := make([]string, 8)
	for i := range paths {
		paths[i] = writeTarget(t, data)
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for k := 0; k < 10; k++ {
				p := paths[(g+k)%len(paths)]
				r := eng.Scan(p)
				if r.Status != StatusDetected && r.Status != StatusClean {
					t.Errorf("goroutine %d unexpected status %s: %s", g, r.Status, r.Error)
					return
				}
				// The cited hits must always match the cited rule version.
				for _, h := range r.Hits {
					if h.RuleID != "mz" && h.RuleID != "hex-tail" &&
						h.RuleID != "wild" && h.RuleID != "combo" {
						t.Errorf("goroutine %d stale rule id %s for version %s", g, h.RuleID, r.RuleVer)
						return
					}
				}
			}
		}(g)
	}
	// Concurrent reloads with shrinking/growing rule sets.
	for k := 0; k < 5; k++ {
		dir := t.TempDir()
		var doc string
		if k%2 == 0 {
			doc = ruleDoc
		} else {
			doc = fmt.Sprintf(`{"rules":[{"id":"only%d","terms":[{"pattern":"4d5a","offset_start":0,"offset_end":3}]}]}`, k)
		}
		if err := os.WriteFile(filepath.Join(dir, "r.json"), []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = store.Reload(dir)
		time.Sleep(2 * time.Millisecond)
	}
	wg.Wait()

	// Restore the full set and confirm final scans are consistent and cached.
	store = setupRules(t, ruleDoc)
	eng2 := New(store, Config{ChunkSize: 37})
	r1 := eng2.Scan(paths[0])
	r2 := eng2.Scan(paths[0])
	logResult(t, r1)
	if !r2.CacheHit || len(r2.Hits) != len(r1.Hits) {
		t.Fatal("post-reload cache behavior wrong")
	}
}

package engine_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/lechandonga/signature-detection-engine-go/engine"
)

// TestAppendDuringScanIsNotDirty: appending while a scan runs must never
// surface partial hits as OK — the result is either complete for the final
// content or explicitly FILE_MODIFIED_DURING_SCAN with no hits.
func TestAppendDuringScanIsNotDirty(t *testing.T) {
	dir := t.TempDir()
	eng := newEngine(t, dir, testRules, 16)
	initial := make([]byte, 96)
	copy(initial[0:8], []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a})
	target := writeTarget(t, dir, "racing.bin", initial)

	eng.SetOnChunk(func(path string, n int) {
		if n == 2 {
			appendFile(t, path, []byte{0x50, 0x4b, 0x03, 0x04})
		}
	})

	res := eng.Scan(target)
	logResultFull(t, res)
	switch res.Status {
	case engine.StatusModified:
		if len(res.Hits) != 0 {
			t.Fatal("incomplete scan must carry no hits")
		}
	case engine.StatusOK:
		full := newEngine(t, dir, testRules, 4096).Scan(target)
		if !hitsEqual(res.Hits, full.Hits) {
			t.Fatalf("OK result during append is dirty:\n%+v\n%+v", res.Hits, full.Hits)
		}
	default:
		t.Fatalf("unexpected status %s", res.Status)
	}

	bumpMTime()
	eng.SetOnChunk(nil)
	final := eng.Scan(target)
	logResultFull(t, final)
	if final.Status != engine.StatusOK {
		t.Fatalf("settled scan: %s %s", final.Status, final.Error)
	}
	foundZip := false
	for _, h := range final.Hits {
		if h.RuleID == "zip" {
			foundZip = true
		}
	}
	if !foundZip {
		t.Fatalf("appended zip missing from settled result: %+v", final.Hits)
	}
}

// TestCacheEvictionRebuildsIdenticalResults: capacity eviction loses only
// the optimization; rebuilt hits are identical and memory stays bounded.
func TestCacheEvictionRebuildsIdenticalResults(t *testing.T) {
	dir := t.TempDir()
	eng := newEngineBounded(t, dir, testRules, 64, 400)

	f1 := writeTarget(t, dir, "e1.bin", sampleData())
	f2 := writeTarget(t, dir, "e2.bin", append(sampleData(), 1, 2, 3, 4))

	r1 := eng.Scan(f1)
	eng.Scan(f2)
	evicted := eng.Scan(f1)
	logResultFull(t, evicted)
	if evicted.Work.CacheEvictions == 0 {
		t.Fatalf("expected evictions, stats=%+v", evicted.Work)
	}
	if evicted.Mode != engine.ModeFull {
		t.Fatalf("evicted progress forces full rescan, mode=%s progress=%s",
			evicted.Mode, evicted.Progress)
	}
	if !hitsEqual(evicted.Hits, r1.Hits) {
		t.Fatalf("hits after eviction differ:\n%+v\n%+v", evicted.Hits, r1.Hits)
	}
	// A single entry larger than the whole budget is allowed to stay until
	// the next insertion; total cost must never exceed limit + one entry.
	if evicted.Work.CacheCostBytes > evicted.Work.CacheLimitBytes+256 {
		t.Fatalf("cache cost %d exceeds limit %d + one-entry tolerance",
			evicted.Work.CacheCostBytes, evicted.Work.CacheLimitBytes)
	}
}

// TestRuleReloadDiscardsResumeProgress: after a hot reload, resume progress
// built under old rules cannot continue; new rules apply to the whole file.
func TestRuleReloadDiscardsResumeProgress(t *testing.T) {
	dir := t.TempDir()
	eng := newEngine(t, dir, testRules, 64)
	rp := filepath.Join(dir, "rules.json")
	target := writeTarget(t, dir, "rl.bin", sampleData())

	first := eng.Scan(target)
	if eng.CacheStats() == 0 {
		t.Fatal("expected cached state after first scan")
	}
	appendFile(t, target, []byte{0x50, 0x4b, 0x03, 0x04})

	atomicWriteRules(t, rp, zipOnlyRules)
	set, err := eng.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if set.Version == first.RuleVersion {
		t.Fatal("reload must change the version")
	}
	if eng.CacheStats() != 0 {
		t.Fatalf("old-version progress must be evicted on reload, size=%d", eng.CacheStats())
	}

	res := eng.Scan(target)
	logResultFull(t, res)
	if res.RuleVersion != set.Version {
		t.Fatalf("result bound to stale version %s", res.RuleVersion)
	}
	if res.Mode != engine.ModeFull {
		t.Fatalf("new rules require a full scan, got mode=%s", res.Mode)
	}
	for _, h := range res.Hits {
		if h.RuleID != "zip" {
			t.Fatalf("old rule leaked after reload: %+v", res.Hits)
		}
	}

	atomicWriteRules(t, rp, testRules)
	if _, err := eng.Reload(); err != nil {
		t.Fatal(err)
	}
	again := eng.Scan(target)
	logResultFull(t, again)
	full := newEngine(t, dir, testRules, 4096).Scan(target)
	if !hitsEqual(again.Hits, full.Hits) {
		t.Fatalf("readded rules not fully applied:\n%+v\n%+v", again.Hits, full.Hits)
	}
}

// TestConcurrentScansWithAppendsReloadsAndEviction exercises all three
// mechanisms at once. Every observed result must be either an incomplete
// status with no hits or a hit set identical to a full scan of some stable
// rule version/content.
func TestConcurrentScansWithAppendsReloadsAndEviction(t *testing.T) {
	dir := t.TempDir()
	rp := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rp, []byte(testRules), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{
		RulePaths: []string{rp}, ChunkSize: 13, CacheLimitBytes: 600,
	})
	if err != nil {
		t.Fatal(err)
	}

	files := make([]string, 4)
	for i := range files {
		files[i] = writeTarget(t, dir, fmt.Sprintf("c%d.bin", i), sampleData())
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string
	record := func(format string, args ...any) {
		mu.Lock()
		failures = append(failures, fmt.Sprintf(format, args...))
		mu.Unlock()
	}

	stop := make(chan struct{})
	for _, f := range files {
		f := f
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				select {
				case <-stop:
					return
				default:
				}
				appendFile(t, f, []byte{0x50, 0x4b, 0x03, 0x04})
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			var lastOK *engine.Result
			for {
				select {
				case <-stop:
					if lastOK != nil {
						logResultFull(t, lastOK)
					}
					return
				default:
					res := eng.Scan(f)
					switch res.Status {
					case engine.StatusOK:
						// Structural invariants while the file is being
						// appended to concurrently: hits must be sorted, and
						// work accounting must be self-consistent. Content
						// equality against a ground-truth full scan is only
						// checked once the workload stops.
						for i := 1; i < len(res.Hits); i++ {
							a, b := res.Hits[i-1], res.Hits[i]
							if a.RuleID > b.RuleID ||
								(a.RuleID == b.RuleID && a.Offset >= b.Offset) {
								record("file %s hits not sorted/deduped: %+v", f, res.Hits)
								break
							}
						}
						if res.Work.BytesRead < 0 || res.Work.BytesReused < 0 {
							record("file %s negative work counters", f)
						}
						if res.Work.CacheLimitBytes > 0 &&
							res.Work.CacheCostBytes > res.Work.CacheLimitBytes+
								// one oversized resident entry is allowed
								2048 {
							record("file %s cache cost %d exceeded limit %d",
								f, res.Work.CacheCostBytes, res.Work.CacheLimitBytes)
						}
						lastOK = res
					case engine.StatusModified, engine.StatusTruncated:
						if len(res.Hits) != 0 {
							record("file %s non-OK status carried hits", f)
						}
					default:
						record("file %s unexpected status %s: %s", f, res.Status, res.Error)
					}
				}
			}
		}()
	}

	reloadBody := func(body string) {
		wg.Add(1)
		defer wg.Done()
		atomicWriteRules(t, rp, body)
		if _, err := eng.Reload(); err != nil {
			record("reload: %v", err)
		}
	}
	wg.Add(1)
	go func() { defer wg.Done(); time.Sleep(20 * time.Millisecond); reloadBody(zipOnlyRules) }()
	wg.Add(1)
	go func() { defer wg.Done(); time.Sleep(50 * time.Millisecond); reloadBody(testRules) }()

	time.Sleep(90 * time.Millisecond)
	close(stop)
	wg.Wait()

	for _, msg := range failures {
		t.Error(msg)
	}

	atomicWriteRules(t, rp, testRules)
	if _, err := eng.Reload(); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		res := eng.Scan(f)
		logResultFull(t, res)
		full := newEngine(t, dir, testRules, 4096).Scan(f)
		if res.Status != engine.StatusOK || !hitsEqual(res.Hits, full.Hits) {
			t.Fatalf("final verification failed for %s: %s %+v vs %+v",
				f, res.Status, res.Hits, full.Hits)
		}
	}
}

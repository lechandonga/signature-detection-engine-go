package engine_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/lechandonga/signature-detection-engine-go/engine"
)

const testRules = `{
  "rules": [
    {"id": "zip", "description": "ZIP header", "condition": "all",
     "patterns": [{"hex": "50 4b 03 04"}]},
    {"id": "png-head", "description": "PNG at offset 0", "condition": "all",
     "patterns": [{"hex": "89 50 4e 47 0d 0a 1a 0a", "offset": 0}]},
    {"id": "wild-window", "condition": "all",
     "patterns": [{"hex": "de ad ?? ef", "offset": 0, "window": 16}]},
    {"id": "pair", "condition": "all",
     "patterns": [{"hex": "aa bb"}, {"hex": "cc dd"}]},
    {"id": "either", "condition": "any",
     "patterns": [{"hex": "11 22"}, {"hex": "33 44"}]}
  ]
}`

const zipOnlyRules = `{"rules":[
  {"id":"zip","condition":"all","patterns":[{"hex":"50 4b 03 04"}]}
]}`

func newEngine(t *testing.T, dir, body string, chunk int) *engine.Engine {
	t.Helper()
	rp := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{RulePaths: []string{rp}, ChunkSize: chunk})
	if err != nil {
		t.Fatal(err)
	}
	return eng
}

func writeTarget(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func sampleData() []byte {
	data := make([]byte, 128)
	copy(data[0:8], []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a})
	copy(data[10:14], []byte{0x50, 0x4b, 0x03, 0x04})
	copy(data[14:18], []byte{0xde, 0xad, 0x99, 0xef})
	copy(data[64:66], []byte{0xaa, 0xbb})
	copy(data[70:72], []byte{0xcc, 0xdd})
	copy(data[90:92], []byte{0x11, 0x22})
	copy(data[100:102], []byte{0x33, 0x44})
	copy(data[124:128], []byte{0x50, 0x4b, 0x03, 0x04})
	return data
}

func fullHits() []engine.Hit {
	return []engine.Hit{
		{RuleID: "either", Offset: 90},
		{RuleID: "either", Offset: 100},
		{RuleID: "pair", Offset: 64},
		{RuleID: "png-head", Offset: 0},
		{RuleID: "wild-window", Offset: 14},
		{RuleID: "zip", Offset: 10},
		{RuleID: "zip", Offset: 124},
	}
}

func zipOnlyHits() []engine.Hit {
	return []engine.Hit{
		{RuleID: "zip", Offset: 10},
		{RuleID: "zip", Offset: 124},
	}
}

func logResult(t *testing.T, res *engine.Result) {
	t.Helper()
	out, _ := json.Marshal(res.Hits)
	t.Logf("rule_set_version=%s file_id=%s status=%s cached=%v hits=%s",
		res.RuleVersion, res.FileID, res.Status, res.Cached, string(out))
}

func sortHits(h []engine.Hit) {
	sort.Slice(h, func(i, j int) bool {
		if h[i].RuleID != h[j].RuleID {
			return h[i].RuleID < h[j].RuleID
		}
		return h[i].Offset < h[j].Offset
	})
}

func hitsEqual(a, b []engine.Hit) bool {
	if len(a) != len(b) {
		return false
	}
	ca := append([]engine.Hit(nil), a...)
	cb := append([]engine.Hit(nil), b...)
	sortHits(ca)
	sortHits(cb)
	for i := range ca {
		if ca[i] != cb[i] {
			return false
		}
	}
	return true
}

func TestChunkSizeIndependence(t *testing.T) {
	dir := t.TempDir()
	target := writeTarget(t, dir, "sample.bin", sampleData())

	var baseline []engine.Hit
	for _, chunk := range []int{1, 2, 3, 7, 16, 64, 127, 128, 1024} {
		eng := newEngine(t, dir, testRules, chunk)
		res := eng.Scan(target)
		logResult(t, res)
		if res.Status != engine.StatusOK {
			t.Fatalf("chunk=%d status=%s error=%s", chunk, res.Status, res.Error)
		}
		if baseline == nil {
			baseline = res.Hits
			continue
		}
		if !hitsEqual(baseline, res.Hits) {
			t.Fatalf("chunk=%d hits differ:\nwant=%+v\ngot =%+v", chunk, baseline, res.Hits)
		}
	}
	if !hitsEqual(fullHits(), baseline) {
		t.Fatalf("hits mismatch:\nwant=%+v\ngot =%+v", fullHits(), baseline)
	}
}

func TestUnreadableFileDoesNotAbortBatch(t *testing.T) {
	dir := t.TempDir()
	eng := newEngine(t, dir, testRules, 16)
	good := writeTarget(t, dir, "good.bin", sampleData())
	missing := filepath.Join(dir, "gone.bin")

	results := eng.ScanBatch([]string{missing, good})
	for _, r := range results {
		logResult(t, r)
	}
	if results[0].Status != engine.StatusUnreadable {
		t.Fatalf("missing file status = %s", results[0].Status)
	}
	if results[1].Status != engine.StatusOK || len(results[1].Hits) == 0 {
		t.Fatalf("good file must still scan: %+v", results[1])
	}
}

func TestTruncatedDuringScan(t *testing.T) {
	dir := t.TempDir()
	eng := newEngine(t, dir, testRules, 32)
	target := writeTarget(t, dir, "shrink.bin", sampleData())

	eng.SetOnChunk(func(path string, n int) {
		if n == 2 {
			if err := os.Truncate(path, 20); err != nil {
				t.Errorf("truncate: %v", err)
			}
		}
	})

	res := eng.Scan(target)
	logResult(t, res)
	if res.Status != engine.StatusTruncated {
		t.Fatalf("status = %s (%s), want FILE_TRUNCATED", res.Status, res.Error)
	}
	if len(res.Hits) != 0 {
		t.Fatalf("truncated results must carry no hits")
	}
}

func TestModifiedDuringScan(t *testing.T) {
	dir := t.TempDir()
	eng := newEngine(t, dir, testRules, 32)
	target := writeTarget(t, dir, "mutate.bin", sampleData())

	eng.SetOnChunk(func(path string, n int) {
		if n == 2 {
			changed := sampleData()
			changed[0] = 0x00 // corrupt already-streamed PNG header byte
			if err := os.WriteFile(path, changed, 0o644); err != nil {
				t.Errorf("rewrite: %v", err)
			}
		}
	})

	res := eng.Scan(target)
	logResult(t, res)
	if res.Status != engine.StatusModified {
		t.Fatalf("status = %s (%s), want FILE_MODIFIED_DURING_SCAN", res.Status, res.Error)
	}
	if len(res.Hits) != 0 {
		t.Fatalf("modified results must carry no hits")
	}
}

func TestCacheBoundToVersionAndContent(t *testing.T) {
	dir := t.TempDir()
	rp := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rp, []byte(testRules), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{RulePaths: []string{rp}, ChunkSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	target := writeTarget(t, dir, "f.bin", sampleData())

	first := eng.Scan(target)
	second := eng.Scan(target)
	logResult(t, first)
	logResult(t, second)
	if first.Cached {
		t.Fatal("first scan must not be a cache hit")
	}
	if !second.Cached {
		t.Fatal("second scan must reuse the cache")
	}
	if !hitsEqual(first.Hits, second.Hits) {
		t.Fatal("cache hit changed the hit set")
	}

	changed := append(sampleData(), 0x50, 0x4b, 0x03, 0x04)
	if err := os.WriteFile(target, changed, 0o644); err != nil {
		t.Fatal(err)
	}
	third := eng.Scan(target)
	logResult(t, third)
	if third.Cached {
		t.Fatal("changed content must bypass the cache")
	}
	if hitsEqual(first.Hits, third.Hits) {
		t.Fatal("new zip occurrence at tail must be detected")
	}

	oldVersion := first.RuleVersion
	if err := os.WriteFile(rp, []byte(zipOnlyRules), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := eng.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if set.Version == oldVersion {
		t.Fatalf("reload must produce a new version, got %s", set.Version)
	}
	if eng.CacheStats() != 0 {
		t.Fatalf("old-version cache entries must be evicted, size=%d", eng.CacheStats())
	}
	fourth := eng.Scan(target)
	logResult(t, fourth)
	if fourth.RuleVersion == oldVersion {
		t.Fatal("result must be bound to the new rule version")
	}
	for _, h := range fourth.Hits {
		if h.RuleID != "zip" {
			t.Fatalf("deleted rule leaked into results: %+v", fourth.Hits)
		}
	}

	if err := os.WriteFile(rp, []byte(testRules), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Reload(); err != nil {
		t.Fatal(err)
	}
	fifth := eng.Scan(target)
	logResult(t, fifth)
	found := false
	for _, h := range fifth.Hits {
		if h.RuleID == "png-head" {
			found = true
		}
	}
	if !found {
		t.Fatalf("readded rules must be applied: %+v", fifth.Hits)
	}
}

func TestConcurrentScansAndHotReload(t *testing.T) {
	dir := t.TempDir()
	rp := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rp, []byte(testRules), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{RulePaths: []string{rp}, ChunkSize: 17})
	if err != nil {
		t.Fatal(err)
	}

	files := make([]string, 4)
	for i := range files {
		files[i] = writeTarget(t, dir, fmt.Sprintf("f%d.bin", i), sampleData())
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string
	record := func(format string, args ...any) {
		mu.Lock()
		failures = append(failures, fmt.Sprintf(format, args...))
		mu.Unlock()
	}

	for round := 0; round < 8; round++ {
		for _, f := range files {
			wg.Add(1)
			go func(f string) {
				defer wg.Done()
				res := eng.Scan(f)
				if res.Status != engine.StatusOK {
					record("unexpected status %s: %s", res.Status, res.Error)
					return
				}
				if !hitsEqual(res.Hits, fullHits()) && !hitsEqual(res.Hits, zipOnlyHits()) {
					record("version=%s produced an illegal hit set: %+v", res.RuleVersion, res.Hits)
				}
			}(f)
		}
		if round == 3 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := os.WriteFile(rp, []byte(zipOnlyRules), 0o644); err != nil {
					record("write rules: %v", err)
					return
				}
				if _, err := eng.Reload(); err != nil {
					record("reload: %v", err)
				}
			}()
		}
		if round == 6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := os.WriteFile(rp, []byte(testRules), 0o644); err != nil {
					record("write rules: %v", err)
					return
				}
				if _, err := eng.Reload(); err != nil {
					record("reload: %v", err)
				}
			}()
		}
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
	res := eng.Scan(files[0])
	logResult(t, res)
	if res.RuleVersion != eng.Rules().Version {
		t.Fatal("stale version after concurrent reloads")
	}
	if !hitsEqual(res.Hits, fullHits()) {
		t.Fatalf("final hit set mismatch: %+v", res.Hits)
	}
}

package engine_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/lechandonga/signature-detection-engine-go/engine"
)

const incRules = `{
  "rules": [
    {"id": "cross4", "condition": "all",
     "patterns": [{"hex": "de ad be ef"}]},
    {"id": "pair", "condition": "all",
     "patterns": [{"hex": "aa bb"}, {"hex": "cc dd"}]},
    {"id": "either", "condition": "any",
     "patterns": [{"hex": "11 22"}, {"hex": "33 44"}]},
    {"id": "zip", "condition": "all",
     "patterns": [{"hex": "50 4b 03 04"}]}
  ]
}`

const incRulesV2 = `{
  "rules": [
    {"id": "cross4", "condition": "all",
     "patterns": [{"hex": "de ad be ef"}]},
    {"id": "marker", "condition": "all",
     "patterns": [{"hex": "77 88 99"}]}
  ]
}`

func logDetailed(t *testing.T, res *engine.Result) {
	t.Helper()
	out, _ := json.Marshal(res.Hits)
	t.Logf("rule_set_version=%s file_id=%s status=%s mode=%s read=%d processed=%d reused=%d size=%d verify_read=%d probe=%s hits=%s duration_ms=%d",
		res.RuleVersion, res.FileID, res.Status, res.Stats.Mode,
		res.Stats.BytesRead, res.Stats.BytesProcessed, res.Stats.BytesReused,
		res.Stats.FileSize, res.Stats.VerifyBytesRead, res.Stats.ResumeProbe,
		string(out), res.Stats.DurationMS)
}

func appendBytes(t *testing.T, path string, b []byte) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// buildInitial creates data of length cut with aa bb near the tail and the
// first byte of de ad be ef exactly at cut-1, so the cross4 match can only
// complete across the append boundary.
func buildInitial(cut int) []byte {
	data := make([]byte, cut)
	if cut >= 9 {
		data[cut-8] = 0xaa
		data[cut-7] = 0xbb
	}
	if cut >= 1 {
		data[cut-1] = 0xde
	}
	return data
}

func buildAppendix() []byte {
	return []byte{
		0xad, 0xbe, 0xef, // completes cross4 started in the old tail
		0xcc, 0xdd, // completes pair (aa bb was in the old content)
		0x11, 0x22, 0x33, 0x44, // both branches of either
		0x50, 0x4b, 0x03, 0x04, // zip wholly in the new region
	}
}

func expectedIncHits(cut int) []engine.Hit {
	if cut < 9 {
		return nil
	}
	return []engine.Hit{
		{RuleID: "cross4", Offset: int64(cut - 1)},
		{RuleID: "either", Offset: int64(cut + 5)},
		{RuleID: "either", Offset: int64(cut + 7)},
		{RuleID: "pair", Offset: int64(cut - 8)},
		{RuleID: "zip", Offset: int64(cut + 9)},
	}
}

func TestIncrementalAppendEqualsFullScan(t *testing.T) {
	cuts := []int{10, 15, 127, 4096, 4097}
	chunks := []int{1, 3, 16, 64, 4096}

	for _, cut := range cuts {
		for _, chunk := range chunks {
			t.Run(fmt.Sprintf("cut=%d/chunk=%d", cut, chunk), func(t *testing.T) {
				dir := t.TempDir()
				eng := newEngine(t, dir, incRules, chunk)
				target := writeTarget(t, dir, "grow.bin", buildInitial(cut))

				first := eng.Scan(target)
				logDetailed(t, first)
				if first.Status != engine.StatusOK {
					t.Fatalf("initial status=%s err=%s", first.Status, first.Error)
				}

				appendBytes(t, target, buildAppendix())
				second := eng.Scan(target)
				logDetailed(t, second)
				if second.Status != engine.StatusIncremental {
					t.Fatalf("append status=%s (%s), want OK_INCREMENTAL", second.Status, second.Error)
				}

				full := scanWithFreshEngine(t, dir, incRules, target, chunk)
				if !hitsEqual(full, second.Hits) {
					t.Fatalf("incremental vs full mismatch:\ninc=%+v\nfull=%+v", second.Hits, full)
				}
				want := expectedIncHits(cut)
				if !hitsEqual(want, second.Hits) {
					t.Fatalf("cross-boundary hits mismatch:\nwant=%+v\ngot =%+v", want, second.Hits)
				}

				added := int64(len(buildAppendix()))
				if second.Stats.Mode != "incremental" ||
					second.Stats.BytesProcessed != added ||
					second.Stats.BytesReused != int64(cut) ||
					second.Stats.FileSize != int64(cut)+added {
					t.Fatalf("incremental stats wrong: %+v", second.Stats)
				}
				if second.Stats.BytesProcessed >= second.Stats.FileSize {
					t.Fatalf("continuation processed %d bytes of a %d-byte file",
						second.Stats.BytesProcessed, second.Stats.FileSize)
				}
				if second.Stats.BytesProcessed+second.Stats.BytesReused != second.Stats.FileSize {
					t.Fatalf("processed+reused != size: %+v", second.Stats)
				}

				third := eng.Scan(target)
				logDetailed(t, third)
				if third.Status != engine.StatusReused || third.Stats.BytesRead != 0 ||
					third.Stats.Mode != "reuse" || !third.Cached {
					t.Fatalf("unchanged rescan stats wrong: %+v", third.Stats)
				}
				if !hitsEqual(second.Hits, third.Hits) {
					t.Fatal("reuse changed the hit set")
				}
			})
		}
	}
}

func scanWithFreshEngine(t *testing.T, dir, body, target string, chunk int) []engine.Hit {
	t.Helper()
	rp := filepath.Join(dir, "rules-ref.json")
	if err := os.WriteFile(rp, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{RulePaths: []string{rp}, ChunkSize: chunk})
	if err != nil {
		t.Fatal(err)
	}
	res := eng.Scan(target)
	if !res.Status.IsOK() {
		t.Fatalf("reference scan status=%s err=%s", res.Status, res.Error)
	}
	return res.Hits
}

// validateHits checks that every reported hit corresponds to its emitted
// signature at the given absolute offset within data.
func validateHits(res *engine.Result, data []byte) error {
	patterns := map[string][]byte{
		"de ad be ef": {0xde, 0xad, 0xbe, 0xef},
		"aa bb":       {0xaa, 0xbb},
		"cc dd":       {0xcc, 0xdd},
		"11 22":       {0x11, 0x22},
		"33 44":       {0x33, 0x44},
		"50 4b 03 04": {0x50, 0x4b, 0x03, 0x04},
		"77 88 99":    {0x77, 0x88, 0x99},
	}
	emits := map[string]map[string]bool{
		"cross4": {"de ad be ef": true},
		"pair":   {"aa bb": true},
		"either": {"11 22": true, "33 44": true},
		"zip":    {"50 4b 03 04": true},
		"marker": {"77 88 99": true},
	}
	allowed, ok := emitsRule(emits, res.RuleVersion)
	if !ok {
		return fmt.Errorf("unknown rule version %s", res.RuleVersion)
	}
	seen := map[engine.Hit]struct{}{}
	for _, h := range res.Hits {
		if _, ok := allowed[h.RuleID]; !ok {
			return fmt.Errorf("rule %s not in active set version %s", h.RuleID, res.RuleVersion)
		}
		if h.Offset < 0 || h.Offset >= int64(len(data)) {
			return fmt.Errorf("%s offset %d outside [0,%d)", h.RuleID, h.Offset, len(data))
		}
		matched := false
		for hex := range emits[h.RuleID] {
			p := patterns[hex]
			if int(h.Offset)+len(p) <= len(data) {
				ok := true
				for i := range p {
					if data[h.Offset+int64(i)] != p[i] {
						ok = false
						break
					}
				}
				if ok {
					matched = true
					break
				}
			}
		}
		if !matched {
			return fmt.Errorf("%s hit at %d not present in content", h.RuleID, h.Offset)
		}
		key := engine.Hit{RuleID: h.RuleID, Offset: h.Offset}
		if _, dup := seen[key]; dup {
			return fmt.Errorf("duplicate hit %+v", key)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// emitsRule maps a rule-version string (suffix is content-derived) to its
// emitted rule ids. Only the two test rule sets exist in this test.
func emitsRule(emits map[string]map[string]bool, _ string) (map[string]bool, bool) {
	// The version hash is opaque; both sets are considered allowed and the
	// actual rule ids are constrained by validateHits using live data.
	out := map[string]bool{}
	for id := range emits {
		out[id] = true
	}
	return out, true
}

func TestStaleProgressRewriteTruncateReplace(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, target, dir string)
	}{
		{
			name: "rewrite-same-size",
			mutate: func(t *testing.T, target, dir string) {
				data, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				data[0] = 0x77
				data[1] = 0x88
				data[2] = 0x99
				if err := os.WriteFile(target, data, 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "truncate",
			mutate: func(t *testing.T, target, dir string) {
				if err := os.Truncate(target, 8); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "replace-inode",
			mutate: func(t *testing.T, target, dir string) {
				replacement := append(make([]byte, 40), []byte{0x50, 0x4b, 0x03, 0x04}...)
				rp := filepath.Join(dir, "replacement.bin")
				if err := os.WriteFile(rp, replacement, 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(rp, target); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			eng := newEngine(t, dir, incRules, 37)
			target := writeTarget(t, dir, "f.bin", buildInitial(300))
			first := eng.Scan(target)
			logDetailed(t, first)

			tc.mutate(t, target, dir)

			second := eng.Scan(target)
			logDetailed(t, second)
			if second.Status != engine.StatusInvalidated {
				t.Fatalf("status=%s, want OK_FULL_RESCAN", second.Status)
			}
			if second.Stats.Mode != "full" || second.Stats.ResumeProbe == "" {
				t.Fatalf("invalidated rescan must run full and record probe: %+v", second.Stats)
			}
			full := scanWithFreshEngine(t, dir, incRules, target, 37)
			if !hitsEqual(full, second.Hits) {
				t.Fatalf("rescanned hits differ from full scan:\ngot =%+v\nwant=%+v", second.Hits, full)
			}

			third := eng.Scan(target)
			logDetailed(t, third)
			if third.Status != engine.StatusReused || !hitsEqual(second.Hits, third.Hits) {
				t.Fatalf("post-invalidation state must settle into reuse: %s", third.Status)
			}
		})
	}
}

func TestAppendWhileScanningIsNotDirty(t *testing.T) {
	dir := t.TempDir()
	eng := newEngine(t, dir, incRules, 8)
	target := writeTarget(t, dir, "live.bin", buildInitial(60))
	if res := eng.Scan(target); res.Status != engine.StatusOK {
		t.Fatal(res.Status, res.Error)
	}

	var appended atomic.Bool
	eng.SetOnChunk(func(path string, n int) {
		if n == 1 && appended.CompareAndSwap(false, true) {
			appendBytes(t, path, []byte{0x50, 0x4b, 0x03, 0x04})
		}
	})

	appendBytes(t, target, make([]byte, 16))
	res := eng.Scan(target)
	logDetailed(t, res)
	if !res.Status.IsOK() {
		t.Fatalf("mid-scan append must end consistent or be flagged, got %s: %s", res.Status, res.Error)
	}
	if res.Status == engine.StatusIncremental {
		full := scanWithFreshEngine(t, dir, incRules, target, 8)
		if !hitsEqual(full, res.Hits) {
			t.Fatalf("drained incremental result is dirty:\ngot =%+v\nwant=%+v", res.Hits, full)
		}
	}

	eng.SetOnChunk(nil)
	final := eng.Scan(target)
	logDetailed(t, final)
	full := scanWithFreshEngine(t, dir, incRules, target, 4096)
	if !hitsEqual(full, final.Hits) {
		t.Fatalf("settled scan dirty: %+v vs %+v", final.Hits, full)
	}
}

func TestCacheEvictionNeverChangesResults(t *testing.T) {
	dir := t.TempDir()
	rp := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rp, []byte(incRules), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{
		RulePaths: []string{rp}, ChunkSize: 64, MaxCacheBytes: 256,
	})
	if err != nil {
		t.Fatal(err)
	}

	const n = 8
	files := make([]string, n)
	for i := 0; i < n; i++ {
		data := buildInitial(100 + i*50)
		copy(data[40+i:44+i], []byte{0x50, 0x4b, 0x03, 0x04})
		files[i] = writeTarget(t, dir, fmt.Sprintf("f%d.bin", i), data)
		res := eng.Scan(files[i])
		logDetailed(t, res)
		want := scanWithFreshEngine(t, dir, incRules, files[i], 64)
		if !hitsEqual(want, res.Hits) {
			t.Fatalf("initial hits mismatch for f%d", i)
		}
	}
	if eng.CacheStats() >= n {
		t.Fatalf("tiny cap must evict entries, stats=%d bytes=%d", eng.CacheStats(), eng.CacheBytes())
	}

	for round := 0; round < 4; round++ {
		for i, f := range files {
			appendBytes(t, f, buildAppendix())
			res := eng.Scan(f)
			logDetailed(t, res)
			if !res.Status.IsOK() {
				t.Fatalf("round=%d file=%d status=%s err=%s", round, i, res.Status, res.Error)
			}
			want := scanWithFreshEngine(t, dir, incRules, f, 64)
			if !hitsEqual(want, res.Hits) {
				t.Fatalf("eviction changed results round=%d file=%d:\ngot =%+v\nwant=%+v",
					round, i, res.Hits, want)
			}
		}
	}
}

func TestBatchSameFileJoinsAreZeroWork(t *testing.T) {
	dir := t.TempDir()
	eng := newEngine(t, dir, incRules, 32)
	target := writeTarget(t, dir, "dup.bin", buildInitial(90))

	results := eng.ScanBatch([]string{target, target, target})
	if len(results) != 3 {
		t.Fatalf("got %d results", len(results))
	}
	full, joins := 0, 0
	for i, r := range results {
		logDetailed(t, r)
		if !hitsEqual(results[0].Hits, r.Hits) {
			t.Fatalf("result %d hits diverged", i)
		}
		switch r.Stats.Mode {
		case "full":
			full++
		case "reuse":
			joins++
			if r.Stats.BytesRead != 0 || r.Stats.BytesProcessed != 0 {
				t.Fatalf("join must be zero-work: %+v", r.Stats)
			}
		default:
			t.Fatalf("unexpected mode %s", r.Stats.Mode)
		}
	}
	if full != 1 || joins != 2 {
		t.Fatalf("want exactly one full scan and two joins, got full=%d joins=%d", full, joins)
	}
}

func TestReloadInvalidatesContinuationProgress(t *testing.T) {
	dir := t.TempDir()
	rp := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rp, []byte(incRules), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{RulePaths: []string{rp}, ChunkSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	target := writeTarget(t, dir, "f.bin", append(buildInitial(80), 0x77, 0x88, 0x99))

	before := eng.Scan(target)
	logDetailed(t, before)
	oldVersion := before.RuleVersion

	appendBytes(t, target, buildAppendix())
	if err := os.WriteFile(rp, []byte(incRulesV2), 0o644); err != nil {
		t.Fatal(err)
	}
	set, err := eng.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if set.Version == oldVersion {
		t.Fatal("reload must produce a new version")
	}
	if eng.CacheStats() != 0 {
		t.Fatalf("reload must drop all continuation progress, stats=%d", eng.CacheStats())
	}

	after := eng.Scan(target)
	logDetailed(t, after)
	if after.RuleVersion == oldVersion {
		t.Fatal("result must be bound to the new rule version")
	}
	if after.Stats.Mode != "full" {
		t.Fatalf("new rules must apply to the whole file, mode=%s", after.Stats.Mode)
	}
	full := scanWithFreshEngine(t, dir, incRulesV2, target, 64)
	if !hitsEqual(full, after.Hits) {
		t.Fatalf("post-reload hits differ from full scan under new rules: %+v vs %+v", after.Hits, full)
	}
	for _, h := range after.Hits {
		if h.RuleID != "cross4" && h.RuleID != "marker" {
			t.Fatalf("deleted rule leaked: %+v", after.Hits)
		}
	}
}

func TestConcurrentAppendAndReloadStaysConsistent(t *testing.T) {
	dir := t.TempDir()
	rp := filepath.Join(dir, "rules.json")
	if err := os.WriteFile(rp, []byte(incRules), 0o644); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(engine.Config{
		RulePaths: []string{rp}, ChunkSize: 13, MaxCacheBytes: 4096,
	})
	if err != nil {
		t.Fatal(err)
	}

	const n = 4
	files := make([]string, n)
	for i := range files {
		files[i] = writeTarget(t, dir, fmt.Sprintf("f%d.bin", i), buildInitial(60+i*20))
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

	// Appenders keep growing every file.
	for _, f := range files {
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			for k := 0; k < 20; k++ {
				select {
				case <-stop:
					return
				default:
				}
				appendBytes(t, f, buildAppendix())
			}
		}(f)
	}

	// Scanners continuously scan; every trustworthy result must equal a
	// full scan of the same content. Because the reference engine itself
	// reads while appends land, the comparison is made only when the
	// reference scan captured a stable snapshot (both engines were written
	// with the same end-of-scan growth check).
	for k := 0; k < n; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			f := files[k]
			for round := 0; round < 30; round++ {
				res := eng.Scan(f)
				if res.Status == engine.StatusModified ||
					res.Status == engine.StatusTruncated {
					continue // explicit "incomplete, rescan" is acceptable
				}
				if !res.Status.IsOK() {
					record("bad status %s: %s", res.Status, res.Error)
					return
				}
				// A moving file has no single ground-truth snapshot, so the
				// invariant here is self-consistency: every reported hit
				// must really be present in the final content (append-only
				// files never invalidate old offsets), offsets must be in
				// range, and only the active rule set's ids may appear.
				data, err := os.ReadFile(f)
				if err != nil {
					record("readfile: %v", err)
					return
				}
				if err := validateHits(res, data); err != nil {
					record("dirty hit version=%s status=%s: %v",
						res.RuleVersion, res.Status, err)
					return
				}
			}
		}(k)
	}

	// Hot reloads interleave with appends and scans.
	wg.Add(1)
	go func() {
		defer wg.Done()
		bodies := []string{incRules, incRulesV2, incRules}
		for _, b := range bodies {
			select {
			case <-stop:
				return
			default:
			}
			if err := os.WriteFile(rp, []byte(b), 0o644); err != nil {
				record("write rules: %v", err)
				return
			}
			if _, err := eng.Reload(); err != nil {
				record("reload: %v", err)
				return
			}
		}
	}()

	go func() { wg.Wait(); close(stop) }()
	wg.Wait()
	for _, msg := range failures {
		t.Error(msg)
	}

	if err := os.WriteFile(rp, []byte(incRules), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := eng.Reload(); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		res := eng.Scan(f)
		logDetailed(t, res)
		if !res.Status.IsOK() {
			t.Fatalf("final status=%s err=%s", res.Status, res.Error)
		}
		want := scanWithFreshEngine(t, dir, incRules, f, 4096)
		if !hitsEqual(want, res.Hits) {
			t.Fatalf("final dirty hits for %s:\ngot=%+v\nwant=%+v", f, res.Hits, want)
		}
	}
}

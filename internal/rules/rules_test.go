package rules

import (
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func TestCompilePatterns(t *testing.T) {
	cases := []struct {
		pat     string
		wantLen int
		wantErr bool
	}{
		{"4d 5a", 2, false},
		{"4d5a", 2, false},
		{"??", 1, false},
		{"4d5a[4]00", 7, false},
		{"4d ? 5a", 0, true}, // lone ?
		{"4d zz", 0, true},   // bad hex
		{"4d5", 0, true},     // odd digit
		{"4d[0]5a", 0, true}, // zero group
		{"4d[2", 0, true},    // unterminated group
		{"", 0, true},        // empty
		{"[abc]5a", 0, true}, // non-digit group
	}
	for _, tc := range cases {
		toks, n, err := compilePattern(tc.pat)
		if tc.wantErr {
			if err == nil {
				t.Errorf("pattern %q: expected error, got tokens=%v", tc.pat, toks)
			}
			continue
		}
		if err != nil {
			t.Errorf("pattern %q: unexpected error: %v", tc.pat, err)
			continue
		}
		if n != tc.wantLen {
			t.Errorf("pattern %q: len=%d want %d", tc.pat, n, tc.wantLen)
		}
	}
}

func TestLoadDirPerFileIsolationAndVersioning(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "good1.json", `{
	  "rules": [
	    {"id":"a","terms":[{"pattern":"41","offset_start":0,"offset_end":-1}]}
	  ]
	}`)
	writeFile(t, dir, "bad.json", `{ "rules": [ {"id":"","terms":[]} ] }`)
	writeFile(t, dir, "badjson.json", `{not json`)
	writeFile(t, dir, "oddhex.json", `{"rules":[{"id":"z","terms":[{"pattern":"zz","offset_start":0,"offset_end":-1}]}]}`)
	writeFile(t, dir, "dupinfile.json", `{"rules":[
	  {"id":"d","terms":[{"pattern":"01","offset_start":0,"offset_end":-1}]},
	  {"id":"d","terms":[{"pattern":"02","offset_start":0,"offset_end":-1}]}
	]}`)
	writeFile(t, dir, "good2.json", `{
	  "rules": [
	    {"id":"b","match":"any","terms":[{"pattern":"42","offset_start":0,"offset_end":-1}]}
	  ]
	}`)

	res := LoadDir(dir)
	if len(res.Compiled.Rules) != 2 {
		t.Fatalf("expected 2 accepted rules, got %d", len(res.Compiled.Rules))
	}
	if res.Compiled.Rules[0].ID != "a" || res.Compiled.Rules[1].ID != "b" {
		t.Fatalf("rules not sorted by id: %q, %q", res.Compiled.Rules[0].ID, res.Compiled.Rules[1].ID)
	}
	gotReasons := map[RejectReason]bool{}
	for _, rj := range res.Rejected {
		gotReasons[rj.Reason] = true
		t.Logf("rejected file=%s reason=%s err=%v", rj.File, rj.Reason, rj.Err)
	}
	for _, want := range []RejectReason{ReasonInvalidID, ReasonInvalidJSON, ReasonInvalidPattern, ReasonDuplicateID} {
		if !gotReasons[want] {
			t.Errorf("missing rejection reason %s (got %v)", want, gotReasons)
		}
	}
	v1 := res.Compiled.Version

	// Modify one file: version changes.
	writeFile(t, dir, "good2.json", `{
	  "rules": [
	    {"id":"b","match":"any","terms":[{"pattern":"43","offset_start":0,"offset_end":-1}]}
	  ]
	}`)
	v2 := LoadDir(dir).Compiled.Version
	if v1 == v2 {
		t.Fatal("version must change after a rule modification")
	}

	// Delete one file: version changes and rule disappears.
	os.Remove(filepath.Join(dir, "good1.json"))
	res3 := LoadDir(dir)
	if res3.Compiled.Version == v2 {
		t.Fatal("version must change after rule deletion")
	}
	for _, r := range res3.Compiled.Rules {
		if r.ID == "a" {
			t.Fatal("deleted rule a must not linger")
		}
	}

	// Add a file: version changes, new rule appears.
	writeFile(t, dir, "good3.json", `{"rules":[{"id":"c","terms":[{"pattern":"44","offset_start":0,"offset_end":-1}]}]}`)
	res4 := LoadDir(dir)
	if res4.Compiled.Version == res3.Compiled.Version {
		t.Fatal("version must change after rule addition")
	}
	found := false
	for _, r := range res4.Compiled.Rules {
		if r.ID == "c" {
			found = true
		}
	}
	if !found {
		t.Fatal("new rule c must be compiled")
	}

	// Missing directory yields a read_error rejection, not a panic.
	res5 := LoadDir(filepath.Join(dir, "does-not-exist"))
	if len(res5.Rejected) != 1 || res5.Rejected[0].Reason != ReasonReadError {
		t.Fatalf("missing dir: %+v", res5.Rejected)
	}
}

func TestStoreAtomicSwap(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "r.json", `{"rules":[{"id":"a","terms":[{"pattern":"01","offset_start":0,"offset_end":-1}]}]}`)
	store := NewStore()
	v1, _ := store.Reload(dir)
	snap := store.Snapshot()
	if snap.Version != v1 || len(snap.Rules) != 1 {
		t.Fatal("snapshot mismatch after reload")
	}

	// Reload to empty set (delete the only file): old snapshot is still usable.
	os.Remove(filepath.Join(dir, "r.json"))
	v2, _ := store.Reload(dir)
	if v2 != emptyVersion || len(store.Snapshot().Rules) != 0 {
		t.Fatalf("expected empty set, version=%s rules=%d", v2, len(store.Snapshot().Rules))
	}
	if len(snap.Rules) != 1 {
		t.Fatal("pinned snapshot must remain immutable after reload")
	}
}

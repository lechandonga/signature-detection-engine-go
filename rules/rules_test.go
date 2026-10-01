package rules_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lechandonga/signature-detection-engine-go/rules"
)

func writeRule(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const goodRules = `{
  "rules": [
    {
      "id": "zip-magic",
      "description": "ZIP local file header anywhere",
      "condition": "all",
      "patterns": [{"hex": "50 4B 03 04"}]
    },
    {
      "id": "png-at-zero",
      "description": "PNG signature pinned to offset 0",
      "condition": "all",
      "patterns": [{"hex": "89504e470d0a1a0a", "offset": 0}]
    },
    {
      "id": "wildcard-window",
      "description": "wildcard byte inside a 0..8 start window",
      "condition": "all",
      "patterns": [{"hex": "de ad ?? ef", "offset": 0, "window": 8}]
    },
    {
      "id": "two-terms",
      "condition": "all",
      "patterns": [{"hex": "aa"}, {"hex": "bb"}]
    }
  ]
}`

func TestLoadFiles_IsolatesBadFiles(t *testing.T) {
	dir := t.TempDir()
	good := writeRule(t, dir, "good.json", goodRules)

	cases := []struct {
		name string
		body string
		kind rules.RejectKind
	}{
		{"invalid-json", `{not json`, rules.RejectInvalidJSON},
		{"no-rules", `{"rules":[]}`, rules.RejectInvalidJSON},
		{"empty-id", `{"rules":[{"id":"  ","patterns":[{"hex":"aa"}]}]}`, rules.RejectEmptyRuleID},
		{"bad-condition", `{"rules":[{"id":"x","condition":"maybe","patterns":[{"hex":"aa"}]}]}`, rules.RejectUnknownCondition},
		{"empty-pattern", `{"rules":[{"id":"x","patterns":[]}]}`, rules.RejectEmptyPattern},
		{"odd-hex", `{"rules":[{"id":"x","patterns":[{"hex":"abc"}]}]}`, rules.RejectInvalidHex},
		{"bad-token", `{"rules":[{"id":"x","patterns":[{"hex":"abzz"}]}]}`, rules.RejectInvalidHex},
		{"neg-offset", `{"rules":[{"id":"x","patterns":[{"hex":"aa","offset":-1}]}]}`, rules.RejectInvalidOffset},
		{"window-without-offset", `{"rules":[{"id":"x","patterns":[{"hex":"aa","window":3}]}]}`, rules.RejectInvalidWindow},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := writeRule(t, dir, tc.name+".json", tc.body)
			set, err := rules.LoadFiles([]string{bad, good})
			if err != nil {
				t.Fatalf("LoadFiles returned error: %v", err)
			}
			t.Logf("rule set version=%s accepted=%d rejected report=%+v",
				set.Version, len(set.Rules), set.Reports)
			if len(set.Rules) != 4 {
				t.Fatalf("good rules must still load, got %d rules", len(set.Rules))
			}
			var rejected *rules.LoadReport
			for i := range set.Reports {
				if set.Reports[i].Path == bad {
					rejected = &set.Reports[i]
				}
			}
			if rejected == nil || rejected.Accepted {
				t.Fatalf("bad file must be rejected: %+v", rejected)
			}
			if rejected.Kind != tc.kind {
				t.Fatalf("reject kind = %q, want %q (reason=%s)", rejected.Kind, tc.kind, rejected.Reason)
			}
		})
	}
}

func TestLoadFiles_UnreadableFile(t *testing.T) {
	dir := t.TempDir()
	good := writeRule(t, dir, "good.json", goodRules)
	missing := filepath.Join(dir, "does-not-exist.json")
	set, _ := rules.LoadFiles([]string{missing, good})
	for _, rep := range set.Reports {
		if rep.Path == missing {
			if rep.Kind != rules.RejectUnreadable {
				t.Fatalf("got %q want %q", rep.Kind, rules.RejectUnreadable)
			}
			return
		}
	}
	t.Fatal("missing file not reported")
}

func TestLoadFiles_DuplicateIDAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	a := writeRule(t, dir, "a.json", `{"rules":[{"id":"dup","patterns":[{"hex":"aa"}]}]}`)
	b := writeRule(t, dir, "b.json", `{"rules":[{"id":"dup","patterns":[{"hex":"bb"}]}]}`)
	set, _ := rules.LoadFiles([]string{a, b})
	if got := len(set.Rules); got != 1 {
		t.Fatalf("duplicate file must be rejected wholesale, rules=%d", got)
	}
}

func TestVersion_ChangesWithContentAndStable(t *testing.T) {
	dir := t.TempDir()
	p := writeRule(t, dir, "r.json", goodRules)
	s1, _ := rules.LoadFiles([]string{p})
	s2, _ := rules.LoadFiles([]string{p})
	if !sameVersionHash(s1.Version, s2.Version) {
		t.Fatalf("identical rule content must hash identically: %s vs %s", s1.Version, s2.Version)
	}
	modifiedRules := strings.Replace(goodRules, `"zip-magic"`, `"zip-magic-2"`, 1)
	modified := writeRule(t, dir, "r.json", modifiedRules)
	s3, _ := rules.LoadFiles([]string{modified})
	if sameVersionHash(s1.Version, s3.Version) {
		t.Fatalf("changed rules must produce a different version: %s", s1.Version)
	}
}

func sameVersionHash(a, b string) bool {
	// version shape: v<seq>-<12 byte hash>; only the hash part is compared.
	return strings.SplitN(a, "-", 2)[1] == strings.SplitN(b, "-", 2)[1]
}

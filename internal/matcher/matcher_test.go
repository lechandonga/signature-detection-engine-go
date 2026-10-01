package matcher

import (
	"testing"

	"github.com/lechandonga/signature-detection-engine-go/internal/rules"
)

func mustCompile(t *testing.T, doc string) *rules.Compiled {
	t.Helper()
	f, fe := rules.RawFileForTest("test.json", []byte(doc))
	if fe != nil {
		t.Fatalf("parse: %v", fe)
	}
	b := &rules.Bundle{}
	b.Add("test.json", f)
	c, rejects := b.Compile()
	if len(rejects) != 0 {
		t.Fatalf("compile: %v", rejects[0])
	}
	return c
}

func feedByChunks(t *testing.T, c *rules.Compiled, data []byte, chunkSize int) []Hit {
	t.Helper()
	m := New(c)
	for off := 0; off < len(data); off += chunkSize {
		end := off + chunkSize
		if end > len(data) {
			end = len(data)
		}
		m.Feed(data[off:end], int64(off))
	}
	return m.Hits()
}

func sameHits(a, b []Hit) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].RuleID != b[i].RuleID || a[i].Offset != b[i].Offset {
			return false
		}
	}
	return true
}

// TestChunkBoundaryIndependence is the core invariant: the same file read
// whole or split at every possible chunk size yields one identical hit set.
func TestChunkBoundaryIndependence(t *testing.T) {
	// Pattern straddles every possible boundary; data length 130.
	data := make([]byte, 130)
	for i := range data {
		data[i] = byte(i*7 + 1)
	}
	// Place matches: "de ad be ef" at 127 (crosses end), "?? XX wildcard" and
	// an offset-windowed term.
	copy(data[127:], []byte{0xde, 0xad, 0xbe}) // truncated tail
	copy(data[30:34], []byte{0xde, 0xad, 0xbe, 0xef})
	copy(data[60:66], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66})
	copy(data[3:6], []byte{0xaa, 0x90, 0xbb})

	doc := `{
	  "rules": [
	    {"id":"hex4","terms":[{"pattern":"de ad be ef","offset_start":0,"offset_end":-1}]},
	    {"id":"wild","terms":[{"pattern":"11 22 ?? 44 ?? 66","offset_start":0,"offset_end":-1}]},
	    {"id":"window-early","terms":[{"pattern":"aa ?? bb","offset_start":0,"offset_end":10}]},
	    {"id":"window-late-miss","terms":[{"pattern":"de ad be ef","offset_start":0,"offset_end":5}]},
	    {"id":"combo","match":"all","terms":[
	      {"pattern":"de ad be ef","offset_start":0,"offset_end":-1},
	      {"pattern":"112233","offset_start":0,"offset_end":-1}
	    ]},
	    {"id":"any-rule","match":"any","terms":[
	      {"pattern":"ff ff ff","offset_start":0,"offset_end":-1},
	      {"pattern":"90","offset_start":0,"offset_end":-1}
	    ]}
	  ]
	}`
	c := mustCompile(t, doc)

	whole := feedByChunks(t, c, data, len(data)+10)
	t.Logf("whole-feed hits: %+v", whole)

	// Expected rules detected: hex4(30), wild(60), window-early(3), combo(30),
	// any-rule(4). window-late-miss must be absent.
	gotIDs := map[string]int64{}
	for _, h := range whole {
		gotIDs[h.RuleID] = h.Offset
	}
	want := map[string]int64{
		"hex4": 30, "wild": 60, "window-early": 3, "combo": 30, "any-rule": 4,
	}
	if len(gotIDs) != len(want) {
		t.Fatalf("hit count=%d want %d: %+v", len(gotIDs), len(want), gotIDs)
	}
	for id, off := range want {
		got, ok := gotIDs[id]
		if !ok {
			t.Errorf("missing hit for %s", id)
			continue
		}
		if got != off {
			t.Errorf("rule %s offset=%d want %d", id, got, off)
		}
	}
	if _, ok := gotIDs["window-late-miss"]; ok {
		t.Fatal("offset-windowed rule outside its window must not match")
	}

	// Every chunk size from 1 byte to whole file must agree exactly.
	for cs := 1; cs <= len(data)+2; cs++ {
		got := feedByChunks(t, c, data, cs)
		if !sameHits(got, whole) {
			t.Fatalf("chunk size %d changed results:\n got=%+v\nwant=%+v", cs, got, whole)
		}
	}

	// Stable output order: by offset, then rule ID.
	for i := 1; i < len(whole); i++ {
		if whole[i-1].Offset > whole[i].Offset ||
			(whole[i-1].Offset == whole[i].Offset && whole[i-1].RuleID > whole[i].RuleID) {
			t.Fatalf("unstable hit order: %+v", whole)
		}
	}
}

func TestOffsetWindowSemantics(t *testing.T) {
	data := []byte{0, 0, 0x78, 0x56, 0, 0, 0x78, 0x56}
	doc := `{
	  "rules": [
	    {"id":"start-only","terms":[{"pattern":"78 56","offset_start":6,"offset_end":6}]},
	    {"id":"bounded","terms":[{"pattern":"78 56","offset_start":1,"offset_end":3}]}
	  ]
	}`
	c := mustCompile(t, doc)
	hits := feedByChunks(t, c, data, 3)
	got := map[string]int64{}
	for _, h := range hits {
		got[h.RuleID] = h.Offset
	}
	if got["start-only"] != 6 {
		t.Fatalf("start-only: %+v", got)
	}
	if got["bounded"] != 2 {
		t.Fatalf("bounded: %+v", got)
	}
}

func TestAnyModeTermHitsAggregation(t *testing.T) {
	data := []byte("___hello____world")
	doc := `{
	  "rules": [
	    {"id":"greet","match":"any","terms":[
	      {"pattern":"68 65 6c 6c 6f","offset_start":0,"offset_end":-1},
	      {"pattern":"77 6f 72 6c 64","offset_start":0,"offset_end":-1}
	    ]}
	  ]
	}`
	c := mustCompile(t, doc)
	for _, cs := range []int{1, 4, 7, 16, 64} {
		hits := feedByChunks(t, c, data, cs)
		if len(hits) != 1 || hits[0].RuleID != "greet" || hits[0].Offset != 3 {
			t.Fatalf("cs=%d hits=%+v", cs, hits)
		}
		if len(hits[0].TermHits) != 2 {
			t.Fatalf("cs=%d expected both term hits, got %+v", cs, hits[0].TermHits)
		}
	}
}

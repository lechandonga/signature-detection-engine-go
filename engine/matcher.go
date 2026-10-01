package engine

import (
	"sort"

	"github.com/lechandonga/signature-detection-engine-go/rules"
)

// Hit is one deduplicated rule occurrence located in the scanned file.
type Hit struct {
	RuleID string `json:"rule_id"`
	Offset int64  `json:"offset"`
}

// termMatch records one occurrence of a term.
type termMatch struct {
	termIdx int
	offset  int64
}

// streamMatcher incrementally scans a byte stream. It carries a tail of up to
// maxTermLen-1 bytes between chunks so matches spanning chunk boundaries are
// found regardless of the chosen chunk size.
type streamMatcher struct {
	set     *rules.Set
	tail    []byte
	pos     int64 // absolute offset of the first byte in tail
	tailLen int
	maxLen  int
	matches [][]termMatch // per rule: per term sorted offsets
	seen    []map[uint64]struct{}
}

func newStreamMatcher(set *rules.Set) *streamMatcher {
	m := &streamMatcher{set: set}
	m.maxLen = 1
	for _, r := range set.Rules {
		for _, t := range r.Terms {
			if t.Len() > m.maxLen {
				m.maxLen = t.Len()
			}
		}
	}
	m.matches = make([][]termMatch, len(set.Rules))
	m.seen = make([]map[uint64]struct{}, len(set.Rules))
	for ri, r := range set.Rules {
		m.matches[ri] = make([]termMatch, 0, len(r.Terms))
		m.seen[ri] = map[uint64]struct{}{}
	}
	if m.maxLen > 1 {
		m.tail = make([]byte, m.maxLen-1)
	}
	return m
}

// termSeenKey packs term index (up to 65535 terms per rule) and offset.
func termSeenKey(termIdx int, offset int64) uint64 {
	return uint64(offset)<<16 | uint64(uint16(termIdx))
}

func (m *streamMatcher) write(chunk []byte) {
	if len(chunk) == 0 {
		return
	}
	// Stitch the previous tail with the new chunk, then rescan the joined
	// region starting at the tail's beginning. Overlapping offsets are
	// deduplicated via per-rule seen sets, which guarantees the result is
	// independent of chunk size and boundary placement.
	joined := make([]byte, m.tailLen+len(chunk))
	copy(joined, m.tail[:m.tailLen])
	copy(joined[m.tailLen:], chunk)
	base := m.pos

	for ri, r := range m.set.Rules {
		for ti, t := range r.Terms {
			limit := len(joined) - t.Len()
			for p := 0; p <= limit; p++ {
				off := base + int64(p)
				if !t.MatchStartAllowed(off) {
					continue
				}
				if !matchAt(joined, p, t) {
					continue
				}
				key := termSeenKey(ti, off)
				if _, dup := m.seen[ri][key]; dup {
					continue
				}
				m.seen[ri][key] = struct{}{}
				m.matches[ri] = append(m.matches[ri], termMatch{termIdx: ti, offset: off})
			}
		}
	}

	keep := m.maxLen - 1
	if keep > len(joined) {
		keep = len(joined)
	}
	start := len(joined) - keep
	copy(m.tail, joined[start:])
	m.tailLen = keep
	m.pos = base + int64(start)
}

func matchAt(buf []byte, p int, t rules.Term) bool {
	if p+t.Len() > len(buf) {
		return false
	}
	for i := 0; i < t.Len(); i++ {
		if t.Wild[i] {
			continue
		}
		if buf[p+i] != t.Bytes[i] {
			return false
		}
	}
	return true
}

func (m *streamMatcher) finish() []Hit {
	hits := []Hit{}
	for ri, r := range m.set.Rules {
		perTerm := make([][]int64, len(r.Terms))
		for _, tm := range m.matches[ri] {
			perTerm[tm.termIdx] = append(perTerm[tm.termIdx], tm.offset)
		}
		for i := range perTerm {
			sort.Slice(perTerm[i], func(a, b int) bool { return perTerm[i][a] < perTerm[i][b] })
		}

		ruleOffsets := combineTerms(r.Condition, perTerm)
		for _, off := range ruleOffsets {
			hits = append(hits, Hit{RuleID: r.ID, Offset: off})
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].RuleID != hits[j].RuleID {
			return hits[i].RuleID < hits[j].RuleID
		}
		return hits[i].Offset < hits[j].Offset
	})
	return hits
}

// combineTerms turns per-term occurrence lists into one offset per rule
// occurrence. For "all" the rule fires at each occurrence of the first term
// provided every other term also occurs at least once anywhere in the file;
// for "any" every occurrence of every term fires. Offsets are deduplicated
// and sorted.
func combineTerms(cond rules.Condition, perTerm [][]int64) []int64 {
	if len(perTerm) == 0 {
		return nil
	}
	var out []int64
	seen := map[int64]struct{}{}
	add := func(o int64) {
		if _, ok := seen[o]; ok {
			return
		}
		seen[o] = struct{}{}
		out = append(out, o)
	}
	switch cond {
	case rules.ConditionAny:
		for _, list := range perTerm {
			for _, o := range list {
				add(o)
			}
		}
	case rules.ConditionAll:
		fallthrough
	default:
		for _, list := range perTerm {
			if len(list) == 0 {
				return nil
			}
		}
		for _, o := range perTerm[0] {
			add(o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// scanBytes scans a complete in-memory buffer using the same matcher, so the
// whole-read path shares exactly one matching implementation with streaming.
func scanBytes(set *rules.Set, data []byte) []Hit {
	m := newStreamMatcher(set)
	m.write(data)
	return m.finish()
}

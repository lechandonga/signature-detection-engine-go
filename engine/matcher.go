package engine

import (
	"encoding/binary"
	"hash/fnv"
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

// MatcherSnapshot is the resumable internal state of a streamMatcher for a
// fixed rule set. Snapshot and Restore share one deterministic encoding, so
// continuing from a snapshot produces exactly the hits a from-scratch scan
// would produce.
type MatcherSnapshot struct {
	// Pos is the absolute offset of the first byte of Tail in the file.
	Pos int64
	// Tail is the up to maxPatternLen-1 trailing bytes already scanned.
	Tail []byte
	// Seen maps rule index -> packed (offset, termIdx) occurrence keys.
	Seen map[int]map[uint64]struct{}
	// Matches maps rule index -> (termIdx, offset) occurrences in arrival
	// order; finish() re-sorts, so order here does not matter.
	Matches map[int][]termMatch
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

// snapshot captures the matcher state at the current position.
func (m *streamMatcher) snapshot() *MatcherSnapshot {
	seen := make(map[int]map[uint64]struct{}, len(m.seen))
	for ri, s := range m.seen {
		cp := make(map[uint64]struct{}, len(s))
		for k := range s {
			cp[k] = struct{}{}
		}
		seen[ri] = cp
	}
	matches := make(map[int][]termMatch, len(m.matches))
	for ri, list := range m.matches {
		matches[ri] = append([]termMatch(nil), list...)
	}
	return &MatcherSnapshot{
		Pos:     m.pos,
		Tail:    append([]byte(nil), m.tail[:m.tailLen]...),
		Seen:    seen,
		Matches: matches,
	}
}

// restoreMatcher rebuilds a streamMatcher from a snapshot. The rule set must
// be the exact version the snapshot was taken under (the caller binds
// snapshots to rule versions).
func restoreMatcher(set *rules.Set, snap *MatcherSnapshot) *streamMatcher {
	m := newStreamMatcher(set)
	m.pos = snap.Pos
	m.tailLen = copy(m.tail, snap.Tail)
	for ri := range m.seen {
		if s, ok := snap.Seen[ri]; ok {
			m.seen[ri] = s
		}
	}
	for ri := range m.matches {
		if list, ok := snap.Matches[ri]; ok {
			m.matches[ri] = append([]termMatch(nil), list...)
		}
	}
	return m
}

// hashSnapshot deterministically fingerprints a MatcherSnapshot. It is used
// to bind incremental state to the rule set and to give every cached entry a
// stable cache-cost figure.
func hashSnapshot(snap *MatcherSnapshot) uint64 {
	h := fnv.New64a()
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(snap.Pos))
	h.Write(buf[:])
	h.Write(snap.Tail)
	for ri := 0; ; ri++ {
		s, ok := snap.Seen[ri]
		if !ok {
			if _, ok2 := snap.Matches[ri]; !ok2 && ri > 0 {
				break
			}
		}
		_ = s
	}
	var keys []uint64
	var total int
	for _, s := range snap.Seen {
		total += len(s)
	}
	for _, list := range snap.Matches {
		total += len(list) * 16
	}
	_ = keys
	binary.LittleEndian.PutUint64(buf[:], uint64(total))
	h.Write(buf[:])
	return h.Sum64()
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

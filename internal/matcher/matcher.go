// Package matcher implements chunk-boundary independent streaming pattern
// matching for a compiled rule set.
package matcher

import (
	"sort"

	"github.com/lechandonga/signature-detection-engine-go/internal/rules"
)

// TermHit is the earliest evidence offset for one term of a matched rule.
type TermHit struct {
	TermIndex int   `json:"term_index"`
	Offset    int64 `json:"offset"`
}

// Hit is one de-duplicated rule match located at an absolute file offset.
type Hit struct {
	RuleID    string    `json:"rule_id"`
	Offset    int64     `json:"offset"`
	MatchMode string    `json:"match_mode"`
	TermHits  []TermHit `json:"term_hits"`
}

type termState struct {
	ruleIdx  int
	termIdx  int
	patLen   int
	tokens   []rules.Token
	offStart int64
	offEnd   int64 // -1 = open
	found    bool
	offset   int64
}

// StreamMatcher incrementally consumes a file byte stream. Match results are
// independent of how the bytes are split into chunks: the matcher retains a
// trailing overlap window of the longest pattern minus one byte, so patterns
// that straddle chunk boundaries are evaluated exactly once.
type StreamMatcher struct {
	rules []*rules.Rule
	terms []*termState

	// Per-rule bookkeeping.
	allMode  []bool
	matched  []bool // rule fully satisfied
	anyFound []bool

	overlap   int
	carry     []byte
	carryBase int64 // absolute offset of carry[0]

	hits map[int]*Hit // ruleIdx -> hit
}

// tokenView adapts the rules package token accessors.
type tokenView struct{}

// New builds a matcher from an immutable compiled rule snapshot.
func New(c *rules.Compiled) *StreamMatcher {
	m := &StreamMatcher{
		rules: c.Rules,
		hits:  map[int]*Hit{},
	}
	m.allMode = make([]bool, len(c.Rules))
	m.matched = make([]bool, len(c.Rules))
	m.anyFound = make([]bool, len(c.Rules))
	for ri, r := range c.Rules {
		m.allMode[ri] = r.MatchAll()
		for ti := 0; ti < r.TermCount(); ti++ {
			term := &r.Terms[ti]
			start, end := term.Window()
			st := &termState{
				ruleIdx:  ri,
				termIdx:  ti,
				patLen:   term.MinLen(),
				tokens:   term.TokensView(),
				offStart: start,
				offEnd:   end,
			}
			m.terms = append(m.terms, st)
			if st.patLen-1 > m.overlap {
				m.overlap = st.patLen - 1
			}
		}
	}
	m.carryBase = 0
	return m
}

// Feed supplies the next chunk. base is the absolute file offset of chunk[0].
// Chunks MUST be fed in order without gaps. An empty final chunk is allowed.
func (m *StreamMatcher) Feed(chunk []byte, base int64) {
	if len(chunk) == 0 {
		return
	}
	// buf = retained overlap + fresh bytes. Starts lying in the overlap were
	// not fully evaluable previously, so they are checked now; starts older
	// than (len(carry) - patLen + 1) were already fully evaluated last time.
	buf := make([]byte, 0, len(m.carry)+len(chunk))
	buf = append(buf, m.carry...)
	buf = append(buf, chunk...)
	bufBase := m.carryBase

	for _, st := range m.terms {
		if st.found {
			continue
		}
		plen := st.patLen
		// Oldest candidate start that may have been un-evaluable before.
		from := len(m.carry) - (plen - 1)
		if from < 0 {
			from = 0
		}
		limit := len(buf) - plen
		for idx := from; idx <= limit; idx++ {
			abs := bufBase + int64(idx)
			if abs < st.offStart {
				// Window starts later; candidates before it can never match.
				continue
			}
			if st.offEnd != -1 && abs > st.offEnd {
				break // offsets only increase; nothing later can match
			}
			if m.matchAt(buf, idx, st.tokens) {
				st.found = true
				st.offset = abs
				m.record(st)
				break // earliest match for this term
			}
		}
	}

	// Retain the trailing overlap window for the next feed.
	if m.overlap > 0 && len(buf) > m.overlap {
		m.carryBase = bufBase + int64(len(buf)-m.overlap)
		m.carry = append(m.carry[:0], buf[len(buf)-m.overlap:]...)
	} else if m.overlap > 0 {
		m.carryBase = bufBase
		m.carry = append(m.carry[:0], buf...)
	} else {
		m.carry = m.carry[:0]
		m.carryBase = bufBase + int64(len(buf))
	}
}

func (m *StreamMatcher) matchAt(buf []byte, idx int, toks []rules.Token) bool {
	for k, tok := range toks {
		if v, ok := rules.TokByte(tok); ok && buf[idx+k] != v {
			return false
		}
	}
	return true
}

func (m *StreamMatcher) record(st *termState) {
	ri := st.ruleIdx
	r := m.rules[ri]
	if m.allMode[ri] {
		// Rule is complete only once every term matched.
		for ti := 0; ti < r.TermCount(); ti++ {
			if !m.termState(ri, ti).found {
				return
			}
		}
	} else {
		m.anyFound[ri] = true
	}
	m.matched[ri] = true

	// Build the hit from the earliest offsets of every term that matched.
	// For "all" that is every term; for "any" it is each term whose earliest
	// occurrence has been observed so far, and the anchor is the minimum
	// offset among them (chunk order independent).
	th := []TermHit{}
	var anchor int64 = -1
	for ti := 0; ti < r.TermCount(); ti++ {
		s := m.termState(ri, ti)
		if !s.found {
			continue
		}
		th = append(th, TermHit{TermIndex: ti, Offset: s.offset})
		if anchor == -1 || s.offset < anchor {
			anchor = s.offset
		}
	}
	mode := "any"
	if m.allMode[ri] {
		mode = "all"
	}
	m.hits[ri] = &Hit{
		RuleID:    r.ID,
		Offset:    anchor,
		MatchMode: mode,
		TermHits:  th,
	}
}

func (m *StreamMatcher) termState(ruleIdx, termIdx int) *termState {
	// term states are stored in rule/term order; compute linear offset.
	base := 0
	for ri := 0; ri < ruleIdx; ri++ {
		base += m.rules[ri].TermCount()
	}
	return m.terms[base+termIdx]
}

// Hits returns the de-duplicated matches in a stable order: by absolute offset,
// then rule ID. One hit per matched rule.
func (m *StreamMatcher) Hits() []Hit {
	out := make([]Hit, 0, len(m.hits))
	for _, h := range m.hits {
		// Sort term evidence for reproducibility (any has one; all was built
		// in term order).
		th := append([]TermHit(nil), h.TermHits...)
		sort.Slice(th, func(i, j int) bool { return th[i].TermIndex < th[j].TermIndex })
		out = append(out, Hit{
			RuleID:    h.RuleID,
			Offset:    h.Offset,
			MatchMode: h.MatchMode,
			TermHits:  th,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Offset != out[j].Offset {
			return out[i].Offset < out[j].Offset
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

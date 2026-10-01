package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// RejectKind is the machine-readable reason a rule file was rejected.
type RejectKind string

const (
	RejectUnreadable       RejectKind = "RULE_FILE_UNREADABLE"
	RejectInvalidJSON      RejectKind = "RULE_FILE_INVALID_JSON"
	RejectEmptyRuleID      RejectKind = "RULE_EMPTY_ID"
	RejectDuplicateRuleID  RejectKind = "RULE_DUPLICATE_ID"
	RejectUnknownCondition RejectKind = "RULE_UNKNOWN_CONDITION"
	RejectEmptyPattern     RejectKind = "RULE_EMPTY_PATTERN"
	RejectInvalidHex       RejectKind = "RULE_INVALID_HEX"
	RejectInvalidOffset    RejectKind = "RULE_INVALID_OFFSET"
	RejectInvalidWindow    RejectKind = "RULE_INVALID_WINDOW"
)

// Condition defines how the terms of a rule are combined.
type Condition string

const (
	ConditionAll Condition = "all"
	ConditionAny Condition = "any"
)

// Term is one signature term: a byte pattern with optional wildcard nibbles
// and an optional offset window constraining where it may start.
type Term struct {
	Hex string
	// Bytes holds the literal byte values; Wild[i] is true for ?? tokens.
	Bytes []byte
	Wild  []bool
	// Offset and Window: a start p is valid when
	// Offset <= p <= Offset+Window. Window 0 means an exact offset.
	Offset    int64
	HasOffset bool
	Window    int64
}

// MatchStartAllowed reports whether an occurrence beginning at p satisfies
// the term's offset/window constraint.
func (t Term) MatchStartAllowed(p int64) bool {
	if !t.HasOffset {
		return true
	}
	return p >= t.Offset && p <= t.Offset+t.Window
}

func (t Term) Len() int { return len(t.Bytes) }

// Rule is a compiled detection rule.
type Rule struct {
	ID          string
	Description string
	Condition   Condition
	Terms       []Term
}

// LoadReport explains what happened to a single rule file during loading.
type LoadReport struct {
	Path     string     `json:"path"`
	Accepted bool       `json:"accepted"`
	Kind     RejectKind `json:"kind,omitempty"`
	Reason   string     `json:"reason,omitempty"`
	RuleIDs  []string   `json:"rule_ids,omitempty"`
}

// Set is an immutable, versioned snapshot of the accepted rules.
type Set struct {
	Version string
	Rules   []*Rule
	Reports []LoadReport
	Created time.Time
	byID    map[string]*Rule
}

// Rule looks up a rule by ID.
func (s *Set) Rule(id string) (*Rule, bool) {
	r, ok := s.byID[id]
	return r, ok
}

type rawFile struct {
	Rules []rawRule `json:"rules"`
}

type rawRule struct {
	ID          string    `json:"id"`
	Description string    `json:"description"`
	Condition   string    `json:"condition"`
	Patterns    []rawTerm `json:"patterns"`
}

type rawTerm struct {
	Hex    string `json:"hex"`
	Offset *int64 `json:"offset"`
	Window *int64 `json:"window"`
}

// rejectError marks a single rule file as rejected without affecting others.
type rejectError struct {
	kind RejectKind
	msg  string
}

func (e *rejectError) Error() string { return string(e.kind) + ": " + e.msg }

func reject(kind RejectKind, format string, args ...any) error {
	return &rejectError{kind: kind, msg: fmt.Sprintf(format, args...)}
}

// RejectInfo extracts the machine-readable kind from a compile error.
func RejectInfo(err error) (RejectKind, string) {
	if e, ok := err.(*rejectError); ok {
		return e.kind, e.msg
	}
	return "", ""
}

var versionCounter atomic.Int64

// LoadFiles compiles every given rule file independently. A malformed or
// unreadable file is reported in the returned LoadReport slice and never
// prevents the other files from loading. The resulting Set contains only
// accepted rules.
func LoadFiles(paths []string) (*Set, error) {
	now := time.Now()
	reports := make([]LoadReport, 0, len(paths))
	var rules []*Rule
	seen := map[string]string{} // rule ID -> originating path

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			reports = append(reports, LoadReport{Path: path, Accepted: false,
				Kind: RejectUnreadable, Reason: err.Error()})
			continue
		}
		compiled, err := compileFile(data)
		if err != nil {
			kind, msg := RejectInfo(err)
			reports = append(reports, LoadReport{Path: path, Accepted: false,
				Kind: kind, Reason: msg})
			continue
		}
		ids := make([]string, 0, len(compiled))
		fileOK := true
		for _, r := range compiled {
			if origin, dup := seen[r.ID]; dup {
				reports = append(reports, LoadReport{Path: path, Accepted: false,
					Kind:   RejectDuplicateRuleID,
					Reason: fmt.Sprintf("rule id %q already defined in %q", r.ID, origin)})
				fileOK = false
				break
			}
			seen[r.ID] = path
			ids = append(ids, r.ID)
		}
		if !fileOK {
			for _, id := range ids {
				delete(seen, id)
			}
			continue
		}
		rules = append(rules, compiled...)
		reports = append(reports, LoadReport{Path: path, Accepted: true, RuleIDs: ids})
	}

	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	byID := make(map[string]*Rule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
	}

	h := sha256.New()
	for _, r := range rules {
		fmt.Fprintf(h, "rule:%s|cond:%s\n", r.ID, r.Condition)
		for _, t := range r.Terms {
			w := "-"
			if t.HasOffset {
				w = fmt.Sprintf("%d+%d", t.Offset, t.Window)
			}
			fmt.Fprintf(h, "  %s@%s\n", t.Hex, w)
		}
	}
	seq := versionCounter.Add(1)
	set := &Set{
		Version: fmt.Sprintf("v%d-%s", seq, hex.EncodeToString(h.Sum(nil)[:12])),
		Rules:   rules,
		Reports: reports,
		Created: now,
		byID:    byID,
	}
	return set, nil
}

func compileFile(data []byte) ([]*Rule, error) {
	var raw rawFile
	dec := json.NewDecoder(strings.NewReader(string(data)))
	if err := dec.Decode(&raw); err != nil {
		return nil, reject(RejectInvalidJSON, "%v", err)
	}
	if dec.More() {
		return nil, reject(RejectInvalidJSON, "unexpected trailing content")
	}
	if len(raw.Rules) == 0 {
		return nil, reject(RejectInvalidJSON, "no rules defined")
	}
	out := make([]*Rule, 0, len(raw.Rules))
	for _, rr := range raw.Rules {
		r, err := compileRule(rr)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func compileRule(rr rawRule) (*Rule, error) {
	id := strings.TrimSpace(rr.ID)
	if id == "" {
		return nil, reject(RejectEmptyRuleID, "rule id must not be empty")
	}
	cond := Condition(strings.TrimSpace(rr.Condition))
	if cond == "" {
		cond = ConditionAll
	}
	if cond != ConditionAll && cond != ConditionAny {
		return nil, reject(RejectUnknownCondition, "rule %q: condition must be %q or %q", id, ConditionAll, ConditionAny)
	}
	if len(rr.Patterns) == 0 {
		return nil, reject(RejectEmptyPattern, "rule %q: at least one pattern is required", id)
	}
	terms := make([]Term, 0, len(rr.Patterns))
	for i, rp := range rr.Patterns {
		t, err := compileTerm(rp)
		if err != nil {
			kind, msg := RejectInfo(err)
			return nil, reject(kind, "rule %q pattern %d: %s", id, i, msg)
		}
		terms = append(terms, t)
	}
	return &Rule{ID: id, Description: rr.Description, Condition: cond, Terms: terms}, nil
}

func compileTerm(rp rawTerm) (Term, error) {
	var t Term
	clean := strings.TrimSpace(strings.ReplaceAll(rp.Hex, " ", ""))
	if clean == "" {
		return t, reject(RejectEmptyPattern, "hex pattern must not be empty")
	}
	if len(clean)%2 != 0 {
		return t, reject(RejectInvalidHex, "hex pattern %q has odd length", rp.Hex)
	}
	t.Bytes = make([]byte, len(clean)/2)
	t.Wild = make([]bool, len(clean)/2)
	for i := 0; i < len(clean); i += 2 {
		tok := clean[i : i+2]
		if tok == "??" || tok == "xx" || tok == "XX" {
			t.Wild[i/2] = true
			continue
		}
		var b byte
		if _, err := fmt.Sscanf(tok, "%x", &b); err != nil {
			return t, reject(RejectInvalidHex, "invalid byte token %q in %q", tok, rp.Hex)
		}
		t.Bytes[i/2] = b
	}
	t.Hex = strings.ToUpper(clean)
	if rp.Offset != nil {
		if *rp.Offset < 0 {
			return t, reject(RejectInvalidOffset, "offset must be >= 0")
		}
		t.Offset = *rp.Offset
		t.HasOffset = true
	}
	if rp.Window != nil {
		if !t.HasOffset {
			return t, reject(RejectInvalidWindow, "window requires an offset")
		}
		if *rp.Window < 0 {
			return t, reject(RejectInvalidWindow, "window must be >= 0")
		}
		t.Window = *rp.Window
	}
	return t, nil
}

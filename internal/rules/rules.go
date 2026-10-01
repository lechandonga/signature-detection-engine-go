// Package rules defines the local signature rule format, its compiler and a
// versioned, atomically swappable rule store.
package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// RejectReason explains why an individual rule file was rejected while the
// remaining files still loaded successfully.
type RejectReason string

const (
	ReasonReadError      RejectReason = "read_error"
	ReasonInvalidJSON    RejectReason = "invalid_json"
	ReasonEmptyRuleSet   RejectReason = "empty_rule_set"
	ReasonInvalidID      RejectReason = "invalid_id"
	ReasonInvalidPattern RejectReason = "invalid_pattern"
	ReasonInvalidOffset  RejectReason = "invalid_offset"
	ReasonInvalidMatch   RejectReason = "invalid_match_mode"
	ReasonDuplicateID    RejectReason = "duplicate_rule_id"
)

// FileError describes the rejection of a single rule file. One bad file never
// prevents the other files from loading.
type FileError struct {
	File   string
	Reason RejectReason
	Err    error
}

func (e *FileError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("rule file %q rejected (%s): %v", e.File, e.Reason, e.Err)
	}
	return fmt.Sprintf("rule file %q rejected (%s)", e.File, e.Reason)
}

func (e *FileError) Unwrap() error { return e.Err }

// Term is a single byte-string pattern with wildcard support and an optional
// absolute offset window.
//
// Pattern syntax (hex, whitespace ignored):
//
//	"4d 5a ?? ?? 00"   // "??" is a single wildcard byte
//	"4d5a[2]00"        // "[n]" is n wildcard bytes (n >= 1)
//
// An empty pattern string is illegal.
type Term struct {
	Pattern string `json:"pattern"`

	// OffsetStart/OffsetEnd constrain the byte offset of the pattern start.
	// Both bounds are inclusive. OffsetEnd == -1 means "unbounded".
	OffsetStart int64 `json:"offset_start"`
	OffsetEnd   int64 `json:"offset_end"`

	tokens []token
	minLen int
}

type tokenKind int

const (
	tokByte tokenKind = iota
	tokWildcard
)

type token struct {
	kind tokenKind
	val  byte
}

// Token is an exported view of a compiled pattern token.
type Token = token

// Rule combines one or more terms. With Match == "all" every term must be
// present (default); with "any" at least one term must match.
type Rule struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Match       string `json:"match"`
	Terms       []Term `json:"terms"`

	matchAll bool
}

// MatchAll reports whether every term must match.
func (r *Rule) MatchAll() bool { return r.matchAll }

// TermCount returns the number of compiled terms.
func (r *Rule) TermCount() int { return len(r.Terms) }

// File is the on-disk rule document. A file holds one or more rules.
type File struct {
	Rules []Rule `json:"rules"`
}

// Compiled is an immutable, ready-to-scan rule set. Version is a content hash
// over every accepted rule file, so any add/modify/delete changes it.
type Compiled struct {
	Version string
	Rules   []*Rule
}

func stripHexSpace(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

func compilePattern(p string) ([]token, int, error) {
	s := stripHexSpace(p)
	if s == "" {
		return nil, 0, fmt.Errorf("empty pattern")
	}
	var toks []token
	wildcards := 0
	flush := func() {
		for i := 0; i < wildcards; i++ {
			toks = append(toks, token{kind: tokWildcard})
		}
		wildcards = 0
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '?':
			if i+1 >= len(s) || s[i+1] != '?' {
				return nil, 0, fmt.Errorf("wildcard must be '??' at position %d", i)
			}
			wildcards++
			i += 2
		case c == '[':
			flush()
			j := strings.IndexByte(s[i:], ']')
			if j < 0 {
				return nil, 0, fmt.Errorf("unterminated wildcard group at position %d", i)
			}
			nStr := s[i+1 : i+j]
			if nStr == "" {
				return nil, 0, fmt.Errorf("empty wildcard group at position %d", i)
			}
			n := 0
			for _, d := range []byte(nStr) {
				if d < '0' || d > '9' {
					return nil, 0, fmt.Errorf("wildcard group count must be decimal digits at position %d", i)
				}
				n = n*10 + int(d-'0')
			}
			if n == 0 {
				return nil, 0, fmt.Errorf("wildcard group count must be >= 1 at position %d", i)
			}
			for k := 0; k < n; k++ {
				toks = append(toks, token{kind: tokWildcard})
			}
			i += j + 1
		case isHexDigit(c):
			flush()
			if i+1 >= len(s) || !isHexDigit(s[i+1]) {
				return nil, 0, fmt.Errorf("odd hex digit at position %d", i)
			}
			toks = append(toks, token{kind: tokByte, val: hexVal(c)<<4 | hexVal(s[i+1])})
			i += 2
		default:
			return nil, 0, fmt.Errorf("unexpected character %q at position %d", string(c), i)
		}
	}
	flush()
	return toks, len(toks), nil
}

func compileTerm(t *Term) error {
	if t.OffsetStart < 0 {
		return &FileError{Reason: ReasonInvalidOffset, Err: fmt.Errorf("offset_start must be >= 0, got %d", t.OffsetStart)}
	}
	if t.OffsetEnd != -1 && t.OffsetEnd < t.OffsetStart {
		return &FileError{Reason: ReasonInvalidOffset, Err: fmt.Errorf("offset_end (%d) must be >= offset_start (%d), or -1 for unbounded", t.OffsetEnd, t.OffsetStart)}
	}
	toks, n, err := compilePattern(t.Pattern)
	if err != nil {
		return &FileError{Reason: ReasonInvalidPattern, Err: err}
	}
	t.tokens = toks
	t.minLen = n
	return nil
}

func compileRule(r *Rule) *FileError {
	if strings.TrimSpace(r.ID) == "" {
		return &FileError{Reason: ReasonInvalidID, Err: fmt.Errorf("rule id is empty")}
	}
	if strings.ContainsAny(r.ID, " \t\r\n") {
		return &FileError{Reason: ReasonInvalidID, Err: fmt.Errorf("rule id %q contains whitespace", r.ID)}
	}
	if len(r.Terms) == 0 {
		return &FileError{Reason: ReasonEmptyRuleSet, Err: fmt.Errorf("rule %q has no terms", r.ID)}
	}
	switch strings.ToLower(r.Match) {
	case "", "all":
		r.matchAll = true
	case "any":
		r.matchAll = false
	default:
		return &FileError{Reason: ReasonInvalidMatch, Err: fmt.Errorf("rule %q has unknown match mode %q", r.ID, r.Match)}
	}
	for i := range r.Terms {
		if err := compileTerm(&r.Terms[i]); err != nil {
			fe := err.(*FileError)
			fe.Err = fmt.Errorf("rule %q term %d: %w", r.ID, i, fe.Err)
			return fe
		}
	}
	return nil
}

// rawFile parses a rule document, distinguishing malformed JSON from valid
// JSON with an invalid schema.
func rawFile(name string, data []byte) (File, *FileError) {
	var f File
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return File{}, &FileError{File: name, Reason: ReasonInvalidJSON, Err: err}
	}
	if dec.More() {
		return File{}, &FileError{File: name, Reason: ReasonInvalidJSON, Err: fmt.Errorf("unexpected trailing data")}
	}
	if len(f.Rules) == 0 {
		return File{}, &FileError{File: name, Reason: ReasonEmptyRuleSet, Err: fmt.Errorf("file contains no rules")}
	}
	return f, nil
}

// RawFileForTest exposes the strict parser for cross-package tests.
func RawFileForTest(name string, data []byte) (File, *FileError) {
	return rawFile(name, data)
}

// Bundle is an ordered collection of accepted-at-parse-time rule files.
type Bundle struct {
	names []string
	files []File
}

// Add appends one parsed file to the bundle.
func (b *Bundle) Add(name string, f File) {
	b.names = append(b.names, name)
	b.files = append(b.files, f)
}

// Compile validates and compiles a bundle. A rule that fails validation
// rejects only its own file; the returned error carries a distinguishing
// RejectReason.
func (b *Bundle) Compile() (*Compiled, []*FileError) {
	compiled := &Compiled{}
	var rejects []*FileError
	seen := map[string]string{}

	h := sha256.New()

	for i, f := range b.files {
		name := b.names[i]
		fileRules := make([]*Rule, 0, len(f.Rules))
		localIDs := map[string]bool{}
		var fileErr *FileError
		for ri := range f.Rules {
			r := &f.Rules[ri]
			if fe := compileRule(r); fe != nil {
				fe.File = name
				fileErr = fe
				break
			}
			if localIDs[r.ID] {
				fileErr = &FileError{File: name, Reason: ReasonDuplicateID, Err: fmt.Errorf("rule id %q duplicated within file", r.ID)}
				break
			}
			if other, ok := seen[r.ID]; ok {
				fileErr = &FileError{File: name, Reason: ReasonDuplicateID, Err: fmt.Errorf("rule id %q already defined in %q", r.ID, other)}
				break
			}
			localIDs[r.ID] = true
			fileRules = append(fileRules, r)
		}
		if fileErr != nil {
			rejects = append(rejects, fileErr)
			continue
		}
		fmt.Fprintf(h, "%s\x00", name)
		raw, _ := json.Marshal(f)
		h.Write(raw)
		h.Write([]byte{0})
		for _, r := range fileRules {
			seen[r.ID] = name
			compiled.Rules = append(compiled.Rules, r)
		}
	}
	compiled.Version = hex.EncodeToString(h.Sum(nil))[:16]

	// Stable rule order: sorted by ID for reproducible output regardless of
	// filesystem iteration order.
	sort.Slice(compiled.Rules, func(i, j int) bool { return compiled.Rules[i].ID < compiled.Rules[j].ID })
	return compiled, rejects
}

// TokensView exposes compiled tokens to the matcher.
func (t *Term) TokensView() []Token { return t.tokens }

// MinLen returns the compiled pattern length in bytes.
func (t *Term) MinLen() int { return t.minLen }

// Window returns the inclusive absolute offset window. end == -1 means open.
func (t *Term) Window() (start, end int64) { return t.OffsetStart, t.OffsetEnd }

// TokByte reports whether the token is a concrete byte (vs wildcard).
func TokByte(tok Token) (byte, bool) {
	if tok.kind == tokByte {
		return tok.val, true
	}
	return 0, false
}

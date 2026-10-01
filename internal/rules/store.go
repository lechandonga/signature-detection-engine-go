package rules

import "sync/atomic"

// emptyVersion is the deterministic version of a rule set with no accepted
// rules.
const emptyVersion = "0000000000000000"

// Store holds the current rule set behind an atomic pointer. Reload builds a
// brand-new immutable Compiled value before swapping it in, so scans in
// progress keep using the snapshot they started with and no old rules can leak
// into post-reload scans.
type Store struct {
	current atomic.Pointer[Compiled]
}

// NewStore initializes a store with an empty rule set.
func NewStore() *Store {
	s := &Store{}
	s.current.Store(&Compiled{Version: emptyVersion})
	return s
}

// Snapshot returns the immutable rule set visible at this instant.
func (s *Store) Snapshot() *Compiled { return s.current.Load() }

// Reload loads dir and atomically replaces the active rule set. It returns the
// new version and per-file rejections. A rule file that disappears is simply
// absent from the rebuilt set, so deletions take effect immediately.
func (s *Store) Reload(dir string) (string, []*FileError) {
	res := LoadDir(dir)
	s.current.Store(res.Compiled)
	return res.Compiled.Version, res.Rejected
}

// Replace atomically installs a prebuilt rule set (used by tests).
func (s *Store) Replace(c *Compiled) {
	if c == nil {
		c = &Compiled{Version: emptyVersion}
	}
	s.current.Store(c)
}

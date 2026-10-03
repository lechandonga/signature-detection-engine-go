package engine

import (
	"container/list"
	"crypto/sha256"
	"sync"
	"time"
)

// cacheEntry is the persisted scan knowledge for one (rule version, file id)
// pair: the finished result plus everything needed to resume an append-only
// rescan.
type cacheEntry struct {
	version string
	fileID  string

	identity fileIdentity
	size     int64
	modTime  time.Time

	// prefixHash is the hex SHA-256 of bytes [0,size); an append-only
	// resume is accepted only after this prefix hashes identically.
	prefixHash string

	// result of the last complete scan.
	res *Result

	// resumable matcher state at size.
	snapshot *MatcherSnapshot

	// hashState is the marshaled sha256 state over bytes [0,size), so the
	// content hash of an appended file can be finished without re-reading the
	// prefix.
	hashState []byte

	// cost is this entry's contribution to the capacity budget.
	cost int64

	el *list.Element // LRU position
}

// entryStore is a version-partitioned, capacity-bounded LRU of cacheEntry.
// Eviction can only remove optimization state, never correctness: a missing
// entry simply makes the next scan a full one.
type entryStore struct {
	mu          sync.Mutex
	byKey       map[string]*cacheEntry // key: version + "\x00" + fileID
	lru         *list.List             // *cacheEntry, front = most recently used
	limit       int64                  // <=0 means unlimited
	used        int64
	evicted     int64
	recentEvict []string // bounded ring of recently evicted keys (best effort)
}

const recentEvictRing = 4096

func newEntryStore(limit int64) *entryStore {
	return &entryStore{
		byKey: map[string]*cacheEntry{},
		lru:   list.New(),
		limit: limit,
	}
}

func storeKey(version, fileID string) string {
	return version + "\x00" + fileID
}

func (s *entryStore) get(version, fileID string) *cacheEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byKey[storeKey(version, fileID)]
	if !ok {
		return nil
	}
	s.lru.MoveToFront(e.el)
	return e
}

// touch only refreshes recency (fast-path cache reuse).
func (s *entryStore) touch(version, fileID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.byKey[storeKey(version, fileID)]; ok {
		s.lru.MoveToFront(e.el)
	}
}

// put inserts/replaces an entry and evicts least-recently-used entries until
// the budget fits. If a single entry is larger than the whole budget it is
// still stored (a scan result must remain usable once) and evicted again on
// the following insertion.
func (s *entryStore) put(e *cacheEntry) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeKey(e.version, e.fileID)
	if old, ok := s.byKey[key]; ok {
		s.used -= old.cost
		s.lru.Remove(old.el)
		delete(s.byKey, key)
	}
	e.el = s.lru.PushFront(e)
	s.byKey[key] = e
	s.used += e.cost

	var n int64
	if s.limit > 0 {
		// Never evict the entry just inserted on this insertion; older
		// entries pay first so the newest scan always keeps its progress.
		for s.used > s.limit && s.lru.Len() > 1 {
			oldest := s.lru.Back()
			old := oldest.Value.(*cacheEntry)
			if old == e {
				break
			}
			s.lru.Remove(oldest)
			delete(s.byKey, storeKey(old.version, old.fileID))
			s.used -= old.cost
			s.recentEvict = append(s.recentEvict, storeKey(old.version, old.fileID))
			if len(s.recentEvict) > recentEvictRing {
				s.recentEvict = s.recentEvict[len(s.recentEvict)-recentEvictRing:]
			}
			n++
		}
	}
	s.evicted += n
	return n
}

// wasEvicted best-effort distinguishes "progress was evicted" from "file was
// never seen", so ProgressReaction can say evicted.
func (s *entryStore) wasEvicted(version, fileID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := storeKey(version, fileID)
	for _, k := range s.recentEvict {
		if k == key {
			return true
		}
	}
	return false
}

// pruneVersion drops every entry not belonging to keepVersion. A rule hot
// reload must not let resume progress computed against old rules continue.
func (s *entryStore) pruneVersion(keepVersion string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.byKey {
		if e.version != keepVersion {
			s.lru.Remove(e.el)
			s.used -= e.cost
			delete(s.byKey, k)
		}
	}
}

func (s *entryStore) stats() (entries int, used, limit, evicted int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lru.Len(), s.used, s.limit, s.evicted
}

// entryCost is the explicit eviction accounting: the file bytes the entry
// lets us skip on the next scan, plus the matcher occurrence bookkeeping
// (16 bytes per recorded occurrence), plus the snapshot tail and the
// marshaled hash state.
func entryCost(size int64, snapshot *MatcherSnapshot) int64 {
	cost := size
	if snapshot != nil {
		cost += int64(len(snapshot.Tail))
		var occ int
		for _, m := range snapshot.Seen {
			occ += len(m)
		}
		for _, m := range snapshot.Matches {
			occ += len(m)
		}
		cost += int64(occ) * 16
	}
	cost += sha256.Size
	return cost
}

// usable reports whether the entry carries everything an append-only resume
// (or an unchanged-file reuse) needs.
func (e *cacheEntry) usable() bool {
	return e != nil && e.res != nil && e.snapshot != nil && e.hashState != nil
}

package engine

import (
	"container/list"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/lechandonga/signature-detection-engine-go/rules"
)

// Status is the machine-readable outcome of scanning one file.
type Status string

const (
	StatusOK         Status = "OK"
	StatusUnreadable Status = "FILE_UNREADABLE"
	StatusTruncated  Status = "FILE_TRUNCATED"
	StatusModified   Status = "FILE_MODIFIED_DURING_SCAN"
	StatusPanic      Status = "SCAN_INTERNAL_ERROR"
)

// Mode reports how much of the file actually went through the matcher.
type Mode string

const (
	// ModeReuse: content already known; zero bytes read or processed.
	ModeReuse Mode = "REUSE"
	// ModeIncremental: only bytes appended since the previous scan were
	// processed; the prefix was verified unchanged.
	ModeIncremental Mode = "INCREMENTAL"
	// ModeFull: every byte of the file was processed from scratch.
	ModeFull Mode = "FULL"
)

// Basis reports what happened to the incremental-scan basis.
type Basis string

const (
	BasisReused      Basis = "REUSED"
	BasisValid       Basis = "ESTABLISHED"
	BasisInvalidated Basis = "INVALIDATED"
)

// Machine-readable invalidation reasons.
const (
	ReasonEvicted   = "CACHE_EVICTED"
	ReasonRuleVer   = "RULE_VERSION_CHANGED"
	ReasonTruncated = "FILE_TRUNCATED_OR_REPLACED"
	ReasonRewritten = "PREFIX_CHANGED"
)

// WorkStats quantifies what a scan actually did. Counters count file
// content bytes only; cache/state bookkeeping is excluded.
type WorkStats struct {
	// BytesRead: bytes actually read from the OS, including verification.
	BytesRead int64 `json:"bytes_read"`
	// BytesProcessed: bytes fed through the signature matcher.
	BytesProcessed int64 `json:"bytes_processed"`
	// BytesReused: bytes whose match result was taken from the saved basis.
	BytesReused int64 `json:"bytes_reused"`
	// FileSize: total size of the file this result describes.
	FileSize int64 `json:"file_size"`
}

// Result is the scan outcome for a single file.
type Result struct {
	FileID      string `json:"file_id"`
	Path        string `json:"path"`
	Status      Status `json:"status"`
	Error       string `json:"error,omitempty"`
	RuleVersion string `json:"rule_version"`
	Hits        []Hit  `json:"hits"`
	ContentHash string `json:"content_hash,omitempty"`
	// Cached stays true when the judgment was served from cache (REUSE and
	// singleflight waiters), preserving the original field semantics.
	Cached bool `json:"cached"`
	Mode   Mode `json:"mode"`
	// Basis: REUSED (basis served the scan), ESTABLISHED (first full scan),
	// INVALIDATED (prior basis discarded; see BasisReason).
	Basis       Basis     `json:"basis,omitempty"`
	BasisReason string    `json:"basis_reason,omitempty"`
	Stats       WorkStats `json:"stats"`
}

// FileIDer maps a path to a stable identifier. By default the absolute path
// is used.
type FileIDer func(path string) string

// fileIdentity identifies the inode-like object behind a path. A change
// proves the path was replaced (rename-over, rotation, new mount).
type fileIdentity struct {
	dev  uint64
	ino  uint64
	size int64
}

// tombstone records that a file had a basis under a superseded rule version
// or that its basis was evicted. It carries no match data and only marks the
// next full scan as INVALIDATED rather than a clean first scan.
type tombstone struct {
	version string
	reason  string
}

// cacheEntry is one per-file continuation basis bound to one rule version.
type cacheEntry struct {
	fileID     string
	version    string
	identity   fileIdentity
	modTime    int64 // unix-nano mtime of the content this basis describes
	size       int64
	hash       string // sha256 of the whole file content
	prefixHash []byte // marshaled sha256 state after size bytes
	matcher    *matcherState
	hits       []Hit
}

// Engine owns the active rule snapshot and a bounded, version-bound basis
// cache. All methods are safe for concurrent use.
type Engine struct {
	rulePaths []string
	idFor     FileIDer
	chunkSize int

	mu          sync.Mutex
	active      *rules.Set
	entries     map[string]*list.Element
	lru         *list.List // front = most recently used; values are *cacheEntry
	maxBytes    int64      // represented-file-bytes budget; <0 = unlimited
	trackedSize int64
	tombstones  map[string]tombstone // keyed by fileID
	inflight    sync.Map             // version + "\x01" + fileID -> *call

	onChunk func(path string, chunkIndex int)
}

// Config configures an Engine.
type Config struct {
	RulePaths []string
	FileID    FileIDer
	ChunkSize int
	// CacheMaxBytes bounds the basis cache, counted as the sum of file sizes
	// represented by cached entries. 0 (default) means 64 MiB; negative means
	// unlimited.
	CacheMaxBytes int64
}

// New loads the initial rule set and builds an Engine.
func New(cfg Config) (*Engine, error) {
	chunk := cfg.ChunkSize
	if chunk <= 0 {
		chunk = 4096
	}
	idFor := cfg.FileID
	if idFor == nil {
		idFor = func(p string) string {
			if abs, err := filepath.Abs(p); err == nil {
				return abs
			}
			return p
		}
	}
	maxBytes := int64(64 << 20)
	if cfg.CacheMaxBytes != 0 {
		maxBytes = cfg.CacheMaxBytes
	}
	e := &Engine{
		rulePaths:  append([]string(nil), cfg.RulePaths...),
		idFor:      idFor,
		chunkSize:  chunk,
		entries:    map[string]*list.Element{},
		lru:        list.New(),
		maxBytes:   maxBytes,
		tombstones: map[string]tombstone{},
	}
	set, err := rules.LoadFiles(e.rulePaths)
	if err != nil {
		return nil, err
	}
	e.active = set
	return e, nil
}

// Rules returns the active immutable rule snapshot.
func (e *Engine) Rules() *rules.Set {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.active
}

// Reload recompiles all rule files and atomically swaps the snapshot.
// In-flight scans keep using the snapshot they started with. Every basis
// bound to a superseded rule version is evicted, so the new rules are always
// applied to the whole file — never continued incrementally under old rules.
func (e *Engine) Reload() (*rules.Set, error) {
	set, err := rules.LoadFiles(e.rulePaths)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.active = set
	e.pruneCacheLocked()
	e.mu.Unlock()
	return set, nil
}

// pruneCacheLocked drops entries not belonging to the active version.
func (e *Engine) pruneCacheLocked() {
	prefix := e.active.Version + "\x00"
	for key, el := range e.entries {
		if len(key) <= len(prefix) || key[:len(prefix)] != prefix {
			en := el.Value.(*cacheEntry)
			e.tombstones[en.fileID] = tombstone{version: en.version, reason: ReasonRuleVer}
			e.removeElementLocked(el)
		}
	}
}

func (e *Engine) cacheKey(version, fileID string) string {
	return version + "\x00" + fileID
}

func (e *Engine) removeElementLocked(el *list.Element) {
	en := el.Value.(*cacheEntry)
	delete(e.entries, e.cacheKey(en.version, en.fileID))
	e.trackedSize -= en.size
	e.lru.Remove(el)
}

// putLocked installs en and evicts least-recently-used entries until the
// represented-bytes budget fits. Other entries are evicted before the new
// one; a single file larger than the budget evicts everything else but is
// itself retained, since eviction must never affect results.
func (e *Engine) putLocked(en *cacheEntry) {
	if old, ok := e.entries[e.cacheKey(en.version, en.fileID)]; ok {
		e.removeElementLocked(old)
	}
	el := e.lru.PushFront(en)
	e.entries[e.cacheKey(en.version, en.fileID)] = el
	e.trackedSize += en.size

	if e.maxBytes < 0 {
		return
	}
	for e.trackedSize > e.maxBytes {
		victim := e.lru.Back()
		if victim == nil || victim == el {
			break
		}
		vn := victim.Value.(*cacheEntry)
		e.tombstones[vn.fileID] = tombstone{version: vn.version, reason: ReasonEvicted}
		e.removeElementLocked(victim)
	}
}

func (e *Engine) getLocked(version, fileID string) *cacheEntry {
	if el, ok := e.entries[e.cacheKey(version, fileID)]; ok {
		e.lru.MoveToFront(el)
		return el.Value.(*cacheEntry)
	}
	return nil
}

// CacheStats reports the number of cached bases and the represented file
// bytes they account for.
func (e *Engine) CacheStats() (entries int, representedBytes int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lru.Len(), e.trackedSize
}

// SetCacheMaxBytes changes the represented-bytes capacity at runtime and
// immediately enforces it with LRU eviction. A negative value disables the
// limit. Eviction only removes bases; it never alters scan results.
func (e *Engine) SetCacheMaxBytes(n int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.maxBytes = n
	if n < 0 {
		return
	}
	for e.trackedSize > n {
		victim := e.lru.Back()
		if victim == nil {
			break
		}
		en := victim.Value.(*cacheEntry)
		e.tombstones[en.fileID] = tombstone{version: en.version, reason: ReasonEvicted}
		e.removeElementLocked(victim)
	}
}

// call deduplicates concurrent scans of the same key (singleflight).
type call struct {
	done chan struct{}
	res  *Result
}

// ScanBatch scans many files concurrently. One file's failure never affects
// the others; the slice order matches the input order.
func (e *Engine) ScanBatch(paths []string) []*Result {
	results := make([]*Result, len(paths))
	var wg sync.WaitGroup
	for i, p := range paths {
		wg.Add(1)
		go func(idx int, path string) {
			defer wg.Done()
			results[idx] = e.Scan(path)
		}(i, p)
	}
	wg.Wait()
	return results
}

// Scan scans one file, transparently reusing saved work:
//
//   - same inode object, same size, same full-file hash -> REUSE, zero I/O;
//   - append-only change (same object, verified-identical prefix) ->
//     INCREMENTAL, only the suffix is matched;
//   - rewrite/truncation/replacement, evicted basis, or new rule version ->
//     FULL; Basis is INVALIDATED with a reason when a prior basis was
//     discarded.
//
// Concurrent scans of the same file and rule version share one computation.
// Returned Results are private copies.
func (e *Engine) Scan(path string) (result *Result) {
	fileID := e.idFor(path)
	set := e.Rules()
	flightKey := set.Version + "\x01" + fileID

	c := &call{done: make(chan struct{})}
	if actual, loaded := e.inflight.LoadOrStore(flightKey, c); loaded {
		<-actual.(*call).done
		return cloneResult(actual.(*call).res, true)
	}
	defer func() {
		c.res = result
		close(c.done)
		e.inflight.Delete(flightKey)
	}()

	defer func() {
		if r := recover(); r != nil {
			result = &Result{
				FileID: fileID, Path: path, Status: StatusPanic,
				Error:       fmt.Sprintf("panic: %v", r),
				RuleVersion: set.Version,
				Hits:        []Hit{},
				Mode:        ModeFull,
			}
		}
	}()

	return e.scanOnce(path, fileID, set)
}

func cloneResult(r *Result, cached bool) *Result {
	cp := *r
	cp.Hits = append([]Hit(nil), r.Hits...)
	cp.Cached = cached
	return &cp
}

func failureResult(fileID, path, version string, status Status, err error) *Result {
	return &Result{
		FileID: fileID, Path: path, Status: status,
		Error: err.Error(), RuleVersion: version, Hits: []Hit{},
		Mode: ModeFull,
	}
}

func identityOf(fi os.FileInfo) fileIdentity {
	id := fileIdentity{size: fi.Size()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		id.dev = uint64(st.Dev)
		id.ino = st.Ino
	}
	return id
}

func (e *Engine) scanOnce(path, fileID string, set *rules.Set) *Result {
	f, err := os.Open(path)
	if err != nil {
		return failureResult(fileID, path, set.Version, StatusUnreadable, err)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return failureResult(fileID, path, set.Version, StatusUnreadable, err)
	}
	currentSize := fi.Size()
	identity := identityOf(fi)

	e.mu.Lock()
	prior := e.getLocked(set.Version, fileID)
	var priorBasis *cacheEntry
	var staleReason string
	if prior == nil {
		// No basis under the active version: first scan, a capacity
		// eviction, or a rule-version change. A tombstone distinguishes the
		// invalidation cases from a clean first scan.
		if tb, ok := e.tombstones[fileID]; ok {
			priorBasis = &cacheEntry{fileID: fileID, version: tb.version}
			staleReason = tb.reason
		}
	}
	e.mu.Unlock()

	switch {
	case prior == nil:
		return e.fullScan(f, path, fileID, set, currentSize, priorBasis, staleReason)

	case sameObjectSameSize(prior, identity):
		// Same inode object and same size. An unchanged mtime serves the
		// result with zero I/O (the common unchanged-file inspection). If
		// the mtime moved, a same-size rewrite may have happened, so prove
		// content identity with a full hash before reusing anything.
		if fi.ModTime().UnixNano() == prior.modTime {
			return &Result{
				FileID: fileID, Path: path, Status: StatusOK,
				RuleVersion: set.Version, Hits: append([]Hit(nil), prior.hits...),
				ContentHash: prior.hash, Cached: true,
				Mode: ModeReuse, Basis: BasisReused,
				Stats: WorkStats{BytesReused: currentSize, FileSize: currentSize},
			}
		}
		sum, n, err := hashRange(f, 0, currentSize)
		if err != nil {
			return failureResult(fileID, path, set.Version, StatusUnreadable, err)
		}
		if sum == prior.hash {
			return &Result{
				FileID: fileID, Path: path, Status: StatusOK,
				RuleVersion: set.Version, Hits: append([]Hit(nil), prior.hits...),
				ContentHash: prior.hash, Cached: true,
				Mode: ModeReuse, Basis: BasisReused,
				Stats: WorkStats{BytesRead: n, BytesReused: currentSize, FileSize: currentSize},
			}
		}
		if _, serr := f.Seek(0, io.SeekStart); serr != nil {
			return failureResult(fileID, path, set.Version, StatusUnreadable, serr)
		}
		return e.fullScan(f, path, fileID, set, currentSize, prior, ReasonRewritten)

	case currentSize < prior.size:
		return e.fullScan(f, path, fileID, set, currentSize, prior, ReasonTruncated)

	case !sameObject(prior, identity):
		return e.fullScan(f, path, fileID, set, currentSize, prior, ReasonTruncated)

	default:
		// Grew. This is an incremental candidate only if the old prefix is
		// provably byte-identical; otherwise (e.g. truncate-then-rewrite to a
		// longer size) fall back to a full scan.
		return e.incrementalScan(f, path, fileID, set, currentSize, prior)
	}
}

func sameObject(a *cacheEntry, id fileIdentity) bool {
	return a.identity.dev == id.dev && a.identity.ino == id.ino
}

func sameObjectSameSize(a *cacheEntry, id fileIdentity) bool {
	return sameObject(a, id) && a.size == id.size
}

// fullScan reads and matches the entire file from offset 0. invalidReason
// is empty for a first scan (Basis ESTABLISHED) or names why a prior basis
// had to be discarded (Basis INVALIDATED).
func (e *Engine) fullScan(f *os.File, path, fileID string, set *rules.Set,
	expectedSize int64, prior *cacheEntry, invalidReason string) *Result {

	matcher := newStreamMatcher(set)
	h := sha256.New()
	buf := make([]byte, e.chunkSize)
	var readTotal int64
	chunkIndex := 0

	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			matcher.write(chunk)
			h.Write(chunk)
			readTotal += int64(n)
			chunkIndex++
			if e.onChunk != nil {
				e.onChunk(path, chunkIndex)
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return failureResult(fileID, path, set.Version, StatusUnreadable, rerr)
		}
	}

	if readTotal < expectedSize {
		return &Result{
			FileID: fileID, Path: path, Status: StatusTruncated,
			Error:       fmt.Sprintf("expected %d bytes but read %d", expectedSize, readTotal),
			RuleVersion: set.Version, Hits: []Hit{}, Mode: ModeFull,
		}
	}

	// Independent verification re-read. Any difference (rewrite, truncation,
	// append) proves the result would not describe the current content, so a
	// dirty partial result is never returned.
	verify, vbytes, err := hashRange(f, 0, -1)
	if err != nil {
		return failureResult(fileID, path, set.Version, StatusUnreadable, err)
	}
	streamHash := hex.EncodeToString(h.Sum(nil))
	if verify != streamHash {
		return &Result{
			FileID: fileID, Path: path, Status: StatusModified,
			Error: fmt.Sprintf("content changed while scanning: streamed=%s verified=%s",
				streamHash, verify),
			RuleVersion: set.Version, Hits: []Hit{}, Mode: ModeFull,
			Stats: WorkStats{BytesRead: readTotal + vbytes, BytesProcessed: readTotal, FileSize: readTotal},
		}
	}

	hits := matcher.finish()
	id0, mt0 := identityOfStat(f)
	en := &cacheEntry{
		fileID:     fileID,
		version:    set.Version,
		identity:   id0,
		modTime:    mt0,
		size:       readTotal,
		hash:       streamHash,
		prefixHash: marshalHash(h),
		matcher:    matcher.snapshot(),
		hits:       append([]Hit(nil), hits...),
	}
	e.mu.Lock()
	delete(e.tombstones, fileID)
	e.putLocked(en)
	e.mu.Unlock()

	basis := BasisValid
	if prior != nil || invalidReason != "" {
		basis = BasisInvalidated
	}
	return &Result{
		FileID: fileID, Path: path, Status: StatusOK,
		RuleVersion: set.Version, Hits: hits, ContentHash: streamHash,
		Cached: false, Mode: ModeFull, Basis: basis, BasisReason: invalidReason,
		Stats: WorkStats{
			BytesRead:      readTotal + vbytes,
			BytesProcessed: readTotal,
			FileSize:       readTotal,
		},
	}
}

// incrementalScan verifies the saved prefix and matches only the suffix.
func (e *Engine) incrementalScan(f *os.File, path, fileID string, set *rules.Set,
	currentSize int64, prior *cacheEntry) *Result {

	prefixLen := prior.size

	// 1. Verify the prefix is byte-identical (reads, but does not match).
	prefixSum, preBytes, err := hashRange(f, 0, prefixLen)
	if err != nil {
		return failureResult(fileID, path, set.Version, StatusUnreadable, err)
	}
	h2 := restoreHash(prior.prefixHash)
	wantPrefix := hex.EncodeToString(h2.Sum(nil))
	if prefixSum != wantPrefix {
		if _, serr := f.Seek(0, io.SeekStart); serr != nil {
			return failureResult(fileID, path, set.Version, StatusUnreadable, serr)
		}
		return e.fullScan(f, path, fileID, set, currentSize, prior, ReasonRewritten)
	}

	// 2. Restore the matcher checkpoint (which carries the cross-boundary
	// tail) and the prefix hash state, then process only appended bytes.
	matcher := restoreMatcher(set, prior.matcher)
	h := restoreHash(prior.prefixHash)
	buf := make([]byte, e.chunkSize)
	var suffixRead int64
	chunkIndex := 0

	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			matcher.write(buf[:n])
			h.Write(buf[:n])
			suffixRead += int64(n)
			chunkIndex++
			if e.onChunk != nil {
				e.onChunk(path, chunkIndex)
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return failureResult(fileID, path, set.Version, StatusUnreadable, rerr)
		}
	}

	if prefixLen+suffixRead < currentSize {
		return &Result{
			FileID: fileID, Path: path, Status: StatusTruncated,
			Error: fmt.Sprintf("expected %d bytes but read %d (prefix=%d suffix=%d)",
				currentSize, prefixLen+suffixRead, prefixLen, suffixRead),
			RuleVersion: set.Version, Hits: []Hit{}, Mode: ModeIncremental,
		}
	}

	// 3. Independent full verification. A concurrent append or rewrite makes
	// the hash differ (or the file shorter), which is reported explicitly
	// instead of returning a seemingly complete partial result.
	verify, vbytes, err := hashRange(f, 0, -1)
	if err != nil {
		return failureResult(fileID, path, set.Version, StatusUnreadable, err)
	}
	streamHash := hex.EncodeToString(h.Sum(nil))
	if verify != streamHash {
		return &Result{
			FileID: fileID, Path: path, Status: StatusModified,
			Error: fmt.Sprintf("content changed while incremental scanning: streamed=%s verified=%s",
				streamHash, verify),
			RuleVersion: set.Version, Hits: []Hit{}, Mode: ModeIncremental,
			Stats: WorkStats{
				BytesRead:      preBytes + suffixRead + vbytes,
				BytesProcessed: suffixRead,
				BytesReused:    prefixLen,
				FileSize:       prefixLen + suffixRead,
			},
		}
	}

	hits := matcher.finish()
	id1, mt1 := identityOfStat(f)
	en := &cacheEntry{
		fileID:     fileID,
		version:    set.Version,
		identity:   id1,
		modTime:    mt1,
		size:       prefixLen + suffixRead,
		hash:       streamHash,
		prefixHash: marshalHash(h),
		matcher:    matcher.snapshot(),
		hits:       append([]Hit(nil), hits...),
	}
	e.mu.Lock()
	delete(e.tombstones, fileID)
	e.putLocked(en)
	e.mu.Unlock()

	return &Result{
		FileID: fileID, Path: path, Status: StatusOK,
		RuleVersion: set.Version, Hits: hits, ContentHash: streamHash,
		Cached: false, Mode: ModeIncremental, Basis: BasisReused,
		Stats: WorkStats{
			BytesRead:      preBytes + suffixRead + vbytes,
			BytesProcessed: suffixRead,
			BytesReused:    prefixLen,
			FileSize:       prefixLen + suffixRead,
		},
	}
}

func identityOfStat(f *os.File) (fileIdentity, int64) {
	fi, err := f.Stat()
	if err != nil {
		return fileIdentity{}, 0
	}
	return identityOf(fi), fi.ModTime().UnixNano()
}

// hashRange hashes length bytes starting at offset. length < 0 means "to EOF"
// and the final file size is reflected by the returned byte count. It leaves
// the file offset unspecified; callers re-seek as needed.
func hashRange(f *os.File, offset, length int64) (digest string, bytes int64, err error) {
	if _, err = f.Seek(offset, io.SeekStart); err != nil {
		return "", 0, err
	}
	h := sha256.New()
	buf := make([]byte, 32*1024)
	remaining := length
	for length < 0 || remaining > 0 {
		n := len(buf)
		if length >= 0 && int64(n) > remaining {
			n = int(remaining)
		}
		n, rerr := f.Read(buf[:n])
		if n > 0 {
			h.Write(buf[:n])
			bytes += int64(n)
			remaining -= int64(n)
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return "", bytes, rerr
		}
	}
	return hex.EncodeToString(h.Sum(nil)), bytes, nil
}

// marshalHash serializes a sha256 digest state; restoreHash rebuilds an
// equivalent digest. Prefix verification uses the restored state to continue
// hashing appended bytes without reprocessing the verified prefix.
func marshalHash(h hash.Hash) []byte {
	b, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		panic(fmt.Sprintf("hash marshal: %v", err))
	}
	return b
}

func restoreHash(state []byte) hash.Hash {
	h := sha256.New()
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(state); err != nil {
		panic(fmt.Sprintf("hash unmarshal: %v", err))
	}
	return h
}

// SetOnChunk installs (or clears with nil) a callback fired after each
// streamed chunk during full and incremental matching. For incremental scans
// chunk indices restart at 1 over the appended suffix.
func (e *Engine) SetOnChunk(fn func(path string, chunkIndex int)) {
	e.onChunk = fn
}

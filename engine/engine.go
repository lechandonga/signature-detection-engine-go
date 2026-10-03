package engine

import (
	"container/list"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/lechandonga/signature-detection-engine-go/rules"
)

// Status is the machine-readable outcome of scanning one file.
type Status string

const (
	// StatusOK means the file was fully scanned from the beginning and
	// Hits are trustworthy.
	StatusOK Status = "OK"
	// StatusIncremental means an append-only continuation: only bytes past
	// the previous scan point were fed to the matcher, but Hits are
	// byte-for-byte identical to a from-scratch scan of the current file.
	StatusIncremental Status = "OK_INCREMENTAL"
	// StatusReused means the file was untouched since the previous scan;
	// the stored result was reused without re-reading anything.
	StatusReused Status = "OK_REUSED"
	// StatusInvalidated means stored continuation progress was detected as
	// stale (the old content was rewritten, truncated or the file was
	// replaced) and the file was rescanned from the beginning. Hits are
	// trustworthy for the current content; the distinct status lets callers
	// tell this apart from a normal full scan or a clean continuation.
	StatusInvalidated Status = "OK_FULL_RESCAN"
	// StatusUnreadable means the file could not be opened at all.
	StatusUnreadable Status = "FILE_UNREADABLE"
	// StatusTruncated means reading ended before the initially observed size
	// (e.g. the file shrank between stat and read).
	StatusTruncated Status = "FILE_TRUNCATED"
	// StatusModified means the file changed during scanning, as proven by a
	// final verification hash that differs from the streamed content hash
	// (full scan) or by growth/rewrite observed mid-continuation. The
	// returned hits are deliberately empty and must not be trusted.
	StatusModified Status = "FILE_MODIFIED_DURING_SCAN"
	// StatusPanic means an unexpected internal failure while scanning the
	// file; it never aborts the rest of the batch.
	StatusPanic Status = "SCAN_INTERNAL_ERROR"
)

// IsOK reports whether the status denotes a trustworthy completed scan.
func (s Status) IsOK() bool {
	return s == StatusOK || s == StatusIncremental || s == StatusReused || s == StatusInvalidated
}

// Stats reports the actual work done by one scan. Read bytes come from the
// operating system; processed bytes were fed to the signature matcher.
type Stats struct {
	// Mode is "full" (from-scratch scan), "incremental" (append-only
	// continuation) or "reuse" (nothing re-read).
	Mode string `json:"mode"`
	// BytesRead counts bytes physically read during this scan, including
	// cheap integrity-verification reads (prefix hash / tail comparison).
	BytesRead int64 `json:"bytes_read"`
	// BytesProcessed counts bytes actually fed to the matcher.
	BytesProcessed int64 `json:"bytes_processed"`
	// BytesReused counts covered bytes not reprocessed: for a clean
	// continuation it is the previous file size; for a reuse it is the
	// whole file size.
	BytesReused int64 `json:"bytes_reused"`
	// FileSize is the total size of the scanned content.
	FileSize int64 `json:"file_size"`
	// VerifyBytesRead counts the extra bytes read solely to prove that old
	// content is unchanged; included in BytesRead, broken out for clarity.
	VerifyBytesRead int64 `json:"verify_bytes_read"`
	// ResumeProbe describes how stored progress was classified:
	// "none", "unchanged", "appended", "rewrite-suspect", "truncated",
	// "replaced".
	ResumeProbe string `json:"resume_probe,omitempty"`
	// DurationMS is the wall-clock time spent scanning the file.
	DurationMS int64 `json:"duration_ms"`
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
	// Cached is kept for compatibility: true when no matching work was
	// needed this round (unchanged file or concurrent in-flight join).
	Cached bool  `json:"cached"`
	Stats  Stats `json:"stats"`
}

// FileIDer maps a path to a stable identifier. By default the absolute path
// is used.
type FileIDer func(path string) string

// fileIdentity is the cheap OS fingerprint used to classify how a file
// changed since the last scan without reading its content.
type fileIdentity struct {
	Size    int64
	Dev     uint64
	Ino     uint64
	MtimeNS int64
}

// fileState is the per-file continuation progress plus the reusable result.
type fileState struct {
	identity   fileIdentity
	covered    int64
	prefixHash []byte // SHA-256 sum of bytes [0, covered)
	headLen    int64
	headHash   []byte // SHA-256 of [0, headLen)
	tailOff    int64
	tailHash   []byte // SHA-256 of [tailOff, covered)
	hashState  []byte // marshaled streaming hash over [0, covered)
	snapshot   *MatcherSnapshot
	result     *Result
	cost       int // estimated memory cost in bytes
}

// cacheEntry wraps a fileState for LRU bookkeeping.
type cacheEntry struct {
	key  string
	st   *fileState
	elem *list.Element
}

// Engine owns the active rule snapshot, continuation state and the
// capacity-bounded cache. All methods are safe for concurrent use; Reload may
// run while scans are in flight.
type Engine struct {
	rulePaths []string
	idFor     FileIDer
	chunkSize int
	maxBytes  int // <=0 means unbounded
	verifyLen int // prefix/tail integrity probe length

	mu         sync.RWMutex
	active     *rules.Set
	cache      map[string]*cacheEntry
	lru        *list.List // front = most recently used
	cacheBytes int
	inflight   sync.Map // version+"\x01"+fileID -> *call

	// onChunk is invoked after each streamed chunk is processed. It exists
	// for tests that must deterministically mutate a file mid-scan.
	onChunk func(path string, chunkIndex int)
}

// Config configures an Engine.
type Config struct {
	RulePaths []string
	FileID    FileIDer
	ChunkSize int // streaming read size; <=0 means 4096
	// MaxCacheBytes bounds estimated memory used by continuation state and
	// stored results. <=0 means unbounded. Eviction is LRU and can only
	// ever cost speed, never correctness.
	MaxCacheBytes int
	// VerifyLen bounds how many bytes of the old prefix are hashed to prove
	// it is unchanged before a continuation is trusted. The full prefix hash
	// is always finalized when the prefix is smaller than this; <=0 means
	// 4096.
	VerifyLen int
}

// New loads the initial rule set and builds an Engine.
func New(cfg Config) (*Engine, error) {
	chunk := cfg.ChunkSize
	if chunk <= 0 {
		chunk = 4096
	}
	verify := cfg.VerifyLen
	if verify <= 0 {
		verify = 4096
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
	e := &Engine{
		rulePaths: append([]string(nil), cfg.RulePaths...),
		idFor:     idFor,
		chunkSize: chunk,
		maxBytes:  cfg.MaxCacheBytes,
		verifyLen: verify,
		cache:     map[string]*cacheEntry{},
		lru:       list.New(),
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
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.active
}

// Reload recompiles all rule files and atomically swaps the snapshot. Old
// results and continuation progress stay bound to the old version and can
// never be used under the new version; all of them are evicted, so the new
// rules take effect over the whole file on the next scan.
func (e *Engine) Reload() (*rules.Set, error) {
	set, err := rules.LoadFiles(e.rulePaths)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.active = set
	e.cache = map[string]*cacheEntry{}
	e.lru.Init()
	e.cacheBytes = 0
	e.mu.Unlock()
	return set, nil
}

// call deduplicates concurrent scans of the same key (singleflight).
type call struct {
	done chan struct{}
	res  *Result
}

// ScanBatch scans many files concurrently. One file's failure never affects
// the others. The returned slice is in the same order as paths, so output is
// reproducible regardless of concurrency.
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

// Scan scans one file. Unchanged files reuse the stored result without any
// I/O; append-only files are continued from saved matcher progress; files
// whose old content changed are rescanned from the start and reported with
// StatusInvalidated. Concurrent scans of the same file share one computation
// (singleflight).
func (e *Engine) Scan(path string) (result *Result) {
	fileID := e.idFor(path)
	set := e.Rules()
	flightKey := set.Version + "\x01" + fileID

	c := &call{done: make(chan struct{})}
	if actual, loaded := e.inflight.LoadOrStore(flightKey, c); loaded {
		<-actual.(*call).done
		// A joining scan should observe the same outcome as a scan that
		// starts just after the leader finishes: if the file identity is
		// unchanged that is a zero-work reuse, not a copy of the leader's
		// full/incremental workload.
		return e.serveAfterJoin(path, fileID, set, actual.(*call).res)
	}
	defer func() {
		c.res = result
		close(c.done)
		e.inflight.Delete(flightKey)
	}()

	defer func() {
		if r := recover(); r != nil {
			result = &Result{
				FileID:      fileID,
				Path:        path,
				Status:      StatusPanic,
				Error:       fmt.Sprintf("panic: %v", r),
				RuleVersion: set.Version,
				Hits:        []Hit{},
				Stats:       Stats{Mode: "full"},
			}
		}
	}()

	return e.scanOnce(path, fileID, set)
}

// serveAfterJoin returns the result observed by a goroutine that shared an
// in-flight scan: a zero-work reuse when the leader's stored state matches
// the file now, otherwise the leader's result (e.g. it already flagged the
// file as modified mid-scan).
func (e *Engine) serveAfterJoin(path, fileID string, set *rules.Set, leader *Result) *Result {
	start := time.Now()
	id, err := identify(path)
	key := set.Version + "\x00" + fileID
	if err == nil {
		if st, ok := e.getState(key); ok && st.identity == id {
			res := cloneResult(st.result, true)
			res.Status = StatusReused
			res.Stats = Stats{
				Mode: "reuse", BytesReused: id.Size, FileSize: id.Size,
				ResumeProbe: "unchanged", DurationMS: msSince(start),
			}
			return res
		}
	}
	res := cloneResult(leader, true)
	return res
}

func cloneResult(r *Result, cached bool) *Result {
	cp := *r
	cp.Hits = append([]Hit(nil), r.Hits...)
	cp.Cached = cached
	return &cp
}

func (e *Engine) scanOnce(path, fileID string, set *rules.Set) *Result {
	start := time.Now()
	id, idErr := identify(path)

	key := set.Version + "\x00" + fileID
	prev, hadPrev := e.getState(key)

	if idErr != nil {
		return &Result{
			FileID: fileID, Path: path, Status: StatusUnreadable,
			Error: idErr.Error(), RuleVersion: set.Version, Hits: []Hit{},
			Stats: Stats{Mode: "full", DurationMS: msSince(start)},
		}
	}

	// Fast path: identical OS fingerprint means the file is unchanged.
	if hadPrev && id == prev.identity {
		res := cloneResult(prev.result, true)
		res.Status = StatusReused
		res.Stats = Stats{
			Mode: "reuse", BytesReused: id.Size, FileSize: id.Size,
			ResumeProbe: "unchanged", DurationMS: msSince(start),
		}
		e.touch(key)
		return res
	}

	switch {
	case hadPrev && identityReplaced(prev.identity, id):
		return e.fullScan(path, fileID, set, start, key, id, StatusInvalidated, "replaced")
	case hadPrev && id.Size < prev.identity.Size:
		return e.fullScan(path, fileID, set, start, key, id, StatusInvalidated, "truncated")
	case !hadPrev:
		return e.fullScan(path, fileID, set, start, key, id, StatusOK, "none")
	}

	// Size grew (or stayed equal with a changed mtime): try a verified
	// continuation; full rescan on any proof that the old prefix changed.
	res, ok := e.continueScan(path, fileID, set, start, key, id, prev)
	if !ok {
		return e.fullScan(path, fileID, set, start, key, id, StatusInvalidated, "rewrite-suspect")
	}
	return res
}

// failureResult builds an empty-hit error result.
func failureResult(fileID, path string, set *rules.Set, status Status, msg, mode string, start time.Time, size int64) *Result {
	return &Result{
		FileID: fileID, Path: path, Status: status,
		Error: msg, RuleVersion: set.Version, Hits: []Hit{},
		Stats: Stats{Mode: mode, FileSize: size, DurationMS: msSince(start)},
	}
}

// continueScan feeds only newly appended bytes to a restored matcher. It
// verifies the old prefix first (bounded prefix hash + tail block compare),
// drains data appended while the scan runs, and returns ok=false when the
// stored progress proves stale.
func (e *Engine) continueScan(path, fileID string, set *rules.Set, start time.Time,
	key string, id fileIdentity, prev *fileState) (*Result, bool) {

	f, err := os.Open(path)
	if err != nil {
		return failureResult(fileID, path, set, StatusUnreadable, err.Error(),
			"incremental", start, id.Size), true
	}
	defer f.Close()

	var verifyRead int64

	// 1) Verify the old prefix with two bounded probes: a head block
	// [0, headLen) and the final tail block [tailOff, covered). Together
	// with stat (inode replacement / shrink / mtime), these cover every
	// practical non-append change; see README ("Continuation integrity")
	// for the exact trust model.
	if prev.headLen > 0 {
		got, n, herr := hashRange(f, 0, prev.headLen)
		verifyRead += n
		if herr != nil {
			return failureResult(fileID, path, set, StatusUnreadable, herr.Error(),
				"incremental", start, id.Size), true
		}
		if string(got) != string(prev.headHash) {
			return nil, false
		}
	}
	if prev.tailOff < prev.covered {
		got, n, herr := hashRange(f, prev.tailOff, prev.covered-prev.tailOff)
		verifyRead += n
		if herr != nil {
			return failureResult(fileID, path, set, StatusUnreadable, herr.Error(),
				"incremental", start, id.Size), true
		}
		if string(got) != string(prev.tailHash) {
			return nil, false
		}
	}

	// 2) Restore matcher and content hash at the old boundary.
	matcher := restoreMatcher(set, prev.snapshot)
	hh := sha256.New()
	if len(prev.hashState) > 0 {
		if herr := hh.(encoding.BinaryUnmarshaler).UnmarshalBinary(prev.hashState); herr != nil {
			return nil, false
		}
	}

	// 3) Stream only bytes [covered, currentEnd). If the file keeps being
	// appended while we read, drain a bounded number of growth rounds; if it
	// is still moving after that, report incomplete instead of pretending
	// the result is current.
	buf := make([]byte, e.chunkSize)
	pos := prev.covered
	targetEnd := id.Size
	var processed int64
	chunkIndex := 0
	drainRounds := 0
	const maxDrainRounds = 16

	for {
		for pos < targetEnd {
			want := int64(len(buf))
			if targetEnd-pos < want {
				want = targetEnd - pos
			}
			n, rerr := f.ReadAt(buf[:want], pos)
			if n > 0 {
				chunk := buf[:n]
				matcher.write(chunk)
				hh.Write(chunk)
				pos += int64(n)
				processed += int64(n)
				chunkIndex++
				if e.onChunk != nil {
					e.onChunk(path, chunkIndex)
				}
			}
			if rerr != nil && !errors.Is(rerr, io.EOF) {
				return failureResult(fileID, path, set, StatusUnreadable, rerr.Error(),
					"incremental", start, id.Size), true
			}
			if n == 0 && errors.Is(rerr, io.EOF) {
				break
			}
		}

		now, nerr := identify(path)
		if nerr != nil {
			return failureResult(fileID, path, set, StatusUnreadable, nerr.Error(),
				"incremental", start, id.Size), true
		}
		switch {
		case now.Size < pos:
			return failureResult(fileID, path, set, StatusTruncated,
				fmt.Sprintf("file truncated during continuation: at=%d size=%d", pos, now.Size),
				"incremental", start, now.Size), true
		case now.Ino != id.Ino || now.Dev != id.Dev:
			return failureResult(fileID, path, set, StatusModified,
				"file replaced while scanning; rescan required",
				"incremental", start, now.Size), true
		case now.Size == pos:
			id = now
			targetEnd = pos
		case now.Size > pos:
			drainRounds++
			if drainRounds > maxDrainRounds {
				return failureResult(fileID, path, set, StatusModified,
					fmt.Sprintf("file still growing after %d drain rounds; result incomplete, rescan required", maxDrainRounds),
					"incremental", start, now.Size), true
			}
			id = now
			targetEnd = now.Size
		}
		if pos >= targetEnd {
			break
		}
	}

	// One last identity check: an append landing between the final stat and
	// here would make the result a snapshot of older content, which is safe
	// to reuse but must be explicitly flagged.
	finalID, ferr := identify(path)
	if ferr != nil {
		return failureResult(fileID, path, set, StatusUnreadable, ferr.Error(),
			"incremental", start, id.Size), true
	}
	if finalID.Ino != id.Ino || finalID.Dev != id.Dev {
		return failureResult(fileID, path, set, StatusModified,
			"file replaced immediately after continuation; rescan required",
			"incremental", start, finalID.Size), true
	}
	if finalID.Size != pos {
		return failureResult(fileID, path, set, StatusModified,
			fmt.Sprintf("file size changed from %d to %d at scan end; rescan required", pos, finalID.Size),
			"incremental", start, finalID.Size), true
	}
	id = finalID

	hits := matcher.finish()
	sum := hh.Sum(nil)
	contentHash := hex.EncodeToString(sum)
	res := &Result{
		FileID:      fileID,
		Path:        path,
		Status:      StatusIncremental,
		RuleVersion: set.Version,
		Hits:        hits,
		ContentHash: contentHash,
		Cached:      false,
		Stats: Stats{
			Mode:            "incremental",
			BytesRead:       processed + verifyRead,
			BytesProcessed:  processed,
			BytesReused:     prev.covered,
			FileSize:        id.Size,
			VerifyBytesRead: verifyRead,
			ResumeProbe:     "appended",
			DurationMS:      msSince(start),
		},
	}

	// 4) Persist new continuation progress. The new prefix is the entire
	// file, so its hash equals the content hash and the hash state covers it.
	snap := matcher.snapshot()
	hashState, _ := hh.(encoding.BinaryMarshaler).MarshalBinary()
	st := e.buildState(f, id, sum, hashState, snap, id.Size)
	st.cost = estimateCost(st, res)
	st.result = cloneResult(res, false)
	st.result.Status = StatusOK
	st.result.Stats = Stats{Mode: "full", FileSize: id.Size}
	e.putState(key, st)

	return res, true
}

// fullScan reads and matches the whole file, then independently verifies the
// content hash (as the original streaming path did). status is StatusOK for
// the first scan or StatusInvalidated when stale progress was discarded.
func (e *Engine) fullScan(path, fileID string, set *rules.Set, start time.Time,
	key string, id fileIdentity, status Status, probe string) *Result {

	f, err := os.Open(path)
	if err != nil {
		return failureResult(fileID, path, set, StatusUnreadable, err.Error(), "full", start, id.Size)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return failureResult(fileID, path, set, StatusUnreadable, err.Error(), "full", start, id.Size)
	}
	expectedSize := fi.Size()

	matcher := newStreamMatcher(set)
	hh := sha256.New()
	buf := make([]byte, e.chunkSize)
	var readTotal int64
	chunkIndex := 0

	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			matcher.write(chunk)
			hh.Write(chunk)
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
			return failureResult(fileID, path, set, StatusUnreadable, rerr.Error(), "full", start, expectedSize)
		}
	}

	if readTotal < expectedSize {
		return failureResult(fileID, path, set, StatusTruncated,
			fmt.Sprintf("expected %d bytes but read %d", expectedSize, readTotal),
			"full", start, expectedSize)
	}

	verify, _, err := hashRangeFile(path, 0, readTotal)
	if err != nil {
		return failureResult(fileID, path, set, StatusUnreadable, err.Error(), "full", start, expectedSize)
	}
	sum := hh.Sum(nil)
	if string(verify) != string(sum) {
		return failureResult(fileID, path, set, StatusModified,
			fmt.Sprintf("content hash changed while scanning: streamed=%x verified=%x", sum, verify),
			"full", start, readTotal)
	}

	// Equal hashes over [0, readTotal) do not rule out a pure tail append
	// that raced with the read. A final stat proves the file did not grow;
	// otherwise the result is incomplete and must be rescanned rather than
	// returned looking normal.
	endID, idErr := identify(path)
	if idErr != nil {
		return failureResult(fileID, path, set, StatusUnreadable, idErr.Error(), "full", start, readTotal)
	}
	if endID.Ino != id.Ino || endID.Dev != id.Dev {
		return failureResult(fileID, path, set, StatusModified,
			"file replaced while scanning; rescan required",
			"full", start, endID.Size)
	}
	if endID.Size != readTotal {
		return failureResult(fileID, path, set, StatusModified,
			fmt.Sprintf("file grew from %d to %d while scanning; rescan required", readTotal, endID.Size),
			"full", start, endID.Size)
	}
	id = endID

	hits := matcher.finish()
	contentHash := hex.EncodeToString(sum)
	res := &Result{
		FileID:      fileID,
		Path:        path,
		Status:      status,
		RuleVersion: set.Version,
		Hits:        hits,
		ContentHash: contentHash,
		Cached:      false,
		Stats: Stats{
			Mode: "full", BytesRead: readTotal, BytesProcessed: readTotal,
			FileSize: readTotal, ResumeProbe: probe, DurationMS: msSince(start),
		},
	}

	hashState, _ := hh.(encoding.BinaryMarshaler).MarshalBinary()
	st := e.buildState(f, id, sum, hashState, matcher.snapshot(), readTotal)
	st.result = cloneResult(res, false)
	st.result.Status = StatusOK
	st.result.Stats = Stats{Mode: "full", FileSize: readTotal}
	st.cost = estimateCost(st, res)
	e.putState(key, st)

	return res
}

// ---------------- cache / continuation state ----------------

func (e *Engine) getState(key string) (*fileState, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ce, ok := e.cache[key]
	if !ok {
		return nil, false
	}
	e.lru.MoveToFront(ce.elem)
	return ce.st, true
}

func (e *Engine) touch(key string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ce, ok := e.cache[key]; ok {
		e.lru.MoveToFront(ce.elem)
	}
}

func (e *Engine) putState(key string, st *fileState) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if ce, ok := e.cache[key]; ok {
		e.cacheBytes -= ce.st.cost
		e.lru.Remove(ce.elem)
		delete(e.cache, key)
	}
	ce := &cacheEntry{key: key, st: st}
	ce.elem = e.lru.PushFront(ce)
	e.cache[key] = ce
	e.cacheBytes += st.cost
	e.evictLocked()
}

// evictLocked drops least-recently-used entries while over capacity. An
// evicted file simply has no continuation state next time and is fully
// rescanned; results are therefore unaffected.
func (e *Engine) evictLocked() {
	if e.maxBytes <= 0 {
		return
	}
	for e.cacheBytes > e.maxBytes {
		back := e.lru.Back()
		if back == nil {
			return
		}
		ce := back.Value.(*cacheEntry)
		e.lru.Remove(back)
		delete(e.cache, ce.key)
		e.cacheBytes -= ce.st.cost
	}
}

// CacheStats reports the number of cached file states.
func (e *Engine) CacheStats() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.cache)
}

// CacheBytes reports the estimated memory currently occupied by the cache.
func (e *Engine) CacheBytes() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cacheBytes
}

// estimateCost approximates the memory footprint of one continuation state:
// matcher occurrence records, tail, hashes and the stored result.
// buildState assembles continuation progress and computes the bounded
// integrity probes: a head block [0, headLen) and a final tail block
// [tailOff, covered), each with its own SHA-256, plus the full-prefix
// digest. The next continuation re-hashes only the two blocks to prove the
// old content is unchanged.
func (e *Engine) buildState(f *os.File, id fileIdentity, fullSum, hashState []byte,
	snap *MatcherSnapshot, covered int64) *fileState {

	st := &fileState{
		identity:   id,
		covered:    covered,
		prefixHash: append([]byte(nil), fullSum...),
		hashState:  append([]byte(nil), hashState...),
		snapshot:   snap,
	}
	probe := int64(e.verifyLen)
	if probe > covered {
		probe = covered
	}
	half := probe / 2
	if half < 1 && probe > 0 {
		half = probe
	}
	if half > covered {
		half = covered
	}
	if half > 0 {
		if sum, _, err := hashRange(f, 0, half); err == nil {
			st.headLen = half
			st.headHash = sum
		}
	}
	tailLen := probe - half
	if tailLen > covered {
		tailLen = covered
	}
	if tailLen > 0 {
		off := covered - tailLen
		if sum, _, err := hashRange(f, off, tailLen); err == nil {
			st.tailOff = off
			st.tailHash = sum
		}
	}
	return st
}

func estimateCost(st *fileState, res *Result) int {
	cost := 64 + len(st.prefixHash) + len(st.hashState) + len(st.snapshot.Tail)
	cost += len(st.headHash) + len(st.tailHash)
	for _, s := range st.snapshot.Seen {
		cost += 24 + len(s)*8
	}
	for _, list := range st.snapshot.Matches {
		cost += 24 + len(list)*16
	}
	cost += len(res.Hits)*24 + len(res.ContentHash) + 128
	if cost < 1 {
		cost = 1
	}
	return cost
}

// SetOnChunk installs (or clears with nil) a callback fired after each
// streamed chunk. Intended for deterministic tests that mutate a file while
// it is being scanned.
func (e *Engine) SetOnChunk(fn func(path string, chunkIndex int)) {
	e.onChunk = fn
}

// ---------------- file identity & hashing helpers ----------------

func msSince(t time.Time) int64 {
	return time.Since(t).Milliseconds()
}

// identityReplaced reports whether two fingerprints refer to different
// physical files (inode/device change, i.e. rotation or replacement).
func identityReplaced(a, b fileIdentity) bool {
	return a.Dev != b.Dev || a.Ino != b.Ino
}

// hashRange hashes length bytes starting at off from an open file. It
// returns the digest and the number of bytes read.
func hashRange(f *os.File, off, length int64) ([]byte, int64, error) {
	if length <= 0 {
		return sha256.New().Sum(nil), 0, nil
	}
	h := sha256.New()
	buf := make([]byte, 32*1024)
	var total int64
	for total < length {
		want := int64(len(buf))
		if length-total < want {
			want = length - total
		}
		n, err := f.ReadAt(buf[:want], off+total)
		if n > 0 {
			h.Write(buf[:n])
			total += int64(n)
		}
		if err != nil {
			if errors.Is(err, io.EOF) && total == length {
				break
			}
			return nil, total, err
		}
	}
	return h.Sum(nil), total, nil
}

func hashRangeFile(path string, off, length int64) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	return hashRange(f, off, length)
}

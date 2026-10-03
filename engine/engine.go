package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"

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

// Result is the scan outcome for a single file.
type Result struct {
	FileID      string `json:"file_id"`
	Path        string `json:"path"`
	Status      Status `json:"status"`
	Error       string `json:"error,omitempty"`
	RuleVersion string `json:"rule_version"`
	Hits        []Hit  `json:"hits"`
	ContentHash string `json:"content_hash,omitempty"`
	// Cached is kept for backward compatibility: it is true exactly when the
	// result was reused without reading any file content (mode == "cached").
	Cached   bool             `json:"cached"`
	Mode     ScanMode         `json:"mode"`
	Progress ProgressReaction `json:"progress,omitempty"`
	Work     WorkStats        `json:"work"`
}

// FileIDer maps a path to a stable identifier. By default the absolute path
// is used.
type FileIDer func(path string) string

// Engine owns the active rule snapshot, resume progress and the bounded
// result cache. All methods are safe for concurrent use; Reload may run while
// scans are in flight.
type Engine struct {
	rulePaths  []string
	idFor      FileIDer
	chunkSize  int
	cacheLimit int64

	mu     sync.RWMutex
	active *rules.Set
	store  *entryStore

	// Scans of one file id are serialized so two goroutines can never resume
	// from the same stored progress concurrently. Different files still run
	// in parallel.
	scanMu    sync.Mutex
	scanLocks map[string]*sync.Mutex

	onChunk func(path string, chunkIndex int)
}

// Config configures an Engine.
type Config struct {
	RulePaths []string
	FileID    FileIDer
	ChunkSize int
	// CacheLimitBytes bounds the accounted cost of cached results and resume
	// progress. <=0 means unlimited. Eviction affects speed only, never hits.
	CacheLimitBytes int64
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
	e := &Engine{
		rulePaths:  append([]string(nil), cfg.RulePaths...),
		idFor:      idFor,
		chunkSize:  chunk,
		cacheLimit: cfg.CacheLimitBytes,
		store:      newEntryStore(cfg.CacheLimitBytes),
		scanLocks:  map[string]*sync.Mutex{},
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

// Reload recompiles all rule files and atomically swaps the snapshot. Resume
// progress and cached results of superseded versions are dropped, so new
// rules apply to the whole file on the next scan.
func (e *Engine) Reload() (*rules.Set, error) {
	set, err := rules.LoadFiles(e.rulePaths)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.active = set
	e.mu.Unlock()
	e.store.pruneVersion(set.Version)
	return set, nil
}

// ScanBatch scans many files concurrently; one file's failure never affects
// the others. The returned slice is in input order.
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

func (e *Engine) scanLockFor(fileID string) *sync.Mutex {
	e.scanMu.Lock()
	defer e.scanMu.Unlock()
	m, ok := e.scanLocks[fileID]
	if !ok {
		m = &sync.Mutex{}
		e.scanLocks[fileID] = m
	}
	return m
}

// Scan scans one file with append-only incremental resume. Progress is
// resumed only when the same file identity grew and its already-scanned
// prefix hashes identically; truncation, in-place rewrite, replacement,
// rule reload or eviction force a full rescan distinguishable via
// Result.Mode and Result.Progress.
func (e *Engine) Scan(path string) (result *Result) {
	fileID := e.idFor(path)
	set := e.Rules()

	lock := e.scanLockFor(fileID)
	lock.Lock()
	defer lock.Unlock()

	defer func() {
		if r := recover(); r != nil {
			result = e.finishWork(&Result{
				FileID: fileID, Path: path, Status: StatusPanic,
				Error: fmt.Sprintf("panic: %v", r), RuleVersion: set.Version,
				Hits: []Hit{}, Mode: ModeFull,
			})
		}
	}()

	f, err := os.Open(path)
	if err != nil {
		return e.finishWork(errResult(fileID, path, set.Version, StatusUnreadable, err))
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return e.finishWork(errResult(fileID, path, set.Version, StatusUnreadable, err))
	}
	expectedSize := fi.Size()
	ident := fileIdentityOf(fi)
	modTime := fi.ModTime()

	entry := e.store.get(set.Version, fileID)

	// Fast path: identity, size and mtime unchanged since the last complete
	// scan — reuse the result without reading file content.
	if entry != nil && entry.usable() && entry.identity == ident &&
		entry.size == expectedSize && entry.modTime.Equal(modTime) {
		cp := copyResult(entry.res)
		cp.Cached = true
		cp.Mode = ModeCached
		cp.Progress = ProgressReused
		cp.Work = WorkStats{
			Mode: ModeCached, Progress: ProgressReused,
			BytesReused: expectedSize,
		}
		e.store.touch(set.Version, fileID)
		return e.finishWork(cp)
	}

	var (
		matcher       *streamMatcher
		contentHash   hash.Hash
		startPos      int64
		mode          = ModeFull
		reaction      ProgressReaction
		bytesVerified int64
	)

	switch {
	case entry == nil:
		if e.store.wasEvicted(set.Version, fileID) {
			reaction = ProgressEvicted
		} else {
			reaction = ProgressNew
		}
	case !entry.usable():
		reaction = ProgressEvicted
	case ident.ok && entry.identity.ok && entry.identity != ident:
		reaction = ProgressInvalidatedReplaced
	case expectedSize < entry.size:
		reaction = ProgressInvalidatedTruncated
	case expectedSize == entry.size && !modTime.Equal(entry.modTime):
		reaction = ProgressInvalidatedRewritten
	case expectedSize > entry.size:
		// Grew: independently hash the already-scanned prefix. This catches
		// a rewrite-then-append that kept a growing size and proves that
		// stored matcher state still describes the file's prefix exactly.
		ph, n, perr := hashRange(f, 0, entry.size)
		bytesVerified += n
		if perr == nil && ph == entry.prefixHash {
			if restored := restoreMatcherMaybe(set, entry.snapshot); restored != nil {
				if rh := restoreHash(entry.hashState); rh != nil {
					matcher = restored
					contentHash = rh
					startPos = entry.size
					mode = ModeIncremental
					reaction = ProgressResumed
				}
			}
		}
		if mode != ModeIncremental {
			reaction = ProgressInvalidatedPrefix
		}
	default:
		reaction = ProgressInvalidatedRewritten
	}

	if mode == ModeFull {
		matcher = newStreamMatcher(set)
		contentHash = sha256.New()
		startPos = 0
	}

	if startPos > 0 {
		if _, serr := f.Seek(startPos, io.SeekStart); serr != nil {
			return e.finishWork(errResult(fileID, path, set.Version, StatusUnreadable, serr))
		}
	}

	buf := make([]byte, e.chunkSize)
	var readBytes, processedBytes int64
	chunkIndex := 0

	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			processedBytes += int64(matcher.write(chunk))
			contentHash.Write(chunk)
			readBytes += int64(n)
			chunkIndex++
			if e.onChunk != nil {
				e.onChunk(path, chunkIndex)
			}
		}
		if errors.Is(rerr, io.EOF) {
			break
		}
		if rerr != nil {
			return e.finishWork(errResult(fileID, path, set.Version, StatusUnreadable, rerr))
		}
	}

	finalSize := startPos + readBytes
	if readBytes < expectedSize-startPos {
		return e.finishWork(&Result{
			FileID: fileID, Path: path, Status: StatusTruncated,
			Error:       fmt.Sprintf("expected %d bytes but read %d", expectedSize, finalSize),
			RuleVersion: set.Version, Hits: []Hit{}, Mode: mode, Progress: reaction,
		})
	}

	// Independent verification of the complete current file. A size move or
	// hash mismatch proves the file changed while scanning: no hits are
	// returned and the status stays distinguishable from OK, so the caller
	// must rescan. This also covers appends racing an incremental scan.
	curFI, statErr := f.Stat()
	verifyHash, verifyN, verr := hashFileAll(path)
	bytesVerified += verifyN
	if statErr != nil {
		return e.finishWork(errResult(fileID, path, set.Version, StatusUnreadable, statErr))
	}
	if verr != nil {
		return e.finishWork(errResult(fileID, path, set.Version, StatusUnreadable, verr))
	}
	streamHash := hex.EncodeToString(contentHash.Sum(nil))
	if curFI.Size() != expectedSize || finalSize != expectedSize || verifyHash != streamHash {
		return e.finishWork(&Result{
			FileID: fileID, Path: path, Status: StatusModified,
			Error: fmt.Sprintf("file changed while scanning: stat_size=%d streamed=%d current=%d streamed_hash=%s verified_hash=%s",
				expectedSize, finalSize, curFI.Size(), streamHash, verifyHash),
			RuleVersion: set.Version, Hits: []Hit{}, Mode: mode, Progress: reaction,
			Work: WorkStats{
				Mode: mode, Progress: reaction, BytesRead: readBytes,
				BytesProcessed: processedBytes, BytesReused: startPos,
				BytesVerified: bytesVerified,
			},
		})
	}

	res := &Result{
		FileID:      fileID,
		Path:        path,
		Status:      StatusOK,
		RuleVersion: set.Version,
		Hits:        matcher.finish(),
		ContentHash: streamHash,
		Mode:        mode,
		Progress:    reaction,
	}

	snap := matcher.snapshot()
	hashState, _ := contentHash.(interface {
		MarshalBinary() ([]byte, error)
	}).MarshalBinary()

	e.store.put(&cacheEntry{
		version:    set.Version,
		fileID:     fileID,
		identity:   ident,
		size:       finalSize,
		modTime:    modTime,
		res:        copyResult(res),
		snapshot:   snap,
		hashState:  hashState,
		prefixHash: streamHash,
		cost:       entryCost(finalSize, snap),
	})

	res.Work = WorkStats{
		Mode: mode, Progress: reaction,
		BytesRead: readBytes, BytesProcessed: processedBytes,
		BytesReused: startPos, BytesVerified: bytesVerified,
	}
	return e.finishWork(res)
}

func (e *Engine) finishWork(r *Result) *Result {
	if r.Hits == nil {
		r.Hits = []Hit{}
	}
	entries, used, limit, evicted := e.store.stats()
	r.Work.CacheEntries = entries
	r.Work.CacheCostBytes = used
	r.Work.CacheLimitBytes = limit
	r.Work.CacheEvictions = evicted
	if r.Work.Mode == "" {
		r.Work.Mode = r.Mode
	}
	if r.Work.Progress == "" {
		r.Work.Progress = r.Progress
	}
	return r
}

func errResult(fileID, path, version string, st Status, err error) *Result {
	return &Result{
		FileID: fileID, Path: path, Status: st, Error: err.Error(),
		RuleVersion: version, Hits: []Hit{}, Mode: ModeFull,
	}
}

func copyResult(r *Result) *Result {
	cp := *r
	cp.Hits = append([]Hit(nil), r.Hits...)
	return &cp
}

// SetOnChunk installs (or clears with nil) a callback fired after each
// streamed chunk. Intended for deterministic tests that mutate a file while
// it is being scanned.
func (e *Engine) SetOnChunk(fn func(path string, chunkIndex int)) {
	e.onChunk = fn
}

// CacheStats reports the current number of cached entries.
func (e *Engine) CacheStats() int {
	entries, _, _, _ := e.store.stats()
	return entries
}

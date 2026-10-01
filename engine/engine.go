package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/lechandonga/signature-detection-engine-go/rules"
)

// Status is the machine-readable outcome of scanning one file.
type Status string

const (
	// StatusOK means the file was fully scanned and Hits are trustworthy.
	StatusOK Status = "OK"
	// StatusUnreadable means the file could not be opened at all.
	StatusUnreadable Status = "FILE_UNREADABLE"
	// StatusTruncated means reading ended before the initially observed size
	// (e.g. the file shrank between stat and read).
	StatusTruncated Status = "FILE_TRUNCATED"
	// StatusModified means the file changed during scanning, as proven by a
	// final verification hash that differs from the streamed content hash.
	StatusModified Status = "FILE_MODIFIED_DURING_SCAN"
	// StatusPanic means an unexpected internal failure while scanning the
	// file; it never aborts the rest of the batch.
	StatusPanic Status = "SCAN_INTERNAL_ERROR"
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
	Cached      bool   `json:"cached"`
}

// FileIDer maps a path to a stable identifier. By default the absolute path
// is used.
type FileIDer func(path string) string

// Engine owns the active rule snapshot and the content/version-bound result
// cache. All methods are safe for concurrent use; Reload may run while scans
// are in flight.
type Engine struct {
	rulePaths []string
	idFor     FileIDer
	chunkSize int

	mu       sync.RWMutex
	active   *rules.Set
	cache    map[string]*Result // key: ruleVersion + "\x00" + contentHash + "\x00" + fileID
	inflight sync.Map           // same key -> *call

	// onChunk is invoked after each streamed chunk is processed. It exists
	// for tests that must deterministically mutate a file mid-scan.
	onChunk func(path string, chunkIndex int)
}

// Config configures an Engine.
type Config struct {
	RulePaths []string
	FileID    FileIDer
	ChunkSize int // streaming read size; <=0 means 4096
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
		rulePaths: append([]string(nil), cfg.RulePaths...),
		idFor:     idFor,
		chunkSize: chunk,
		cache:     map[string]*Result{},
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
// results stay bound to the old version and can never be returned under the
// new version; cache entries of superseded versions are evicted.
func (e *Engine) Reload() (*rules.Set, error) {
	set, err := rules.LoadFiles(e.rulePaths)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	old := e.active
	e.active = set
	e.pruneCacheLocked()
	e.mu.Unlock()
	_ = old
	return set, nil
}

// pruneCacheLocked drops entries that do not belong to the active version.
func (e *Engine) pruneCacheLocked() {
	prefix := e.active.Version + "\x00"
	for k := range e.cache {
		if len(k) <= len(prefix) || k[:len(prefix)] != prefix {
			delete(e.cache, k)
		}
	}
}

func (e *Engine) cacheKey(version, hash, fileID string) string {
	return version + "\x00" + hash + "\x00" + fileID
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

// Scan scans one file, reusing a cached judgment when the same rule version
// and file content have already been evaluated. Cache hits return a defensive
// copy and only set the Cached flag; Hits are identical either way.
func (e *Engine) Scan(path string) (result *Result) {
	fileID := e.idFor(path)
	set := e.Rules()
	flightKey := set.Version + "\x01" + fileID

	// Concurrent scans of the same file under the same rule version share a
	// single computation (singleflight).
	c := &call{done: make(chan struct{})}
	if actual, loaded := e.inflight.LoadOrStore(flightKey, c); loaded {
		<-actual.(*call).done
		cp := *actual.(*call).res
		cp.Hits = append([]Hit(nil), cp.Hits...)
		cp.Cached = true
		return &cp
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
			}
		}
	}()

	res, fresh := e.scanOnce(path, fileID, set)
	if !fresh {
		cp := *res
		cp.Hits = append([]Hit(nil), res.Hits...)
		cp.Cached = true
		result = &cp
		return result
	}
	result = res
	return result
}

func (e *Engine) scanOnce(path, fileID string, set *rules.Set) (*Result, bool) {
	f, err := os.Open(path)
	if err != nil {
		return &Result{
			FileID: fileID, Path: path, Status: StatusUnreadable,
			Error: err.Error(), RuleVersion: set.Version, Hits: []Hit{},
		}, true
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return &Result{
			FileID: fileID, Path: path, Status: StatusUnreadable,
			Error: err.Error(), RuleVersion: set.Version, Hits: []Hit{},
		}, true
	}
	expectedSize := fi.Size()

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
			return &Result{
				FileID: fileID, Path: path, Status: StatusUnreadable,
				Error: rerr.Error(), RuleVersion: set.Version, Hits: []Hit{},
			}, true
		}
	}

	if readTotal < expectedSize {
		return &Result{
			FileID: fileID, Path: path, Status: StatusTruncated,
			Error:       fmt.Sprintf("expected %d bytes but read %d", expectedSize, readTotal),
			RuleVersion: set.Version, Hits: []Hit{},
		}, true
	}

	// Verification pass: re-read the whole file independently and compare
	// hashes. A mismatch proves the content changed during scanning.
	verify, err := hashFile(path)
	if err != nil {
		return &Result{
			FileID: fileID, Path: path, Status: StatusUnreadable,
			Error: err.Error(), RuleVersion: set.Version, Hits: []Hit{},
		}, true
	}
	streamHash := hex.EncodeToString(h.Sum(nil))
	if verify != streamHash {
		return &Result{
			FileID: fileID, Path: path, Status: StatusModified,
			Error:       fmt.Sprintf("content hash changed while scanning: streamed=%s verified=%s", streamHash, verify),
			RuleVersion: set.Version, Hits: []Hit{},
		}, true
	}

	res := &Result{
		FileID:      fileID,
		Path:        path,
		Status:      StatusOK,
		RuleVersion: set.Version,
		Hits:        matcher.finish(),
		ContentHash: streamHash,
		Cached:      false,
	}

	return e.storeOrReuse(set.Version, streamHash, fileID, res)
}

// storeOrReuse caches the computed result keyed by rule version, content
// hash and file id. Every caller receives its own copy.
func (e *Engine) storeOrReuse(version, hash, fileID string, computed *Result) (*Result, bool) {
	key := e.cacheKey(version, hash, fileID)

	e.mu.Lock()
	if cached, ok := e.cache[key]; ok {
		e.mu.Unlock()
		return cached, false
	}
	e.cache[key] = computed
	e.mu.Unlock()

	return computed, true
}

func hashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// CacheStats reports the current cache size (mostly useful in tests).
func (e *Engine) CacheStats() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.cache)
}

// SetOnChunk installs (or clears with nil) a callback fired after each
// streamed chunk. Intended for deterministic tests that mutate a file while
// it is being scanned.
func (e *Engine) SetOnChunk(fn func(path string, chunkIndex int)) {
	e.onChunk = fn
}

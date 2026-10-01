// Package engine ties rules, streaming matching, result caching and concurrent
// file scanning together.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/lechandonga/signature-detection-engine-go/internal/matcher"
	"github.com/lechandonga/signature-detection-engine-go/internal/rules"
)

// Status is the distinguishable outcome of scanning one file.
type Status string

const (
	// StatusClean means the file was fully read and no rule matched.
	StatusClean Status = "clean"
	// StatusDetected means one or more rules matched.
	StatusDetected Status = "detected"
	// StatusUnreadable means the file could not be opened/stat'd (missing,
	// permission denied, not a regular file).
	StatusUnreadable Status = "unreadable"
	// StatusTruncated means reading ended with fewer bytes than the initial
	// size advertised (file shrank / content was cut).
	StatusTruncated Status = "truncated"
	// StatusModified means size/mtime changed, or the final checksum did not
	// agree with a re-verification while the length stayed the same.
	StatusModified Status = "modified"
	// StatusScanError covers other I/O failures during reading.
	StatusScanError Status = "scan_error"
)

// Result is the externally visible, reproducible verdict for one file.
type Result struct {
	Path       string        `json:"path"`
	FileID     string        `json:"file_id"`
	RuleVer    string        `json:"rule_version"`
	Status     Status        `json:"status"`
	Hits       []matcher.Hit `json:"hits,omitempty"`
	Size       int64         `json:"size"`
	ContentSHA string        `json:"content_sha256,omitempty"`
	Error      string        `json:"error,omitempty"`
	// CacheHit is observability only: whether this verdict was served from
	// cache/in-flight coalescing. It never affects the verdict itself.
	CacheHit bool `json:"cache_hit"`
}

// Fingerprint identifies a concrete file content version independently of the
// rule set. Size and mtime gate cache lookups; the streamed SHA-256 binds the
// verdict to exact bytes and is re-verified after reading.
type Fingerprint struct {
	Size  int64
	MTime int64
	Mode  os.FileMode
}

var (
	errTruncated = errors.New("file truncated during scan: read fewer bytes than advertised size")
	errModified  = errors.New("file modified during scan: size or checksum changed")
	errFileGrew  = errors.New("file grew during scan")
)

type cacheEntry struct {
	fp     Fingerprint
	result Result
}

// Config controls scanner behavior.
type Config struct {
	// ChunkSize feeds the stream in buffers of this size. Any positive value
	// produces identical matches. Defaults to 64 KiB.
	ChunkSize int
	// Workers bounds concurrent file scans in ScanBatch. Defaults to 4.
	Workers int
}

// Engine scans files against the rule snapshot of its rules.Store. Every scan
// pins the snapshot it started with, so a hot reload never alters an in-flight
// scan, and cached verdicts are served only when both rule version AND file
// fingerprint match.
type Engine struct {
	store *rules.Store
	cfg   Config

	// test hooks (nil outside tests)
	afterChunk func(feedNo int, totalRead int64)

	mu       sync.Mutex
	cache    map[string]map[string]*cacheEntry // ruleVersion -> fileID -> entry
	inflight map[string]*call                  // ruleVersion+"\x00"+fileID
}

type call struct {
	done chan struct{}
	fp   Fingerprint
	res  Result
}

// New constructs an engine bound to a rule store.
func New(store *rules.Store, cfg Config) *Engine {
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = 64 * 1024
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 4
	}
	return &Engine{
		store:    store,
		cfg:      cfg,
		cache:    map[string]map[string]*cacheEntry{},
		inflight: map[string]*call{},
	}
}

// SetAfterChunkHook installs a hook invoked after every streamed chunk. It is
// intended for tests that mutate files mid-scan.
func (e *Engine) SetAfterChunkHook(f func(feedNo int, totalRead int64)) {
	e.afterChunk = f
}

// scanFile performs the actual streaming scan against a pinned snapshot.
func (e *Engine) scanFile(path string, snap *rules.Compiled, fp Fingerprint) Result {
	res := Result{Path: path, FileID: FileID(path), RuleVer: snap.Version, Size: fp.Size}

	f, err := os.Open(path)
	if err != nil {
		res.Status = StatusUnreadable
		res.Error = err.Error()
		return res
	}
	defer f.Close()

	sm := matcher.New(snap)
	hasher := sha256.New()
	buf := make([]byte, e.cfg.ChunkSize)
	var total int64
	feedNo := 0

	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			sm.Feed(buf[:n], total)
			hasher.Write(buf[:n])
			total += int64(n)
			feedNo++
			if e.afterChunk != nil {
				e.afterChunk(feedNo, total)
			}
			if total > fp.Size {
				res.Status = StatusModified
				res.Error = errFileGrew.Error()
				return res
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			res.Status = StatusScanError
			res.Error = rerr.Error()
			return res
		}
	}

	if total < fp.Size {
		res.Status = StatusTruncated
		res.Error = errTruncated.Error()
		return res
	}
	sum := hex.EncodeToString(hasher.Sum(nil))

	// Post-scan size/mtime verification.
	st, err := os.Stat(path)
	if err != nil {
		res.Status = StatusUnreadable
		res.Error = "post-scan stat failed: " + err.Error()
		return res
	}
	if st.Size() != fp.Size || st.ModTime().UnixNano() != fp.MTime {
		res.Status = StatusModified
		res.Error = errModified.Error()
		return res
	}

	// Re-hash the file: same-length in-place edits produce a different digest
	// and are reported as StatusModified rather than a silent wrong verdict.
	vf, err := os.Open(path)
	if err != nil {
		res.Status = StatusUnreadable
		res.Error = err.Error()
		return res
	}
	vhash := sha256.New()
	if _, err := io.Copy(vhash, vf); err != nil {
		vf.Close()
		res.Status = StatusScanError
		res.Error = err.Error()
		return res
	}
	vf.Close()
	if hex.EncodeToString(vhash.Sum(nil)) != sum {
		res.Status = StatusModified
		res.Error = errModified.Error()
		return res
	}

	res.ContentSHA = sum
	res.Hits = sm.Hits()
	if len(res.Hits) > 0 {
		res.Status = StatusDetected
	} else {
		res.Status = StatusClean
	}
	return res
}

// Scan scans one file, pinning the current rule snapshot. Concurrent identical
// scans coalesce; cached verdicts are reused only when both the rule version
// and the file fingerprint match. Cache hit or miss never changes the verdict.
func (e *Engine) Scan(path string) Result {
	snap := e.store.Snapshot()

	st, err := os.Stat(path)
	if err != nil || st.IsDir() || !st.Mode().IsRegular() {
		res := Result{Path: path, FileID: FileID(path), RuleVer: snap.Version, Status: StatusUnreadable}
		switch {
		case err != nil:
			res.Error = err.Error()
		case st.IsDir():
			res.Error = "path is a directory"
		default:
			res.Error = "not a regular file"
		}
		return res
	}
	fp := Fingerprint{Size: st.Size(), MTime: st.ModTime().UnixNano(), Mode: st.Mode()}
	id := FileID(path)
	key := snap.Version + "\x00" + id

	var c *call
	for {
		e.mu.Lock()
		if bucket, ok := e.cache[snap.Version]; ok {
			if ent, ok := bucket[id]; ok && equalFingerprint(ent.fp, fp) {
				r := cloneResult(ent.result)
				r.CacheHit = true
				e.mu.Unlock()
				return r
			}
		}
		if existing, ok := e.inflight[key]; ok {
			e.mu.Unlock()
			<-existing.done
			if equalFingerprint(existing.fp, fp) {
				r := cloneResult(existing.res)
				r.CacheHit = true
				return r
			}
			// Content changed while that scan ran: re-check fresh state.
			continue
		}
		c = &call{done: make(chan struct{})}
		e.inflight[key] = c
		e.mu.Unlock()
		break
	}

	res := e.scanFile(path, snap, fp)

	e.mu.Lock()
	delete(e.inflight, key)
	// Only trustworthy verdicts are cached; transient failures get retried.
	if res.Status == StatusClean || res.Status == StatusDetected {
		bucket := e.cache[snap.Version]
		if bucket == nil {
			bucket = map[string]*cacheEntry{}
			e.cache[snap.Version] = bucket
		}
		stored := cloneResult(res)
		stored.CacheHit = false
		bucket[id] = &cacheEntry{fp: fp, result: stored}
	}
	c.fp = fp
	c.res = res
	close(c.done)
	e.mu.Unlock()

	res.CacheHit = false
	return res
}

// ScanBatch scans many files concurrently. One file's failure never interrupts
// another; results are returned in input order for reproducibility.
func (e *Engine) ScanBatch(paths []string) []Result {
	results := make([]Result, len(paths))
	sem := make(chan struct{}, e.cfg.Workers)
	var wg sync.WaitGroup
	for i, p := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, p string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = e.Scan(p)
		}(i, p)
	}
	wg.Wait()
	return results
}

// CacheStats reports cache entry counts per rule version (diagnostics).
func (e *Engine) CacheStats() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := map[string]int{}
	for v, b := range e.cache {
		out[v] = len(b)
	}
	return out
}

// SortedVersions lists cached rule versions in sorted order (diagnostics).
func (e *Engine) SortedVersions() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	vs := make([]string, 0, len(e.cache))
	for v := range e.cache {
		vs = append(vs, v)
	}
	sort.Strings(vs)
	return vs
}

func equalFingerprint(a, b Fingerprint) bool {
	return a.Size == b.Size && a.MTime == b.MTime
}

func cloneResult(r Result) Result {
	out := r
	if r.Hits != nil {
		out.Hits = append([]matcher.Hit(nil), r.Hits...)
		for i := range out.Hits {
			out.Hits[i].TermHits = append([]matcher.TermHit(nil), r.Hits[i].TermHits...)
		}
	}
	return out
}

// FileID is the stable identifier of a scan target: its absolute path.
func FileID(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	return abs
}

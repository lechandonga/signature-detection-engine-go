package engine

// ScanMode reports how a scan was actually performed.
type ScanMode string

const (
	// ModeFull is a complete from-scratch scan of the whole file.
	ModeFull ScanMode = "full"
	// ModeIncremental resumes from stored progress and only processes the
	// newly appended tail (plus a small overlap for boundary matches).
	ModeIncremental ScanMode = "incremental"
	// ModeCached processed no bytes at all: file identity was unchanged and
	// the previously computed result was reused.
	ModeCached ScanMode = "cached"
)

// ProgressReaction explains what happened to previously stored resume
// progress. It is empty for a first scan and for a clean resume.
type ProgressReaction string

const (
	// ProgressNew means no prior progress existed.
	ProgressNew ProgressReaction = "new"
	// ProgressResumed means stored progress was used for an append-only scan.
	ProgressResumed ProgressReaction = "resumed"
	// ProgressReused means the file was unchanged and the cached result was
	// returned without reading anything.
	ProgressReused ProgressReaction = "reused"
	// ProgressInvalidatedTruncated means the file became smaller than the
	// stored position; progress was discarded and a full scan was done.
	ProgressInvalidatedTruncated ProgressReaction = "invalidated_truncated"
	// ProgressInvalidatedRewritten means old content changed at the same
	// length (e.g. an in-place overwrite); progress was discarded.
	ProgressInvalidatedRewritten ProgressReaction = "invalidated_rewritten"
	// ProgressInvalidatedReplaced means the file identity (inode/device)
	// changed, i.e. the path points at a different file now.
	ProgressInvalidatedReplaced ProgressReaction = "invalidated_replaced"
	// ProgressInvalidatedPrefix means the file grew but verification proved
	// the already-scanned prefix no longer matches stored content.
	ProgressInvalidatedPrefix ProgressReaction = "invalidated_prefix"
	// ProgressEvicted means bounded-cache eviction had removed the progress;
	// the scan is correct but had to start over.
	ProgressEvicted ProgressReaction = "evicted"
)

// WorkStats is the honest accounting of how much work one scan performed.
// Byte counters count this scan only; they never include previous scans.
type WorkStats struct {
	// BytesRead is the number of file bytes streamed from disk for matching
	// on this scan. It is 0 for an unchanged-file cache reuse and equals the
	// appended length (not the whole file) for an incremental resume.
	BytesRead int64 `json:"bytes_read"`
	// BytesProcessed is how many bytes were fed through the rule matcher on
	// this scan. For incremental scans it is BytesRead plus the small tail
	// overlap rescanned to find matches crossing the old/new boundary.
	BytesProcessed int64 `json:"bytes_processed"`
	// BytesReused is how many already-scanned bytes were skipped because
	// their matcher state was resumed (incremental) or their result reused
	// (cached). It is the quantified savings versus a full scan.
	BytesReused int64 `json:"bytes_reused"`
	// BytesVerified is bytes read by the independent post-scan verification
	// pass. Verification proves the file did not change while being scanned.
	BytesVerified int64 `json:"bytes_verified"`
	// Mode is full / incremental / cached.
	Mode ScanMode `json:"mode"`
	// Progress says how prior resume state was treated.
	Progress ProgressReaction `json:"progress"`
	// CacheEntries is the number of result/progress entries held afterwards.
	CacheEntries int `json:"cache_entries"`
	// CacheCostBytes is the summed cost of held entries under the eviction
	// accounting (file bytes plus matcher-occurrence bookkeeping).
	CacheCostBytes int64 `json:"cache_cost_bytes"`
	// CacheLimitBytes is the configured capacity (0 means unlimited).
	CacheLimitBytes int64 `json:"cache_limit_bytes"`
	// CacheEvictions is the cumulative number of entries evicted in this
	// engine because capacity was exceeded.
	CacheEvictions int64 `json:"cache_evictions"`
}

# Signature Detection Engine (local, deterministic)

A fully local file-signature scanning engine. Rules and scanned files both
come from the local filesystem; there are no network calls or external
services. Results are explainable (rule id + exact byte offset), reproducible
(sorted, deduplicated, chunk-size independent) and bound to an explicit rule
set version and file content hash.

## Layout

- `rules/` — rule file parsing, compilation and immutable versioned rule sets.
- `engine/` — streaming matcher, file integrity classification, result cache
  and concurrent hot reload.
- `cmd/sigscan/` — command line front end.
- `examples/rules/signatures.json` — example rule file.

## Rule file format

Each rule file is a single JSON document; multiple rule files may be loaded
together. Files are compiled independently: one malformed file is rejected
with a machine-readable reason and never prevents the other files from
loading. Duplicate rule ids across files reject the later whole file.

```json
{
  "rules": [
    {
      "id": "pe-with-stub",
      "description": "free text",
      "condition": "all",
      "patterns": [
        {"hex": "4d 5a", "offset": 0},
        {"hex": "50 45 00 00", "offset": 128, "window": 384}
      ]
    }
  ]
}
```

### Fields

- `id` (required, unique): stable rule identifier used in every hit.
- `condition` (optional, default `all`):
  - `all` — every pattern must occur at least once; the rule emits one hit
    per occurrence of the first pattern.
  - `any` — the rule emits one hit per occurrence of any pattern.
- `patterns` (required, non-empty).
- `patterns[].hex`: hex byte string, spaces optional. `??` (also `xx`) is a
  wildcard byte that matches any value, e.g. `"de ad ?? ef"`.
- `patterns[].offset`: non-negative start offset constraint.
- `patterns[].window`: non-negative slack added to `offset`; a match starting
  at `p` is accepted when `offset <= p <= offset+window`. `window: 0` (the
  default) means an exact offset. A `window` without an `offset` is rejected.

### Rejection reasons (per file)

`RULE_FILE_UNREADABLE`, `RULE_FILE_INVALID_JSON`, `RULE_EMPTY_ID`,
`RULE_DUPLICATE_ID`, `RULE_UNKNOWN_CONDITION`, `RULE_EMPTY_PATTERN`,
`RULE_INVALID_HEX`, `RULE_INVALID_OFFSET`, `RULE_INVALID_WINDOW`.

### Rule set versioning

A compiled `rules.Set` is immutable. Its version is
`v<sequence>-<sha256-prefix>` where the hash covers every accepted rule id,
condition, normalized hex pattern, offset and window. Identical rule content
produces an identical hash; adding, changing or removing any rule changes it.

## Matching semantics

- Scanning is streaming. Between chunks the matcher keeps a tail of
  `maxPatternLen-1` bytes and re-scans the stitched region; overlap offsets
  are deduplicated. Consequently matches crossing chunk boundaries are always
  found, and the hit set is identical for any chunk size (1 byte, 4 KiB,
  whole-file read, …).
- Hits are `{rule_id, offset}` pairs, deduplicated and sorted by
  `(rule_id, offset)` for stable, reproducible output.
- Offset/window constraints apply to the **start** of a match.

## File integrity statuses

Each scanned file gets one of these statuses; one file's failure never
interrupts the batch:

- `OK` — fully scanned; `hits` and `content_hash` (SHA-256 of streamed bytes)
  are trustworthy.
- `FILE_UNREADABLE` — the file could not be opened/stat/read initially.
- `FILE_TRUNCATED` — fewer bytes were read than the size observed before
  scanning (the file shrank/was truncated during the read).
- `FILE_MODIFIED_DURING_SCAN` — streaming completed, but an independent
  verification re-read hashes differently from the streamed content, proving
  the file changed while it was being scanned. No hits are returned.
- `SCAN_INTERNAL_ERROR` — defensive status for an unexpected panic while
  handling that file.

Truncated/modified files deliberately return no hits: a half-scanned file's
matches are not trustworthy.

## Caching and concurrency

### Per-file basis and incremental rescans

The engine keeps, per file id and rule version, a **continuation basis**:
the file identity (`st_dev`/`st_ino`), size and mtime, the full-content
SHA-256, a serializable SHA-256 state over the consumed prefix, a checkpoint
of the streaming matcher (including its cross-boundary tail), and the
deduplicated hit list. On the next `Scan` of the same path:

1. Same inode object, same size, same mtime -> `mode: REUSE`, the cached
   hits are returned with **zero bytes read and zero bytes processed**.
2. Same inode object, same size, mtime moved -> the whole file is hashed; if
   bytes changed it is a same-size rewrite (full scan,
   `basis: INVALIDATED`, `basis_reason: PREFIX_CHANGED`), otherwise reuse.
3. Same inode object, file grew -> the old prefix is re-read and hashed
   (read but not matched) and compared with the saved prefix hash. Equal:
   `mode: INCREMENTAL`, the matcher checkpoint is restored and only the
   appended suffix is matched; the carried tail guarantees matches that
   complete across the old/new splice point are found, and hit offsets stay
   absolute. Different: full scan with `PREFIX_CHANGED`.
4. File shrank or the inode object changed (`st_dev`/`st_ino`; rename-over,
   log rotation, replacement) -> full scan, `basis: INVALIDATED`,
   `basis_reason: FILE_TRUNCATED_OR_REPLACED`.
5. No basis known (first scan or previously evicted) -> full scan,
   `basis: ESTABLISHED`.

An incremental scan therefore yields exactly the same hits, order,
deduplication and absolute offsets as a from-zero full scan: the matcher
checkpoint is the state the same matcher would have reached after the
verified prefix, so one matching implementation serves both paths.

### Files that change during a scan

Every scan ends with an independent verification re-read whose hash must
equal the hash of the bytes processed. A mismatch (a concurrent append,
rewrite or truncation) produces `FILE_MODIFIED_DURING_SCAN` (or
`FILE_TRUNCATED`) with **no hits** — a half-scanned, stale or partial result
is never returned as `OK`. A follow-up scan after the file settles
converges to the correct hits.

### Capacity and eviction

The basis cache is bounded by represented file bytes (`CacheMaxBytes`,
default 64 MiB; negative means unlimited; CLI flag `-cache-max-bytes`;
runtime `SetCacheMaxBytes`). When exceeded, least-recently-used bases are
evicted; an entry that is itself larger than the budget evicts the others
but is retained. Eviction only changes speed: an evicted file simply
rescans from zero (`basis: ESTABLISHED`) with identical hits.

### Rule hot reload

`Reload()` atomically swaps in a new `rules.Set`; scans in flight keep
their snapshot, new scans use the new set. **All bases bound to superseded
versions are evicted**, so new/changed/deleted rules are always applied to
the whole file — an incremental continuation under old rules never
happens. Incremental behavior is re-established from the first scan under
each new version.

### Concurrency

Concurrent scans of the same file under the same rule version share one
in-flight computation (singleflight); per-result copies and per-scan stats
keep goroutines from observing each other's data. Batch results come back in
input order.

### Result fields and workload stats

New fields are additive; existing JSON fields keep their meaning.

- `mode`: `FULL` (every byte matched), `INCREMENTAL` (only appended bytes
  matched), `REUSE` (nothing read or matched).
- `basis`: `ESTABLISHED` (first clean full scan), `REUSED` (served from a
  valid basis) or `INVALIDATED` (a prior basis was discarded;
  `basis_reason` is one of `PREFIX_CHANGED` (old bytes rewritten),
  `FILE_TRUNCATED_OR_REPLACED` (shrank or inode object changed),
  `CACHE_EVICTED` (basis removed by the capacity policy) or
  `RULE_VERSION_CHANGED` (hot reload)).
- `cached`: preserved — true for cache-served judgments and singleflight
  waiters.
- `stats.bytes_read`: file bytes actually read from the OS this scan
  (includes verification reads).
- `stats.bytes_processed`: bytes fed through the signature matcher (the real
  matching cost: full file / suffix only / zero).
- `stats.bytes_reused`: bytes whose matches came from the saved basis.
- `stats.file_size`: size of the content the result describes.

For any successful scan, `bytes_processed + bytes_reused == file_size`.

## CLI

```sh
go build ./...
go run ./cmd/sigscan -rules examples/rules/signatures.json file1.bin file2.bin
go run ./cmd/sigscan -rules a.json,b.json -chunk-size 4096 target.bin
go run ./cmd/sigscan -rules r.json -cache-max-bytes 1048576 target.bin
go run ./cmd/sigscan -rules @rule-list.txt -reload   # print load report
```

Exit code `2` means at least one file ended with a non-OK status.

JSON results go to stdout (unchanged layout, new fields added); a
human-readable per-file workload summary (rule version, file id, status,
mode, basis, bytes read/processed/reused, hit count) goes to stderr. Note
that the CLI builds a new engine per invocation, so REUSE/INCREMENTAL show
when the engine is embedded in a long-running service (the intended use);
use the Go API or the unit tests to observe repeated scans of evolving
files within one process.

## Verification

```sh
go test ./... -v                       # all unit tests
go test -race -count=3 ./...           # race + repeated runs (needs CGO)
```

Tests additionally cover: tail-append incremental scans producing exactly
the full-scan hit set (including a rule whose terms straddle the splice
point) with only the suffix processed; REUSE doing zero I/O; basis
invalidation with the distinct reason for same-size rewrite, truncation and
inode replacement; append-during-scan producing either a fully correct `OK`
or an explicit incomplete status and then converging; LRU capacity eviction
with byte-identical rescans; hot reload forcing a whole-file rescan before
incremental behavior resumes; and concurrent same-file scans interleaved
with appends, eviction and reloads. Test logs print the rule set version,
file id, status, mode, basis/reason, full hit list and the read/processed/
reused counters.

To observe incremental behavior end to end in one process, run
`go test ./engine/ -run TestIncrementalAppendMatchesFullScan -v`:
the first log line shows `mode=FULL processed=128`, the second
`mode=INCREMENTAL processed=32 reused=128` with identical hits, and the
third `mode=REUSE processed=0`.

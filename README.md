# Signature Detection Engine (local, deterministic)

A fully local file-signature scanning engine. Rules and scanned files both
come from the local filesystem; there are no network calls or external
services. Results are explainable (rule id + exact byte offset), reproducible
(sorted, deduplicated, chunk-size independent) and bound to an explicit rule
set version and file content hash.

## Layout

- `rules/` — rule file parsing, compilation and immutable versioned rule sets.
- `engine/` — streaming/resumable matcher, continuation-based incremental
  scanning, file integrity classification, capacity-bounded LRU state cache,
  workload statistics and concurrent hot reload.
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

- `OK` — fully scanned from the beginning; `hits` and `content_hash`
  (SHA-256 of the whole content) are trustworthy.
- `OK_INCREMENTAL` — append-only continuation. Only the bytes past the
  previous scan point were fed to the matcher, but the hit set, offsets
  (absolute, relative to the start of the file), deduplication and ordering
  are identical to a from-scratch scan, including matches that straddle the
  old/new boundary.
- `OK_REUSED` — the file was untouched since the previous scan (identical
  size/mtime/inode fingerprint); the stored result was reused without
  re-reading anything. `cached` is `true` for this status.
- `OK_FULL_RESCAN` — stored continuation progress was found stale (the old
  prefix was rewritten, the file was truncated, or the file was replaced)
  and discarded; the file was rescanned from the beginning. Hits are
  trustworthy for the current content. This distinct status lets callers
  tell "progress invalidated and rebuilt" apart from a normal completion.
- `Status.IsOK()` returns true for all four successful statuses.
- `FILE_UNREADABLE` — the file could not be opened/stat/read initially.
- `FILE_TRUNCATED` — fewer bytes were read than the size observed before
  scanning (the file shrank/was truncated during the read).
- `FILE_MODIFIED_DURING_SCAN` — streaming completed, but an independent
  verification proved the file changed while it was being scanned (prefix
  hash mismatch on a full scan, inode replacement, growth observed at scan
  end, or the file still growing after bounded drain rounds during a
  continuation). No hits are returned; the result must be treated as
  incomplete and the file rescanned — it never looks like a normal, current
  result.
- `SCAN_INTERNAL_ERROR` — defensive status for an unexpected panic while
  handling that file.

Truncated/modified files deliberately return no hits: a half-scanned file's
matches are not trustworthy.

## Continuation progress and incremental scanning

Progress is kept in the engine, in memory, keyed by
`rule version + file id`. After every successful scan the stored state holds:

- the OS fingerprint (size, mtime, device/inode),
- the covered length and the SHA-256 content hash over `[0, covered)`,
- the serialized streaming-hash state,
- a resumable `MatcherSnapshot` (trailing overlap tail plus per-rule
  occurrence/dedup state),
- the completed result.

On the next scan of the same file:

1. **Identical fingerprint** → `OK_REUSED`, nothing is read.
2. **Different device/inode** (replacement/rotation) or **smaller size**
   (truncation) → progress discarded, full rescan, `OK_FULL_RESCAN` with
   `resume_probe` set to `replaced`/`truncated`.
3. **Same or larger size with a changed mtime** → a continuation is
   attempted. The old prefix is first proved unchanged with two bounded
   SHA-256 probes: a head block `[0, verify-len/2)` and the final tail block
   `(covered - verify-len/2, covered)`. Any mismatch (an in-place rewrite of
   the old prefix) discards progress and returns `OK_FULL_RESCAN` with
   `resume_probe = rewrite-suspect`.
4. After the probes pass, only bytes from the previous covered offset to the
   current end are fed into the restored matcher. The matcher keeps an overlap
   tail, so patterns that started in the old bytes and finish in the new
   bytes are found exactly once at their absolute offset; the `all`
   condition sees old and new term occurrences together.
5. If the file is appended while that read is in flight, new growth is
   drained and matched too (bounded to 16 drain rounds). Persistent growth,
   shrinkage, inode replacement or a size change in the final stat produces
   `FILE_MODIFIED_DURING_SCAN` with no hits instead of a stale-looking OK.

### Continuation integrity — what is and isn't detected

Replacement, truncation, mtime-stamped in-place rewrites, and growth racing
the scan are all detected and handled as described above. The one
undetectable case with bounded reads is an **in-place rewrite of the middle
of the old prefix that also grows the file, performed while preserving the
original mtime**; no scan that refuses to read the whole old prefix can rule
that out. The head/tail probes (total `verify-len` bytes, default 4096) make
rewrites of the file start/end cheaply detectable; raise `-verify-len`
toward the file size if your workload needs a stronger prefix guarantee
(verification reads are hashing-only and charged to `verify_bytes_read`,
never to `bytes_processed`). Filesystems with nanosecond mtime resolution
(Linux ext4/tmpfs/xfs, …) make mtime-preserving rewrites extremely
unlikely in practice.

### Rule hot reload

Progress is bound to the rule version it was built under. `Reload()` evicts
**all** continuation state and results of superseded versions, so new or
changed rules always take effect over the whole file on the next scan (a
full scan under the new version); old rules can never leak through restored
state.

## Cache capacity and eviction

`Config.MaxCacheBytes` (CLI `-max-cache-bytes`) bounds the estimated memory
occupied by continuation state and stored results. The cost of an entry is
the occurrence/dedup records in the matcher snapshot, the overlap tail, the
hash/probe digests and the stored hit list; the running total is reported
internally (`Engine.CacheBytes()`). When inserting a new entry would exceed
the cap, least-recently-used entries (scans, including reuses, touch LRU
order) are evicted first. The default (`0`) is unbounded.

Eviction can only cost speed, never correctness: an evicted file simply has
no progress next time and is fully rescanned, producing exactly the same
hits as if it had never been cached. Capacity eviction, concurrent scans of
the same file and hot reload all operate on independent, version-scoped
keys and never share or revive state.

## Workload statistics

Every result carries a `stats` object:

- `mode` — `full`, `incremental` or `reuse`.
- `bytes_read` — bytes physically read from the OS during this scan,
  including verification probes.
- `bytes_processed` — bytes actually fed to the signature matcher. This is
  the figure that measures optimization effect: `0` for reuse, only the
  appended length for a clean continuation, the whole file for a full scan.
- `bytes_reused` — previously covered bytes not reprocessed (0 for full
  scans, previous size for continuations, whole size for reuse).
- `file_size` — total size of the scanned content.
- `verify_bytes_read` — subset of `bytes_read` spent on the bounded prefix
  integrity probes (hashing only, no matcher work).
- `resume_probe` — how stored progress was classified: `none`,
  `unchanged`, `appended`, `rewrite-suspect`, `truncated`, `replaced`.
- `duration_ms` — wall-clock time spent on this file.

Invariant: `bytes_read >= bytes_processed`, and for trustworthy results
`bytes_processed + bytes_reused == file_size`.

## Concurrency

- Concurrent scans of the same file under the same rule version share one
  in-flight computation (singleflight) and then all reuse the cached result.
- `Reload()` compiles a fresh `rules.Set` and atomically swaps it in; scans
  in flight keep using the snapshot they started with, and new scans use the
  new set.
- Batch results are returned in input order regardless of goroutine
  scheduling.

## CLI

```sh
go build ./...
go run ./cmd/sigscan -rules examples/rules/signatures.json file1.bin file2.bin
go run ./cmd/sigscan -rules a.json,b.json -chunk-size 4096 target.bin
go run ./cmd/sigscan -rules a.json -max-cache-bytes 67108864 -verify-len 65536 target.bin
go run ./cmd/sigscan -rules @rule-list.txt -reload   # print load report
```

Flags:

- `-chunk-size` (default 4096): streaming read chunk size.
- `-max-cache-bytes` (default 0): LRU capacity for continuation state;
  `0` means unbounded.
- `-verify-len` (default 4096): total bytes of bounded head/tail prefix
  probes hashed before trusting a continuation.
- `-quiet`: suppress the per-file workload summary on stderr.

JSON results keep printing to stdout (existing fields unchanged; `stats` and
the new statuses are additive). A one-line workload summary per file is
printed to stderr, e.g.:

```
sigscan: rule_set_version=v12-... file_id=/data/log.bin status=OK_INCREMENTAL mode=incremental read=4100 processed=4 bytes_reused=100000 size=100004 verify_read=4096 probe=appended hits=2 duration_ms=1
```

Exit code `2` means at least one file ended with a non-OK status (the four
`OK*` statuses all count as success).

Note: continuation state is in-process; repeated invocations of the CLI
start cold. Repeated scans of the same arguments inside one batch reuse
state, and long-lived callers of the library benefit across scans.

## Verification

```sh
go test ./... -v                       # all unit tests
CGO_ENABLED=1 go test -race -count=10 ./...   # race + repeated runs
```

### Step-by-step local check of the incremental behavior

```sh
# 1) incremental == full, with the workload counters
go test -run TestIncrementalAppendEqualsFullScan -v ./engine
#    expect status=OK (mode=full), then OK_INCREMENTAL with
#    bytes_processed == number of appended bytes and bytes_reused == old size,
#    then OK_REUSED with bytes_read=0
# 2) stale progress is invalidated and visibly distinguished
go test -run TestStaleProgressRewriteTruncateReplace -v ./engine
#    expect status=OK_FULL_RESCAN, mode=full, probe=truncated|replaced|rewrite-suspect
# 3) appends racing the scan never produce a dirty result
go test -run TestAppendWhileScanningIsNotDirty -v ./engine
# 4) LRU eviction changes speed only, never hits
go test -run TestCacheEvictionNeverChangesResults -v ./engine
# 5) reload drops continuation state and applies new rules to the whole file
go test -run TestReloadInvalidatesContinuationProgress -v ./engine
# 6) concurrent scanners + appenders + reloads
CGO_ENABLED=1 go test -race -run TestConcurrentAppendAndReloadStaysConsistent -v ./engine
```

Tests cover: malformed rules with each distinct rejection reason, duplicate
ids, version stability/change, identical hit sets across chunk sizes 1..4096,
unreadable files inside a batch, deterministic truncation and mid-scan
modification, append-only continuation equality with full scans across many
boundary/chunk combinations (including matches and multi-term rules
straddling the old/new boundary), invalidation on rewrite/truncate/inode
replace, tail appends racing the scan, LRU eviction result invariance,
continuation-state invalidation on hot reload, and concurrent scans
interleaved with appends, eviction pressure and reloads. Verbose test logs
print the rule set version, file id, status, mode, full/inc/reuse counters,
probe reason, the full hit list and duration.

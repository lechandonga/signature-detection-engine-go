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

The cache lives in process memory and is keyed by `rule version + file id`;
each entry additionally records the file identity (device/inode), size,
mtime, the content hash, the resumable matcher snapshot and a marshaled
streaming-hash state. Entries are therefore bound to **both** the rule set
and the exact content.

### Resume progress: when it is built, used and discarded

- A scan builds progress after every successful complete scan: matcher
  occurrence state, a tail of `maxPatternLen-1` bytes for boundary matches,
  the SHA-256 streaming state and the prefix content hash.
- On the next scan of the same file id under the same rule version:
  - file identity + size + mtime unchanged → the cached result is reused
    with zero file-content reads (`mode: "cached"`);
  - the file grew → the already-scanned prefix `[0, oldSize)` is hashed
    independently and compared to the stored prefix hash. Only when it
    matches is the matcher state resumed and just the appended bytes read
    (`mode: "incremental"`, `progress: "resumed"`). The matcher reseeds its
    overlap tail, so a pattern starting in the old prefix and finishing in
    the new tail is found exactly as in a full scan. All emitted offsets are
    still absolute from the start of the file; hits are deduplicated and
    sorted by the same code path as full scans.
  - the file shrank, kept the same length but with a new mtime, changed
    inode (atomic replacement/rotation), grew with a rewritten prefix, or
    lost its progress to capacity eviction → progress is discarded and a
    full rescan runs. `progress` reports the precise reason:
    `invalidated_truncated`, `invalidated_rewritten`,
    `invalidated_replaced`, `invalidated_prefix` or `evicted`.
- A scan that observes the file changing while it reads (size moves or the
    independent whole-file verification hash differs) returns
    `FILE_MODIFIED_DURING_SCAN` / `FILE_TRUNCATED` with **no hits**. This
    also covers an append racing an incremental scan: a caller never gets a
    stale or partial hit set marked `OK`; rescanning after the file settles
    returns the correct result.
- Scans of the same file id are serialized within one engine (different
    files still scan in parallel), so concurrent goroutines cannot corrupt
    or cross-feed resume state. A second concurrent caller simply observes
    the freshly computed result.
- `Reload()` compiles a fresh `rules.Set` and atomically swaps it in; scans
  in flight keep using the snapshot they started with. **All** cached
  results and resume progress belonging to superseded versions are evicted
  on reload, so new/changed rules always apply to whole files and deleted
  rules can never leak.
- Batch results are returned in input order regardless of goroutine
  scheduling.

### Bounded capacity and eviction

`Config.CacheLimitBytes` (CLI: `-cache-bytes`) bounds the accounted cost of
all stored entries. The cost of an entry is:

- the file size in bytes (the bytes a resume would skip),
- plus 16 bytes per recorded matcher occurrence,
- plus the matcher overlap tail and the marshaled hash state.

Eviction is LRU (least recently scanned/reused first). Eviction only ever
removes optimization state, never correctness: an evicted file is simply
full-scanned again (`progress: "evicted"`) and its hits are identical to a
run without a limit. The newest scan's own entry is guaranteed to stay
resident; a single file larger than the whole budget may therefore remain as
the sole entry until the next insertion. The cumulative eviction count is
exposed in every result. The default limit `0` means unlimited.

### Workload accounting (`work`)

Every result carries a `work` object describing what that scan actually did;
the CLI prints the same fields to stderr. Counters count this scan only:

- `bytes_read` — file bytes streamed through the matcher (0 for cached,
  appended length for incremental, whole length for full).
- `bytes_processed` — bytes fed to the matcher; for an incremental scan this
  is `bytes_read` plus the small overlap tail rescanned for boundary
  matches.
- `bytes_reused` — bytes skipped thanks to prior work: 0 for full scans, the
  old file size for incremental/cached scans.
- `bytes_verified` — bytes read by independent verification (the prefix
  hash check and the post-scan whole-file hash).
- `mode` — `full` / `incremental` / `cached`.
- `progress` — `new` / `resumed` / `reused` / `invalidated_*` / `evicted`.
- `cache_entries`, `cache_cost_bytes`, `cache_limit_bytes`,
  `cache_evictions` — current cache footprint and cumulative evictions.

The legacy top-level `cached` field is preserved unchanged in meaning (true
only for zero-work `cached` reuse).

## CLI

```sh
go build ./...
go run ./cmd/sigscan -rules examples/rules/signatures.json file1.bin file2.bin
go run ./cmd/sigscan -rules a.json,b.json -chunk-size 4096 target.bin
go run ./cmd/sigscan -rules @rule-list.txt -reload   # print load report
go run ./cmd/sigscan -rules sigs.json -cache-bytes 67108864 dir/*.bin  # 64 MiB bound
```

JSON results continue to go to stdout (one object per file, in argument
order); the per-file workload line goes to stderr so existing JSON consumers
are unaffected.

Exit code `2` means at least one file ended with a non-OK status.

## Verification

```sh
go test ./... -v                       # all unit tests
go test -race -count=3 ./...           # race + repeated runs (needs CGO)
```

Tests cover: malformed rules with each distinct rejection reason, duplicate
ids, version stability/change, identical hit sets across chunk sizes 1..1024,
unreadable files inside a batch, deterministic truncation and mid-scan
modification, cache reuse and content-based invalidation, cache eviction and
result rebinding after hot reload, append-only incremental resume
(including matches crossing the old/new boundary) byte-for-byte against full
scans, progress invalidation for same-size rewrite / truncation / inode
replacement / rewrite-then-append, racing appends never producing dirty OK
results, bounded eviction rebuilding identical hits, reload discarding
resume progress, and concurrent scans interleaved with both appends and
reloads under a tight cache budget. Test logs (`go test -v`) print the rule
set version, file id, status, mode, progress, full hit list and all workload
counters.

### Verifying the incremental behavior locally

Incremental resume is an in-process optimization, so exercise it with one
engine (the unit tests do this directly), or via this shape of program:

1. `eng.Scan(path)` on a file → `mode=full, progress=new`.
2. Scan the unchanged path again → `mode=cached, bytes_read=0`, same hits.
3. Append bytes to the file (place a signature across the append boundary)
   and scan → `mode=incremental, progress=resumed`, `bytes_read` equal to
   the appended length, `bytes_reused` equal to the old size; compare hits
   and `content_hash` with a fresh-engine full scan — identical.
4. Rewrite bytes in place / truncate / rename a new file over the path /
   `Reload()` with changed rules → next scan is `mode=full` with the
   matching `invalidated_*` progress (or no reuse after reload).
5. Set `CacheLimitBytes` smaller than the directory, scan many files and
   watch `cache_evictions` rise while `cache_cost_bytes` stays bounded and
   hit sets remain unchanged.

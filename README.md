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

- Cache key is `rule version + file content hash + file id`, so entries are
  bound to **both** the rule set and the exact content. A cache hit only adds
  `cached: true` to the response; the hit set is byte-for-byte identical to a
  fresh scan.
- Concurrent scans of the same file under the same rule version share one
  in-flight computation (singleflight) and then all reuse the cached result.
- `Reload()` compiles a fresh `rules.Set` and atomically swaps it in; scans in
  flight keep using the snapshot they started with, and new scans use the new
  set. Cache entries belonging to superseded versions are evicted on reload,
  so deleted rules can never leak and added rules are always applied.
- Batch results are returned in input order regardless of goroutine
  scheduling.

## CLI

```sh
go build ./...
go run ./cmd/sigscan -rules examples/rules/signatures.json file1.bin file2.bin
go run ./cmd/sigscan -rules a.json,b.json -chunk-size 4096 target.bin
go run ./cmd/sigscan -rules @rule-list.txt -reload   # print load report
```

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
result rebinding after hot reload, and concurrent scans interleaved with
reloads. Test logs print the rule set version, file id, status, cache flag
and the full hit list.

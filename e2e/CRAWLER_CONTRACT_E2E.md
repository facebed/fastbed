# Crawler classification process E2E

This suite validates crawler classification through Fastbed's real HTTP
process. It is not a unit test and does not call `fb_crawler_is_bot()`
directly. A crawler response is the unsupported-route fallback (`200`); a
non-crawler response is the browser redirect (`302`). The process runs in a
loopback-only network namespace, so a mistaken crawler decision cannot reach
an external upstream.

## Failure model recorded before the harness

The E2E must be able to distinguish all of these failures:

1. The bundled database is not the claimed crawler-user-agents `1.59.0`
   payload, is truncated, has reordered entries, or silently changes hash or
   count.
2. JSON loading skips an entry, accepts a malformed pattern entry, changes the
   order, or chunks the 1,498 patterns incorrectly.
3. Pattern concatenation changes regex precedence, capture behavior, or UTF
   semantics compared with compiling each expression independently.
4. PCRE2 compilation, JIT, match, depth, heap, or stack errors are mistaken for
   positive matches, negative matches, or process success.
5. The optimized combined expression disagrees with the bounded per-chunk
   fallback.
6. ASCII-insensitive behavior diverges because only the subject or only the
   pattern is folded, locale-sensitive folding leaks in, or a byte on a chunk
   boundary is skipped.
7. The common-unfurler shortcut recognizes a token absent from the database,
   fails to recognize a database token, or is not ASCII-case-insensitive.
8. The 512-byte inline/heap boundary truncates, aliases, or fails allocation;
   later large user agents accidentally reuse bytes from an earlier request.
9. Long accepted HTTP header values are parsed differently from the bytes
   given to the oracle. Resource-bound headers may be rejected, but rejection
   must be explicit and the process must remain healthy.
10. A missing or empty `User-Agent` is treated as a crawler.
11. The HTTP layer returns the correct status but the wrong `Location`,
    `Vary`, cache policy, content type, or body class.
12. The suite accidentally exercises `/`, `/healthz`, or a route that bypasses
    classification, or a crawler case performs an upstream request.
13. The reference accidentally duplicates the production combined-regex
    implementation. The oracle therefore compiles every pattern independently
    and reports every matching database index.
14. The reference PCRE2 runtime, compiler, flags, database, generated case set,
    or Fastbed binary drifts between the run and replay.
15. The process crashes, times out, leaks a request result, exits nonzero, or
    becomes unhealthy after a classification case.
16. The run stops early yet leaves a superficially green summary.
17. Raw requests/responses or per-case oracle decisions are omitted, making a
    result impossible to audit or replay exactly.

## Oracle and cases

`crawler_pcre2_oracle.c` is a standalone reference executable built by the
harness. It parses the vendored JSON independently, ASCII-lowercases each
pattern and subject, compiles each expression separately with
`PCRE2_UTF | PCRE2_UCP | PCRE2_MATCH_INVALID_UTF`, and uses bounded interpreter
matching. The harness pins PCRE2 `10.47`, the vendor SHA-256, version, and
pattern count. It records the reference source, build command, compiler,
runtime library identity, and output.

The generated contract includes:

- all 2,116 published instances across the 1,453 entries that provide them,
  plus a literal witness for the 45 entries that do not;
- a positive target witness for every one of the 1,498 patterns. Three vendor
  expressions (indices 704, 710, and 810) contain `\\S`; version 1.59.0's
  `case_sensitive=False` implementation lowercases the regex source and turns
  `\\S` into `\\s`, so those three published instances are retained as known
  negative compatibility cases and whitespace-only positive witnesses are
  added for the lowered expressions;
- an ASCII case-swapped representative for every pattern;
- exact, noisy, upper-case, and one-character-short common unfurler tokens;
- ordinary browsers, crawler-looking English words, missing/empty headers, and
  deterministic negative near-misses;
- positive and negative crawler tokens adjacent to invalid UTF-8 `obs-text`
  bytes, exercising the pinned `PCRE2_MATCH_INVALID_UTF` contract through the
  HTTP parser;
- matching and non-matching user agents at 511, 512, 513, 4,096, and 16,384
  bytes, plus resource-bound 30,000-byte and 48,000-byte pairs.

Every positive target case is rejected before HTTP execution unless the
independent oracle reports the intended pattern index. Every strict near-miss
and known 1.59.0 published-instance nonmatch is rejected unless the oracle
reports no matching pattern. Every accepted HTTP classification must equal the
oracle. The 30,000-byte and 48,000-byte resource-bound cases may instead
receive an HTTP `4xx` or a connection close, but the process must remain
healthy; a server-side `5xx` is a failure.

Some real crawler instances intentionally match more than one vendor pattern.
`oracle-coverage.json` records which positive target witnesses are unique and
the complete matching-index set for every overlap. This prevents a boolean
HTTP result from being misreported as pattern attribution while still proving
that the intended expression independently matches its witness.

Synthetic literal witnesses ending in HTTP optional whitespace receive a
deterministic `contract` suffix. This keeps the regex-significant space inside
the field value instead of asking the HTTP parser to preserve trailing OWS;
currently this applies to pattern 40, `webmon `.

## Startup database policy audit

Current startup accepts a database path from `--crawler-db` or
`FASTBED_CRAWLER_DB`, and the loader checks JSON shape, a nonzero count, and
compilability. It does not authenticate the bundled bytes or log their digest.
The install rule copies a pinned vendor file, but a replaced installed file can
still start successfully.

Recommended policy:

1. Compute SHA-256 while reading every crawler database and log the digest,
   entry count, and source mode.
2. When no custom override is requested, require the bundled `1.59.0` digest
   `4e414e18ed3f64b9b8298a9f042c83e1ccf54414d8a742fb1f0ec9441d5170e4`
   and exactly 1,498 entries. Fail closed before listening on mismatch.
3. Preserve custom databases, because `--crawler-db` is an intentional
   operator surface. Require an explicit custom mode plus an expected SHA-256
   (for example `--crawler-db PATH --crawler-db-sha256 HEX`). An emergency
   unpinned override, if retained, should be named as such and emit a prominent
   warning.
4. Treat `FASTBED_CRAWLER_DB` as a path selector, not as implicit permission to
   bypass integrity. A matching `FASTBED_CRAWLER_DB_SHA256` or an explicit
   unpinned opt-in should still be required.
5. Hash the exact in-memory bytes that are parsed and compiled. Open the file
   once with `O_CLOEXEC` and, for the bundled/default path, `O_NOFOLLOW`; verify
   a regular bounded file with `fstat`. A separate preflight hash followed by a
   second pathname open would leave a time-of-check/time-of-use substitution
   window.

This gives the production default a supply-chain invariant without forbidding
private or newer crawler databases. This document is a proposal only; the E2E
does not modify production C.

## Run

```sh
python3 e2e/run_crawler_contract_e2e.py build-pinned/fastbed \
  --output artifacts/crawler-contract-YYYYMMDD-NN
```

The output contains the canonical input manifest, raw requests and responses,
the exact oracle input and output, per-case JSONL, process logs, environment
metadata, an artifact manifest, a replay command with expected fingerprints,
and `SHA256SUMS`.

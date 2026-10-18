# Access logging contract

Fastbed emits one access line from GNU libmicrohttpd's completion callback for
every response that was successfully queued:

```text
[INFO] [YYYY-MM-DD HH:MM:SS] REMOTE METHOD DISPLAY_URL STATUS REASON[ TITLE]
```

This matches Facebed's production formatter boundary. Request routing and
upstream fetches continue to use the original request target. Only the log
copy is made readable.

- A title is attached only when the application produced a successfully
  parsed post. Static pages, health, redirects, overloads, timeouts, method
  errors, and HTTP-200 fallback cards retain their ordinary title-free line.
- Success-cache entries store the parsed title beside the rendered body. Both
  values are copied under the same shard lock and charged against the same
  byte bound, so a warm hit cannot inherit a stale or unrelated title.
- Contiguous `%HH` runs are decoded once only when the complete run is valid
  UTF-8 and contains no C0/C1 control, `U+2028`, or `U+2029`. Invalid or unsafe
  runs remain encoded. `+` is never changed.
- Sensitive query values are replaced with `[REDACTED]` after display decoding.
  This also catches a query nested in one percent-encoded URL layer.
- Titles receive two HTML5 unescape passes around valid literal `\uXXXX` and
  `\UXXXXXXXX` decoding, then Python-compatible whitespace collapsing.
  Malformed, unpaired-surrogate, out-of-range, and control escapes remain
  literal. Raw controls and invalid UTF-8 cannot split or steer a terminal log.
- Fallback diagnostics cap and collapse detail text, and replace the whole
  query in their diagnostic URL with `?[redacted]`. The access line retains the
  useful, selectively redacted display URL.

## Cost model

The ordinary path is allocation-free in the access formatter: already-safe
UTF-8 request targets and already-normalized titles are borrowed from their
request-local storage. Exotic URL decoding uses three bounded temporary
buffers; exotic title decoding uses four. Those allocations happen after the
response has completed and never alter request or cache state.

The complete Python-compatible HTML5 named-entity table adds 37,426 bytes of
read-only data to the server translation unit. Keeping the formatting call
out-of-line leaves the completion callback itself at 241 bytes in the measured
GCC release binary, rather than inlining roughly 7.6 KiB of formatter
code into the lifecycle path.

A loopback snapshot on 2026-10-17, with four persistent clients, 20,000
requests per case, a GCC release binary, and stderr directed to `/dev/null`,
measured:

| Process request | Requests/second |
|---|---:|
| `/healthz` | 9,519.5 |
| ASCII browser redirect with query | 9,212.8 |
| Browser redirect with valid/invalid percent runs and redaction | 8,992.4 |

These numbers include HTTP parsing, response generation, completion, timestamp
formatting, and stdio locking. They are a local comparison, not a deployment
capacity claim.

## Repeatable verification

The ASan/UBSan exact-line artifact is
`artifacts/fastbed-access-log-exact-asan-20261017-12`. It covers five mutated
medium-hard parsed-title cases, safe percent decoding, malformed UTF-8,
encoded controls and separators, nested encoding, secret redaction, HEAD,
405, fallback-title isolation, and exact one-line completion counts. The
artifact retains its harness, bodies, raw process log, source/binary hashes,
expected and actual lines, and checksums.

```sh
(cd artifacts/fastbed-access-log-exact-asan-20261017-12 && \
  sha256sum -c SHA256SUMS)
```

The concurrent lifecycle artifact is
`artifacts/fastbed-access-log-concurrency-asan-20261017-13`. It adds cold
singleflight, warm-cache fan-out, overload, disconnect, graceful-drain, and
forced-timeout coverage against a 2.2 MiB saved group-post response.

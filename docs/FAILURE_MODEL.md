# Fastbed failure model

This document was written before implementation. It defines how the C port can
fail, which failures are observable compatibility defects, and what evidence is
required before an optimization is accepted.

## Pinned oracle

- Repository: `/home/pie/src/facebed`
- Git revision: `60159f365ac3a47bf7f0f71bd9c2eee090288198`
- `facebed.py` SHA-256:
  `e1d9faec4ac2a3e35254a9359fd6df9a2025f32d94fd8f3b40d2fe0a3dc7697e`
- Active-gate baseline manifest SHA-256:
  `720f18270cd6165271efb47b04075849a46cd31c7913d07f6f17c95591758f4b`
- Corpus: 10,659 URL rows, 13,653 content-addressed HTML bodies,
  5 non-HTML bodies, and 22,187 response references.

The Python service is the behavioral oracle. Historical capture outcomes are
provenance, not expected answers: both implementations must replay the same
saved transport evidence at the pinned source revision.

## Transport failures

1. A stock TLS fingerprint can receive different Facebook content from the
   `chrome146` impersonation used by `curl_cffi`.
2. A caller-supplied `Cookie` header, libcurl cookie engine, `Set-Cookie` on a
   redirect, pooled easy handle, or reused connection can leak state between
   requests or redirect hops.
3. Automatic redirect handling can replay cookies, lose exact hop provenance,
   change methods incorrectly, retain first-hop parameters, accept credentials
   in a target URL, cross to a non-HTTP scheme, loop, or exceed ten hops.
4. Retry policy can drift in status set, attempt count, 250 ms delay, or in
   whether a terminal response is retained for diagnostics.
5. Connect/read timeouts can collapse into the wrong reason code or trigger a
   parser fallback that the oracle would not try.
6. Compression or charset decoding can change raw attachment bytes or decoded
   HTML. Diagnostic bodies must remain byte-exact.
7. Request-local GET cache keys can alias requests with different headers,
   parameters, redirect policy, or method.
8. `last_get_response` can accidentally replace `selected_get_response`, making
   diagnostics and identity decisions refer to a later probe.
9. Connection pooling can retain headers, method state, body callbacks, error
   buffers, redirect state, or cookies from an earlier request.
10. An unbounded concurrency increase can overload Facebook, exhaust file
    descriptors or memory, or amplify retries. Backpressure must be explicit.
11. A fixture miss can silently fall through to the live network. Replay must
    run in an isolated network namespace and record every attempted endpoint.
12. A replay transport can invent redirect hops or reuse a response from a
    different corpus row. Matches must remain row-local and provenance-bearing.

### Archive-backed full-corpus replay

The former `fulltest/corpus` metadata tree has been permanently retired. Before
implementing its replacement, the archive adapter is required to fail closed on
all of these cases:

1. The Python-oracle JSONL is malformed, has duplicate or non-sequential source
   lines, or does not contain every selected line.
2. A selected line is changed while a resumable artifact is in progress. The
   oracle JSONL hash, archive indexes, runner, broker, binary, and exact ordered
   selection are immutable run identity.
3. A row-local operation is served out of occurrence order, borrowed from a
   different row, normalized more broadly than the retired broker, or reused
   after its saved occurrences are exhausted.
4. A transport error is converted to an HTTP response, a saved fixture miss is
   converted to a transport error, or either is silently replaced with another
   occurrence. Multiple HEAD/GET operations and retries remain distinct.
5. A redirect loses its recorded next hop or final URL. The broker may derive a
   redirect hop only from the next ordered request in the same saved operation;
   an ambiguous hop is an integrity error, not a guessed redirect.
6. A request-trace body hash is absent from the canonical zstd body index, the
   indexed path escapes the archive, decompression fails, or decompressed size
   or SHA-256 differs. No historical gzip path is trusted or synthesized.
7. A saved shared gap is reported as a new Fastbed gap, a new miss is hidden by
   an old gap, or archive/index corruption is counted as either kind of gap.
   Shared fixture gaps, new fixture gaps, overuse, and integrity errors remain
   separate result axes.
8. Row selection can race an in-flight request. Selection is sequential: the
   broker rejects a new row until the current row has no active exchanges, and
   each report is bound to the selected source line.
9. The adapter falls through to the live network or accepts an archive that is
   not independently marked complete. Replay remains loopback-only and validates
   the archive completion and index identities before serving any row.

## URL and route failures

1. C URL parsing can differ from Python `urlparse`, `parse_qs`, `urljoin`,
   `unquote`, and `urlencode` for blank values, duplicate keys, encoded
   delimiters, Unicode, fragments, ports, credentials, and scheme-relative URLs.
2. Host suffix checks can accept lookalikes such as `notfacebook.com` or reject
   valid Facebook subdomains.
3. Legacy `story.php` normalization can rewrite ambiguous or invalid IDs, drop
   required comment identity, or retain unrelated query parameters.
4. `/watch?v=` cleanup can normalize a value that is not exactly a numeric ID
   followed by ASCII whitespace or slashes.
5. Comment and reply IDs can accept blanks, duplicates, non-ASCII digits,
   mismatched parentage, or identical comment/reply IDs.
6. Share resolution can change a requested comment identity or trust a
   canonical URL without target-bound payload evidence.
7. Unsupported profile, Marketplace, album, and landing routes can enter a
   generic parser and borrow unrelated recommendation content.
8. `/dump`, trailing slash, query preservation, and crawler/non-crawler routing
   can be evaluated in the wrong order.

## HTML/document failures

1. A specialized scanner can miss mixed-case tags/attributes, reordered or
   quoted attributes, whitespace, entities, malformed end tags, or script text
   recovery that BeautifulSoup accepts.
2. Treating `</script>` inside JSON strings as ordinary text or as markup can
   differ from the HTML parser's raw-text rules.
3. Canonical and `og:url` extraction can decode entities differently or lose
   document order and duplicates.
4. Login/checkpoint forms and private-group markers can be missed if only JSON
   scripts are retained.
5. A body limit can reject valid captured pages; existing evidence includes
   multi-megabyte pages and notifier attachments above 7 MiB.
6. In-situ JSON parsing can mutate the only copy of raw upstream bytes needed
   by dump/restricted-page reporting.
7. A malformed JSON block must be skipped without invalidating other blocks.
8. JSON depth, value-count, integer-width, invalid UTF-8, and allocation limits
   can turn attacker-controlled input into stack exhaustion or memory denial.

## JSON traversal and identity failures

1. The oracle visits the current dict, then list-valued descendants, then
   dict-valued descendants. Ordinary DFS, hash-table iteration, or key sorting
   can select a different candidate.
2. Duplicate JSON keys and insertion order are observable. An index must retain
   traversal rank and all occurrences, not only the last value.
3. `first`, `all`, shortest-candidate, score, and tie-breaking semantics can
   select a sibling post, comment, or recommendation.
4. Numeric IDs, `pfbid` tokens, base64 comment IDs, and IDs embedded in URLs or
   opaque strings can be normalized or compared incorrectly.
5. Route metadata, request/final URLs, redirect provenance, canonical/OG URLs,
   story IDs, video delivery IDs, and playable media must reach the same target
   consensus before content is trusted.
6. Stale SEO metadata must not veto the narrowly proven reel case, but the
   exception must not weaken negative controls.
7. A valid HTTP 404/500 body with target data can be rejected too early.
   Conversely, a 200 login wall can be treated as a valid post.
8. Authentication/private-group classification, target mismatch, target
   missing, and generic upstream status precedence can drift.
9. Parser-specific document mutation can contaminate later fallback parsers or
   a cached document.
10. A precomputed key index can omit contextual inherited IDs and therefore
    attach reactions from a different feedback subtree.

## Parser and dispatch failures

1. Dispatch order can differ for `type=3`, comments, shares, slugged videos,
   reels, photos, watch URLs, normal posts, and groups.
2. Terminal no-data and unsupported-route errors must suppress fallbacks that
   ordinary parser errors allow.
3. Error preference can select a generic error instead of a more specific
   reason or lose the response body attached to a parse error.
4. Comment extraction can borrow parent-post author, body, media, timestamp,
   reactions, or replies.
5. Photo/reel/watch fallbacks can select media not bound to the requested ID or
   emit an unsafe non-HTTPS/credential-bearing media URL.
6. Attached-story recursion can duplicate images/videos, recurse cyclically,
   or change display order.
7. Missing values can render as `0`, `null`, or empty inconsistently.
8. Existing parser-specific banned-user behavior is inconsistent. The port
   must match it until a separately approved behavior change.

## Rendering and HTTP failures

1. Python's 1,024-character description limit counts Unicode code points, not
   UTF-8 bytes. Truncation must never split a code point.
2. HTML escaping, URL quoting, JSON string escaping in redirects, entity
   unescaping, whitespace prettification, and attribute quoting can change
   unfurler-visible output or create injection vulnerabilities.
3. The success templates differ for video and image posts; only four images are
   emitted and the `contains 4+ images` marker has exact semantics.
4. Timezone offset, timestamp formatting, reaction ordering, human-number
   formatting, and top-reaction limits can drift.
5. Successful embeds are HTTP 200 with `public, max-age=900`; fallbacks are also
   HTTP 200 but remain `no-store`. Catch-all responses vary on `User-Agent`.
6. Ordinary browsers require both HTTP 302 and the HTML/meta/JavaScript redirect.
7. Root/static/health routes must not increment scrape metrics. Parser-entry and
   error counters must retain their current definitions under concurrency.
8. Crawler detection must preserve the exact versioned 1,498-pattern routing
   contract, including case-insensitive regex semantics.
9. Static-file path handling can introduce traversal or content-type defects.
10. A success cache can serve signed media after expiry, cache a fallback,
    ignore configuration changes, or let an attacker force unbounded memory.

## Configuration, notification, and lifecycle failures

1. Unknown YAML keys, wrong scalar/list types, unreadable files, and timezone
   values outside `[-12, 14]` must fail startup without printing secrets.
2. YAML implicit typing can differ from PyYAML's exact-type checks.
3. Webhook URLs and local credentials must never enter logs, artifacts, command
   output, repository files, or core dumps.
4. Reporter threads can outlive request-owned data, race shutdown, grow without
   bound, or lose the exact raw attachment.
5. Bodies over 7 MiB require deterministic gzip (`mtime=0` equivalent) without
   lossy truncation; rate-limit retry and timeout behavior must be bounded.
6. SIGTERM can drop accepted requests or queued reports. Shutdown needs a
   bounded graceful drain and a forced-exit deadline.
7. Counters can false-share, overflow silently, or become inconsistent if
   updated with relaxed atomics without a defined snapshot contract.
8. A suspended libmicrohttpd connection does not time out and does not notice a
   disconnected client. Admission and queued work must therefore stay bounded,
   and shutdown must cancel or drain every job and resume every suspended
   connection before `MHD_stop_daemon`. Production and development builds must
   use libmicrohttpd 1.0.10 or newer; earlier releases also lack suspend/resume
   race fixes required by this lifecycle.
9. Only the access callback may suspend a connection. A worker may publish a
   completed application response and call `MHD_resume_connection`, but it must
   never queue the response, touch MHD-owned request pointers, resume twice, or
   free request state; those actions remain on the MHD callback/completion path.
10. Request data used after suspension must be copied into request-owned
    storage. The arena, response bytes, cancellation flag, and connection state
    must outlive both the application job and asynchronous transmission.
11. Queue saturation must return a bounded overload response without suspending
    the connection. Shutdown must not leave detached workers, queued notifier
    work referring to request memory, or an ownerless single-flight reservation.
12. A stale cache owner must not commit or abort a newer reservation for the
    same key after the in-flight deadline. Reservations and timeout removals
    need an identity/generation check in addition to the keyed hash.

## Internal-cache opt-in and linkage failures

1. Merely renaming `--disable-success-cache` can leave the cache enabled by
   default through an inverted boolean. A process started without
   `--internal-cache` must not allocate the global post cache, coalesce
   requests, or reuse a prior response.
2. A deprecated negative flag can turn a typo or stale deployment command into
   an ambiguous cache policy. `--disable-success-cache` must be rejected;
   cache state has one positive control, `--internal-cache`.
3. `--internal-cache` can enable storage but fail to enable singleflight, or it
   can coalesce the cold wave but refetch warm hits. A real repeated-post E2E
   must distinguish default upstream call count from cold and warm opt-in call
   counts while verifying every public response byte.
4. Opt-in caching must retain its existing safety boundary: only successful
   rendered posts are eligible, parser fallbacks and dump responses bypass it,
   TTL and byte/entry limits stay bounded, and shutdown cannot strand an owner
   or waiter.
5. A benchmark or replay harness that still passes the removed negative flag
   can fail for the wrong reason, while a cache benchmark that forgets the new
   positive flag silently measures the uncached path. Harnesses must state the
   intended policy explicitly only when they exercise caching.
6. Naming a CMake target `STATIC` does not prove the final ELF contains it, and
   linking one curl archive statically does not prove its TLS, HTTP/2,
   compression, or IDN closure is also static. The captured link command must
   include yyjson and every verified curl-impersonate archive.
7. A host `libcurl`, OpenSSL, nghttp2, zlib/Zstandard/Brotli, IDN, or yyjson
   shared object can enter `DT_NEEDED` through configuration drift. Production
   configuration and the post-link gate must reject every such dependency.
8. Conversely, forcing the base runtime ABI static can make DNS/NSS, libc,
   security updates, and deployment compatibility worse. libc, libstdc++,
   PCRE2, and their system transitive dependencies remain dynamically linked.
   Libmicrohttpd and libyaml are explicit exceptions: their pinned archives
   must be embedded alongside curl-impersonate and yyjson and represented in
   source, license, receipt, and relink evidence.
9. A system-curl diagnostic build can accidentally become the default. It must
   require an explicit non-production CMake opt-in and remain incompatible with
   the production static-link verification claim.
10. A linkage checker that only searches filenames is tautological. It must
    inspect the finished ELF dynamic table, confirm compiled-in curl
    impersonation and yyjson symbols, preserve the exact link command, and
    reject a real dynamic-curl negative-control binary.

## Embedded-resource and release-surface failures

1. Embedding generated C from assets can normalize newlines, decode image
   bytes, omit a trailing byte, or reorder crawler patterns. Generated arrays
   must be byte-identical to the four source files and hash-bound by the build.
2. Embedded read-only storage is process-lifetime memory, not an mmap or arena
   allocation. Cleanup must never `munmap`, free, or overwrite it, while
   verification overrides must still release their mapped files exactly once.
3. The root template still needs the one exact credit-placeholder replacement;
   serving the raw embedded template or replacing multiple markers changes
   public HTML.
4. The crawler loader must compile the same 1,498 ordered expressions from the
   embedded JSON and retain all JIT/resource limits. A separate embedded parser
   path can silently drift from file-backed verification behavior.
5. A source file can change without regenerating the embedded translation unit.
   CMake dependencies, generated metadata, and the final E2E must bind each
   source SHA-256 to the bytes compiled into the tested executable.
6. Keeping `--assets`, `--crawler-db`, `--allow-stock-curl`, or replay-port
   arguments in a release binary leaves development/fixture surfaces exposed.
   They must be absent from help and rejected unless the binary was compiled
   with the explicit verification-build option.
7. Conversely, removing those switches globally can make exact offline replay
   impossible. The verification build must expose them and differ from release
   only at that guarded boundary; both variants need build-identity evidence.
8. A default config path, working directory, or environment override can
   accidentally remain required after embedding. The release executable must
   start from an unrelated read-only working directory with no asset/crawler
   arguments or resource environment variables.
9. `build.sh --run` can hide missing runtime inputs by injecting source-tree
   paths. The production script must accept no mode flag, build the native
   full-LTO/static candidate, and leave a directly runnable `build/fastbed`.
10. Dead file-loading code cannot be assumed absent from release merely because
    its CLI is hidden. Link-time garbage collection and symbol/argument audits
    must prove the release surface, while verification builds retain the
    explicit override path needed by process-level replay.

## Optimization failures

1. A microbenchmark can measure only `/healthz`, hot cache hits, or synthetic
   tiny JSON while real work is 300 KiB–multi-megabyte Facebook HTML.
2. Comparing a concurrent C server to the synchronous Python server without
   separating server, transport, parse, render, and end-to-end timings obscures
   where speedup comes from.
3. PGO trained on only successes or one route type can pessimize comments,
   failures, and adversarial paths. The training set must be stratified.
4. `-march=native` can produce an illegal instruction on deployment hosts.
   Host-tuned and portable artifacts must be separate and labeled.
5. `-ffast-math`, unchecked UTF-8, strict-aliasing violations, unsafe overreads,
   and omitted bounds checks can corrupt observable values or create security
   defects. They are not accepted without workload-specific proof.
6. SIMD tail handling can read across an unmapped page. Padded buffers or
   masked/scalar tails are mandatory.
7. Arena reuse can leak data or pointers across requests; high-water retention
   can become a memory DoS.
8. A lock-free cache or queue can have ABA, reclamation, ordering, or shutdown
   races. Simpler sharded locks win unless profiling proves otherwise.
9. False sharing can make counters, queue heads, or worker state slower at high
   concurrency. Hot per-worker fields need measured cache-line separation.
10. HTTP/2 multiplexing and connection reuse can improve throughput while
    worsening tail latency or upstream fairness; both must be measured.
11. Huge pages, custom allocators, busy polling, `io_uring`, BOLT, and explicit
    prefetching can be neutral or harmful. None ship merely because they sound
    advanced; each needs an A/B artifact on the representative workload.
12. Compiler flags can remove hardening or alter semantics. Release, host-tuned,
    sanitizer, and PGO builds must remain distinct and reproducible.

## Required evidence gates

An implementation milestone is accepted only when its durable artifact records
the source hashes, compiler/dependency versions, exact command, input manifest,
network namespace, CPU/build profile, per-case results, output hashes, timing,
peak memory, and failures.

1. **Active behavior gate:** real Fastbed process plus fixture transport covers
   anonymous redirects, 137 upstream cases, 81 fallback cases, 11 adversarial
   cases, and 56 comment/reply scenarios.
2. **Full differential gate:** all 10,659 corpus rows run against pinned Python
   and Fastbed with the same saved responses. Report exact output matches,
   semantically equivalent outputs, regressions, fixture gaps, integrity errors,
   and network attempts separately.
3. **Concurrency gate:** a mixed medium-hard workload includes large posts,
   comments/replies, reels, shares, fallbacks, duplicates (single-flight), slow
   upstream responses, disconnects, and queue saturation.
4. **Safety gate:** the same process-level E2E runs under ASan+UBSan and then
   Valgrind/heap profiling on a bounded representative subset. These are not
   isolated unit tests.
5. **Performance gate:** cold and warm parse-only, server-only, replayed
   end-to-end, and live-bounded timings compare Python, portable C, native C,
   PGO C, and any experimental optimization. Publish median, dispersion, p95,
   p99, throughput, CPU time, allocations, RSS, and output correctness.
6. **Deployment gate:** multi-arch container builds, non-root runtime, health
   check, graceful termination, and a real crawler request are independently
   verified. A registry push alone is not deployment evidence.


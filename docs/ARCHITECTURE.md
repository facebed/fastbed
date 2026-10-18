# Fastbed architecture

Fastbed is a native C17 Facebook embed service. It preserves Facebed's public
HTTP behavior while bounding memory, concurrency, redirects, parser traversal,
and shutdown time. The production executable contains its landing page,
favicon, banner, and crawler database, so serving does not depend on a source
checkout.

## Request flow

```text
libmicrohttpd I/O threads
        |
        | parse target and classify User-Agent
        v
bounded application queue and worker pool
        |
        v
app routing -> URL normalization -> optional success cache
        |                              |
        | cache miss                   | cache hit
        v                              v
curl-impersonate transport          rendered response
        |
        v
HTML scan and ordered JSON indexes
        |
        v
route parser and target identity validation
        |
        v
post model -> OG/Twitter renderer -> HTTP response
        |
        +-> bounded asynchronous notifier
```

Non-crawler requests take a short redirect path and do not enter the upstream
parser pipeline. Crawler failures deliberately render the same HTTP 200
fallback contract as Facebed.

## Components

| Component | Main files | Responsibility |
|---|---|---|
| Process and CLI | `src/main.c`, `src/config.c` | Strict options, YAML configuration, CPU and cgroup worker sizing, signal handling, and the shutdown watchdog. |
| HTTP server | `src/server.c` | libmicrohttpd integration, I/O threads, bounded work queue, request deadlines, application workers, and graceful or forced drain. |
| Application | `src/app.c` | Crawler gate, public routes, assets, cache policy, parser invocation, response headers, and metrics. |
| Upstream transport | `src/transport.c` | curl-impersonate handles, anonymous request scope, manual redirects, retry policy, response limits, and request traces. |
| Document index | `src/document.c` | One-pass HTML scanning, script extraction, yyjson parsing, effective duplicate-key semantics, and lazy ordered indexes. |
| Parser | `src/parser.c` | Share resolution, route dispatch, strict target identity consensus, post extraction, and stable fallback reasons. |
| Model and rendering | `src/model.c`, `src/render.c` | Request-owned post data and Facebed-compatible escaped OG/Twitter HTML. |
| Supporting paths | `src/url.c`, `src/crawler.c`, `src/cache.c`, `src/notifier.c`, `src/metrics.c` | URL semantics, PCRE2 crawler matching, opt-in success cache, webhook delivery, and low-contention counters. |

Public interfaces live under `include/fastbed/`. Third-party source, data, patch
sets, and notices live under `third_party/`.

## Concurrency and ownership

libmicrohttpd I/O threads perform bounded request parsing and crawler
classification. Work that may block moves to the application pool. The queue,
connection counts, per-IP counts, and worker count all have explicit limits.

Each request receives an arena. Parsed URL slices, HTML metadata, JSON indexes,
post fields, and rendered output die with that arena. Transport bodies live in
the request's transport scope; the scope owns a persistent per-worker curl easy
handle but never shares response state across requests. The thread-local arena
recycler retains only bounded storage.

Embedded resources have process lifetime and are read-only. Verification builds
may replace them with file-backed inputs, but that path is compiled out of a
release build. The notifier owns copies of queued data and drains independently
during shutdown.

## Cache policy

The cross-request post cache is disabled by default. `--internal-cache` enables
a 16-shard, 4,096-entry, 64 MiB success cache with a 900-second TTL and
duplicate-request singleflight. Fallbacks and dump responses are never cached.
Request-local transport reuse remains active in both modes.

## Trust boundaries

Facebook HTML, redirects, media URLs, request targets, User-Agent strings, YAML,
and webhook responses are untrusted. The implementation checks sizes before
allocation, rejects credential-bearing or unsafe redirect targets, clears
cookies at every redirect hop, and requires target-local identity evidence
before rendering extracted content.

The process disables core dumps before loading configuration. Production builds
hide replay and file-override controls, verify their bundled libraries after
linking, and retain only libc, libstdc++, libgcc, and PCRE2 as direct dynamic
dependencies.

## Build profiles

- `build.sh` creates the host-native `-O3`, full-LTO, lld-linked release.
- CMake can create portable, x86-64-v3, sanitizer, PGO, and BOLT-ready builds.
- `FASTBED_VERIFICATION_BUILD=ON` exposes offline replay controls; it is not a
  production profile.
- The Docker build creates a portable amd64 or arm64 image and records exact
  dependency receipts. Only amd64 has completed the current release gates.

Compatibility, performance, live transport, memory safety, supply chain, and
container behavior are separate evidence axes. See
[`VERIFICATION.md`](VERIFICATION.md) for the gates and
[`COMPATIBILITY.md`](COMPATIBILITY.md) for the public contract.

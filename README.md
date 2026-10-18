# Fastbed

[![Build and Push Docker Image](https://github.com/facebed/fastbed/actions/workflows/docker-build.yml/badge.svg)](https://github.com/facebed/fastbed/actions/workflows/docker-build.yml)

Fastbed is a from-scratch C port of Facebed: a Facebook embed provider for
Discord and other unfurl clients. The project targets behavioral compatibility
with the pinned Python service while making parsing and concurrent serving
substantially faster.

Status: the behavioral C port is implemented and the amd64 build is a
production candidate. The current curl 8.23 HTTP/2-only candidate replayed all
**10,659/10,659**
oracle rows with exact bodies, statuses, stable headers, and upstream request
traces; it introduced no fixture gap or archive-integrity error. See
[`docs/FAILURE_MODEL.md`](docs/FAILURE_MODEL.md),
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md), and the retained evidence
inventory in [`docs/VERIFICATION.md`](docs/VERIFICATION.md).

The amd64 image also passed the fail-closed SBOM/VEX/relink gate and a 48-check
locked-down embedded-resource container E2E. The source and container are
public, but Fastbed has no owner-selected project license. Publication grants
no unstated reuse rights, and the evidence records the license as
`NOASSERTION`. Arm64 remains a separate, uncertified target until its native
image, SBOM, runtime, and fingerprint gates run on arm64 hardware. Do not
publish an arm64 tag from the amd64 evidence.

The embedded crawler database passed all 3,721 contract cases in the optimized
build and under ASan/UBSan/LSan, with no sanitizer finding.

The final scratch image also passed bounded live photo, reel, and permalink
canaries through Facebook DNS, certificate validation, browser impersonation,
and parsing with zero recorded errors.

The verification strategy is process-level and artifact-producing. The retired
10,659-row corpus is replayed from its frozen Python-oracle request traces and
the canonical content-addressed zstd upstream archive without external network
access, then separate bounded live and deployment checks run.
The canonical replay command and artifact contract are documented in
[`e2e/ARCHIVE_CORPUS_E2E.md`](e2e/ARCHIVE_CORPUS_E2E.md).

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) maps request flow, concurrency,
  ownership, and trust boundaries.
- [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) defines the public contract.
- [`docs/VERIFICATION.md`](docs/VERIFICATION.md) lists the E2E gates and retained
  amd64 evidence.
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) covers hardening and shutdown.
- [`docs/TOOLCHAIN.md`](docs/TOOLCHAIN.md) covers native, sanitizer, PGO, BOLT,
  and portable builds.
- [`docs/SUPPLY_CHAIN.md`](docs/SUPPLY_CHAIN.md) covers SBOM, VEX, source offers,
  and relinking.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) records code and evidence rules.

## Container package

Every push to `main` builds, publishes, and smoke-tests the amd64 image at
`ghcr.io/facebed/fastbed`. The moving tags are `main` and `latest`:

```sh
docker pull ghcr.io/facebed/fastbed:latest
docker run --rm \
  --user 65532:65532 \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --ulimit core=0:0 \
  --stop-timeout 90 \
  -p 9812:9812 \
  ghcr.io/facebed/fastbed:latest
```

Arm64 remains unpublished until the native runtime, fingerprint, container, and
SBOM gates pass on arm64 hardware.

The amd64 package requires an x86-64-v3 CPU. Its 9.8 MB scratch filesystem
contains a static-PIE Fastbed binary, the CA trust bundle, licenses, source
offers, and build receipts—no shell, package database, ELF interpreter, or
shared library.

## Measured service comparison

The final quiet-host comparison ran five randomized paired blocks for three
medium-hard 16-row scenarios. All 3,840 measured responses and 2,560 warm-up
responses matched their pinned status and body SHA-256; there were no status,
hash, protocol, transport, or timeout failures. These figures are the retained
pre-embedding portable baseline, whose tested binary had SHA-256
`15395b0a30f7bda245131c9e940274ac4f5117bc236f56998e6baf676dc856ef`.

- Uncached: median 143.67 requests/s versus Facebed's 3.391 requests/s
  (**42.11x**); median p99 was 147.17 ms versus 37.481 s.
- Opt-in internal cache: median 37,897 requests/s versus 3.381 requests/s
  (**11,208x**); median p99 was 0.528 ms versus 37.625 s.
- Open-loop baseline saturation at a fixed 5 requests/s: Fastbed median p99
  was 0.382 ms versus 4.473 s. This schedule saturates the Facebed baseline;
  it is intentionally not a Fastbed maximum-throughput claim.
- Median server RSS was 43.59 MiB versus 98.30 MiB uncached, 33.17 MiB versus
  99.63 MiB warm, and 30.52 MiB versus 98.72 MiB under the fixed-rate run.

The original checkout retains the raw records, process samples, broker bundle,
randomized schedule, analysis, manifest, and checksum closure under
`artifacts/facebed-fastbed-service-final-20261018-06`.

Production hardening, container limits, and the bounded shutdown contract are
documented in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Cache policy

Fastbed does not keep a cross-request post cache by default. Every crawler
request performs its own upstream fetch and parse unless the process is started
with `--internal-cache`. The flag enables the bounded 4,096-entry, 64 MiB,
900-second success cache and duplicate-request singleflight. Fallbacks and dump
responses remain uncached. The former `--disable-success-cache` option is
removed and rejected.

The sealed cache-policy matrix ran two randomized real-process blocks per mode
over 16 medium-hard rows. All 512 responses were exact: default mode made one
upstream call per request, while `--internal-cache` reduced each distinct target
to one upstream call per broker generation. The exact artifact is recorded in
[`docs/VERIFICATION.md`](docs/VERIFICATION.md).

## Native build dependency boundary

Production builds require two verified native prefixes:

```sh
tools/build-static-deps.sh /absolute/path/static-deps amd64
tools/build-curl-impersonate.sh /absolute/path/curl-impersonate amd64

FASTBED_STATIC_DEPS_ROOT=/absolute/path/static-deps \
FASTBED_CURL_IMPERSONATE_ROOT=/absolute/path/curl-impersonate \
./build.sh

./build/fastbed
```

With the verified local evidence tree present, `./build.sh` defaults to
`artifacts/static-deps-amd64-20261018-02-prefix` and
`artifacts/curl823-production-amd64-20261018-06-prefix`. Set the two variables
shown above only to use different verified prefixes.

The executable statically embeds curl-impersonate and its HTTP/TLS/compression
closure, yyjson, GNU libmicrohttpd, and libyaml. CMake inspects the completed
ELF and fails if those libraries appear in `DT_NEEDED` or their required
compiled-in symbols are absent. The host-native build retains libc, libstdc++,
libgcc, and PCRE2 as system dependencies; the scratch package statically links
those as well and has no interpreter or `DT_NEEDED`. Dynamic system libcurl is
available only through the explicit non-production CMake option
`FASTBED_ALLOW_DYNAMIC_SYSTEM_CURL=ON`.

`build.sh` accepts no mode arguments. It produces a host-native, full-LTO,
lld-linked release binary with embedded assets and crawler data; the old
`build.sh --run` path is removed. Offline replay and file overrides require a
separate CMake build with `FASTBED_VERIFICATION_BUILD=ON`. Release builds omit
`--assets`, `--crawler-db`, `--allow-stock-curl`, and both replay-port options
from their CLI and compiled string surface.

The current host-native binary has SHA-256
`a244404a4845f819eeb3d418566e70e717ed710e2a6e352921bf10afa207afc3`.
The stripped static-PIE binary in the scratch package has SHA-256
`bf9f96b2c6e0937871ec21e8de8ea9a264fd878a4fd1ed6775be2ef79447a83b`.
The sealed CLI and linkage E2E also proves that a deliberately dynamic-curl
diagnostic build is rejected by the production linkage verifier; see
[`docs/VERIFICATION.md`](docs/VERIFICATION.md).

## Worker sizing

Without `--workers`, Fastbed uses the logical CPUs allowed by
`sched_getaffinity()`, capped at 256. On cgroup v2 it also walks the current
cgroup and its mounted ancestors and applies the tightest finite `cpu.max` as a
ceiling, rounding a fractional CPU quota up so usable partial capacity is not
discarded. `max` is unlimited. Missing or malformed cgroup data is ignored; if
the affinity cannot be read safely, the conservative default is one worker.
Fastbed does not infer an SMT ratio. An explicit `--workers N` (1 through 256)
always overrides auto-sizing.

`--request-timeout-seconds N` sets the total request deadline from 1 through
86,400 seconds (default 3,600). `--graceful-shutdown-seconds N` sets the
SIGINT/SIGTERM drain window from 1 through 30 seconds (default 30); after that
window Fastbed cooperatively cancels queued, transport, parser, and renderer
work before entering the forced cleanup phase.


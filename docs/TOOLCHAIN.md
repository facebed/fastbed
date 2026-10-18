# Toolchain optimization contract

Toolchain variants are release candidates, not correctness shortcuts. The
portable full-LTO build remains the control. A candidate is promotable only
after it produces the same process-level outputs and request traces as the
sealed corpus baseline and then wins a representative holdout benchmark.

## Clang profile-guided builds

`FASTBED_PGO_GENERATE=ON` now defaults to Clang IR instrumentation
(`-fprofile-generate`). Clang documents IR PGO as the performance-oriented
instrumentation mode; `FRONTEND` remains available only for coverage-oriented
compatibility. Counter updates default to `ATOMIC` because training exercises a
multithreaded server. The production binary contains no update instrumentation.

The supported generation modes are:

- `IR`: first-pass IR instrumentation;
- `CSIR`: post-inline context-sensitive instrumentation, consuming the IR
  profile named by `FASTBED_PGO_USE`;
- `FRONTEND`: explicit legacy `-fprofile-instr-generate` mode.

Use the artifact-producing wrapper instead of assembling flags manually:

```sh
tools/build-pgo.sh OUTPUT CURL_ARCHIVE -- TRAINER [ARGS...]
tools/build-pgo.sh --csir OUTPUT CURL_ARCHIVE -- TRAINER [ARGS...]
```

The trainer must execute `FASTBED_PROFILE_BINARY` and exit cleanly. In CSIR
mode it is called twice, with `FASTBED_PROFILE_PHASE=ir` and then `csir`; its
own artifact paths therefore need to include that phase. The training workload
must cover a stratified mix of large posts, comments/replies, reels, shares,
fallbacks, retries, and concurrent requests. A health-check-only or tiny-JSON
trainer is invalid.

`tools/train-pgo-corpus.sh` is the process-level offline trainer for the saved
corpus. It creates one normal E2E artifact under `OUTPUT_ROOT/PHASE` and enters
a fresh network namespace itself:

```sh
tools/build-pgo.sh OUTPUT CURL_ARCHIVE -- \
  tools/train-pgo-corpus.sh CORPUS PYTHON_RESULTS TRAINING_OUTPUT [LINES]
```

An explicit `LINES` selection is suitable for workflow checks only when it is a
medium-hard, stratified set. A production profile needs the broader workload
and a separate concurrent trainer; this sequential differential runner must not
be presented as the concurrency benchmark.

The isolated trainer must fail closed for each of these conditions:

- `unshare`, unprivileged user namespaces, or network namespaces are
  unavailable;
- the new namespace is not distinct from the parent, or it contains an
  interface other than loopback;
- loopback cannot be brought up before the fixture broker starts;
- `ip`, Python, OpenSSL, the broker, or the instrumented binary is unavailable;
- a phase output already exists, including a partial result from a failed run;
- the broker or Fastbed fails its readiness deadline;
- the corpus, Python oracle, saved response, or response hash is missing or
  inconsistent;
- any external network path is reachable from the training namespace;
- the process cannot shut down cleanly and flush its raw profile;
- IR and CSIR phases reuse an output directory or overwrite one another.

Set `FASTBED_TRAINING_MANIFEST` to the trainer's completed manifest, or to the
directory containing both phase artifacts for CSIR. A directory hash covers
each phase's `manifest.json` and `SHA256SUMS`. The wrapper records the resulting
SHA-256 without copying paths, arguments, credentials, or response data into
the build manifest. It also records the source-tree digest, exact
compiler/tool versions, merged profile and summary hashes, curl archive hash,
binary hash, and build ID. A release artifact with
`training_manifest_sha256=unprovided` is incomplete provenance.

The wrapper deliberately checks that Clang and `llvm-profdata` have the same
major version. It creates all stages beneath a new output directory and never
reconfigures `build-pinned`.

The optimized-build log is retained and hashed. Its
`profile_mismatch_warnings` count is also recorded rather than suppressed.
Clang may discard a mismatched function's counts while still producing a valid
binary; that candidate is performance-incomplete until the named functions and
discarded counts are reviewed. Do not hide this warning with
`-Wno-backend-plugin` in a release build.

lld safe ICF remains enabled for the optimized release, but is disabled for
instrumented training binaries. Folding training functions has no production
benefit and can obscure the profile identity that the optimized compile later
consumes.

References:

- <https://clang.llvm.org/docs/UsersManual.html#profiling-with-instrumentation>
- <https://clang.llvm.org/docs/UsersManual.html#cmdoption-fcs-profile-generate>
- <https://clang.llvm.org/docs/ThinLTO.html>

## GCC compatibility

The GCC `-fprofile-generate`/`-fprofile-use` behavior is unchanged. The Clang
mode settings are ignored by GCC. A future GCC artifact wrapper must keep its
instrumented and optimized path mapping stable with `-fprofile-prefix-path`;
the current Clang wrapper must not be relabeled as a tested GCC workflow.

When `FASTBED_BOLT_READY=ON` is combined with GCC, the build adds
`-fno-reorder-blocks-and-partition`, as required by BOLT for GCC 8 and newer.

References:

- <https://gcc.gnu.org/onlinedocs/gcc/Instrumentation-Options.html>
- <https://github.com/llvm/llvm-project/blob/main/bolt/README.md>

## Pinned static server and parser dependencies

Fastbed requires GNU libmicrohttpd 1.0.10 or newer. The asynchronous server
depends on the suspend/resume fixes released in 1.0.10, including the
per-thread inter-thread communication channel fix and the resume assertion
fix. CMake rejects older development packages instead of compiling a server
against the affected lifecycle implementation.

The production container does not consume Alpine's moving libmicrohttpd
package. It builds the architecture-neutral GNU 1.0.10 source release as a
static archive inside each target `amd64` or `arm64` build stage from:

```text
https://ftp.gnu.org/gnu/libmicrohttpd/libmicrohttpd-1.0.10.tar.gz
sha256 04bfe8ef75db7d629a33de767599765cecadc56274a39822d5d081030d577685
```

The container enables production compiler hardening while disabling the shared
library, unused HTTPS backend, and build-only documentation, examples, and
tools. `tools/build-static-deps.sh` also builds pinned libyaml 0.2.5 and PCRE2
10.47 as static archives. PCRE2 enables Unicode and JIT support; its source
archive SHA-256 is
`47fe8c99461250d42f89e6e8fdaeba9da057855d06eb7fc08d9ca03fd08d7bc7`.
All three archives are checksum-closed, inspected after final link, and included
in source/relink evidence. Inbound TLS remains the reverse proxy's
responsibility; this does not affect the separately pinned curl-impersonate
archive or its outbound Facebook TLS/HTTP fingerprint.

References:

- <https://ftp.gnu.org/gnu/libmicrohttpd/>
- <https://git.gnunet.org/gnunet/libmicrohttpd/commit/7922bbd7a9561fc3f8ebd6f5cecdc288dcd4457f.html>
- <https://github.com/PCRE2Project/pcre2/releases/tag/pcre2-10.47>

## BOLT

`FASTBED_BOLT_READY=ON` is restricted to Linux x86-64/AArch64 and requires the
linker to support `--emit-relocs`. `tools/build-bolt.sh` refuses inputs without
both `.symtab` and `.rela.text`, an accepted machine type, or a build ID.

The script uses only the conservative recipe published in LLVM's BOLT README:
instrumentation, `ext-tsp` block ordering, `cdsort` function ordering, and
hot/cold splitting. It records tool identity, input and output build IDs,
profile/input/training provenance, fixed flags, logs, and content hashes.
Set `FASTBED_INPUT_MANIFEST` to the PGO manifest when BOLT consumes a PGO
binary. The optimized binary still requires the complete process-level E2E
gate; successful rewriting is not behavioral verification.

The script does not install BOLT. Missing `llvm-bolt` or `merge-fdata` fails
before it creates the output directory. Linux `perf` branch-stack collection
may later replace instrumentation on a native benchmark host, but only through
a separately reviewed workflow that verifies the perf build ID against the
exact unstripped input.

Reference: <https://github.com/llvm/llvm-project/blob/main/bolt/README.md>

## Patched source-built curl-impersonate

The pinned v1.5.2 Linux archive is a roughly 50 MB, one-member relocatable
archive. Its large monolithic `.text` includes protocols and codecs that
Fastbed does not call, so `--gc-sections` cannot discard most unused functions
at function granularity. It also embeds curl 8.15.0, which is affected by
CVE-2026-92392. The prebuilt archive is therefore an offline/control input,
not a production dependency.

The production dependency starts from the signed official curl 8.23.0 release
archive and applies the reviewed browser delta derived from curl-impersonate
v1.5.2 commit `9607b22ccf6c440e560c5f8ad5292b8044bb6dd7`. It pins BoringSSL revision
`673e61fc215b178a90c0e67858bbf162c8158993`, nghttp2 1.68.1, Brotli 1.2.0,
zlib 1.3.2, Zstandard 1.5.7, libidn2 2.3.8, and libunistring 1.4.2. Fetches,
publisher signature/checksum files, and patches are content-addressed.

`tools/build-curl-impersonate.sh` is the production builder. It verifies every
source and patch before use, applies patches with zero fuzz, checks selected
post-patch source hashes, and builds ordinary function/data-section static
archives on the target architecture. It stages matching headers and all
required notices, then emits a component manifest, compiler flags, exact
archive hashes, the direct impersonation-API result, and a complete prefix
`SHA256SUMS`. The Docker build uses this prefix through
`FASTBED_CURL_IMPERSONATE_ROOT`; `FASTBED_CURL_IMPERSONATE_ARCHIVE` remains an
explicit vulnerable control.

Each architecture builds at the exclusive deterministic work root
`/tmp/fastbed-curl-impersonate-ARCH`. This prevents random configure prefixes
from entering static archives and makes concurrent same-architecture builds
fail instead of racing. Failed builds normally remove that work tree. Set
`FASTBED_CURL_KEEP_WORK=1` only for diagnosis; the builder then prints and
retains the exact directory, including per-component logs and generated
configuration. Remove that explicitly retained directory before retrying. A
retained work tree is debugging evidence, not a releasable prefix. Successful
release inputs remain the checksum-closed prefix and source-archive output
directories.

The Docker build keeps release material separate from the runtime image. The
`release-artifacts` target exports verified upstream source archives, a
deterministic LGPL relink bundle containing the application objects and exact
link recipe, and detached Fastbed/libmicrohttpd debug files bound by build ID
and SHA-256. The runtime carries licenses, small source pointers, build
manifests, and `.gnu_debuglink` records, but no source tarballs, relink objects,
or detached debug payloads.

Security and wire-compatibility evidence are kept distinct:

- curl 8.23.0 is newer than the curl releases affected by CVE-2026-92392;
- nghttp2 1.68.1 contains the CVE-2026-27135 fix. The local compatibility patch
  changes only outbound RFC 7540 priority serialization; the fixed
  `nghttp2_session.c` remains byte-identical to the official release;
- the v1.5.2 BoringSSL revision receives both prerequisite commit
  `5386d908a663a424d154cbae7f76f2266c60c2fe` and CVE-2026-35189 fix commit
  `9b639f5b3b086508c03f6a4a1792e4a6043777ac` in the combined patch whose
  SHA-256 is
  `2c9277a0576c6ed943386490c1ed53ba2e5b8ccef2f1ec4c0c326e4e2177c2dd`;
- nghttp3 and ngtcp2 are absent, so their code and advisories are outside the
  production binary rather than configuration-only mitigations.

The production source build retains BoringSSL, HTTP/2, ECH, HTTPS RR, IDN,
IPv6, proxy, cookies, MIME, gzip/deflate, Brotli, and Zstandard. Only `http` and
`https` protocols are present. HTTP/3/QUIC, unrelated URL protocols, DoH,
Unix-socket, WebSocket, and runtime-option enumeration surfaces are disabled.
The builder and CMake both reject an HTTP/3 archive or manifest. This H2-only
boundary requires all of these gates:

1. it exports the required libcurl and `curl_easy_impersonate` APIs and accepts
   the exact `chrome146` preset;
2. HTTPS, HTTP/2, redirect handling, DNS, CA verification, gzip/deflate,
   Brotli, and Zstandard remain enabled while HTTP/3 stays absent;
3. the 10,659-row offline differential remains exact, with fixture gaps and
   network attempts reported separately;
4. anonymous redirect-hop handling and bounded live Facebook requests remain
   accepted;
5. a live fingerprint service confirms the same TLS/JA3/JA4 and HTTP/2 settings
   as the pinned release;
6. the candidate wins the holdout benchmark, and its source/dependency/build
   manifests are sealed with the binary and container digests.

The final independently reproduced amd64 prefix has `SHA256SUMS` SHA-256
`9783e167b83993fc6ab8a8d25ce11a0d31150dfd0839accb1ce1efd096b93fd4`
and prefix aggregate
`b2640cb189a0331b4c378681ad10b7133ce0cac900e98c7427156c2fa5fa0750`.
Those digests are evidence for one exact toolchain build, not portable expected
hashes for arm64 or future compiler revisions. Every production build records
its own per-architecture archive and binary hashes in the generated manifest.

A bounded live comparison against the verified v1.5.2 control produced the
same normalized Chrome 146 JA4/JA4_r, peetprint, HTTP/2 settings/window update,
pseudo-header order, header order, and priority. Raw JA3 changes between
requests because this profile intentionally permutes TLS extensions; compare
the normalized fingerprint instead. The upstream v1.5.2 signature fixtures
stop at Chrome 142, so the live Chrome 146 gate cannot be replaced by upstream
`make check`.

The amd64 full offline differential, bounded Facebook acceptance,
final-BoringSSL fingerprint replay, container/SBOM gate, and representative
performance holdout have passed. Native arm64 build/runtime/fingerprint/SBOM
evidence remains outstanding. The builder refuses an amd64/arm64 host mismatch;
BuildKit emulation may establish structural and behavioral evidence but is not
native performance evidence.

References:

- <https://github.com/lexiforest/curl-impersonate/releases/tag/v1.5.2>
- <https://github.com/lexiforest/curl_cffi/blob/main/docs/dev.rst>
- <https://curl.se/docs/install.html>

## Scratch container and architecture rules

The published amd64 image is an explicitly constrained x86-64-v3 package, not
a baseline x86-64 image. Its production binary is static PIE and enables `-O3`,
full LTO, lld's LTO-O3 pass, safe identical-code folding, section garbage
collection, fortify, stack protection, and a GNU build ID. The post-link gate
requires no `PT_INTERP` and no `DT_NEEDED` before the binary can enter the
scratch runtime.

The final filesystem contains the binary, CA bundle, licenses, exact source
offers, embedded-resource manifest, runtime provenance, and build receipt. It
does not contain a shell, package database, loader, or shared library. The CA
bundle is SHA-bound to the scratch runtime manifest. External orchestration
probes `/healthz`; adding an in-image health client would weaken this boundary.

PGO and BOLT remain architecture- and workload-specific rather than generic
switches. They must be trained on a representative native workload and checked
against a disjoint holdout, so the hosted package build does not fabricate a
profile or train under QEMU. Docker documents emulation as substantially slower
for compilation and compression, and emulation does not provide representative
PMU or branch-history data.

The arm64 profile must be independently trained and certified on arm64
hardware; neither PGO nor BOLT data is portable across architectures. The GHCR
manifest stays amd64-only until that work is complete.

References:

- <https://docs.docker.com/build/building/multi-platform/>
- <https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html>

## Measurement protocol

Build one factor at a time before testing combinations:

1. portable full LTO control;
2. IR PGO plus full LTO;
3. CSIR PGO plus full LTO;
4. winning PGO build plus BOLT;
5. separately labeled x86-64-v3/native builds;
6. allocator or dependency experiments only after the preceding results.

Use a stratified training set and a disjoint medium-hard performance holdout.
Run the complete correctness corpus on every candidate. On a quiet native host,
pin the server and load generator to disjoint physical cores, record SMT,
governor/turbo, microcode, kernel, mitigations, temperatures, and container
digest, and randomize paired candidate/control order.

Collect at least wall time, throughput, p50/p95/p99 latency, CPU time, maximum
RSS, and allocation totals. Run PMU groups separately to avoid multiplexing:

- cycles, instructions, branches, branch misses;
- L1 data-cache and LLC loads/misses;
- iTLB and dTLB loads/misses;
- task clock, context switches, migrations, and page faults.

Persist perf's event runtime and percentage-running fields and reject heavily
multiplexed samples. Save raw per-run JSON/JSONL, profile and binary hashes,
the exact workload manifest, environment metadata, and `SHA256SUMS`. The Linux
perf tooling supports repeated runs, JSON output, and percentage-running data.

Reference: <https://man7.org/linux/man-pages/man1/perf-stat.1.html>

## Rejected defaults

The following are not enabled:

- `-ffast-math`, unsafe overreads, or relaxed aliasing: observable and security
  semantics take priority;
- lld `--icf=all` or constant merging: address identity can be observable;
- ThinLTO as the release default: it primarily reduces build cost here, while
  full LTO is affordable for Fastbed's small source set;
- `-fsplit-machine-functions` in a BOLT build: both transform hot/cold layout;
  test it only as a non-BOLT alternative;
- Propeller, aggressive BOLT inlining/ICF/jump-table flags, JCC padding, or
  temporal startup ordering: no Fastbed PMU evidence currently justifies the
  extra profile/toolchain surface;
- transparent/explicit huge pages: Fastbed has no measured TLB bottleneck or
  long-lived aligned allocation large enough to justify the deployment and RSS
  risk;
- `target_clones`/IFUNC dispatch in the Alpine image: musl intentionally does
  not support GNU IFUNC; use separate ISA artifacts or explicit portable
  function-pointer dispatch if profiling later justifies source changes;
- allocator replacement by default: request arenas already remove much of the
  allocation traffic, so jemalloc remains an RSS/throughput A/B experiment;
- DT_RELR packing on arm64: the pinned arm64 musl runtime still needs a native
  startup/loader proof. The amd64 Alpine image enables it only behind its
  architecture gate and must pass the normal runtime smoke before release.

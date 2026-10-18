# Fastbed performance artifact harness

This directory contains an independent HTTP load generator and a release-matrix
runner. It is intentionally outside the production build: benchmark code cannot
change the server being measured.

The generator is a single-threaded C17 epoll client. It supports closed-loop
and fixed-rate open-loop arrival schedules, persistent HTTP/1.1 connections,
graceful per-request FIN, immediate post-send RST, and repeated numeric source
address binds. It parses Content-Length, chunked, and close-delimited responses,
streams decoded body bytes through SHA-256, and accepts only workload-pinned
(status, digest) pairs. Every request produces an unaggregated
CLOCK_MONOTONIC_RAW record.

The matrix runner:

- requires the control, current, native, ir-pgo, bolt, and allocator variants;
- requires cold, nocache, warm, singleflight, slow, and queue scenarios;
- starts a fresh server for every (block, scenario, variant) observation;
- randomizes variant order independently inside seeded paired blocks;
- pins server and client to disjoint CPU sets before exec;
- fails a quiet-host gate and refuses moving source or binary inputs;
- optionally places server/client processes in delegated cgroup v2 children;
- samples /proc RSS, HWM, faults, CPU ticks, I/O, thread count, affinity, and
  voluntary/involuntary context switches;
- retains raw records, process/sidecar logs, controller hooks, schedule, hashes,
  build IDs, cgroup counters, host state, analysis, manifest, and SHA256SUMS.

The default `release-matrix` profile keeps those six variants and six scenario
kinds mandatory. The separate `service-compare` profile allows heterogeneous
HTTP services while retaining the same randomized blocks, byte verification,
affinity, host gate, resource sampling and artifact seal. It requires an
explicit baseline, required scenario kinds, per-variant launch commands and
immutable non-binary inputs. Omitting `profile` preserves the strict release
matrix behavior.

Read [FAILURE_MODEL.md](FAILURE_MODEL.md) before interpreting the numbers.

## Process-level self-test

The self-test compiles the generator, starts a real HTTP/1.1 process, and checks
a medium-sized mix of Content-Length and adversarially split chunked responses.
It exercises closed/open scheduling, keep-alive, FIN, RST, 127/8 source bind,
and a deliberately wrong digest that must fail closed.

    python3 benchmark/run_selftest.py \
      --output /tmp/fastbed-loadgen-selftest-20261017
    (cd /tmp/fastbed-loadgen-selftest-20261017 && sha256sum -c SHA256SUMS)

This is a functional E2E, not a release performance run.

## Workload format

UTF-8 TSV, one request target per row:

    # fastbed-http-workload-v1
    /some/path?query=1    200:0123...cdef    label
    /queue/path    200:aaaa...aaaa,503:bbbb...bbbb    queue-success-or-overload

The second field is one to eight comma-separated STATUS:SHA256 alternatives.
The queue form is how expected overload responses remain correctness checked.
Blank lines and # comments are ignored.

Generate workloads from the pinned Python oracle rather than hand-copying a
digest:

    python3 benchmark/prepare_workload.py \
      artifacts/python-oracle-full-20261016/results.jsonl \
      /tmp/medium-hard.tsv \
      --lines 521,7784,9222,9878

For a queue workload, add the exact overload body:

    python3 benchmark/prepare_workload.py ORACLE.jsonl /tmp/queue.tsv \
      --lines 521 --allow-response 503:/path/to/exact-overload-body.html

The companion workload manifest verifies every oracle output before writing.
Use multiple large/Unicode/video/parser-heavy rows for ordinary throughput; use
one such row for the singleflight race.

## Release matrix plan

Copy [plan.example.json](plan.example.json), replace every /ABS/... value, and
keep secrets out of it. Sensitive environment keys must use $ENV:NAME; the
artifact records only the template. The allocator variant normally points at
the same binary as current and sets LD_PRELOAD to a reviewed allocator.

Control means the pinned pre-optimization C binary, not an in-process mock.
Current, native, IR-PGO, and BOLT binaries must all implement the same server
CLI. Input hashes and ELF build IDs are captured. The runner checks their hashes
again throughout the matrix.

Plans that use loopback replay ports must point at binaries built with
`FASTBED_VERIFICATION_BUILD=ON`. Production/native release binaries omit those
arguments entirely; do not weaken the release build just to run a benchmark.

Cold is a fresh Fastbed process with `--internal-cache` and an empty cache. It
is not a cold kernel page cache. Nocache uses Fastbed's default uncached mode.
Warm runs a retained,
hash-verified warm-up. Singleflight starts cold with one target. Slow and queue
require explicit broker-controller hooks; broker reports remain the authority
for gate delay, arrival counts, and deduplication.

Run the plan check before reserving the host:

    python3 benchmark/run_matrix.py /path/to/plan.json \
      --output /tmp/not-created --check-plan

For a release run, enter a loopback-only user/network namespace, bring up lo,
ensure the source tree is frozen, stop unrelated CPU-heavy jobs, and use a new
artifact directory:

    unshare --user --map-root-user --net sh -c '
      ip link set lo up
      exec python3 benchmark/run_matrix.py /path/to/plan.json \
        --output /evidence/fastbed-benchmark-20261017
    '

The runner defaults to requiring exactly the loopback interface. It compiles
the client first, then waits through the quiet-host sample. A busy host, source
edit, binary replacement, response mismatch, process crash, controller failure,
or required-cgroup failure seals a failed artifact instead of producing a
performance claim.

Verify any completed artifact:

    (cd /evidence/fastbed-benchmark-20261017 && sha256sum -c SHA256SUMS)

analysis.json reports descriptive per-block medians/ranges and paired ratios to
control. Use latency.records.tsv, process_samples.jsonl, cgroup counters, and the
randomized schedule for conclusions; do not select only the fastest run.

## Facebed versus Fastbed

[service_compare.example.json](service_compare.example.json) is the template
for a fair process-level comparison. Facebed and Fastbed receive the same
request schedule from `http_loadgen`, run on the same server CPU set, and send
their upstream requests over real loopback HTTP/TLS to one broker on a disjoint
CPU set. Facebed still runs its shipped Bottle entry point; the benchmark
launcher changes only curl's physical peer and restores the saved logical final
URL. Fastbed uses its verification-only replay ports. Every public response is
accepted only when its status and SHA-256 match the pinned workload.

The old `fulltest/corpus` tree has been retired. `archive_broker.py` consumes the
retained Python oracle rows and the canonical `fulltest/upstream_archive`
Zstandard objects. It deliberately accepts only medium-hard rows with one
successful GET and no redirect, retry, fixture miss, transport error, or reused
response. Before readiness it verifies and decompresses every selected body,
copies the exact compressed objects, certificate, key, workload and selected
oracle records into the output artifact, and then serves immutable memory. The
per-run reset/assert hooks fail on a missing endpoint, malformed logical URL,
write failure, active request or zero upstream traffic.

Create the mixed workload from the preserved oracle outputs. Use several large,
Unicode and video/parser-heavy rows; the four rows below are a bounded smoke
selection, not the final release selection:

    python3 benchmark/prepare_workload.py \
      artifacts/python-oracle-full-20261016/results.jsonl \
      /evidence-inputs/medium-hard.tsv \
      --lines 521,7784,9222,9878

Generate a dedicated self-signed fixture certificate, write notifier-free
Facebed/Fastbed configs on the benchmark port, copy the service-comparison plan,
and replace every `/ABS/` placeholder. Validate without starting anything:

    python3 benchmark/run_matrix.py /evidence-inputs/service-compare.json \
      --output /tmp/not-created --check-plan

Run it under the same loopback-only namespace used by the release matrix:

    unshare --user --map-root-user --net sh -c '
      ip link set lo up
      exec python3 benchmark/run_matrix.py \
        /evidence-inputs/service-compare.json \
        --output /evidence/facebed-fastbed-service-compare-20261018
    '

The `nocache` scenario uses Fastbed's default no-cache policy; this measures
repeated parse/transport work. The `warm` and `saturation` scenarios apply
`--internal-cache` only to Fastbed through `kind_args`. The open-loop
`saturation` scenario retains scheduled arrival and client queue delay. Report
those as separate results. `analysis.json` names the explicit baseline and
contains paired per-block ratios; process samples include the persistent broker
so a saturated sidecar is visible rather than silently attributed to a server.
The saturation workload must add the exact Fastbed overload body as an allowed
`503` outcome and must spread concurrency above the per-IP admission limit over
explicit `127/8` source addresses. This preserves byte verification while
measuring admitted successes plus intentional overloads, instead of treating
connection-limit resets or valid backpressure as service corruption.
It also uses a separately recorded closed-loop prewarm so the measured open
burst exercises steady-state admission capacity rather than the variants'
different first-fill stampede behavior.
The example's 5 request/second open schedule is a baseline-saturation test: it
is above current Facebed service capacity while remaining far below Fastbed's
ceiling. It is not a Fastbed maximum-throughput claim.

The preserved oracle currently pins a historical Facebed source. That is safe
only as a fail-closed expected-output set: both current services must still
produce every pinned body. A mismatch invalidates the run and must be resolved
as behavior drift before publishing performance numbers.

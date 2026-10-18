# Benchmark failure model

This harness treats performance numbers as evidence only when the load, response
bytes, process lifecycle, and host conditions are all recorded and verified.
It intentionally does not share code with Fastbed.

## Load generation

- A closed-loop test can hide queueing delay by issuing the next request only
  after the previous response. An open-loop test therefore records the intended
  arrival time separately from the actual socket start time. Both schedules are
  retained as raw records; neither is presented as the other.
- An overloaded open-loop client can become the bottleneck. The generator keeps
  every scheduled arrival, records its client-side queue delay and maximum
  pending depth, and never silently drops an arrival.
- Wall-clock adjustment can corrupt latency. All scheduling and timestamps use
  `CLOCK_MONOTONIC_RAW`; UTC is metadata only.
- The load generator can perturb the server through CPU contention, allocation,
  logging, or hashing. Client and server CPU sets must be disjoint. Raw body
  hashes are streamed and latency records are buffered until the run ends.
- Reusing one request order can favor a variant. A seeded schedule fixes the
  request sequence, while each paired block independently randomizes variant
  order. Every variant in a block receives the same scenario and workload.
- Client connection behavior changes server cost. Keep-alive, a graceful FIN
  per response, and an immediate post-send RST are distinct modes. RST records
  are explicitly unverified fire-and-abort operations and cannot contribute to
  response throughput or latency claims.
- Source-address binding can fail, bind the wrong family, or be optimized away.
  Each new socket binds one requested numeric source address before connect;
  bind failure fails that request and the selected source index is retained.
- A one-address saturation run can hit a service's per-IP admission limit before
  it saturates parser or cache throughput. When concurrency exceeds that limit,
  the plan must distribute sockets across explicit loopback source addresses;
  transport resets are failures, not overload throughput samples.

## HTTP and byte verification

- TCP reads do not preserve HTTP boundaries. The generator incrementally parses
  headers, Content-Length bodies, chunked bodies and connection-close bodies.
- A truncated response, invalid status line, conflicting framing, oversized
  header/body, malformed chunk, unexpected bytes after a framed body, timeout,
  reset, or early EOF is a protocol/transport failure, never a latency sample.
- Status alone is not correctness. Every complete body is hashed incrementally
  with SHA-256 and must match an allowed `(status, digest)` pair from the pinned
  workload. Queue scenarios may deliberately allow both the exact success body
  and the exact overload body.
- Persistent sockets can be closed between requests. Idle HUP/EOF discards the
  connection; the next request reconnects. A reused connection is identified in
  each raw record so connect time is never fabricated.
- RST is issued with `SO_LINGER {1,0}` only after the complete request bytes are
  accepted by the local kernel. Such a record has no response digest and is
  excluded from correctness claims.

## Server and scenario isolation

- Every measured `(block, scenario, variant)` starts a new Fastbed process. A
  cold run therefore means a cold process and empty Fastbed cache, not a claim
  that the kernel page cache or storage device is cold.
- `nocache` relies on Fastbed's default no-internal-cache policy; it does not
  mutate global kernel caches. Cache scenarios pass `--internal-cache`
  explicitly. The harness never writes `/proc/sys/vm/drop_caches`.
- `warm` performs a recorded, hash-verified warm-up against the same process
  before measurement. Warm-up records are retained but excluded from results.
- A cold open-loop saturation burst can measure initial cache-fill stampedes
  instead of steady-state admission capacity, especially when variants have
  different singleflight behavior. A saturation plan may request an explicit
  hash-verified closed-loop prewarm; its mode, concurrency, records, and summary
  must be retained separately from the measured open-loop phase.
- One paired offered rate cannot simultaneously saturate services whose
  capacities differ by orders of magnitude while also requiring every request
  to complete correctly. A bounded common-rate scenario must name which
  baseline it saturates and must not be presented as the faster variant's
  maximum throughput.
- `singleflight` requires one workload target and concurrent scheduled arrivals
  against a new process. Upstream deduplication still needs separate broker
  evidence; throughput alone cannot prove singleflight.
- `slow` and `queue` require explicit controller hooks in the benchmark plan.
  Hooks are argv arrays, not shell fragments, and their output/exit status is
  retained. The fixture broker remains the authority for delay, gate and
  upstream-request-count assertions.
- A readiness response can warm unrelated code. Only `/healthz` should be used
  for readiness. It is recorded and occurs before any measured or warm-up load.
- A crashed, hung, leaked, or force-killed server invalidates the run even when
  the client completed. Process-group termination and exact exit status are
  retained.

## Variant and host comparability

- Variant labels do not prove build identity. Every executable, workload,
  benchmark source and plan is content-hashed; ELF build IDs are recorded when
  present. Allocator variants record their non-secret environment template.
- Source movement during a matrix can compare different programs. A deterministic
  source-tree digest is checked before and after every measured run. A changed or
  unstable file aborts and seals the partial artifact.
- CPU affinity alone does not prevent noisy neighbors, throttling, thermal
  changes, frequency changes, NUMA migration, or IRQ work. The runner fails its
  initial quiet-host gate, records affinity/cgroup/topology/governor/turbo data,
  samples `/proc`, and retains cgroup counters when a delegated cgroup is
  available. Those records bound a claim; they do not make a shared host a lab.
- A missing or unwritable cgroup is explicit. Plans may require cgroup isolation,
  in which case absence is fatal; otherwise the artifact says it was unavailable.
- `taskset` is a pre-exec wrapper. Reading `/proc/PID/status` immediately after
  `Popen` can observe the wrapper's inherited affinity before it applies the
  requested mask, producing a false mismatch. Affinity proof must poll the same
  PID/start-time identity until the exact mask appears, the process exits, or a
  short bounded deadline expires; it must never accept a different mask.
- PID reuse or `/proc` disappearance can corrupt resource samples. Samples carry
  the process start tick and stop when it changes or the process exits.
- A fast client can finish before the first periodic sampling interval. The
  affinity-verified synchronous snapshot must seed the raw process-sample
  stream; absence of both that snapshot and periodic rows remains fatal.
- RSS is sampled and may miss a short spike. `VmHWM` and cgroup `memory.peak` are
  retained when the kernel exposes them. Context-switch deltas are taken from
  monotonically increasing process counters and never inferred from sample count.
- Turbo, ASLR, allocator state and page-cache state introduce variance. Results
  are paired across multiple randomized blocks and reported per block; a single
  best run is never selected.

## Facebed versus Fastbed service comparison

- A historical Python oracle is not proof of current Facebed behavior. A
  service-comparison workload is accepted only when every measured response
  still matches the pinned status and body digest. The artifact records the
  current Facebed source, interpreter, launcher and dependency inputs; a stale
  oracle therefore fails the run instead of silently becoming the definition
  of current behavior.
- Comparing Fastbed through a loopback fixture broker with Facebed through an
  in-process fixture object would measure different systems. Both services must
  traverse their real public HTTP server and a real loopback HTTP/TLS upstream.
  The Facebed launcher may change only how curl reaches that isolated broker;
  logical URLs, response bytes, recorded final URLs and production parsing stay
  unchanged.
- The retired gzip corpus cannot be reconstructed by guessing from filenames.
  The archive broker selects rows from a hash-pinned oracle, loads the matching
  content-addressed Zstandard object, verifies compressed and uncompressed
  hashes and sizes, and refuses ambiguous request mappings. Selected rows with
  retries, redirects, transport errors or multiple upstream operations are not
  eligible for the stateless mixed-workload broker.
- A replay broker can become the throughput bottleneck or favor one runtime.
  Selected response bodies are verified and decompressed before readiness, then
  served from immutable memory by the same broker on CPUs disjoint from both
  servers and the load generator. Per-run broker counters must show no miss,
  malformed logical URL, integrity error or write failure. Resource samples and
  open-loop queue delay still bound any throughput claim.
- Facebed and Fastbed do not share a command line, working directory, shutdown
  code or cache switch. Service-comparison plans use explicit per-variant server
  commands, input files, expected exits and per-scenario arguments. Falling
  back to the release matrix's shared Fastbed command is a plan error.
- "Cold", "uncached" and "warm" answer different questions. A cold process can
  populate a cache during the measurement. An uncached comparison disables the
  Fastbed success cache with variant-specific arguments while leaving Facebed's
  production behavior intact. A warm production comparison deliberately
  includes each implementation's shipped caching behavior. Results from those
  scenarios must not be merged into one speedup claim.
- Equal CPU affinity is a resource budget, not evidence that both programs use
  the same number of threads. Facebed's shipped Bottle server and Fastbed's
  worker pool remain part of the service comparison. Any alternative Python
  WSGI server is a separate product/configuration and needs a separately named
  variant.
- Hashing only the Python executable would omit the program being measured.
  Every service variant declares additional immutable input files. The runner
  snapshots and rechecks them before each observation and includes their hashes
  in the final manifest. Python package versions and the Facebed source revision
  remain required interpretation metadata even when the interpreter binary is
  unchanged.

## Artifact integrity and safety

- Output directories are new-only. Commands, raw records, summaries, logs,
  samples, hooks, schedule, input hashes, failure details and a manifest are
  written before a sorted `SHA256SUMS` inventory seals the artifact.
- A failed run is preserved and sealed. Partial evidence is not deleted or
  relabeled as a pass.
- Environment values whose names look secret are never accepted literally in a
  plan. External secret references remain redacted. Benchmark configs should use
  an empty notifier URL and an isolated loopback-only fixture broker.
- The runner refuses a release matrix while the quiet-host gate fails. Syntax
  checks and the bounded loopback self-test are not release measurements.


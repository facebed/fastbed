# Deployment

Fastbed fails closed on Linux unless it can set both the soft and hard
`RLIMIT_CORE` values to zero and set `PR_SET_DUMPABLE` to zero. It does this
before loading the configuration or any webhook secret. The process-level
check is still required when the container is started: run Docker with an
explicit zero core limit so the runtime policy agrees with the application
policy.

```sh
docker run --rm \
  --user fastbed:fastbed \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 64 \
  --ulimit core=0:0 \
  --stop-timeout 90 \
  --env FASTBED_HEALTH_PORT=9812 \
  -p 9812:9812 \
  fastbed:latest --workers 16
```

The example fixes the application at 16 workers so its PID budget is
meaningful. The pinned curl build uses a threaded asynchronous resolver, so a
busy process can have approximately one resolver thread per application
worker in addition to the application workers, two HTTP I/O threads, the main
thread, deadline/notifier/watchdog threads, and a health-check process. Size a
deployment's limit as at least `2 * workers + safety margin`; `64` is a
conservative limit for the 16-worker example. Do not reuse `64` with the
maximum 256-worker setting. Measure the chosen workload and leave enough room
for shutdown and health checks without allowing unbounded process creation.

Fastbed has been exercised with a read-only root filesystem, all Linux
capabilities dropped, `no-new-privileges`, and the container runtime's default
seccomp filter. It needs no writable filesystem or capability when listening
on its default unprivileged port. Do not run it with `--privileged`, add
capabilities, or disable seccomp. Mount configuration and secrets read-only.

The image health check reads `FASTBED_HEALTH_PORT`, which defaults to `9812`.
If the YAML configuration changes the listening port, set
`FASTBED_HEALTH_PORT` to exactly the same value; otherwise the healthy service
will correctly run on its configured port while Docker probes the wrong port
and marks the container unhealthy. The health client explicitly disables
proxy use, so injected `http_proxy` settings cannot divert the loopback probe.

Fastbed handles `SIGINT` and `SIGTERM` synchronously. Once either signal is
received, it arms a monotonic 75-second hard watchdog, stops accepting work,
runs the server's graceful and forced phases, joins every server worker, and
then drains the notifier. A normal signal-driven shutdown exits with status
zero. If any part of that sequence is still blocked at 75 seconds, the watchdog
calls `_Exit(124)` for the entire process. It never detaches a worker and then
frees state the worker could still reference.

The request deadline is configurable with `--request-timeout-seconds N`
(1 through 86,400; default 3,600). The graceful drain is configurable with
`--graceful-shutdown-seconds N` (1 through 30; default 30). Keep the graceful
window at or below 30 seconds so the forced server phase and notifier drain
retain headroom inside the independent 75-second watchdog.

Set the supervisor's stop grace strictly above 75 seconds. Ninety seconds is
the recommended minimum; it leaves the application watchdog time to terminate
a stuck process before the supervisor sends `SIGKILL`. For Docker Compose use:

```yaml
services:
  fastbed:
    image: fastbed:latest
    user: fastbed:fastbed
    read_only: true
    cap_drop: ["ALL"]
    security_opt:
      - no-new-privileges:true
    pids_limit: 64
    environment:
      FASTBED_HEALTH_PORT: "9812"
    command: ["--workers", "16"]
    stop_grace_period: 90s
    ulimits:
      core:
        soft: 0
        hard: 0
```

For Kubernetes, set `terminationGracePeriodSeconds: 90` (or higher) in the Pod
specification and keep the container runtime's core limit at zero. Apply this
container security context:

```yaml
securityContext:
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

Use a native HTTP readiness/liveness probe for `/healthz` on the same named or
numeric port as the Fastbed configuration; Kubernetes does not use the image's
Docker health check as a substitute for Pod probes. Enforce a suitably scaled
PID limit through the container runtime or kubelet policy. Do not set a
supervisor timeout equal to 75 seconds: scheduling and signal-delivery latency
would race the internal watchdog.

The core limit is visible in `/proc/PID/limits`. `PR_SET_DUMPABLE=0` also denies
same-UID access to dump-sensitive `/proc/PID` files such as `mem`; use those
properties in a deployment smoke test rather than relying on a core-pattern
setting alone.

## Lifecycle verification

`process_lifecycle_e2e.py` exercises a real built binary. Its normal case
probes `/healthz`, checks both core limits in `/proc/PID/limits`, compares
`/proc/PID/mem` access with a dumpable child control, sends `SIGTERM`, and
requires status zero. A medium-hard case holds a real crawler request inside a
local TLS upstream while `SIGTERM` drives the server through graceful and
forced shutdown, worker joins, and sanitizer-checked destruction. The hard case
fills a local FIFO used as Fastbed's standard-error sink, proves the post-signal
shutdown log was not accepted, and requires the independent watchdog to exit
with status 124 at approximately 75 seconds. Every run copies the tested binary,
assets, crawler database, runner, configuration, and captured evidence into the
artifact and covers them with `SHA256SUMS`; the replay command uses those copies.

```sh
python3 docs/process_lifecycle_e2e.py \
  --binary build-release/fastbed \
  --output artifacts/fastbed-lifecycle-release \
  --assets assets \
  --crawler-db third_party/crawler-user-agents/crawler-user-agents.json
```

Use `--skip-watchdog --require-sanitizers` for a shorter sanitizer pass when
the full 75-second watchdog case has already passed for the same source
revision. The active-request case still exercises the 30-second forced cleanup
path under ASan and UBSan.

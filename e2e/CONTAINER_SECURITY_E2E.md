# Container security E2E

This gate starts the production image as the documented non-root user with a
read-only root filesystem, every Linux capability dropped, no-new-privileges,
a bounded PID budget, and a zero core limit. It exercises the real entrypoint,
image health check, HTTP listener, static assets, process policy, and graceful
shutdown. The output is a checksum-sealed, replayable artifact.

## Failure model

The gate must fail if any of these conditions occurs:

1. The requested image is missing, changes identity during the run, or the
   artifact does not bind its immutable image ID and RepoDigest.
2. Docker accepts a weaker policy than requested: a writable root filesystem,
   added or retained capabilities, privilege escalation, a nonzero core limit,
   an absent or different PID limit, or a root effective UID.
3. The application fails closed because the container policy and its own
   `RLIMIT_CORE` or `PR_SET_DUMPABLE` setup disagree.
4. `/proc/1/status` reports effective capabilities or permits new privileges,
   `/proc/1/limits` reports a nonzero soft or hard core limit, or a same-UID
   process can read `/proc/1/mem`.
5. A write probe succeeds on `/`, `/tmp`, or `/var/tmp`. A read-only image that
   silently receives an undeclared writable mount is not equivalent.
6. Docker reports the container ready while `/healthz` is unreachable, is
   reached through a proxy or wrong host port, returns a non-200 response, or
   does not satisfy Fastbed's JSON and `no-store` contract.
7. The root page differs from the deterministic credit substitution over its
   source template, or the favicon differs byte-for-byte from its source
   asset, including status and content type.
8. The container exceeds its intended PID/thread budget before receiving any
   crawler workload, is OOM-killed, or exits before the explicit shutdown.
9. `SIGTERM` does not produce a bounded graceful exit with status zero, or a
   process survives after Docker reports the container stopped.
10. A command, HTTP response, inspect record, log, or harness input is omitted
    from the final checksum closure, the output directory already exists, or
    the harness changes while the run is in progress.

The checks are intentionally process-level. They are not unit tests and do not
mock Docker, the health client, the server, the filesystem, or Linux process
policy.

## Run

```sh
python3 e2e/run_container_security_e2e.py \
  --image fastbed:supply-amd64 \
  --output artifacts/fastbed-container-security-amd64-20261018-01

(cd artifacts/fastbed-container-security-amd64-20261018-01 && \
  sha256sum -c SHA256SUMS)
```

The harness removes only the uniquely named container that it creates. It
does not remove the image, volumes, networks, or unrelated containers.

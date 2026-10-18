# Container security E2E

This gate starts the scratch production image as its numeric non-root user with
a read-only root filesystem, every Linux capability dropped,
no-new-privileges, a bounded PID budget, and a zero core limit. It exercises
the real entrypoint, external health probe, HTTP listener, static assets,
process policy, fully static ELF boundary, and graceful shutdown. The output is
a checksum-sealed, replayable artifact.

## Failure model

The gate must fail if any of these conditions occurs:

1. The requested image is missing, changes identity during the run, or the
   artifact does not bind its immutable image ID and RepoDigest.
2. Docker accepts a weaker policy than requested: a writable root filesystem,
   added or retained capabilities, privilege escalation, a nonzero core limit,
   an absent or different PID limit, or a root effective UID.
3. The application fails closed because the container policy and its own
   `RLIMIT_CORE` or `PR_SET_DUMPABLE` setup disagree.
4. The runtime ELF has an interpreter or `DT_NEEDED`, is not static PIE, or the
   scratch filesystem contains a shell, package database, loader, or shared
   object.
5. The CA bundle, scratch manifest, or build-package provenance is absent or
   disagrees with its recorded SHA-256 and exact package set.
6. Host-visible process state reports effective capabilities, permits new
   privileges, exposes a nonzero core limit, runs as the wrong UID, or permits
   same-UID access to `/proc/PID/mem`.
7. The external `/healthz` probe uses the wrong host port, returns a non-200
   response, or violates Fastbed's JSON and `no-store` contract.
8. The root page differs from the deterministic credit substitution over its
   source template, or the favicon differs byte-for-byte from its source
   asset, including status and content type.
9. The container exceeds its intended PID/thread budget before receiving any
   crawler workload, is OOM-killed, or exits before the explicit shutdown.
10. `SIGTERM` does not produce a bounded graceful exit with status zero, or a
   process survives after Docker reports the container stopped.
11. A command, HTTP response, inspect record, log, or harness input is omitted
    from the final checksum closure, the output directory already exists, or
    the harness changes while the run is in progress.

The checks are intentionally process-level. They are not unit tests and do not
mock Docker, the health client, the server, the filesystem, or Linux process
policy.

## Run

```sh
python3 e2e/run_container_security_e2e.py \
  --image fastbed:scratch-static-amd64 \
  --output artifacts/fastbed-scratch-static-container-amd64-20261018-03

(cd artifacts/fastbed-scratch-static-container-amd64-20261018-03 && \
  sha256sum -c SHA256SUMS)
```

The harness removes only the uniquely named container that it creates. It
does not remove the image, volumes, networks, or unrelated containers.

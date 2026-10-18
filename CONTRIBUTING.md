# Contributing to Fastbed

Fastbed treats the pinned Facebed service as a behavioral contract. A change is
ready when it preserves that contract, stays within the documented resource
bounds, and passes the relevant process-level checks.

## Before changing code

Read the documents that define the surface you plan to touch:

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) maps request flow and ownership.
- [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) defines observable behavior.
- [`docs/FAILURE_MODEL.md`](docs/FAILURE_MODEL.md) lists known failure classes.
- [`docs/VERIFICATION.md`](docs/VERIFICATION.md) explains the evidence gates.

If a subsystem must be tested in isolation, document the ways it can fail
before writing the implementation or harness. Prefer a medium-hard E2E that
starts a real Fastbed process and leaves a checksum-closed artifact. Do not add
tautological snapshots, change-detector tests, or a regression case that does
not close a genuine behavioral gap.

## Build

Production builds need the verified curl-impersonate and static dependency
prefixes. On the original amd64 build host, `./build.sh` uses the retained
repo-local prefixes by default. Elsewhere, build fresh prefixes and pass them
explicitly:

```sh
tools/build-static-deps.sh /absolute/path/static-deps amd64
tools/build-curl-impersonate.sh /absolute/path/curl-impersonate amd64

FASTBED_STATIC_DEPS_ROOT=/absolute/path/static-deps \
FASTBED_CURL_IMPERSONATE_ROOT=/absolute/path/curl-impersonate \
./build.sh
```

`build.sh` produces `build/fastbed` with native tuning, full LTO, lld, RELR,
embedded resources, and production-only CLI exposure. See
[`docs/TOOLCHAIN.md`](docs/TOOLCHAIN.md) for portable, sanitizer, PGO, and BOLT
profiles.

## Code rules

- Keep the production service C17. Do not introduce a Python runtime wrapper.
- Preserve bounded queues, body limits, traversal limits, redirect limits, and
  shutdown deadlines.
- Keep request-owned pointers inside their arena or transport scope. Static
  embedded resources must never enter request cleanup paths.
- Preserve anonymous upstream requests, redirect validation, exact target
  identity checks, and fallback precedence.
- Keep diagnostics and configuration values separate. Never log webhook URLs,
  session data, cookies, CAPTCHA material, or other credentials.
- Treat compiler warnings from the existing warning set as defects.

Formatting should follow the surrounding file. C code uses four spaces and no
tabs. Shell scripts must remain POSIX `sh` unless the file already documents a
different requirement.

## Verification

Run the smallest process-level gate that covers the changed behavior, then run
the broader compatibility gate when the change crosses parser, transport,
rendering, or ownership boundaries. Every retained artifact must include the
tested binary or its exact digest, raw results, a manifest, and `SHA256SUMS`.

Generated evidence belongs under `artifacts/` and is intentionally ignored by
Git. Build directories, local `config.yaml`, profiler output, and Python caches
must also remain untracked.

## Commit hygiene

Keep commits scoped and use an imperative Conventional Commit subject, for
example `fix(parser): reject conflicting reel ids`. Before committing, inspect
the staged diff, check executable bits, and scan for credentials or generated
output.

Fastbed does not yet have an owner-selected project license. Do not publish,
redistribute, or accept external contributions as though a license had already
been granted.

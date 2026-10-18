# Fastbed verification

Fastbed is verified through real processes and exact artifacts. A passing
helper function is not enough: the relevant gate starts the service, drives its
HTTP surface, checks the output and upstream trace, and seals the inputs and
results with SHA-256.

## Evidence model

Each E2E run uses a new output directory and records the tested binary, input
fingerprints, raw responses or measurements, logs, a machine-readable manifest,
and `SHA256SUMS`. Network-sensitive replay runs inside an isolated namespace
with only loopback enabled. Frozen Python results remain the behavioral oracle;
fixture absence is reported separately from a parser mismatch.

The `artifacts/` directory is intentionally ignored by Git. It can contain
large response sets, content-addressed upstream bodies, build prefixes,
container exports, and binaries. Commit the harness and workload definitions,
not their generated output.

## Required gates

| Gate | Entry point | What it proves |
|---|---|---|
| Full compatibility | `e2e/run_corpus_e2e.py` and `e2e/ARCHIVE_CORPUS_E2E.md` | Exact bodies, statuses, stable headers, fallback results, and upstream request traces across the frozen corpus. |
| Adversarial parsing | `e2e/run_adversarial_e2e.py` | Malformed targets, identity conflicts, parser limits, and sanitizer-clean failure handling. |
| Crawler classification | `e2e/run_crawler_contract_e2e.py` | Every vendored expression, common unfurler fast paths, invalid UTF-8, and resource limits against an independent oracle. |
| Concurrency and shutdown | `e2e/run_concurrency_e2e.py`, `e2e/run_cancellation_e2e.py`, and `docs/process_lifecycle_e2e.py` | Queue bounds, cancellation, deadlines, singleflight, worker joins, and watchdog behavior. |
| Cache and linkage | `e2e/run_cli_linkage_e2e.sh` plus the cache matrix | Default-off cache behavior, opt-in singleflight, release CLI surface, static symbols, and dynamic-link rejection. |
| Container | `e2e/run_container_security_e2e.py` | Embedded assets, health behavior, non-root read-only operation, dropped capabilities, and immutable image identity. |
| Supply chain | `tools/run-sbom-e2e.sh` | Reproducible SBOM/VEX generation, receipt binding, source offers, negative controls, and LGPL relink closure. |
| Performance | `benchmark/run_matrix.py` | Randomized paired workloads with exact response hashes, affinity checks, latency distributions, throughput, and RSS. |

Read the failure model beside each harness before changing it. A new isolated
test needs a documented failure surface first. Scenarios should be medium-hard,
not the smallest request that happens to pass.

## Current amd64 evidence

The retained 2026-10-18 evidence in the original checkout records:

- `artifacts/fastbed-scratch-static-archive-full-20261018-01`: all 10,659 rows
  exact with the static musl/x86-64-v3 verification binary
  `9092dee14559b9822242fcb297216cd1b7130ec332d5108addd560cbd3aecaaf`.
  The 257 shared unavailable fixtures remained separate, with no new gap,
  mismatch, trace mismatch, overuse, or integrity error.
- `artifacts/fastbed-internal-cache-embedded-e2e-20261018-02`: four real-process
  runs and 512 exact responses. Default mode made one upstream request per
  request; `--internal-cache` made one request per distinct target and broker
  generation.
- `artifacts/fastbed-embedded-crawler-contract-20261018-02`: 3,721 of 3,721
  crawler cases passed. The ASan/UBSan/LSan companion run also passed all 3,721
  cases without a sanitizer finding.
- `artifacts/fastbed-cli-release-linkage-e2e-20261018-07`: the host-native
  binary SHA-256 is
  `a244404a4845f819eeb3d418566e70e717ed710e2a6e352921bf10afa207afc3`;
  release options, strings, static-link checks, the default-prefix build, and a
  dynamic-curl negative control passed.
- `artifacts/fastbed-scratch-static-container-amd64-20261018-03`: 58 container
  and ELF checks passed for the 9.8 MB scratch image
  `sha256:4f69372a80a6467a757a211ce740589288b96a9ff2c3348be39148a4f458af16`.
- `artifacts/fastbed-scratch-static-sbom-amd64-20261018-04`: official schemas,
  double-generation reproducibility, receipt binding, the unknown-version
  negative control, static PCRE2 inventory, and LGPL relinking passed.
- `artifacts/fastbed-scratch-live-canary-20261018-01`: 29 checks passed through
  the exact scratch image against live Facebook. Photo, reel, and permalink
  routes all returned cacheable parsed embeds; health ended with three requests
  and zero errors.

The full offline replay uses a verification build because production omits the
replay ports and file overrides. Release-specific E2Es separately exercise the
optimized binary and container. Arm64 has build support but no current native
runtime, fingerprint, container, or SBOM certification.

## Reproduce a gate

Build the tested binary and use a new artifact directory. Every runner refuses
to overwrite an existing result. The individual E2E documents contain their
exact commands and input requirements.

After a run, verify its closure from inside the artifact:

```sh
sha256sum -c SHA256SUMS
```

Record the binary digest and source state with the result. Do not copy an old
manifest onto a new binary or treat a catalog, build log, or endpoint probe as
runtime evidence.

## Claim boundaries

- An offline corpus pass does not establish current Facebook routing or TLS
  acceptance; use a bounded live canary for that axis.
- A fixture gap is not a compatibility pass and is not a parser regression.
- A benchmark is valid only when response hashes, status codes, scheduling,
  affinity, and host-noise gates pass.
- Building or pushing an image is not deployment proof. Record the running
  image ID and a live health or schema check separately.
- Fastbed's public visibility grants no reuse permission. An owner-selected
  project license is still required to state redistribution and modification
  terms.

## Published package automation

`.github/workflows/docker-build.yml` mirrors Facebed's GHCR publication path.
Each push to `main` publishes `ghcr.io/facebed/fastbed:main` and `:latest`, then
pulls the immutable digest and exercises the locked-down container, health
endpoint, embedded assets, redirect behavior, and graceful exit. The workflow
publishes an x86-64-v3, fully static scratch image for amd64 only until arm64
completes its separate release gates.

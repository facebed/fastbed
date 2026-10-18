# Fastbed SBOM, VEX, and license workflow

The production inventory describes the source-built curl 8.23.0 HTTP/2-only
closure. It does not contain nghttp3 or ngtcp2. Fastbed's own project license
remains `NOASSERTION`; the supply-chain gate does not infer or invent one.

The sealed amd64 E2E at
`artifacts/fastbed-embedded-static-sbom-amd64-20261018-04` passed official-schema
validation, byte-reproducible double generation, the unknown-version negative
control, post-link receipt binding, and LGPL relink closure. It binds image ID
`sha256:4663cd347812544141b6ecb77cb170f6b9fc9b19313f768c4f9120d889aeb8a2`.
The arm64 workflow is defined but has not been executed on a native arm64
builder; do not infer arm64 release evidence from this amd64 result.

## Failure model

Generation and verification fail closed when any one of these bindings breaks:

- the receipt architecture, image architecture, musl architecture, or curl
  prefix architecture differs;
- the installed Fastbed hash/build ID differs from the post-link receipt;
- the receipt source-tree digest differs from the exact allowlisted build
  sources used by the SBOM;
- either static-prefix checksum closure is incomplete, unsorted, stale, or
  differs from the checksum aggregate and linked-library hashes in the receipt;
- the captured link command omits, duplicates, or substitutes one of the ten
  curl archives or the libmicrohttpd/libyaml archives, or mentions HTTP/3;
- the per-architecture LGPL relink archive is absent, has a different digest,
  has an invalid internal checksum closure, or does not bind the exact
  libmicrohttpd/libidn2/libunistring archives, corresponding source archives,
  and original link command;
- an upstream-fixed VEX record claims a version below its fixed version, or a
  local-backport record lacks its prerequisite, fix commit, patch digest, and
  patched-source digest;
- runtime metadata, licenses, rebuild inputs, source offers, or Alpine package
  metadata are incomplete or disagree with the declared inventory.

The receipt is generated only after the final link, byte-identical LGPL relink
check, debug split, and runtime strip. A curl prefix that merely exists beside
the binary is not accepted as evidence that the binary consumed it.

Fastbed uses a manual, fail-closed supply-chain workflow because ordinary image
scanners see the Alpine packages but miss the application, the source-built
GNU libmicrohttpd library, vendored data and source, and the libraries embedded
through curl-impersonate's static archives.

The authoritative declaration is
`artifact-schema/supply-chain.inventory.json`. It records exact versions,
source and download URLs, upstream archive hashes, licenses, patch hashes, and
named security dispositions. `tools/generate-sbom-vex.py` accepts the
declaration only when it agrees with all of the following evidence:

- the allowlisted Fastbed deployable source tree;
- vendored yyjson and crawler-user-agents bytes;
- the version and hash declarations in `CMakeLists.txt` and `Dockerfile`;
- completed source-built curl and libmicrohttpd/libyaml prefixes, including
  their `COMPONENTS.tsv`,
  `BUILD-MANIFEST.txt`, licenses, and complete `SHA256SUMS` closure;
- the per-architecture post-link receipt and the exact relink archive it names;
- a fresh image's exact Alpine package database, Fastbed hash/build ID,
  embedded-resource manifest, dependency notices, and byte-identical prefix
  metadata/licenses.

Unknown versions, extra or missing curl components, HTTP/3 archives, incomplete
license sets, unbound patches, mismatched patched-source hashes, incomplete
runtime package metadata, source/runtime curl-manifest drift, and any receipt
or relink-archive mismatch are fatal. The generator does not silently
substitute a declared version for missing build evidence.

## Dependency boundary

The generated documents cover:

- Fastbed source and the installed Fastbed binary;
- yyjson 0.13.0 at commit
  `6447536015f3d600f3d65323b10976103b337ca7`;
- crawler-user-agents 1.59.0 data, byte-identical to the pinned wheel;
- GNU libmicrohttpd 1.0.10, built from the verified source archive;
- libyaml 0.2.5, built from the verified source archive;
- curl-impersonate v1.5.2 commit
  `9607b22ccf6c440e560c5f8ad5292b8044bb6dd7`;
- embedded curl 8.23.0, patched BoringSSL, nghttp2 1.68.1, Brotli 1.2.0,
  Zstandard 1.5.7, zlib 1.3.2, libidn2 2.3.8, and libunistring 1.4.2;
- every package installed in the final Alpine image, including exact package
  versions, licenses, origins, architectures, and APK checksums.

Fastbed itself is not published at a version-control URL in this worktree, so
its source locator is the explicit `urn:fastbed:source-tree`; the generated
source-tree SHA-256 and per-file allowlist digest provide its reproducible
identity. The workflow does not mislabel the Python Facebed remote as the C
port's source.

The resolver is curl's threaded resolver backed by the runtime musl
`getaddrinfo`; c-ares is not downloaded or linked. IDN processing comes from
the pinned libidn2/libunistring static pair. Libmicrohttpd and libyaml are in a
separate pinned static prefix; the runtime installs neither shared library.

`tools/create-release-artifacts.sh` emits one post-link receipt per
architecture after relinking, stripping, and debug separation. The receipt
binds the unstripped, relinked, and runtime Fastbed hashes and build ID; the
exact link command; both prefix aggregates and all twelve linked archive
hashes; the embedded-resource/source digest; and the checksum-closed LGPL
relink archive. The same canonical receipt is
installed at `/usr/local/share/fastbed/BUILD-RECEIPT.json`. Runtime capture
reads that fixed file without running image code, extracts independent ELF
build IDs with the host `readelf`, and the generator/verifier compare every
binding to the supplied prefix, image, source tree, and release-artifact root.

`no-named-finding-in-this-vex` is an inventory scope statement, not a claim
that a component has no vulnerabilities. This workflow emits dispositions for
the three reviewed findings below; an external vulnerability feed may add
findings but cannot replace the build and patch evidence.

## Security dispositions

| Finding | Production component | Disposition | Evidence |
|---|---|---|---|
| CVE-2026-92392 | curl 8.23.0-IMPERSONATE | `resolved` by upstream version | Upstream says 8.12.0 through 8.22.0 are affected and 8.23.0 is not affected. The curl 8.23.0 source archive SHA-256 is `8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5`; the manifest also binds the resulting HTTP/2 source. No local CVE backport is claimed. |
| CVE-2026-27135 | nghttp2 1.68.1 | `resolved` by upstream version | The upstream advisory names 1.68.1 as the patched release and fix `5c7df8fa815ac1004d9ecb9d1f7595c4d37f46e1`. The source archive SHA-256 is `b761b53cb64916657ea84437973d508fd675e96bb2feb9593a1e43d1959abe95`; the compatibility patch only restores browser-priority submission and is not labeled a security patch. |
| CVE-2026-35189 | BoringSSL `673e61f...` plus local fix | `resolved_with_pedigree` | Local patch SHA-256 `2c9277a0576c6ed943386490c1ed53ba2e5b8ccef2f1ec4c0c326e4e2177c2dd` contains prerequisite `5386d908a663a424d154cbae7f76f2266c60c2fe` and fix `9b639f5b3b086508c03f6a4a1792e4a6043777ac`. The builder binds resulting `x509_vfy.cc` SHA-256 `b81cc94a5f2bec83cef2c5fd566aa7e05712c87d2fe20e6d8eeca79dd1cd9233`. |

Primary advisories are the [curl advisory for CVE-2026-92392](https://curl.se/docs/CVE-2026-92392.html),
the [nghttp2 advisory for CVE-2026-27135](https://github.com/nghttp2/nghttp2/security/advisories/GHSA-6933-cjhr-5qg6),
and the [BoringSSL advisory for CVE-2026-35189](https://github.com/google/boringssl/blob/main/docs/advisories/2026-09-29.md).

Version-based resolutions and backport pedigree are deliberately different.
Only BoringSSL receives CycloneDX patch pedigree. Curl and nghttp2 cite their
upstream fixed versions and immutable source evidence. The H2-only closure has
no nghttp3/ngtcp2 component and makes no VEX claim for an absent HTTP/3 stack.
The builder retains detached signature/checksum bytes, but this workflow does
not claim signer authenticity; trusted-key signature verification remains a
separate release gate.

## Reproducible production-candidate run

Prerequisites are Python 3, the Python `jsonschema` package, `jq`, `curl`,
`diff`, `sha256sum`, `readelf`, and Docker or Podman. Set
`FASTBED_CONTAINER_ENGINE=podman` to use Podman (Docker is the default). Start
from a cleanly built candidate image;
do not point the capture tool at a long-running or user-modified container.

For an isolated source-bundle audit, build the verified curl prefix directly.
A persistent download cache is optional and does not weaken archive
verification:

```sh
FASTBED_CURL_DOWNLOAD_CACHE=/var/cache/fastbed-curl \
  tools/build-curl-impersonate.sh /tmp/fastbed-curl-prefix amd64
FASTBED_STATIC_DEPS_DOWNLOAD_CACHE=/var/cache/fastbed-static-deps \
  tools/build-static-deps.sh /tmp/fastbed-static-deps amd64
```

For a release-candidate SBOM, the prefix must be the exact prefix consumed by the
image build, not an independently rebuilt lookalike. Export the pinned Docker
build stage, then build the final image from the same BuildKit cache:

```sh
build_root=$(mktemp -d /tmp/fastbed-build-stage.XXXXXX)
docker build --target build --output "type=local,dest=$build_root" .
docker build --tag fastbed:production-candidate .
```

The full medium-hard E2E is then one command:

```sh
tools/run-sbom-e2e.sh \
  fastbed:production-candidate \
  "$build_root/tmp/curl-impersonate" \
  "$build_root/tmp/static-deps" \
  "$build_root/release-artifacts" \
  artifacts/fastbed-sbom-vex-$(date -u +%Y%m%d)-01
```

The E2E performs two byte-for-byte generation runs, validates both, checks
cross-document identities and dependency references, and proves that a
checksum-consistent curl manifest containing an unknown version is rejected.
It produces a checksum-closed integrity snapshot containing:

- `sbom-vex/cyclonedx-sbom.json` (CycloneDX 1.6);
- `sbom-vex/spdx-sbom.json` (SPDX 2.3 JSON);
- `sbom-vex/cyclonedx-vex.json` (CycloneDX 1.6 VEX);
- `sbom-vex/build-receipt.json` (schema-validated post-link receipt);
- `sbom-vex/provenance.json` and both inner and outer `SHA256SUMS` closures;
- `release-artifacts/relink/fastbed-relink-<arch>.tar.gz`, the verified LGPL
  relink closure named by the receipt;
- the exact libidn2/libunistring source archives and detached signatures named
  by the receipt under `release-artifacts/source/curl-impersonate/`;
- the normalized runtime inventory, custom schemas, documentation, and exact
  generator/verifier scripts under `replay/`;
- `e2e-report.json`, including the image ID, source/curl/receipt hashes, and
  relink-archive digest.

Official schemas are not redistributed in the artifact. The included official
schema downloader refuses an existing destination and verifies the exact
CycloneDX 1.6, CycloneDX SPDX-license, JSF signature, SPDX 2.3 schema, and SPDX
3.29.0 license/exception-list hashes before validation. For a manual split run:

The snapshot includes the LGPL relink closure but is not a complete offline
image rebuild kit: it intentionally omits the complete source tree, curl
prefix, container layers, complete non-LGPL source-archive set, and third-party
official schemas.
Preserve those content-addressed build inputs separately when a full offline
release replay is required.

```sh
tools/fetch-sbom-schemas.sh /tmp/fastbed-official-schemas
tools/capture-runtime-inventory.py \
  --image fastbed:production-candidate \
  --output /tmp/fastbed-runtime.json
tools/generate-sbom-vex.py \
  --source-root . \
  --inventory artifact-schema/supply-chain.inventory.json \
  --curl-prefix /tmp/fastbed-curl-prefix \
  --release-artifact-root /tmp/fastbed-release-artifacts \
  --runtime-inventory /tmp/fastbed-runtime.json \
  --output /tmp/fastbed-sbom-vex
tools/verify-sbom-vex.py \
  --artifact /tmp/fastbed-sbom-vex \
  --inventory artifact-schema/supply-chain.inventory.json \
  --runtime-inventory /tmp/fastbed-runtime.json \
  --curl-prefix /tmp/fastbed-curl-prefix \
  --release-artifact-root /tmp/fastbed-release-artifacts \
  --schema-dir artifact-schema \
  --official-schema-dir /tmp/fastbed-official-schemas
(cd /tmp/fastbed-sbom-vex && sha256sum -c SHA256SUMS)
jq -e '.vulnerabilities | length == 3' \
  /tmp/fastbed-sbom-vex/cyclonedx-vex.json
```

## Secret boundary

The runtime capture first resolves the local tag to an immutable image ID, then
creates but never starts an ephemeral container from that ID. It copies only
`/lib/apk/db/installed` and a fixed list of candidate binaries, installed
assets/data, manifests, rebuild material, and license/source-offer files. No
binary or shell from the target image is executed. It does not inspect image
environment variables, history, layers, application configuration, process
memory, repository-untracked files, or arbitrary paths. Do not add credentials
to the inventory or generated artifacts. Build credentials belong in ephemeral
BuildKit secrets and are outside this workflow.

## License release gates

An SBOM is not license compliance by itself.

- Fastbed currently has no project license. The product is deliberately
  recorded as `NOASSERTION`; choose and ship a project license before external
  distribution.
- The statically linked, no-HTTPS GNU libmicrohttpd 1.0.10 build is declared as
  `LGPL-2.1-or-later OR eCos-2.0`. The image contains exact `COPYING` bytes,
  the checksum-closed static-prefix offer, and the exact source archive at
  `/usr/local/share/fastbed-source-offers/libmicrohttpd-1.0.10.tar.gz`.
  The per-architecture relink kit includes `libmicrohttpd.a`, application
  objects, its source, exact link command, and a byte-identical relink proof.
- Statically linked libyaml 0.2.5 retains its MIT notice and exact source
  archive in the runtime/source evidence.
- yyjson and crawler-user-agents MIT notices must be present at the fixed paths
  checked by the runtime inventory.
- Statically linked libidn2 and libunistring are
  `LGPL-3.0-or-later`. Shipping notices and source URLs is insufficient: retain
  and offer the corresponding application object files, exact static archives,
  source archives, link order/options, and instructions needed to relink a
  modified LGPL library. Treat that receipt-bound relink kit as a release
  artifact.
- The curl bundle's copied `licenses/` directory is part of the runtime hash
  gate. Preserve all notices, including BoringSSL's Apache-2.0 notice and the
  extra GNU/Unicode notices.

Have counsel review the final distribution model; these are engineering gates,
not legal advice.

#!/bin/sh
set -eu

if [ "$#" -ne 5 ]; then
    echo "usage: $0 IMAGE CURL_PREFIX STATIC_DEPS_PREFIX RELEASE_ARTIFACT_ROOT OUTPUT_DIR" >&2
    exit 2
fi

image=$1
engine=${FASTBED_CONTAINER_ENGINE:-docker}
case "$engine" in
    docker|podman) ;;
    *) echo "FASTBED_CONTAINER_ENGINE must be docker or podman" >&2; exit 2 ;;
esac
case "$2" in
    /*) curl_prefix=$2 ;;
    *) curl_prefix=$PWD/$2 ;;
esac
case "$3" in
    /*) static_deps_prefix=$3 ;;
    *) static_deps_prefix=$PWD/$3 ;;
esac
case "$4" in
    /*) release_artifact_root=$4 ;;
    *) release_artifact_root=$PWD/$4 ;;
esac
case "$5" in
    /*) output=$5 ;;
    *) output=$PWD/$5 ;;
esac
if [ ! -d "$curl_prefix" ]; then
    echo "curl prefix does not exist: $curl_prefix" >&2
    exit 2
fi
if [ ! -d "$static_deps_prefix" ]; then
    echo "static dependency prefix does not exist: $static_deps_prefix" >&2
    exit 2
fi
if [ ! -d "$release_artifact_root" ]; then
    echo "release artifact root does not exist: $release_artifact_root" >&2
    exit 2
fi
if [ -e "$output" ]; then
    echo "output already exists: $output" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
schema_dir=$repo_dir/artifact-schema
inventory=$schema_dir/supply-chain.inventory.json
parent=$(dirname -- "$output")
mkdir -p -- "$parent"
work=$(mktemp -d "$parent/.fastbed-sbom-e2e.XXXXXX")
cleanup() {
    case "$work" in
        "$parent"/.fastbed-sbom-e2e.*) rm -rf -- "$work" ;;
        *) echo "refusing to remove unexpected E2E directory: $work" >&2 ;;
    esac
}
trap cleanup EXIT HUP INT TERM

official_schemas=$work/official-schemas
runtime_inventory=$work/runtime-inventory.json
artifact_a=$work/artifact-a
artifact_b=$work/artifact-b

"$script_dir/fetch-sbom-schemas.sh" "$official_schemas"
"$script_dir/capture-runtime-inventory.py" \
    --engine "$engine" \
    --image "$image" \
    --output "$runtime_inventory"

for artifact in "$artifact_a" "$artifact_b"; do
    "$script_dir/generate-sbom-vex.py" \
        --source-root "$repo_dir" \
        --inventory "$inventory" \
        --curl-prefix "$curl_prefix" \
        --static-deps-prefix "$static_deps_prefix" \
        --release-artifact-root "$release_artifact_root" \
        --runtime-inventory "$runtime_inventory" \
        --output "$artifact"
    "$script_dir/verify-sbom-vex.py" \
        --artifact "$artifact" \
        --inventory "$inventory" \
        --runtime-inventory "$runtime_inventory" \
        --curl-prefix "$curl_prefix" \
        --static-deps-prefix "$static_deps_prefix" \
        --release-artifact-root "$release_artifact_root" \
        --schema-dir "$schema_dir" \
        --official-schema-dir "$official_schemas"
done

if ! diff --recursive --brief "$artifact_a" "$artifact_b" >/dev/null; then
    echo "generated artifact sets are not byte-reproducible" >&2
    diff --recursive --brief "$artifact_a" "$artifact_b" >&2 || true
    exit 1
fi

jq -e '
    .bomFormat == "CycloneDX" and
    .specVersion == "1.6" and
    (.components | length >= 19) and
    ([.components[].version | ascii_downcase | select(. == "unknown" or . == "noassertion")] | length == 0) and
    ([.metadata.component.properties[] | select(.name == "fastbed:resolver-backend") | .value] == ["threaded"])
' "$artifact_a/cyclonedx-sbom.json" >/dev/null
jq -e '
    ([.vulnerabilities[].id] | sort) ==
      ["CVE-2026-27135", "CVE-2026-35189", "CVE-2026-92392"] and
    ([.vulnerabilities[].analysis.state] | sort) ==
      ["resolved", "resolved", "resolved_with_pedigree"]
' "$artifact_a/cyclonedx-vex.json" >/dev/null
jq -e '
    .spdxVersion == "SPDX-2.3" and
    (.packages | length >= 20) and
    ([.packages[].versionInfo | ascii_downcase | select(. == "unknown" or . == "noassertion")] | length == 0)
' "$artifact_a/spdx-sbom.json" >/dev/null

# Medium-hard negative control: preserve the complete archive/checksum closure,
# replace one known component version with an unknown value, update only that
# metadata checksum, and prove generation still fails closed on identity.
negative_prefix=$work/curl-prefix-unknown-version
cp -a --reflink=auto -- "$curl_prefix" "$negative_prefix"
negative_components=$negative_prefix/share/fastbed-curl-impersonate/COMPONENTS.tsv
negative_sums=$negative_prefix/share/fastbed-curl-impersonate/SHA256SUMS
sed -i 's/^nghttp2\t1\.68\.1\t/nghttp2\tunknown\t/' "$negative_components"
new_digest=$(sha256sum "$negative_components" | awk '{print $1}')
sed -i \
    "s|^[0-9a-f][0-9a-f]*  share/fastbed-curl-impersonate/COMPONENTS.tsv\$|$new_digest  share/fastbed-curl-impersonate/COMPONENTS.tsv|" \
    "$negative_sums"
if "$script_dir/generate-sbom-vex.py" \
    --source-root "$repo_dir" \
    --inventory "$inventory" \
    --curl-prefix "$negative_prefix" \
    --static-deps-prefix "$static_deps_prefix" \
    --release-artifact-root "$release_artifact_root" \
    --runtime-inventory "$runtime_inventory" \
    --output "$work/should-not-exist" \
    >"$work/negative.stdout" 2>"$work/negative.stderr"; then
    echo "generator accepted an unknown curl component version" >&2
    exit 1
fi
grep -F 'curl component nghttp2 version_or_revision mismatch' \
    "$work/negative.stderr" >/dev/null || {
    echo "negative control failed for an unexpected reason" >&2
    sed -n '1,20p' "$work/negative.stderr" >&2
    exit 1
}

mkdir -p -- "$work/final"
mv -- "$artifact_a" "$work/final/sbom-vex"
cp -- "$runtime_inventory" "$work/final/runtime-inventory.json"
target_arch=$(jq -er .image_architecture "$runtime_inventory")
relink_relative="relink/fastbed-relink-$target_arch.tar.gz"
mkdir -p -- "$work/final/release-artifacts/relink"
cp -- "$release_artifact_root/$relink_relative" \
    "$work/final/release-artifacts/$relink_relative"
for lgpl_source in \
    source/curl-impersonate/libidn2-2.3.8.tar.gz \
    source/curl-impersonate/libidn2-2.3.8.tar.gz.sig \
    source/curl-impersonate/libunistring-1.4.2.tar.xz \
    source/curl-impersonate/libunistring-1.4.2.tar.xz.sig \
    source/static-deps/libmicrohttpd-1.0.10.tar.gz \
    source/static-deps/pcre2-10.47.tar.bz2 \
    source/static-deps/yaml-0.2.5.tar.gz; do
    mkdir -p -- "$work/final/release-artifacts/$(dirname -- "$lgpl_source")"
    cp -- "$release_artifact_root/$lgpl_source" \
        "$work/final/release-artifacts/$lgpl_source"
done
mkdir -p -- "$work/final/artifact-schema" "$work/final/replay/tools" \
    "$work/final/replay/docs"
cp -- "$schema_dir"/*.json "$work/final/artifact-schema/"
for tool in capture-runtime-inventory.py create-release-artifacts.sh \
            fetch-sbom-schemas.sh \
            generate-sbom-vex.py run-sbom-e2e.sh verify-sbom-vex.py; do
    cp -- "$script_dir/$tool" "$work/final/replay/tools/$tool"
done
cp -- "$repo_dir/docs/SUPPLY_CHAIN.md" "$work/final/replay/docs/SUPPLY_CHAIN.md"
jq -n \
    --arg image_id "$(jq -r .image_id "$runtime_inventory")" \
    --arg source_tree_sha256 "$(jq -r .source_tree_sha256 "$work/final/sbom-vex/provenance.json")" \
    --arg curl_bundle_sha256 "$(jq -r .curl_bundle_sha256 "$work/final/sbom-vex/provenance.json")" \
    --arg static_deps_bundle_sha256 "$(jq -r .static_deps_bundle_sha256 "$work/final/sbom-vex/provenance.json")" \
    --arg build_receipt_sha256 "$(jq -r .build_receipt_sha256 "$work/final/sbom-vex/provenance.json")" \
    --arg lgpl_relink_archive_sha256 "$(jq -r .lgpl_relink_archive_sha256 "$work/final/sbom-vex/provenance.json")" \
    --arg release_status "$(jq -r .release_status "$inventory")" \
    --arg release_reason "$(jq -r .release_reason "$inventory")" \
    '{
      schema_version: 1,
      result: "pass",
      image_id: $image_id,
      source_tree_sha256: $source_tree_sha256,
      curl_bundle_sha256: $curl_bundle_sha256,
      static_deps_bundle_sha256: $static_deps_bundle_sha256,
      build_receipt_sha256: $build_receipt_sha256,
      lgpl_relink_archive_sha256: $lgpl_relink_archive_sha256,
      official_schema_validation: true,
      byte_reproducibility: true,
      unknown_version_negative_control: "rejected",
      post_link_receipt_binding: true,
      lgpl_relink_closure: true
      ,
      release_status: $release_status,
      release_reason: $release_reason
    }' > "$work/final/e2e-report.json"
(cd "$work/final" && \
    find . -type f ! -path ./SHA256SUMS -print | LC_ALL=C sort | \
    while IFS= read -r file; do
        sha256sum "${file#./}"
    done) > "$work/final/SHA256SUMS"
(cd "$work/final" && sha256sum -c SHA256SUMS >/dev/null)

mv -- "$work/final" "$output"
trap - EXIT HUP INT TERM
cleanup
printf '%s\n' "$output"

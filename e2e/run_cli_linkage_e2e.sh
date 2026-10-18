#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 PRODUCTION_BINARY STATIC_DEPS_ROOT OUTPUT_DIR" >&2
    exit 2
fi

case "$1" in /*) production=$1 ;; *) production=$PWD/$1 ;; esac
case "$2" in /*) static_deps=$2 ;; *) static_deps=$PWD/$2 ;; esac
case "$3" in /*) output=$3 ;; *) output=$PWD/$3 ;; esac
[ -x "$production" ] || { echo "production binary not executable" >&2; exit 2; }
[ -d "$static_deps" ] || { echo "static dependency prefix missing" >&2; exit 2; }
[ ! -e "$output" ] || { echo "output already exists: $output" >&2; exit 2; }

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)
parent=$(dirname -- "$output")
mkdir -p -- "$parent"
work=$(mktemp -d "$parent/.fastbed-cli-linkage-e2e.XXXXXX")
cleanup() {
    case "$work" in
        "$parent"/.fastbed-cli-linkage-e2e.*) rm -rf -- "$work" ;;
        *) echo "refusing to remove unexpected E2E work directory: $work" >&2 ;;
    esac
}
trap cleanup EXIT HUP INT TERM

for command in cmake env grep ninja nm python3 readelf sha256sum strings; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required command missing: $command" >&2
        exit 2
    }
done

mkdir -p "$work/final/harness" "$work/final/binaries"
cp -- "$production" "$work/final/binaries/fastbed"
cp -- "$script_dir/run_cli_linkage_e2e.sh" "$work/final/harness/"
cp -- "$script_dir/INTERNAL_CACHE_LINKAGE_E2E.md" "$work/final/harness/"
cp -- "$root/cmake/VerifyBundledStaticLinkage.cmake" "$work/final/harness/"
cp -- "$root/build.sh" "$work/final/harness/"

"$production" --help >"$work/final/help.stdout" 2>"$work/final/help.stderr"
grep -F -- '--internal-cache' "$work/final/help.stdout" >/dev/null
grep -F -- 'default: off' "$work/final/help.stdout" >/dev/null
if grep -F -- '--disable-success-cache' "$work/final/help.stdout" >/dev/null; then
    echo "removed cache flag remains in help" >&2
    exit 1
fi
for hidden in --assets --crawler-db --allow-stock-curl \
              --replay-http-port --replay-https-port; do
    if grep -F -- "$hidden" "$work/final/help.stdout" >/dev/null; then
        echo "verification-only option leaked into release help: $hidden" >&2
        exit 1
    fi
done

expect_release_rejection() {
    label=$1
    shift
    set +e
    "$production" "$@" --help \
        >"$work/final/rejected-$label.stdout" \
        2>"$work/final/rejected-$label.stderr"
    status=$?
    set -e
    [ "$status" -ne 0 ] || {
        echo "verification-only release option was accepted: $label" >&2
        exit 1
    }
    grep -F -- 'unrecognized option' \
        "$work/final/rejected-$label.stderr" >/dev/null
}
expect_release_rejection assets --assets="$work/forbidden-assets"
expect_release_rejection crawler-db --crawler-db="$work/forbidden-crawler.json"
expect_release_rejection allow-stock-curl --allow-stock-curl
expect_release_rejection replay-http-port --replay-http-port=1
expect_release_rejection replay-https-port --replay-https-port=1

strings -a "$production" >"$work/final/production-strings.txt"
grep -F -- '--internal-cache' "$work/final/production-strings.txt" >/dev/null
for forbidden_string in --assets --crawler-db --allow-stock-curl \
                        --replay-http-port --replay-https-port \
                        --disable-success-cache; do
    if grep -F -- "$forbidden_string" \
        "$work/final/production-strings.txt" >/dev/null; then
        echo "removed option remains in release string table: $forbidden_string" >&2
        exit 1
    fi
done

set +e
"$production" --disable-success-cache \
    >"$work/final/removed-flag.stdout" \
    2>"$work/final/removed-flag.stderr"
removed_status=$?
set -e
[ "$removed_status" -ne 0 ] || {
    echo "removed cache flag was accepted" >&2
    exit 1
}
grep -F -- 'unrecognized option' "$work/final/removed-flag.stderr" >/dev/null

set +e
"$root/build.sh" --run \
    >"$work/final/removed-build-run.stdout" \
    2>"$work/final/removed-build-run.stderr"
removed_build_run_status=$?
set -e
[ "$removed_build_run_status" -eq 2 ] || {
    echo "build.sh --run did not fail with usage status 2" >&2
    exit 1
}
grep -F -- 'usage: ' "$work/final/removed-build-run.stderr" >/dev/null

env -u FASTBED_CURL_IMPERSONATE_ROOT -u FASTBED_STATIC_DEPS_ROOT \
    "$root/build.sh" \
    >"$work/final/default-prefix-build.stdout" \
    2>"$work/final/default-prefix-build.stderr"
default_build=$root/build/fastbed
[ -x "$default_build" ] || {
    echo "default-prefix build did not produce $default_build" >&2
    exit 1
}
default_build_sha256_line=$(sha256sum "$default_build")
default_build_sha256=${default_build_sha256_line%% *}

cmake -DFASTBED_BINARY="$production" \
    -DFASTBED_READELF="$(command -v readelf)" \
    -DFASTBED_NM="$(command -v nm)" \
    -DFASTBED_LINKAGE_REPORT="$work/final/production-linkage.txt" \
    -P "$root/cmake/VerifyBundledStaticLinkage.cmake" \
    >"$work/final/production-verifier.stdout" \
    2>"$work/final/production-verifier.stderr"
readelf -dW "$production" >"$work/final/production-dynamic-table.txt"
nm -a "$production" >"$work/final/production-symbols.txt"

missing_build=$work/missing-curl-build
set +e
cmake -S "$root" -B "$missing_build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DFASTBED_STATIC_DEPS_ROOT="$static_deps" \
    >"$work/final/missing-curl.stdout" \
    2>"$work/final/missing-curl.stderr"
missing_status=$?
set -e
[ "$missing_status" -ne 0 ] || {
    echo "production configure accepted no curl-impersonate prefix" >&2
    exit 1
}
grep -F -- 'Production builds require statically bundled curl-impersonate' \
    "$work/final/missing-curl.stderr" >/dev/null

dynamic_build=$work/dynamic-curl-build
cmake -S "$root" -B "$dynamic_build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang \
    -DFASTBED_STATIC_DEPS_ROOT="$static_deps" \
    -DFASTBED_VERIFICATION_BUILD=ON \
    -DFASTBED_ALLOW_DYNAMIC_SYSTEM_CURL=ON \
    -DFASTBED_LTO=OFF \
    >"$work/final/dynamic-configure.stdout" \
    2>"$work/final/dynamic-configure.stderr"
cmake --build "$dynamic_build" --parallel 8 \
    >"$work/final/dynamic-build.stdout" \
    2>"$work/final/dynamic-build.stderr"
cp -- "$dynamic_build/fastbed" "$work/final/binaries/dynamic-curl-negative"
readelf -dW "$dynamic_build/fastbed" \
    >"$work/final/dynamic-curl-dynamic-table.txt"
"$dynamic_build/fastbed" --help \
    >"$work/final/verification-help.stdout" \
    2>"$work/final/verification-help.stderr"
for exposed in --assets --crawler-db --allow-stock-curl \
               --replay-http-port --replay-https-port; do
    grep -F -- "$exposed" "$work/final/verification-help.stdout" >/dev/null
done

set +e
cmake -DFASTBED_BINARY="$dynamic_build/fastbed" \
    -DFASTBED_READELF="$(command -v readelf)" \
    -DFASTBED_NM="$(command -v nm)" \
    -P "$root/cmake/VerifyBundledStaticLinkage.cmake" \
    >"$work/final/dynamic-negative.stdout" \
    2>"$work/final/dynamic-negative.stderr"
dynamic_verify_status=$?
set -e
[ "$dynamic_verify_status" -ne 0 ] || {
    echo "static-link verifier accepted a dynamic system-curl binary" >&2
    exit 1
}
grep -F -- 'bundled dependency escaped into DT_NEEDED:' \
    "$work/final/dynamic-negative.stderr" >/dev/null
grep -E 'Shared library: \[libcurl\.so(\.|\])' \
    "$work/final/dynamic-curl-dynamic-table.txt" >/dev/null

python3 - "$work/final/report.json" "$production" \
    "$removed_status" "$removed_build_run_status" "$default_build_sha256" \
    "$missing_status" "$dynamic_verify_status" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

binary = Path(sys.argv[2])
digest = hashlib.sha256(binary.read_bytes()).hexdigest()
report = {
    "schema": "fastbed-cli-linkage-e2e-v1",
    "result": "pass",
    "production_binary_sha256": digest,
    "internal_cache_help": True,
    "default_cache_off_documented": True,
    "verification_only_release_arguments_absent": True,
    "verification_only_release_arguments_rejected": True,
    "verification_only_release_strings_absent": True,
    "verification_only_verification_arguments_present": True,
    "removed_disable_flag_exit": int(sys.argv[3]),
    "removed_build_run_exit": int(sys.argv[4]),
    "default_prefix_build_succeeded": True,
    "default_prefix_build_sha256": sys.argv[5],
    "missing_curl_prefix_configure_exit": int(sys.argv[6]),
    "dynamic_curl_negative_verifier_exit": int(sys.argv[7]),
    "production_static_symbols": [
        "curl_easy_impersonate",
        "curl_easy_init",
        "yyjson_read_opts",
        "MHD_start_daemon",
        "yaml_parser_initialize",
        "fb_embedded_index_html",
        "fb_embedded_favicon_ico",
        "fb_embedded_banner_png",
        "fb_embedded_crawler_json",
    ],
    "allowed_direct_dynamic_families": [
        "libc", "libstdc++", "libgcc_s", "libpcre2-8"
    ],
}
Path(sys.argv[1]).write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

(
    cd "$work/final"
    find . -type f ! -path './SHA256SUMS' -print | LC_ALL=C sort |
        while IFS= read -r file; do sha256sum "${file#./}"; done \
        >SHA256SUMS
    sha256sum -c SHA256SUMS >/dev/null
)
mv -- "$work/final" "$output"
trap - EXIT HUP INT TERM
cleanup
printf '%s\n' "$output"

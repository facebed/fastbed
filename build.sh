#!/bin/sh
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
build_dir="$project_dir/build"
default_curl_root="$project_dir/artifacts/curl823-production-amd64-20261018-06-prefix"
default_static_deps_root="$project_dir/artifacts/static-deps-amd64-20261018-02-prefix"
curl_root=${FASTBED_CURL_IMPERSONATE_ROOT:-$default_curl_root}
static_deps_root=${FASTBED_STATIC_DEPS_ROOT:-$default_static_deps_root}

if [ "$#" -ne 0 ]; then
    echo "usage: $0" >&2
    exit 2
fi

[ -d "$curl_root" ] || {
    echo "curl prefix not found: $curl_root" >&2
    echo 'set FASTBED_CURL_IMPERSONATE_ROOT to override the default' >&2
    exit 2
}
[ -d "$static_deps_root" ] || {
    echo "static dependency prefix not found: $static_deps_root" >&2
    echo 'set FASTBED_STATIC_DEPS_ROOT to override the default' >&2
    exit 2
}

cmake -S "$project_dir" -B "$build_dir" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_C_FLAGS= \
    -DCMAKE_EXE_LINKER_FLAGS= \
    -DCMAKE_SHARED_LINKER_FLAGS= \
    -DCMAKE_MODULE_LINKER_FLAGS= \
    -DFASTBED_LTO=ON \
    -DFASTBED_LTO_MODE=FULL \
    -DFASTBED_NATIVE=ON \
    -DFASTBED_USE_LLD=ON \
    -DFASTBED_PACK_RELR=ON \
    -DFASTBED_VERIFICATION_BUILD=OFF \
    -DFASTBED_ALLOW_DYNAMIC_SYSTEM_CURL=OFF \
    -DFASTBED_CURL_IMPERSONATE_ROOT="$curl_root" \
    -DFASTBED_STATIC_DEPS_ROOT="$static_deps_root"

cmake --build "$build_dir" -j "$(nproc)"
printf 'built optimized Fastbed: %s\n' "$build_dir/fastbed"

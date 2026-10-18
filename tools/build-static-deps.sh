#!/bin/sh
set -eu

usage() {
    echo 'usage: build-static-deps.sh OUTPUT_DIR [amd64|arm64]' >&2
    exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
output_arg=$1
target_arch=${2-}
case "$output_arg" in
    /*) output=$output_arg ;;
    *) output=$PWD/$output_arg ;;
esac
[ ! -e "$output" ] || {
    echo "output already exists: $output" >&2
    exit 2
}

machine=$(uname -m)
if [ -z "$target_arch" ]; then
    case "$machine" in
        x86_64|amd64) target_arch=amd64 ;;
        aarch64|arm64) target_arch=arm64 ;;
        *) echo "unsupported native architecture: $machine" >&2; exit 2 ;;
    esac
fi
case "$target_arch:$machine" in
    amd64:x86_64|amd64:amd64|arm64:aarch64|arm64:arm64) ;;
    amd64:*|arm64:*)
        echo "native build required: TARGETARCH=$target_arch host=$machine" >&2
        exit 2
        ;;
    *) usage ;;
esac

for command in curl sha256sum tar make; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required tool not found: $command" >&2
        exit 2
    }
done
CC=${CC:-$(command -v clang 2>/dev/null ||
    command -v clang-22 2>/dev/null || command -v cc)}
AR=${AR:-$(command -v llvm-ar 2>/dev/null ||
    command -v llvm-ar-22 2>/dev/null || command -v ar)}
RANLIB=${RANLIB:-$(command -v llvm-ranlib 2>/dev/null ||
    command -v llvm-ranlib-22 2>/dev/null || command -v ranlib)}
NM=${NM:-$(command -v llvm-nm 2>/dev/null ||
    command -v llvm-nm-22 2>/dev/null || command -v nm)}
for tool in "$CC" "$AR" "$RANLIB" "$NM"; do
    [ -x "$tool" ] || {
        echo "required compiler tool not found: $tool" >&2
        exit 2
    }
done

source_date_epoch=${SOURCE_DATE_EPOCH:-1774606016}
case "$source_date_epoch" in
    ''|*[!0-9]*) echo 'SOURCE_DATE_EPOCH must be a nonnegative integer' >&2; exit 2 ;;
esac

work=/tmp/fastbed-static-deps-$target_arch
if ! (umask 077 && mkdir "$work"); then
    echo "deterministic static-dependency build root already exists: $work" >&2
    exit 2
fi
cleanup() {
    case "$work" in
        /tmp/fastbed-static-deps-amd64|/tmp/fastbed-static-deps-arm64)
            rm -rf -- "$work"
            ;;
        *) echo "refusing to remove unexpected work directory: $work" >&2 ;;
    esac
}
trap cleanup EXIT HUP INT TERM

cache=$work/cache
cache_override=$(printenv FASTBED_STATIC_DEPS_DOWNLOAD_CACHE 2>/dev/null || true)
if [ -n "$cache_override" ]; then
    case "$cache_override" in
        /*) cache=$cache_override ;;
        *) cache=$PWD/$cache_override ;;
    esac
fi
downloads=$work/downloads
sources=$work/sources
stage=$work/stage
logs=$work/logs
mkdir -p -- "$cache" "$downloads" "$sources" "$stage" "$logs"

check_hash() {
    expected=$1
    file=$2
    printf '%s  %s\n' "$expected" "$file" | sha256sum -c -
}

download_verified() {
    url=$1
    expected=$2
    name=$3
    cached=$cache/$name
    partial=$cached.part.$$
    if [ -f "$cached" ]; then
        check_hash "$expected" "$cached"
    else
        rm -f -- "$partial"
        curl --proto '=https' --tlsv1.2 --fail --location --retry 3 \
            --output "$partial" "$url"
        check_hash "$expected" "$partial"
        mv -- "$partial" "$cached"
    fi
    cp -- "$cached" "$downloads/$name"
    check_hash "$expected" "$downloads/$name"
}

download_verified \
    https://ftp.gnu.org/gnu/libmicrohttpd/libmicrohttpd-1.0.10.tar.gz \
    04bfe8ef75db7d629a33de767599765cecadc56274a39822d5d081030d577685 \
    libmicrohttpd-1.0.10.tar.gz
download_verified \
    https://github.com/yaml/libyaml/releases/download/0.2.5/yaml-0.2.5.tar.gz \
    c642ae9b75fee120b2d96c712538bd2cf283228d2337df2cf2988e3c02678ef4 \
    yaml-0.2.5.tar.gz

mkdir "$sources/libmicrohttpd" "$sources/libyaml"
tar -xzf "$downloads/libmicrohttpd-1.0.10.tar.gz" \
    -C "$sources/libmicrohttpd" --strip-components=1
tar -xzf "$downloads/yaml-0.2.5.tar.gz" \
    -C "$sources/libyaml" --strip-components=1
check_hash 7399547209438c93f9b90297954698773d4846cea44cde5ca982c84c45952a3b \
    "$sources/libmicrohttpd/COPYING"
check_hash c40112449f254b9753045925248313e9270efa36d226b22d82d4cc6c43c57f29 \
    "$sources/libyaml/License"

common_flags="-O2 -g1 -fPIC -ffunction-sections -fdata-sections"
mhd_flags="$common_flags -ffile-prefix-map=$sources/libmicrohttpd=/usr/src/libmicrohttpd -fdebug-prefix-map=$sources/libmicrohttpd=/usr/src/libmicrohttpd"
yaml_flags="$common_flags -ffile-prefix-map=$sources/libyaml=/usr/src/libyaml -fdebug-prefix-map=$sources/libyaml=/usr/src/libyaml"

(
    cd "$sources/libmicrohttpd"
    CC="$CC" AR="$AR" RANLIB="$RANLIB" \
    CFLAGS="$mhd_flags" \
    ./configure \
        --prefix="$stage" \
        --enable-static \
        --disable-shared \
        --disable-dependency-tracking \
        --disable-doc \
        --disable-examples \
        --disable-tools \
        --enable-https=no \
        --enable-compiler-hardening \
        --enable-linker-hardening \
        >"$logs/libmicrohttpd-configure.log" 2>&1
    make -j"$(getconf _NPROCESSORS_ONLN)" \
        >"$logs/libmicrohttpd-build.log" 2>&1
    make install >"$logs/libmicrohttpd-install.log" 2>&1
)

(
    cd "$sources/libyaml"
    CC="$CC" AR="$AR" RANLIB="$RANLIB" \
    CFLAGS="$yaml_flags" \
    ./configure \
        --prefix="$stage" \
        --enable-static \
        --disable-shared \
        --disable-dependency-tracking \
        >"$logs/libyaml-configure.log" 2>&1
    make -j"$(getconf _NPROCESSORS_ONLN)" \
        >"$logs/libyaml-build.log" 2>&1
    make install >"$logs/libyaml-install.log" 2>&1
)

for archive in "$stage/lib/libmicrohttpd.a" "$stage/lib/libyaml.a"; do
    [ -f "$archive" ] || {
        echo "static dependency archive missing: $archive" >&2
        exit 1
    }
    "$AR" sD "$archive"
done
if find "$stage" -type f \( -name '*.so' -o -name '*.so.*' \) -print -quit |
   grep . >/dev/null; then
    echo 'static dependency prefix unexpectedly contains a shared library' >&2
    exit 1
fi
"$NM" "$stage/lib/libmicrohttpd.a" | grep -Eq '[[:space:]]T[[:space:]]+MHD_start_daemon$'
"$NM" "$stage/lib/libyaml.a" | grep -Eq '[[:space:]]T[[:space:]]+yaml_parser_initialize$'

metadata=$stage/share/fastbed-static-deps
licenses=$metadata/licenses
rebuild=$metadata/rebuild
mkdir -p "$licenses" "$rebuild/tools"
cp "$sources/libmicrohttpd/COPYING" "$licenses/libmicrohttpd-COPYING"
cp "$sources/libyaml/License" "$licenses/libyaml-License"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cp "$script_dir/build-static-deps.sh" "$rebuild/tools/build-static-deps.sh"

cat >"$metadata/COMPONENTS.tsv" <<'EOF'
component	version	source_sha256	license_file	archive
libmicrohttpd	1.0.10	04bfe8ef75db7d629a33de767599765cecadc56274a39822d5d081030d577685	libmicrohttpd-COPYING	lib/libmicrohttpd.a
libyaml	0.2.5	c642ae9b75fee120b2d96c712538bd2cf283228d2337df2cf2988e3c02678ef4	libyaml-License	lib/libyaml.a
EOF

manifest=$metadata/BUILD-MANIFEST.txt
{
    printf 'profile=fastbed-static-deps-v1\n'
    printf 'target_arch=%s\n' "$target_arch"
    printf 'host_machine=%s\n' "$machine"
    printf 'source_date_epoch=%s\n' "$source_date_epoch"
    printf 'libmicrohttpd_version=1.0.10\n'
    printf 'libmicrohttpd_source_sha256=04bfe8ef75db7d629a33de767599765cecadc56274a39822d5d081030d577685\n'
    printf 'libmicrohttpd_archive_sha256=%s\n' \
        "$(sha256sum "$stage/lib/libmicrohttpd.a" | awk '{print $1}')"
    printf 'libyaml_version=0.2.5\n'
    printf 'libyaml_source_sha256=c642ae9b75fee120b2d96c712538bd2cf283228d2337df2cf2988e3c02678ef4\n'
    printf 'libyaml_archive_sha256=%s\n' \
        "$(sha256sum "$stage/lib/libyaml.a" | awk '{print $1}')"
    printf 'builder_sha256=%s\n' \
        "$(sha256sum "$script_dir/build-static-deps.sh" | awk '{print $1}')"
    printf 'cc=%s\n' "$("$CC" --version | sed -n '1p')"
    printf 'ar=%s\n' "$("$AR" --version | sed -n '1p')"
    printf 'ranlib=%s\n' "$("$RANLIB" --version | sed -n '1p')"
} >"$manifest"

cat >"$metadata/SOURCE-OFFER.txt" <<'EOF'
This prefix embeds libmicrohttpd and libyaml as static archives. The exact
builder is under rebuild/. A distributable Fastbed release must retain the
verified upstream source archives and the LGPL relink kit named by its build
receipt. Rebuild natively on the target architecture with:

    rebuild/tools/build-static-deps.sh OUTPUT_DIR TARGETARCH
EOF

sums=$metadata/SHA256SUMS
(
    cd "$stage"
    find . -type f ! -path './share/fastbed-static-deps/SHA256SUMS' -print |
        sed 's#^\./##' | LC_ALL=C sort |
        while IFS= read -r file; do sha256sum "$file"; done
) >"$sums"
(
    cd "$stage"
    sha256sum -c share/fastbed-static-deps/SHA256SUMS >/dev/null
)

source_output=$(printenv FASTBED_STATIC_DEPS_SOURCE_ARCHIVES_OUTPUT 2>/dev/null || true)
if [ -n "$source_output" ]; then
    case "$source_output" in
        /*) ;;
        *) echo 'FASTBED_STATIC_DEPS_SOURCE_ARCHIVES_OUTPUT must be absolute' >&2; exit 2 ;;
    esac
    [ ! -e "$source_output" ] || {
        echo "source archive output already exists: $source_output" >&2
        exit 2
    }
    mkdir -p "$source_output"
    cp "$downloads/libmicrohttpd-1.0.10.tar.gz" \
       "$downloads/yaml-0.2.5.tar.gz" "$source_output/"
    (
        cd "$source_output"
        sha256sum libmicrohttpd-1.0.10.tar.gz yaml-0.2.5.tar.gz >SHA256SUMS
        sha256sum -c SHA256SUMS >/dev/null
    )
fi

mv -- "$stage" "$output"
trap - EXIT HUP INT TERM
cleanup
printf '%s\n' "$output"

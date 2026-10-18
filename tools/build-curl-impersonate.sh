#!/bin/sh
set -eu

usage() {
    echo 'usage: build-curl-impersonate.sh OUTPUT_DIR [amd64|arm64]' >&2
    exit 2
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    usage
fi

output_arg=$1
target_arch=
if [ "$#" -eq 2 ]; then
    target_arch=$2
fi
case "$output_arg" in
    /*) output=$output_arg ;;
    *) output=$PWD/$output_arg ;;
esac
if [ -e "$output" ]; then
    echo "output already exists: $output" >&2
    exit 2
fi

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

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
patch_dir=$repo_dir/third_party/curl-impersonate/patches
curl_patch=$patch_dir/0001-curl-8.23.0-v1.5.2-production.patch
boringssl_base_patch=$patch_dir/0002-boringssl-v1.5.2-base.patch
boringssl_security_patch=$patch_dir/0003-boringssl-CVE-2026-35189.patch
brotli_patch=$patch_dir/0004-brotli-v1.5.2.patch
nghttp2_patch=$patch_dir/0005-nghttp2-1.68.1-outbound-priority-compat.patch

curl_patch_sha256=5b7034eb94c458eac87a775b6306401b875d7baae13f1aecc443554c8e65c083
boringssl_base_patch_sha256=f6315235ea19778fbca8b6544732024f854f38eaa5a600d621f1ac55b4e22424
boringssl_security_patch_sha256=2c9277a0576c6ed943386490c1ed53ba2e5b8ccef2f1ec4c0c326e4e2177c2dd
brotli_patch_sha256=d59ec1994ae6285222f65dd7192c2cbcbc0d0ae6c85eb5fce1cae735010f4d4f
nghttp2_patch_sha256=bf30fc417c26afcaafe732629073db13fc1563edcd7964ee7c1fbf300f7eb3f3

check_hash() {
    expected=$1
    file=$2
    printf '%s  %s\n' "$expected" "$file" | sha256sum -c -
}

check_hash "$curl_patch_sha256" "$curl_patch"
check_hash "$boringssl_base_patch_sha256" "$boringssl_base_patch"
check_hash "$boringssl_security_patch_sha256" "$boringssl_security_patch"
check_hash "$brotli_patch_sha256" "$brotli_patch"
check_hash "$nghttp2_patch_sha256" "$nghttp2_patch"

keep_work=$(printenv FASTBED_CURL_KEEP_WORK 2>/dev/null || true)
case "$keep_work" in
    ''|0) keep_work=0 ;;
    1) ;;
    *) echo 'FASTBED_CURL_KEEP_WORK must be 0 or 1' >&2; exit 2 ;;
esac
work=/tmp/fastbed-curl-impersonate-$target_arch
if ! (umask 077 && mkdir "$work"); then
    echo "deterministic curl build root already exists: $work" >&2
    echo 'wait for the other build or remove a deliberately retained work tree' >&2
    exit 2
fi
cleanup() {
    if [ "$keep_work" -eq 1 ]; then
        echo "retained curl build work directory: $work" >&2
        return
    fi
    case "$work" in
        /tmp/fastbed-curl-impersonate-amd64|/tmp/fastbed-curl-impersonate-arm64)
            rm -rf -- "$work"
            ;;
        *) echo "refusing to remove unexpected work directory: $work" >&2 ;;
    esac
}
trap cleanup EXIT HUP INT TERM

cache=$work/cache
cache_override=$(printenv FASTBED_CURL_DOWNLOAD_CACHE 2>/dev/null || true)
if [ -n "$cache_override" ]; then
    case "$cache_override" in
        /*) cache=$cache_override ;;
        *) cache=$PWD/$cache_override ;;
    esac
fi
downloads=$work/downloads
sources=$work/sources
logs=$work/logs
deps=$work/deps
curl_build=$work/curl-build
curl_install=$work/curl-install
mkdir -p -- "$cache" "$downloads" "$sources" "$logs" "$deps"

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

# Retain content-addressed release signature/checksum bytes with the sources.
# Authenticating the signer keyrings is a separate release gate.
download_verified https://curl.se/download/curl-8.23.0.tar.xz \
    8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5 \
    curl-8.23.0.tar.xz
download_verified https://curl.se/download/curl-8.23.0.tar.xz.asc \
    dba1562fec2bf698a1226054e6757940e4bf2ab87b3b222a5e7b91348f0b82e2 \
    curl-8.23.0.tar.xz.asc
download_verified \
    https://github.com/lexiforest/curl-impersonate/archive/9607b22ccf6c440e560c5f8ad5292b8044bb6dd7.tar.gz \
    19bcc1aa84a9a69b2ff471af580cae5970baf15e13f77271b0b66c86baeaa131 \
    curl-impersonate-9607b22ccf6c440e560c5f8ad5292b8044bb6dd7.tar.gz
download_verified \
    https://github.com/google/boringssl/archive/673e61fc215b178a90c0e67858bbf162c8158993.zip \
    edb7d61e8de3f791070172723ee41fbc550fb55080cdb187bb4a05e60e059a22 \
    boringssl-673e61fc215b178a90c0e67858bbf162c8158993.zip
download_verified \
    https://github.com/nghttp2/nghttp2/releases/download/v1.68.1/nghttp2-1.68.1.tar.bz2 \
    b761b53cb64916657ea84437973d508fd675e96bb2feb9593a1e43d1959abe95 \
    nghttp2-1.68.1.tar.bz2
download_verified \
    https://github.com/nghttp2/nghttp2/releases/download/v1.68.1/nghttp2-1.68.1.tar.bz2.asc \
    95f96ddec895cbde8afce6b10ac036240cb79bde1fc0f693308e95bcbb6e6f7c \
    nghttp2-1.68.1.tar.bz2.asc
download_verified \
    https://github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.gz \
    bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16 \
    zlib-1.3.2.tar.gz
download_verified \
    https://github.com/madler/zlib/releases/download/v1.3.2/zlib-1.3.2.tar.gz.asc \
    977472e4d306906adbe34f8b1fdbf58c46fe8b4ade1c92117816b8281c5ee096 \
    zlib-1.3.2.tar.gz.asc
download_verified \
    https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz \
    eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3 \
    zstd-1.5.7.tar.gz
download_verified \
    https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz.sha256 \
    954fa350e59ac782eaba5e04db608a0252b465eb3fc9dd02c426050956520161 \
    zstd-1.5.7.tar.gz.sha256
download_verified \
    https://github.com/facebook/zstd/releases/download/v1.5.7/zstd-1.5.7.tar.gz.sig \
    24425933fb954f4608ae9383bc37ad8398e50364c1ec30bbdb5adbfe88209fb1 \
    zstd-1.5.7.tar.gz.sig
download_verified \
    https://github.com/google/brotli/archive/refs/tags/v1.2.0.tar.gz \
    816c96e8e8f193b40151dad7e8ff37b1221d019dbcb9c35cd3fadbfe6477dfec \
    brotli-1.2.0.tar.gz
download_verified \
    https://ftp.gnu.org/gnu/libunistring/libunistring-1.4.2.tar.xz \
    5b46e74377ed7409c5b75e7a96f95377b095623b689d8522620927964a41499c \
    libunistring-1.4.2.tar.xz
download_verified \
    https://ftp.gnu.org/gnu/libunistring/libunistring-1.4.2.tar.xz.sig \
    45c91e28678c341a925a6b1237711d308249aef29db63d8df0376249ebf67d3b \
    libunistring-1.4.2.tar.xz.sig
download_verified \
    https://ftp.gnu.org/gnu/libidn/libidn2-2.3.8.tar.gz \
    f557911bf6171621e1f72ff35f5b1825bb35b52ed45325dcdee931e5d3c0787a \
    libidn2-2.3.8.tar.gz
download_verified \
    https://ftp.gnu.org/gnu/libidn/libidn2-2.3.8.tar.gz.sig \
    268ad6787ed902fba2154bcd64347269af6c4298bdeed8d7db59df7b65fd31f2 \
    libidn2-2.3.8.tar.gz.sig

tar -xJf "$downloads/curl-8.23.0.tar.xz" -C "$sources"
tar -xzf "$downloads/curl-impersonate-9607b22ccf6c440e560c5f8ad5292b8044bb6dd7.tar.gz" \
    -C "$sources"
unzip -q "$downloads/boringssl-673e61fc215b178a90c0e67858bbf162c8158993.zip" \
    -d "$sources"
tar -xjf "$downloads/nghttp2-1.68.1.tar.bz2" -C "$sources"
tar -xzf "$downloads/zlib-1.3.2.tar.gz" -C "$sources"
tar -xzf "$downloads/zstd-1.5.7.tar.gz" -C "$sources"
tar -xzf "$downloads/brotli-1.2.0.tar.gz" -C "$sources"
tar -xJf "$downloads/libunistring-1.4.2.tar.xz" -C "$sources"
tar -xzf "$downloads/libidn2-2.3.8.tar.gz" -C "$sources"

curl_source=$sources/curl-8.23.0
impersonate_source=$sources/curl-impersonate-9607b22ccf6c440e560c5f8ad5292b8044bb6dd7
boringssl_source=$sources/boringssl-673e61fc215b178a90c0e67858bbf162c8158993
nghttp2_source=$sources/nghttp2-1.68.1
brotli_source=$sources/brotli-1.2.0
zlib_source=$sources/zlib-1.3.2
zstd_source=$sources/zstd-1.5.7
unistring_source=$sources/libunistring-1.4.2
idn2_source=$sources/libidn2-2.3.8

(cd "$curl_source" && patch --batch --forward --fuzz=0 -p1 < "$curl_patch")
(cd "$boringssl_source" &&
    patch --batch --forward --fuzz=0 -p1 < "$boringssl_base_patch" &&
    patch --batch --forward --fuzz=0 -p1 < "$boringssl_security_patch")
(cd "$brotli_source" && patch --batch --forward --fuzz=0 -p1 < "$brotli_patch")
(cd "$nghttp2_source" && patch --batch --forward --fuzz=0 -p1 < "$nghttp2_patch")

# Reject a wrong base, offset, or patch order even if patch(1) accepts it.
check_hash 5f492fb8c930277864630c3f6661a437fe1d77338b782ceacb6c90ea25d84b44 "$curl_source/lib/http2.c"
check_hash 34a5c20e944ad4fc2c369984d1cd149a2c998cb775a77d668faf17ceb005bcc0 "$curl_source/lib/easy.c"
check_hash 237e7dd71737ef7fd59579ff33d5c448c2f6151ad7788b7ae586afe91c9d22fa "$curl_source/lib/impersonate.c"
check_hash c47c67ed9ca5346b9bb5d26b8e5190e2d7f5355ed12327e8034577bcbf66e3d1 "$curl_source/lib/easygetopt.c"
check_hash de48350e2a424db0cacea7120abdcb0c151d40d119198112da858da801c5d1fc "$curl_source/include/curl/curl.h"
check_hash 4d067e93f4519945b37c5781ce0e33f489a8813fc443b99647a16234b7a01869 "$curl_source/lib/vtls/openssl.c"
check_hash b81cc94a5f2bec83cef2c5fd566aa7e05712c87d2fe20e6d8eeca79dd1cd9233 "$boringssl_source/crypto/x509/x509_vfy.cc"
check_hash 5cab73674a447d8e276dc09c36e3d369dc07b9eee02c80fdc517f652b05feb81 "$boringssl_source/include/openssl/x509.h"
check_hash 87376614f0704a5dc742f8e8d2caa2e30709f82e1b39931c9336ead70e07b7ed "$boringssl_source/ssl/extensions.cc"
check_hash 159fdac71e2f8df2601b07a2c0afb7a90ce6d572fb110f8dc2a509d622f32da6 "$nghttp2_source/lib/nghttp2_submit.c"
check_hash 8d9c0be1199ab6181d0998a78e49dc34fdbdb75d27922f2a4f66c923b1fd557a "$nghttp2_source/lib/nghttp2_session.c"
check_hash f6c02069ba5fa1600d181a319b3c3efe0be71f8ec7afcbd8e579b62cc4eb665f "$brotli_source/c/common/platform.h"

jobs=$(printenv FASTBED_CURL_JOBS 2>/dev/null || true)
if [ -z "$jobs" ]; then
    jobs=$(getconf _NPROCESSORS_ONLN)
fi
case "$jobs" in
    ''|*[!0-9]*|0) echo "invalid FASTBED_CURL_JOBS: $jobs" >&2; exit 2 ;;
esac

export LC_ALL=C
export TZ=UTC
export SOURCE_DATE_EPOCH=1774606016
export ZERO_AR_DATE=1
export CC=clang
export CXX=clang++
export AR=ar
export RANLIB=ranlib
common_flags="-O3 -g1 -fPIC -ffunction-sections -fdata-sections"
common_flags="$common_flags -fno-semantic-interposition -fstack-protector-strong"
common_flags="$common_flags -fno-common -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"
common_flags="$common_flags -ffile-prefix-map=$work=/usr/src/fastbed-curl-stack"
common_flags="$common_flags -fdebug-prefix-map=$work=/usr/src/fastbed-curl-stack"
recorded_common_flags='-O3 -g1 -fPIC -ffunction-sections -fdata-sections'
recorded_common_flags="$recorded_common_flags -fno-semantic-interposition -fstack-protector-strong"
recorded_common_flags="$recorded_common_flags -fno-common -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3"
recorded_common_flags="$recorded_common_flags -ffile-prefix-map=<BUILD_ROOT>=/usr/src/fastbed-curl-stack"
recorded_common_flags="$recorded_common_flags -fdebug-prefix-map=<BUILD_ROOT>=/usr/src/fastbed-curl-stack"
export CFLAGS=$common_flags
export CXXFLAGS=$common_flags
export LDFLAGS=-Wl,--gc-sections
export PKG_CONFIG_PATH=$deps/lib/pkgconfig

for command in "$CC" "$CXX" "$AR" "$RANLIB" ar awk cmake curl find make \
               ninja nm patch pkg-config readelf sed sha256sum strip tar \
               unzip xz; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required command not found: $command" >&2
        exit 2
    }
done

(cd "$zlib_source" &&
    ./configure --prefix="$deps" --static &&
    make -j"$jobs" &&
    make install) >"$logs/zlib.log" 2>&1

(cd "$zstd_source" &&
    make -C lib -j"$jobs" BUILD_SHARED=0 BUILD_STATIC=1 libzstd.a &&
    mkdir -p "$deps/lib" "$deps/include" &&
    cp lib/libzstd.a "$deps/lib/" &&
    cp lib/zstd.h lib/zstd_errors.h lib/zdict.h "$deps/include/") \
    >"$logs/zstd.log" 2>&1

(cmake -S "$brotli_source" -B "$brotli_source/out" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$deps" \
        -DCMAKE_INSTALL_LIBDIR=lib \
        -DBUILD_SHARED_LIBS=OFF \
        -DBROTLI_DISABLE_TESTS=ON \
        -DBROTLI_DISABLE_TOOLS=ON \
        -DBROTLI_BUILD_TOOLS=OFF \
        -DCMAKE_MACOSX_BUNDLE=OFF &&
    cmake --build "$brotli_source/out" --target install --parallel "$jobs") \
    >"$logs/brotli.log" 2>&1

(cmake -S "$boringssl_source" -B "$boringssl_source/build" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
        -DCMAKE_C_FLAGS="$CFLAGS -Wno-unknown-warning-option -Wno-stringop-overflow -Wno-array-bounds -Wno-macro-redefined" \
        -DCMAKE_CXX_FLAGS="$CXXFLAGS -Wno-macro-redefined" &&
    cmake --build "$boringssl_source/build" \
        --target crypto ssl --parallel "$jobs" &&
    mkdir -p "$deps/include" "$deps/lib" &&
    cp -R "$boringssl_source/include/openssl" "$deps/include/" &&
    cp "$boringssl_source/build/crypto/libcrypto.a" "$deps/lib/" &&
    cp "$boringssl_source/build/ssl/libssl.a" "$deps/lib/") \
    >"$logs/boringssl.log" 2>&1

(cd "$nghttp2_source" &&
    ./configure --prefix="$deps" --with-pic --enable-lib-only \
        --disable-shared --enable-static --disable-python-bindings &&
    make -j"$jobs" &&
    make install) >"$logs/nghttp2.log" 2>&1

(cd "$unistring_source" &&
    ./configure --prefix="$deps" --disable-shared --enable-static --with-pic &&
    make -j"$jobs" &&
    make install) >"$logs/libunistring.log" 2>&1

(cd "$idn2_source" &&
    ./configure --prefix="$deps" --disable-shared --enable-static --with-pic \
        --disable-nls &&
    make -j"$jobs" &&
    make install) >"$logs/libidn2.log" 2>&1

cmake -S "$curl_source" -B "$curl_build" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$curl_install" \
    -DCMAKE_INSTALL_LIBDIR=lib \
    -DCMAKE_PREFIX_PATH="$deps" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_EXE_LINKER_FLAGS="-Wl,--gc-sections" \
    -DCMAKE_C_STANDARD_LIBRARIES="$deps/lib/libunistring.a" \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_STATIC_LIBS=ON \
    -DBUILD_STATIC_CURL=ON \
    -DBUILD_CURL_EXE=ON \
    -DBUILD_EXAMPLES=OFF \
    -DBUILD_LIBCURL_DOCS=OFF \
    -DBUILD_MISC_DOCS=OFF \
    -DBUILD_TESTING=OFF \
    -DCURL_ENABLE_SSL=ON \
    -DCURL_USE_OPENSSL=ON \
    -DCURL_USE_PKGCONFIG=ON \
    -DOPENSSL_ROOT_DIR="$deps" \
    -DOPENSSL_INCLUDE_DIR="$deps/include" \
    -DOPENSSL_SSL_LIBRARY="$deps/lib/libssl.a" \
    -DOPENSSL_CRYPTO_LIBRARY="$deps/lib/libcrypto.a" \
    -DOPENSSL_USE_STATIC_LIBS=ON \
    -DUSE_ECH=ON \
    -DUSE_HTTPSRR=ON \
    -DUSE_NGHTTP2=ON \
    -DNGHTTP2_INCLUDE_DIR="$deps/include" \
    -DNGHTTP2_LIBRARY="$deps/lib/libnghttp2.a" \
    -DUSE_NGTCP2=OFF \
    -DUSE_PROXY_HTTP3=OFF \
    -DUSE_QUICHE=OFF \
    -DUSE_LIBIDN2=ON \
    -DUSE_SSLS_EXPORT=ON \
    -DCURL_ZLIB=ON \
    -DZLIB_ROOT="$deps" \
    -DZLIB_INCLUDE_DIR="$deps/include" \
    -DZLIB_LIBRARY="$deps/lib/libz.a" \
    -DCURL_ZSTD=ON \
    -DZSTD_INCLUDE_DIR="$deps/include" \
    -DZSTD_LIBRARY="$deps/lib/libzstd.a" \
    -DCURL_BROTLI=ON \
    -DENABLE_ARES=OFF \
    -DENABLE_THREADED_RESOLVER=ON \
    -DENABLE_UNIX_SOCKETS=OFF \
    -DENABLE_IPV6=ON \
    -DENABLE_CURL_MANUAL=ON \
    -DCURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    -DCURL_CA_PATH=/etc/ssl/certs \
    -DCURL_USE_LIBPSL=OFF \
    -DCURL_ENABLE_NTLM=OFF \
    -DCURL_DISABLE_DICT=ON \
    -DCURL_DISABLE_DOH=ON \
    -DCURL_DISABLE_FILE=ON \
    -DCURL_DISABLE_FTP=ON \
    -DCURL_DISABLE_GETOPTIONS=ON \
    -DCURL_DISABLE_GOPHER=ON \
    -DCURL_DISABLE_HTTPSIG=ON \
    -DCURL_DISABLE_IMAP=ON \
    -DCURL_DISABLE_IPFS=ON \
    -DCURL_DISABLE_LDAP=ON \
    -DCURL_DISABLE_LDAPS=ON \
    -DCURL_DISABLE_MQTT=ON \
    -DCURL_DISABLE_POP3=ON \
    -DCURL_DISABLE_RTSP=ON \
    -DCURL_DISABLE_SMTP=ON \
    -DCURL_DISABLE_TELNET=ON \
    -DCURL_DISABLE_TFTP=ON \
    -DCURL_DISABLE_WEBSOCKETS=ON \
    >"$logs/curl-configure.log" 2>&1
cmake --build "$curl_build" --parallel "$jobs" >"$logs/curl-build.log" 2>&1
cmake --install "$curl_build" >"$logs/curl-install.log" 2>&1

curl_cli=$curl_install/bin/curl-impersonate
curl_archive=$curl_install/lib/libcurl-impersonate.a
for file in "$curl_cli" "$curl_archive" \
            "$deps/lib/libssl.a" "$deps/lib/libcrypto.a" \
            "$deps/lib/libnghttp2.a" "$deps/lib/libidn2.a" \
            "$deps/lib/libunistring.a" "$deps/lib/libzstd.a" \
            "$deps/lib/libbrotlidec.a" "$deps/lib/libbrotlicommon.a" \
            "$deps/lib/libz.a"; do
    test -f "$file" || {
        echo "required curl H2 build output missing: $file" >&2
        exit 1
    }
done
for forbidden in "$curl_install/lib/libnghttp3.a" \
                 "$curl_install/lib/libngtcp2.a" \
                 "$curl_install/lib/libngtcp2_crypto_boringssl.a" \
                 "$deps/lib/libnghttp3.a" "$deps/lib/libngtcp2.a" \
                 "$deps/lib/libngtcp2_crypto_boringssl.a"; do
    if [ -e "$forbidden" ]; then
        echo "HTTP/3 dependency present in H2-only production prefix: $forbidden" >&2
        exit 1
    fi
done

version_output=$("$curl_cli" -V)
printf '%s\n' "$version_output"
case "$version_output" in
    *"curl 8.23.0-IMPERSONATE"*"BoringSSL"*) ;;
    *) echo 'unexpected curl/BoringSSL version inventory' >&2; exit 1 ;;
esac
protocol_line=$(printf '%s\n' "$version_output" | sed -n 's/^Protocols: //p')
if [ "$protocol_line" != 'http https' ]; then
    echo "unexpected production curl protocols: $protocol_line" >&2
    exit 1
fi
feature_line=$(printf '%s\n' "$version_output" | sed -n 's/^Features: //p')
for feature in alt-svc AsynchDNS brotli ECH HSTS HTTP2 HTTPS-proxy HTTPSRR \
               IDN IPv6 Largefile libz SSL SSLS-EXPORT threadsafe zstd; do
    case " $feature_line " in
        *" $feature "*) ;;
        *) echo "required curl feature missing: $feature" >&2; exit 1 ;;
    esac
done
for forbidden_feature in HTTP3 UnixSockets; do
    case " $feature_line " in
        *" $forbidden_feature "*)
            echo "forbidden curl feature present: $forbidden_feature" >&2
            exit 1
            ;;
    esac
done
if ! nm -g --defined-only "$curl_archive" |
     awk '$3 == "curl_easy_impersonate" { found = 1 } END { exit !found }'; then
    echo 'curl_easy_impersonate is not exported' >&2
    exit 1
fi

cat >"$work/api-probe.c" <<'EOF'
#include <curl/curl.h>
#include <stdio.h>

static CURLcode check_profile(const char *name, int default_headers) {
    CURL *easy = curl_easy_init();
    CURLcode status;
    if (easy == NULL) {
        return CURLE_FAILED_INIT;
    }
    status = curl_easy_impersonate(easy, name, default_headers);
    curl_easy_cleanup(easy);
    return status;
}

int main(void) {
    CURLcode first;
    CURLcode second;
    CURLcode invalid;
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        return 2;
    }
    first = check_profile("chrome146", 0);
    second = check_profile("chrome146", 1);
    invalid = check_profile("fastbed-invalid-profile", 0);
    curl_global_cleanup();
    printf("%d %d %d\n", (int)first, (int)second, (int)invalid);
    return first == CURLE_OK && second == CURLE_OK &&
                   invalid == CURLE_BAD_FUNCTION_ARGUMENT
               ? 0
               : 1;
}
EOF
"$CC" $CFLAGS -I"$curl_install/include" -c "$work/api-probe.c" \
    -o "$work/api-probe.o"
"$CXX" -Wl,--gc-sections -o "$work/api-probe" \
    "$work/api-probe.o" -Wl,--start-group \
    "$curl_archive" "$deps/lib/libnghttp2.a" "$deps/lib/libidn2.a" \
    "$deps/lib/libunistring.a" "$deps/lib/libssl.a" \
    "$deps/lib/libcrypto.a" "$deps/lib/libzstd.a" \
    "$deps/lib/libbrotlidec.a" "$deps/lib/libbrotlicommon.a" \
    "$deps/lib/libz.a" -Wl,--end-group -pthread -ldl -lm
api_probe_output=$("$work/api-probe")
if [ "$api_probe_output" != '0 0 43' ]; then
    echo "unexpected curl_easy_impersonate API result: $api_probe_output" >&2
    exit 1
fi

machine_header=$(readelf -h "$curl_cli")
case "$target_arch:$machine_header" in
    amd64:*"Advanced Micro Devices X86-64"*|arm64:*"AArch64"*) ;;
    *) echo "curl binary architecture does not match $target_arch" >&2; exit 1 ;;
esac

stage=$work/stage
metadata=$stage/share/fastbed-curl-impersonate
licenses=$metadata/licenses
rebuild=$metadata/rebuild
mkdir -p "$stage/bin" "$stage/include" "$stage/lib" "$licenses" \
    "$rebuild/tools" "$rebuild/third_party/curl-impersonate/patches"
cp "$curl_cli" "$stage/bin/curl-impersonate"
strip --strip-unneeded "$stage/bin/curl-impersonate"
cp -R "$deps/include/." "$stage/include/"
rm -rf "$stage/include/curl"
cp -R "$curl_install/include/curl" "$stage/include/"
for library in libcurl-impersonate.a libnghttp2.a libidn2.a libunistring.a \
               libssl.a libcrypto.a libzstd.a libbrotlidec.a \
               libbrotlicommon.a libz.a; do
    case "$library" in
        libcurl-impersonate.a) source_library=$curl_archive ;;
        *) source_library=$deps/lib/$library ;;
    esac
    cp "$source_library" "$stage/lib/$library"
done
# Some upstream build systems recreate the archive symbol-table member without
# deterministic mode even when object members are identical. Re-index every
# staged archive in deterministic mode so wall-clock build time cannot change
# the production prefix or its receipt.
for library in "$stage"/lib/*.a; do
    ar sD "$library"
done

cp "$impersonate_source/LICENSE" "$licenses/curl-impersonate-LICENSE"
cp "$curl_source/COPYING" "$licenses/curl-COPYING"
cp "$boringssl_source/LICENSE" "$licenses/boringssl-LICENSE"
cp "$brotli_source/LICENSE" "$licenses/brotli-LICENSE"
cp "$nghttp2_source/COPYING" "$licenses/nghttp2-COPYING"
cp "$zlib_source/LICENSE" "$licenses/zlib-LICENSE"
cp "$zstd_source/LICENSE" "$licenses/zstd-LICENSE"
cp "$unistring_source/COPYING" "$licenses/libunistring-COPYING"
cp "$unistring_source/COPYING.LIB" "$licenses/libunistring-COPYING.LIB"
cp "$idn2_source/COPYING" "$licenses/libidn2-COPYING"
cp "$idn2_source/COPYING.LESSERv3" "$licenses/libidn2-COPYING.LESSERv3"
cp "$idn2_source/COPYING.unicode" "$licenses/libidn2-COPYING.unicode"
cp "$idn2_source/COPYINGv2" "$licenses/libidn2-COPYINGv2"

check_hash 7d0c5f4b5b4c27299ad6759798772b866b3559ac5edb23845f36328eb734376d "$licenses/curl-impersonate-LICENSE"
check_hash 82f2f4427d6545ee5aaac4f0b80428da6cc8ba41c2cf5da3a03680ec327b9681 "$licenses/curl-COPYING"
check_hash 005fc765ddc5115da796cca915baa9557abae13ff35e0a47c47affc56f6c414d "$licenses/boringssl-LICENSE"
check_hash 3d180008e36922a4e8daec11c34c7af264fed5962d07924aea928c38e8663c94 "$licenses/brotli-LICENSE"
check_hash 6b94f3abc1aabd0c72a7c7d92a77f79dda7c8a0cb3df839a97890b4116a2de2a "$licenses/nghttp2-COPYING"
check_hash e32ff4e00d9d94930537635291da39e7e612703334bf6fde8c7f1686fe8a45a2 "$licenses/zlib-LICENSE"
check_hash 7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8 "$licenses/zstd-LICENSE"
check_hash 3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986 "$licenses/libunistring-COPYING"
check_hash a853c2ffec17057872340eee242ae4d96cbf2b520ae27d903e1b2fef1a5f9d1c "$licenses/libunistring-COPYING.LIB"
check_hash 3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986 "$licenses/libidn2-COPYING"
check_hash e3a994d82e644b03a792a930f574002658412f62407f5fee083f2555c5f23118 "$licenses/libidn2-COPYING.LESSERv3"
check_hash 01d621eef165cf4d3d3dbb737aa0699178d94c6f18cf87e9dde6db3ca7790f46 "$licenses/libidn2-COPYING.unicode"
check_hash edaef632cbb643e4e7a221717a6c441a4c1a7c918e6e4d56debc3d8739b233f6 "$licenses/libidn2-COPYINGv2"

cp "$script_dir/build-curl-impersonate.sh" "$rebuild/tools/build-curl-impersonate.sh"
for patch_file in "$curl_patch" "$boringssl_base_patch" \
                  "$boringssl_security_patch" "$brotli_patch" \
                  "$nghttp2_patch"; do
    cp "$patch_file" "$rebuild/third_party/curl-impersonate/patches/"
done

cat >"$metadata/SOURCE-OFFER.txt" <<'EOF'
The exact content-addressed source builder and production patches are in rebuild/.
Verified upstream source archives and signature/checksum bytes are retained in
the matching release-artifacts source/curl-impersonate directory, outside the
runtime image. Rebuild on the target architecture with:

    rebuild/tools/build-curl-impersonate.sh OUTPUT_DIR TARGETARCH

Fastbed statically links LGPL libidn2 and libunistring. A distributable Fastbed
release must also retain the corresponding sources, application objects, exact
archives, link command, and effective relink instructions.
EOF

cat >"$metadata/COMPONENTS.tsv" <<'EOF'
component	version_or_revision	source_sha256	license_file
curl-impersonate	9607b22ccf6c440e560c5f8ad5292b8044bb6dd7	19bcc1aa84a9a69b2ff471af580cae5970baf15e13f77271b0b66c86baeaa131	curl-impersonate-LICENSE
curl	curl-8_23_0	8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5	curl-COPYING
BoringSSL	673e61fc215b178a90c0e67858bbf162c8158993	edb7d61e8de3f791070172723ee41fbc550fb55080cdb187bb4a05e60e059a22	boringssl-LICENSE
brotli	1.2.0	816c96e8e8f193b40151dad7e8ff37b1221d019dbcb9c35cd3fadbfe6477dfec	brotli-LICENSE
nghttp2	1.68.1	b761b53cb64916657ea84437973d508fd675e96bb2feb9593a1e43d1959abe95	nghttp2-COPYING
zlib	1.3.2	bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16	zlib-LICENSE
zstd	1.5.7	eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3	zstd-LICENSE
libunistring	1.4.2	5b46e74377ed7409c5b75e7a96f95377b095623b689d8522620927964a41499c	libunistring-COPYING.LIB
libidn2	2.3.8	f557911bf6171621e1f72ff35f5b1825bb35b52ed45325dcdee931e5d3c0787a	libidn2-COPYING.LESSERv3
EOF

header_tree_sha=$(
    CDPATH= cd -- "$stage/include/curl"
    find . -type f -print | LC_ALL=C sort |
        while IFS= read -r header; do sha256sum "$header"; done |
        sha256sum | awk '{print $1}'
)
version_output_sha=$(printf '%s\n' "$version_output" | sha256sum | awk '{print $1}')
manifest=$metadata/BUILD-MANIFEST.txt
{
    printf 'profile=http2-only\n'
    printf 'target_arch=%s\n' "$target_arch"
    printf 'host_machine=%s\n' "$machine"
    printf 'source_date_epoch=%s\n' "$SOURCE_DATE_EPOCH"
    printf 'curl_version=8.23.0-IMPERSONATE\n'
    printf 'protocols=http,https\n'
    printf 'http3=false\n'
    printf 'resolver_backend=threaded\n'
    printf 'curl_source_sha256=8dadd7d2536a314f982ad05a651b713f426bf7d02cc2c76cffb9796f2218e6c5\n'
    printf 'curl_source_signature_sha256=dba1562fec2bf698a1226054e6757940e4bf2ab87b3b222a5e7b91348f0b82e2\n'
    printf 'curl_impersonate_source_commit=9607b22ccf6c440e560c5f8ad5292b8044bb6dd7\n'
    printf 'curl_impersonate_source_sha256=19bcc1aa84a9a69b2ff471af580cae5970baf15e13f77271b0b66c86baeaa131\n'
    printf 'curl_production_patch_sha256=%s\n' "$curl_patch_sha256"
    printf 'curl_http2_source_sha256=5f492fb8c930277864630c3f6661a437fe1d77338b782ceacb6c90ea25d84b44\n'
    printf 'curl_easy_source_sha256=34a5c20e944ad4fc2c369984d1cd149a2c998cb775a77d668faf17ceb005bcc0\n'
    printf 'curl_impersonate_source_file_sha256=237e7dd71737ef7fd59579ff33d5c448c2f6151ad7788b7ae586afe91c9d22fa\n'
    printf 'curl_public_headers_sha256=%s\n' "$header_tree_sha"
    printf 'boringssl_revision=673e61fc215b178a90c0e67858bbf162c8158993\n'
    printf 'boringssl_source_sha256=edb7d61e8de3f791070172723ee41fbc550fb55080cdb187bb4a05e60e059a22\n'
    printf 'boringssl_base_patch_sha256=%s\n' "$boringssl_base_patch_sha256"
    printf 'boringssl_security_patch_sha256=%s\n' "$boringssl_security_patch_sha256"
    printf 'boringssl_security_prerequisite_commit=5386d908a663a424d154cbae7f76f2266c60c2fe\n'
    printf 'boringssl_security_fix_commit=9b639f5b3b086508c03f6a4a1792e4a6043777ac\n'
    printf 'boringssl_patched_x509_vfy_sha256=b81cc94a5f2bec83cef2c5fd566aa7e05712c87d2fe20e6d8eeca79dd1cd9233\n'
    printf 'nghttp2_version=1.68.1\n'
    printf 'nghttp2_source_sha256=b761b53cb64916657ea84437973d508fd675e96bb2feb9593a1e43d1959abe95\n'
    printf 'nghttp2_source_signature_sha256=95f96ddec895cbde8afce6b10ac036240cb79bde1fc0f693308e95bcbb6e6f7c\n'
    printf 'nghttp2_priority_compat_patch_sha256=%s\n' "$nghttp2_patch_sha256"
    printf 'nghttp2_patched_submit_sha256=159fdac71e2f8df2601b07a2c0afb7a90ce6d572fb110f8dc2a509d622f32da6\n'
    printf 'nghttp2_security_session_sha256=8d9c0be1199ab6181d0998a78e49dc34fdbdb75d27922f2a4f66c923b1fd557a\n'
    printf 'brotli_patch_sha256=%s\n' "$brotli_patch_sha256"
    printf 'curl_version_output_sha256=%s\n' "$version_output_sha"
    printf 'curl_easy_impersonate_probe=0,0,43\n'
    printf 'libcurl_sha256=%s\n' "$(sha256sum "$stage/lib/libcurl-impersonate.a" | awk '{print $1}')"
    printf 'libnghttp2_sha256=%s\n' "$(sha256sum "$stage/lib/libnghttp2.a" | awk '{print $1}')"
    printf 'libssl_sha256=%s\n' "$(sha256sum "$stage/lib/libssl.a" | awk '{print $1}')"
    printf 'libcrypto_sha256=%s\n' "$(sha256sum "$stage/lib/libcrypto.a" | awk '{print $1}')"
    printf 'builder_sha256=%s\n' "$(sha256sum "$script_dir/build-curl-impersonate.sh" | awk '{print $1}')"
    printf 'cc=%s\n' "$("$CC" --version | sed -n '1p')"
    printf 'cxx=%s\n' "$("$CXX" --version | sed -n '1p')"
    printf 'cflags=%s\n' "$recorded_common_flags"
    printf 'cxxflags=%s\n' "$recorded_common_flags"
    printf 'ldflags=%s\n' "$LDFLAGS"
} >"$manifest"
printf '%s\n' "$version_output" >"$metadata/CURL-VERSION.txt"

sums=$metadata/SHA256SUMS
(cd "$stage" &&
    find . -type f ! -path './share/fastbed-curl-impersonate/SHA256SUMS' \
        -print | sed 's#^\./##' | LC_ALL=C sort |
        while IFS= read -r file; do sha256sum "$file"; done) >"$sums"
(cd "$stage" && sha256sum -c share/fastbed-curl-impersonate/SHA256SUMS >/dev/null)

source_output=$(printenv FASTBED_CURL_SOURCE_ARCHIVES_OUTPUT 2>/dev/null || true)
if [ -n "$source_output" ]; then
    case "$source_output" in
        /*) ;;
        *) echo 'FASTBED_CURL_SOURCE_ARCHIVES_OUTPUT must be absolute' >&2; exit 2 ;;
    esac
    if [ -e "$source_output" ]; then
        echo "source archive output already exists: $source_output" >&2
        exit 2
    fi
    mkdir -p "$source_output/patches"
    cp "$downloads"/* "$source_output/"
    cp "$curl_patch" "$boringssl_base_patch" "$boringssl_security_patch" \
        "$brotli_patch" "$nghttp2_patch" "$source_output/patches/"
    cp "$script_dir/build-curl-impersonate.sh" "$source_output/"
    (cd "$source_output" &&
        find . -type f ! -name SHA256SUMS -print |
            sed 's#^\./##' | LC_ALL=C sort |
            while IFS= read -r file; do sha256sum "$file"; done) \
        >"$source_output/SHA256SUMS"
    (cd "$source_output" && sha256sum -c SHA256SUMS >/dev/null)
fi

mkdir -p -- "$(dirname -- "$output")"
mv -- "$stage" "$output"
trap - EXIT HUP INT TERM
cleanup
printf 'built curl 8.23 H2-only production prefix: %s\n' "$output"

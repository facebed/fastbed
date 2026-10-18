# syntax=docker/dockerfile:1.12@sha256:93bfd3b68c109427185cd78b4779fc82b484b0b7618e36d0f104d4d801e66d25
ARG ALPINE_IMAGE=alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
ARG LIBMICROHTTPD_VERSION=1.0.10
ARG LIBMICROHTTPD_SHA256=04bfe8ef75db7d629a33de767599765cecadc56274a39822d5d081030d577685
ARG SOURCE_DATE_EPOCH=1774606016

FROM ${ALPINE_IMAGE} AS build
ARG ALPINE_IMAGE
ARG TARGETARCH
ARG LIBMICROHTTPD_VERSION
ARG LIBMICROHTTPD_SHA256
ARG SOURCE_DATE_EPOCH
RUN apk add --no-cache \
      autoconf automake bash binutils build-base bzip2 ca-certificates clang \
      cmake curl go gzip libtool linux-headers lld ninja patch perl \
      pkgconf python3 tar unzip xz

WORKDIR /src

COPY tools/build-static-deps.sh /src/tools/build-static-deps.sh
RUN --mount=type=cache,target=/var/cache/fastbed-static-deps,sharing=locked \
    FASTBED_STATIC_DEPS_DOWNLOAD_CACHE=/var/cache/fastbed-static-deps \
    FASTBED_STATIC_DEPS_SOURCE_ARCHIVES_OUTPUT=/release-artifacts/source/static-deps \
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    /src/tools/build-static-deps.sh /tmp/static-deps "${TARGETARCH}"

COPY tools/build-curl-impersonate.sh /src/tools/build-curl-impersonate.sh
COPY third_party/curl-impersonate/ /src/third_party/curl-impersonate/

RUN --mount=type=cache,target=/var/cache/fastbed-curl,sharing=locked \
    FASTBED_CURL_DOWNLOAD_CACHE=/var/cache/fastbed-curl \
    FASTBED_CURL_SOURCE_ARCHIVES_OUTPUT=/release-artifacts/source/curl-impersonate \
    /src/tools/build-curl-impersonate.sh /tmp/curl-impersonate "${TARGETARCH}"; \
    grep -Fx 'profile=http2-only' \
      /tmp/curl-impersonate/share/fastbed-curl-impersonate/BUILD-MANIFEST.txt; \
    grep -Fx 'curl_version=8.23.0-IMPERSONATE' \
      /tmp/curl-impersonate/share/fastbed-curl-impersonate/BUILD-MANIFEST.txt; \
    grep -Fx 'http3=false' \
      /tmp/curl-impersonate/share/fastbed-curl-impersonate/BUILD-MANIFEST.txt; \
    test ! -e /tmp/curl-impersonate/lib/libnghttp3.a; \
    test ! -e /tmp/curl-impersonate/lib/libngtcp2.a; \
    test ! -e /tmp/curl-impersonate/lib/libngtcp2_crypto_boringssl.a

COPY CMakeLists.txt README.md ./
COPY cmake/ ./cmake/
COPY assets/ ./assets/
COPY include/ ./include/
COPY src/ ./src/
COPY third_party/yyjson/ ./third_party/yyjson/
COPY third_party/crawler-user-agents/ ./third_party/crawler-user-agents/
COPY tools/create-release-artifacts.sh tools/embed-resources.py /src/tools/

RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) isa_flag=-DFASTBED_X86_64_V3=ON ;; \
      arm64) isa_flag=-DFASTBED_X86_64_V3=OFF ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    cmake -S . -B /tmp/build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=clang \
      -DCMAKE_INSTALL_PREFIX=/usr/local \
      -DFASTBED_CURL_IMPERSONATE_ROOT=/tmp/curl-impersonate \
      -DFASTBED_STATIC_DEPS_ROOT=/tmp/static-deps \
      -DFASTBED_LTO=ON \
      -DFASTBED_LTO_MODE=FULL \
      -DFASTBED_USE_LLD=ON \
      -DFASTBED_PACK_RELR=OFF \
      -DFASTBED_FULLY_STATIC=ON \
      "${isa_flag}"; \
    cmake --build /tmp/build --parallel; \
    DESTDIR=/out cmake --install /tmp/build; \
    mkdir -p /out/etc/ssl/certs /out/usr/local/share/fastbed-runtime; \
    cp /etc/ssl/certs/ca-certificates.crt \
      /out/etc/ssl/certs/ca-certificates.crt; \
    : > /out/usr/local/share/fastbed-runtime/ALPINE-BUILD-PACKAGES; \
    for package in ca-certificates ca-certificates-bundle libgcc libstdc++ musl; do \
      awk -v wanted="$package" 'BEGIN { RS=""; ORS="\n\n" } \
        { count = split($0, lines, "\n"); \
          for (line_no = 1; line_no <= count; ++line_no) \
            if (lines[line_no] == "P:" wanted) { print; next } }' \
        /lib/apk/db/installed \
        >> /out/usr/local/share/fastbed-runtime/ALPINE-BUILD-PACKAGES; \
      grep -Fx "P:${package}" \
        /out/usr/local/share/fastbed-runtime/ALPINE-BUILD-PACKAGES; \
    done; \
    { \
      echo 'profile=fastbed-scratch-static-v1'; \
      echo "base_image=${ALPINE_IMAGE}"; \
      echo "target_arch=${TARGETARCH}"; \
      echo "source_date_epoch=${SOURCE_DATE_EPOCH}"; \
      printf 'ca_bundle_sha256='; \
      sha256sum /out/etc/ssl/certs/ca-certificates.crt | cut -d' ' -f1; \
    } > /out/usr/local/share/fastbed-runtime/RUNTIME-MANIFEST.txt; \
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
      /src/tools/create-release-artifacts.sh \
      /src /tmp/build /tmp/curl-impersonate /tmp/static-deps \
      /out /release-artifacts \
      "${TARGETARCH}" "${ALPINE_IMAGE}"; \
    mkdir -p \
      /out/usr/share/licenses/fastbed \
      /out/usr/share/licenses/libmicrohttpd \
      /out/usr/share/licenses/libyaml \
      /out/usr/share/licenses/pcre2 \
      /out/usr/local/share/fastbed-source-offers; \
    cp /tmp/static-deps/share/fastbed-static-deps/licenses/libmicrohttpd-COPYING \
      /out/usr/share/licenses/libmicrohttpd/COPYING; \
    cp /tmp/static-deps/share/fastbed-static-deps/licenses/libyaml-License \
      /out/usr/share/licenses/libyaml/License; \
    cp /tmp/static-deps/share/fastbed-static-deps/licenses/pcre2-COPYING \
      /out/usr/share/licenses/pcre2/COPYING; \
    cp -R /tmp/static-deps/share/fastbed-static-deps \
      /out/usr/local/share/fastbed-static-deps; \
    cp -R /tmp/curl-impersonate/share/fastbed-curl-impersonate \
      /out/usr/local/share/fastbed-curl-impersonate; \
    cp /release-artifacts/source/static-deps/libmicrohttpd-${LIBMICROHTTPD_VERSION}.tar.gz \
      /release-artifacts/source/static-deps/yaml-0.2.5.tar.gz \
      /release-artifacts/source/static-deps/pcre2-10.47.tar.bz2 \
      /out/usr/local/share/fastbed-source-offers/; \
    cp /src/third_party/yyjson/LICENSE \
      /out/usr/share/licenses/fastbed/yyjson-LICENSE; \
    cp /src/third_party/crawler-user-agents/LICENSE \
      /out/usr/share/licenses/fastbed/crawler-user-agents-LICENSE

FROM scratch AS release-artifacts
COPY --from=build /release-artifacts/ /

FROM build AS verification-build
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH}" in \
      amd64) isa_flag=-DFASTBED_X86_64_V3=ON ;; \
      arm64) isa_flag=-DFASTBED_X86_64_V3=OFF ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    cmake -S /src -B /tmp/build-verification -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=clang \
      -DFASTBED_CURL_IMPERSONATE_ROOT=/tmp/curl-impersonate \
      -DFASTBED_STATIC_DEPS_ROOT=/tmp/static-deps \
      -DFASTBED_LTO=ON \
      -DFASTBED_LTO_MODE=FULL \
      -DFASTBED_USE_LLD=ON \
      -DFASTBED_PACK_RELR=OFF \
      -DFASTBED_FULLY_STATIC=ON \
      -DFASTBED_VERIFICATION_BUILD=ON \
      "${isa_flag}"; \
    cmake --build /tmp/build-verification --parallel

FROM scratch AS verification
COPY --from=verification-build /tmp/build-verification/fastbed /fastbed

FROM scratch AS runtime
COPY --from=build /out/ /

USER 65532:65532
EXPOSE 9812
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/fastbed"]


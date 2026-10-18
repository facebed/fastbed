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
      cmake curl go gzip libtool linux-headers lld ninja patch pcre2-dev perl \
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
      amd64) pack_relr=ON ;; \
      arm64) pack_relr=OFF ;; \
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
      -DFASTBED_PACK_RELR="${pack_relr}"; \
    cmake --build /tmp/build --parallel; \
    DESTDIR=/out cmake --install /tmp/build; \
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
      /src/tools/create-release-artifacts.sh \
      /src /tmp/build /tmp/curl-impersonate /tmp/static-deps \
      /out /release-artifacts \
      "${TARGETARCH}" "${ALPINE_IMAGE}"

FROM scratch AS release-artifacts
COPY --from=build /release-artifacts/ /

FROM ${ALPINE_IMAGE} AS runtime
ARG LIBMICROHTTPD_VERSION
RUN apk add --no-cache \
      ca-certificates libgcc libstdc++ pcre2 \
    && addgroup -S fastbed \
    && adduser -S -D -H -G fastbed fastbed

COPY --from=build /tmp/static-deps/share/fastbed-static-deps/licenses/libmicrohttpd-COPYING \
    /usr/share/licenses/libmicrohttpd/COPYING
COPY --from=build /tmp/static-deps/share/fastbed-static-deps/licenses/libyaml-License \
    /usr/share/licenses/libyaml/License
COPY --from=build /tmp/static-deps/share/fastbed-static-deps/ \
    /usr/local/share/fastbed-static-deps/
COPY --from=build /release-artifacts/source/static-deps/libmicrohttpd-${LIBMICROHTTPD_VERSION}.tar.gz \
    /usr/local/share/fastbed-source-offers/libmicrohttpd-${LIBMICROHTTPD_VERSION}.tar.gz
COPY --from=build /release-artifacts/source/static-deps/yaml-0.2.5.tar.gz \
    /usr/local/share/fastbed-source-offers/yaml-0.2.5.tar.gz
COPY --from=build /out/ /
COPY --from=build /tmp/curl-impersonate/share/fastbed-curl-impersonate/ \
    /usr/local/share/fastbed-curl-impersonate/
COPY third_party/yyjson/LICENSE /usr/share/licenses/fastbed/yyjson-LICENSE
COPY third_party/crawler-user-agents/LICENSE \
    /usr/share/licenses/fastbed/crawler-user-agents-LICENSE

ENV FASTBED_HEALTH_PORT=9812
USER fastbed:fastbed
EXPOSE 9812
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --start-interval=1s --retries=3 \
  CMD wget -q -Y off -O /dev/null "http://127.0.0.1:${FASTBED_HEALTH_PORT}/healthz" || exit 1

ENTRYPOINT ["/usr/local/bin/fastbed"]


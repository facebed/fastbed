cmake_minimum_required(VERSION 3.24)

project(fastbed VERSION 0.1.0 LANGUAGES C)

include(CheckIPOSupported)
include(CheckLinkerFlag)
include(CheckPIESupported)
include(CheckCSourceCompiles)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(FASTBED_LTO "Enable whole-program link-time optimization" ON)
set(FASTBED_LTO_MODE "FULL" CACHE STRING
    "LTO implementation: FULL, THIN, or AUTO")
set_property(CACHE FASTBED_LTO_MODE PROPERTY STRINGS FULL THIN AUTO)
option(FASTBED_NATIVE "Tune the binary for the build host" OFF)
option(FASTBED_X86_64_V3 "Build an x86-64-v3 deployment binary" OFF)
option(FASTBED_USE_LLD "Link with LLVM lld" OFF)
option(FASTBED_PACK_RELR
    "Pack relative ELF relocations (requires a DT_RELR-capable runtime)" OFF)
option(FASTBED_BOLT_READY "Retain relocations for post-link BOLT optimization" OFF)
option(FASTBED_JEMALLOC "Link jemalloc for an allocator A/B build" OFF)
option(FASTBED_VERIFICATION_BUILD
    "Expose file overrides, stock curl, and loopback replay controls" OFF)
option(FASTBED_ALLOW_DYNAMIC_SYSTEM_CURL
    "Allow an explicit non-production diagnostic build with dynamic system libcurl"
    OFF)
option(FASTBED_SANITIZERS "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(FASTBED_PGO_GENERATE "Instrument a representative-workload PGO build" OFF)
set(FASTBED_CLANG_PGO_GENERATE_MODE "IR" CACHE STRING
    "Clang PGO instrumentation: IR, CSIR, or FRONTEND")
set_property(CACHE FASTBED_CLANG_PGO_GENERATE_MODE PROPERTY
    STRINGS IR CSIR FRONTEND)
set(FASTBED_CLANG_PGO_UPDATE_MODE "ATOMIC" CACHE STRING
    "Clang PGO counter updates: ATOMIC, PREFER_ATOMIC, or SINGLE")
set_property(CACHE FASTBED_CLANG_PGO_UPDATE_MODE PROPERTY
    STRINGS ATOMIC PREFER_ATOMIC SINGLE)
set(FASTBED_PGO_USE "" CACHE STRING
    "Profile to consume for PGO (Clang .profdata file or GCC .gcda directory)")
set(FASTBED_CURL_IMPERSONATE_ROOT "" CACHE PATH
    "Verified curl 8.23 HTTP/2-only production prefix with exact headers and split static archives")
set(FASTBED_CURL_IMPERSONATE_ARCHIVE "" CACHE FILEPATH
    "Vulnerable v1.5.2 mega-archive for offline/control comparisons only")
set(FASTBED_STATIC_DEPS_ROOT "" CACHE PATH
    "Verified native prefix containing static libmicrohttpd and libyaml archives")

if(FASTBED_CURL_IMPERSONATE_ROOT AND FASTBED_CURL_IMPERSONATE_ARCHIVE)
    message(FATAL_ERROR
        "FASTBED_CURL_IMPERSONATE_ROOT and FASTBED_CURL_IMPERSONATE_ARCHIVE are mutually exclusive")
endif()
if(FASTBED_ALLOW_DYNAMIC_SYSTEM_CURL AND
   (FASTBED_CURL_IMPERSONATE_ROOT OR FASTBED_CURL_IMPERSONATE_ARCHIVE))
    message(FATAL_ERROR
        "FASTBED_ALLOW_DYNAMIC_SYSTEM_CURL cannot be combined with a bundled curl-impersonate input")
endif()
if(FASTBED_ALLOW_DYNAMIC_SYSTEM_CURL AND NOT FASTBED_VERIFICATION_BUILD)
    message(FATAL_ERROR
        "Dynamic system curl is available only in FASTBED_VERIFICATION_BUILD")
endif()
if(NOT FASTBED_CURL_IMPERSONATE_ROOT AND
   NOT FASTBED_CURL_IMPERSONATE_ARCHIVE AND
   NOT FASTBED_ALLOW_DYNAMIC_SYSTEM_CURL)
    message(FATAL_ERROR
        "Production builds require statically bundled curl-impersonate. Set "
        "FASTBED_CURL_IMPERSONATE_ROOT to the verified prefix. For an explicit "
        "non-production diagnostic build only, set "
        "FASTBED_ALLOW_DYNAMIC_SYSTEM_CURL=ON.")
endif()
if(NOT FASTBED_STATIC_DEPS_ROOT)
    message(FATAL_ERROR
        "FASTBED_STATIC_DEPS_ROOT must name the verified static libmicrohttpd/libyaml prefix")
endif()

if(FASTBED_NATIVE AND FASTBED_X86_64_V3)
    message(FATAL_ERROR "FASTBED_NATIVE and FASTBED_X86_64_V3 are mutually exclusive")
endif()
string(TOUPPER "${FASTBED_CLANG_PGO_GENERATE_MODE}"
       fastbed_clang_pgo_generate_mode)
if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND
   NOT fastbed_clang_pgo_generate_mode MATCHES "^(IR|CSIR|FRONTEND)$")
    message(FATAL_ERROR
        "FASTBED_CLANG_PGO_GENERATE_MODE must be IR, CSIR, or FRONTEND "
        "(got ${FASTBED_CLANG_PGO_GENERATE_MODE})")
endif()
string(TOUPPER "${FASTBED_CLANG_PGO_UPDATE_MODE}"
       fastbed_clang_pgo_update_mode)
if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND
   NOT fastbed_clang_pgo_update_mode MATCHES
       "^(ATOMIC|PREFER_ATOMIC|SINGLE)$")
    message(FATAL_ERROR
        "FASTBED_CLANG_PGO_UPDATE_MODE must be ATOMIC, PREFER_ATOMIC, or SINGLE "
        "(got ${FASTBED_CLANG_PGO_UPDATE_MODE})")
endif()
if(FASTBED_PGO_GENERATE AND FASTBED_PGO_USE AND
   NOT (CMAKE_C_COMPILER_ID MATCHES "Clang" AND
        fastbed_clang_pgo_generate_mode STREQUAL "CSIR"))
    message(FATAL_ERROR
        "PGO generation and use are mutually exclusive except for Clang CSIR training")
endif()
if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND
   FASTBED_PGO_GENERATE AND
   fastbed_clang_pgo_generate_mode STREQUAL "CSIR" AND
   NOT FASTBED_PGO_USE)
    message(FATAL_ERROR
        "Clang CSIR training requires the first-pass profile in FASTBED_PGO_USE")
endif()

find_package(PkgConfig REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_package(Threads REQUIRED)
set(fastbed_saved_required_flags "${CMAKE_REQUIRED_FLAGS}")
set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -O2")
check_c_source_compiles(
    "#ifndef _FORTIFY_SOURCE\n#error toolchain has no default fortify level\n#endif\nint main(void) { return _FORTIFY_SOURCE < 1; }"
    FASTBED_TOOLCHAIN_HAS_DEFAULT_FORTIFY)
set(CMAKE_REQUIRED_FLAGS "${fastbed_saved_required_flags}")
pkg_check_modules(PCRE2 REQUIRED IMPORTED_TARGET "libpcre2-8>=10.34")
if(NOT FASTBED_CURL_IMPERSONATE_ROOT)
    find_package(ZLIB 1.2.11 REQUIRED)
    find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)
    pkg_check_modules(CURL REQUIRED IMPORTED_TARGET "libcurl>=7.85.0")
endif()
if(FASTBED_JEMALLOC)
    pkg_check_modules(JEMALLOC REQUIRED IMPORTED_TARGET jemalloc)
endif()

set(fastbed_static_deps_manifest
    "${FASTBED_STATIC_DEPS_ROOT}/share/fastbed-static-deps/BUILD-MANIFEST.txt")
set(fastbed_static_deps_checksums
    "${FASTBED_STATIC_DEPS_ROOT}/share/fastbed-static-deps/SHA256SUMS")
foreach(fastbed_static_metadata IN ITEMS
        "${fastbed_static_deps_manifest}"
        "${fastbed_static_deps_checksums}")
    if(NOT EXISTS "${fastbed_static_metadata}")
        message(FATAL_ERROR
            "Static dependency prefix lacks required metadata: ${fastbed_static_metadata}")
    endif()
endforeach()
file(STRINGS "${fastbed_static_deps_manifest}"
     fastbed_static_deps_manifest_lines)
foreach(fastbed_static_required_manifest_line IN ITEMS
        "profile=fastbed-static-deps-v1"
        "libmicrohttpd_version=1.0.10"
        "libyaml_version=0.2.5")
    list(FIND fastbed_static_deps_manifest_lines
         "${fastbed_static_required_manifest_line}"
         fastbed_static_manifest_line_index)
    if(fastbed_static_manifest_line_index EQUAL -1)
        message(FATAL_ERROR
            "Static dependency manifest is missing ${fastbed_static_required_manifest_line}")
    endif()
endforeach()
set(fastbed_static_deps_libraries
    "${FASTBED_STATIC_DEPS_ROOT}/lib/libmicrohttpd.a"
    "${FASTBED_STATIC_DEPS_ROOT}/lib/libyaml.a")
set(fastbed_static_deps_integrity_paths
    "include/microhttpd.h"
    "include/yaml.h"
    "lib/libmicrohttpd.a"
    "lib/libyaml.a"
    "share/fastbed-static-deps/BUILD-MANIFEST.txt")
file(STRINGS "${fastbed_static_deps_checksums}"
     fastbed_static_deps_checksum_lines)
foreach(fastbed_static_integrity_path IN LISTS
        fastbed_static_deps_integrity_paths)
    if(NOT EXISTS
       "${FASTBED_STATIC_DEPS_ROOT}/${fastbed_static_integrity_path}")
        message(FATAL_ERROR
            "Static dependency prefix is incomplete: ${fastbed_static_integrity_path}")
    endif()
    set(fastbed_static_integrity_matches
        ${fastbed_static_deps_checksum_lines})
    list(FILTER fastbed_static_integrity_matches INCLUDE REGEX
         "^[0-9a-f]+  ${fastbed_static_integrity_path}$")
    list(LENGTH fastbed_static_integrity_matches
         fastbed_static_integrity_match_count)
    if(NOT fastbed_static_integrity_match_count EQUAL 1)
        message(FATAL_ERROR
            "Static dependency SHA256SUMS must contain exactly one entry for ${fastbed_static_integrity_path}")
    endif()
    list(GET fastbed_static_integrity_matches 0
         fastbed_static_integrity_line)
    string(SUBSTRING "${fastbed_static_integrity_line}" 0 64
           fastbed_static_integrity_expected)
    file(SHA256
         "${FASTBED_STATIC_DEPS_ROOT}/${fastbed_static_integrity_path}"
         fastbed_static_integrity_observed)
    if(NOT fastbed_static_integrity_observed STREQUAL
       fastbed_static_integrity_expected)
        message(FATAL_ERROR
            "Static dependency prefix integrity mismatch for ${fastbed_static_integrity_path}")
    endif()
endforeach()
file(GLOB_RECURSE fastbed_static_deps_shared_libraries
     "${FASTBED_STATIC_DEPS_ROOT}/*.so"
     "${FASTBED_STATIC_DEPS_ROOT}/*.so.*")
if(fastbed_static_deps_shared_libraries)
    message(FATAL_ERROR
        "Static dependency prefix contains shared libraries: ${fastbed_static_deps_shared_libraries}")
endif()

add_library(fastbed_yyjson STATIC third_party/yyjson/yyjson.c)
target_include_directories(fastbed_yyjson SYSTEM PUBLIC third_party/yyjson)
set_target_properties(fastbed_yyjson PROPERTIES POSITION_INDEPENDENT_CODE ON)

set(fastbed_generated_root "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(fastbed_embedded_source
    "${fastbed_generated_root}/src/embedded_resources.c")
set(fastbed_embedded_header
    "${fastbed_generated_root}/include/fastbed/embedded_resources.h")
set(fastbed_embedded_manifest
    "${fastbed_generated_root}/EMBEDDED-RESOURCES.json")
add_custom_command(
    OUTPUT
        "${fastbed_embedded_source}"
        "${fastbed_embedded_header}"
        "${fastbed_embedded_manifest}"
    COMMAND "${CMAKE_COMMAND}" -E rm -f
        "${fastbed_embedded_source}"
        "${fastbed_embedded_header}"
        "${fastbed_embedded_manifest}"
    COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tools/embed-resources.py"
        --index "${CMAKE_CURRENT_SOURCE_DIR}/assets/index.html"
        --favicon "${CMAKE_CURRENT_SOURCE_DIR}/assets/favicon.ico"
        --banner "${CMAKE_CURRENT_SOURCE_DIR}/assets/banner.png"
        --crawler "${CMAKE_CURRENT_SOURCE_DIR}/third_party/crawler-user-agents/crawler-user-agents.json"
        --output-c "${fastbed_embedded_source}"
        --output-h "${fastbed_embedded_header}"
        --manifest "${fastbed_embedded_manifest}"
    DEPENDS
        tools/embed-resources.py
        assets/index.html
        assets/favicon.ico
        assets/banner.png
        third_party/crawler-user-agents/crawler-user-agents.json
    COMMENT "Embedding immutable Fastbed assets and crawler database"
    VERBATIM)
add_custom_target(fastbed_embedded_resources DEPENDS
    "${fastbed_embedded_source}"
    "${fastbed_embedded_header}"
    "${fastbed_embedded_manifest}")

set(FASTBED_SOURCES
    src/app.c
    src/arena.c
    src/assets.c
    src/buf.c
    src/cache.c
    src/config.c
    src/crawler.c
    src/document.c
    src/main.c
    src/metrics.c
    src/model.c
    src/notifier.c
    src/parser.c
    src/render.c
    src/server.c
    src/transport.c
    src/url.c
    "${fastbed_embedded_source}"
)

add_executable(fastbed ${FASTBED_SOURCES})
add_dependencies(fastbed fastbed_embedded_resources)
check_pie_supported()
set_property(TARGET fastbed PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(fastbed PRIVATE
    include
    "${fastbed_generated_root}/include")
target_include_directories(fastbed SYSTEM BEFORE PRIVATE
    "${FASTBED_STATIC_DEPS_ROOT}/include")
target_link_libraries(fastbed PRIVATE
    fastbed_yyjson
    ${fastbed_static_deps_libraries}
    PkgConfig::PCRE2
    Threads::Threads
)
message(STATUS
    "Using verified static libmicrohttpd/libyaml prefix from ${FASTBED_STATIC_DEPS_ROOT}")
if(FASTBED_JEMALLOC)
    target_link_libraries(fastbed PRIVATE PkgConfig::JEMALLOC)
    target_compile_definitions(fastbed PRIVATE FASTBED_JEMALLOC=1)
endif()

if(FASTBED_CURL_IMPERSONATE_ROOT)
    set(fastbed_curl_impersonate_include
        "${FASTBED_CURL_IMPERSONATE_ROOT}/include")
    set(fastbed_curl_impersonate_manifest
        "${FASTBED_CURL_IMPERSONATE_ROOT}/share/fastbed-curl-impersonate/BUILD-MANIFEST.txt")
    set(fastbed_curl_impersonate_checksums
        "${FASTBED_CURL_IMPERSONATE_ROOT}/share/fastbed-curl-impersonate/SHA256SUMS")
    if(NOT EXISTS "${fastbed_curl_impersonate_manifest}")
        message(FATAL_ERROR
            "Production curl prefix lacks BUILD-MANIFEST.txt: ${fastbed_curl_impersonate_manifest}")
    endif()
    if(NOT EXISTS "${fastbed_curl_impersonate_checksums}")
        message(FATAL_ERROR
            "Production curl prefix lacks SHA256SUMS: ${fastbed_curl_impersonate_checksums}")
    endif()
    file(STRINGS "${fastbed_curl_impersonate_manifest}"
         fastbed_curl_impersonate_manifest_lines)
    foreach(fastbed_curl_required_manifest_line IN ITEMS
            "profile=http2-only"
            "curl_version=8.23.0-IMPERSONATE"
            "protocols=http,https"
            "http3=false")
        string(REGEX REPLACE "=.*$" ""
               fastbed_curl_required_manifest_key
               "${fastbed_curl_required_manifest_line}")
        set(fastbed_curl_manifest_key_lines
            ${fastbed_curl_impersonate_manifest_lines})
        list(FILTER fastbed_curl_manifest_key_lines INCLUDE REGEX
             "^${fastbed_curl_required_manifest_key}=")
        list(LENGTH fastbed_curl_manifest_key_lines
             fastbed_curl_manifest_key_count)
        if(NOT fastbed_curl_manifest_key_count EQUAL 1)
            message(FATAL_ERROR
                "Production curl manifest must contain exactly one ${fastbed_curl_required_manifest_key}= entry")
        endif()
        list(FIND fastbed_curl_impersonate_manifest_lines
             "${fastbed_curl_required_manifest_line}"
             fastbed_curl_manifest_line_index)
        if(fastbed_curl_manifest_line_index EQUAL -1)
            message(FATAL_ERROR
                "Production curl manifest is missing ${fastbed_curl_required_manifest_line}")
        endif()
    endforeach()
    set(fastbed_curl_impersonate_libraries
        "${FASTBED_CURL_IMPERSONATE_ROOT}/lib/libcurl-impersonate.a"
        "${FASTBED_CURL_IMPERSONATE_ROOT}/lib/libnghttp2.a"
        "${FASTBED_CURL_IMPERSONATE_ROOT}/lib/libidn2.a"
        "${FASTBED_CURL_IMPERSONATE_ROOT}/lib/libunistring.a"
        "${FASTBED_CURL_IMPERSONATE_ROOT}/lib/libssl.a"
        "${FASTBED_CURL_IMPERSONATE_ROOT}/lib/libcrypto.a"
        "${FASTBED_CURL_IMPERSONATE_ROOT}/lib/libzstd.a"
        "${FASTBED_CURL_IMPERSONATE_ROOT}/lib/libbrotlidec.a"
        "${FASTBED_CURL_IMPERSONATE_ROOT}/lib/libbrotlicommon.a"
        "${FASTBED_CURL_IMPERSONATE_ROOT}/lib/libz.a"
    )
    foreach(fastbed_curl_forbidden_http3_archive IN ITEMS
            libnghttp3.a libngtcp2_crypto_boringssl.a libngtcp2.a)
        if(EXISTS
           "${FASTBED_CURL_IMPERSONATE_ROOT}/lib/${fastbed_curl_forbidden_http3_archive}")
            message(FATAL_ERROR
                "Production curl prefix contains forbidden HTTP/3 archive: ${fastbed_curl_forbidden_http3_archive}")
        endif()
    endforeach()
    set(fastbed_curl_impersonate_required
        "${fastbed_curl_impersonate_include}/curl/curl.h"
        "${fastbed_curl_impersonate_include}/openssl/evp.h"
        "${fastbed_curl_impersonate_include}/zlib.h"
        ${fastbed_curl_impersonate_libraries}
    )
    foreach(fastbed_curl_file IN LISTS fastbed_curl_impersonate_required)
        if(NOT EXISTS "${fastbed_curl_file}")
            message(FATAL_ERROR
                "Incomplete FASTBED_CURL_IMPERSONATE_ROOT, missing: ${fastbed_curl_file}")
        endif()
    endforeach()
    file(STRINGS "${fastbed_curl_impersonate_checksums}"
         fastbed_curl_impersonate_checksum_lines)
    set(fastbed_curl_integrity_paths
        "include/curl/curl.h"
        "include/openssl/evp.h"
        "include/zlib.h"
        "lib/libcurl-impersonate.a"
        "lib/libnghttp2.a"
        "lib/libidn2.a"
        "lib/libunistring.a"
        "lib/libssl.a"
        "lib/libcrypto.a"
        "lib/libzstd.a"
        "lib/libbrotlidec.a"
        "lib/libbrotlicommon.a"
        "lib/libz.a"
        "share/fastbed-curl-impersonate/BUILD-MANIFEST.txt"
        "share/fastbed-curl-impersonate/CURL-VERSION.txt")
    foreach(fastbed_curl_integrity_path IN LISTS
            fastbed_curl_integrity_paths)
        set(fastbed_curl_integrity_matches
            ${fastbed_curl_impersonate_checksum_lines})
        list(FILTER fastbed_curl_integrity_matches INCLUDE REGEX
             "^[0-9a-f]+  ${fastbed_curl_integrity_path}$")
        list(LENGTH fastbed_curl_integrity_matches
             fastbed_curl_integrity_match_count)
        if(NOT fastbed_curl_integrity_match_count EQUAL 1)
            message(FATAL_ERROR
                "Production curl SHA256SUMS must contain exactly one entry for ${fastbed_curl_integrity_path}")
        endif()
        list(GET fastbed_curl_integrity_matches 0
             fastbed_curl_integrity_line)
        string(SUBSTRING "${fastbed_curl_integrity_line}" 0 64
               fastbed_curl_integrity_expected)
        if(NOT fastbed_curl_integrity_expected MATCHES "^[0-9a-f]+$")
            message(FATAL_ERROR
                "Production curl SHA256SUMS has an invalid digest for ${fastbed_curl_integrity_path}")
        endif()
        file(SHA256
             "${FASTBED_CURL_IMPERSONATE_ROOT}/${fastbed_curl_integrity_path}"
             fastbed_curl_integrity_observed)
        if(NOT fastbed_curl_integrity_observed STREQUAL
           fastbed_curl_integrity_expected)
            message(FATAL_ERROR
                "Production curl prefix integrity mismatch for ${fastbed_curl_integrity_path}")
        endif()
    endforeach()
    list(JOIN fastbed_curl_impersonate_libraries ","
         fastbed_curl_impersonate_link_group)
    target_link_libraries(fastbed PRIVATE
        "$<LINK_GROUP:RESCAN,${fastbed_curl_impersonate_link_group}>"
        stdc++ m dl
    )
    target_include_directories(fastbed SYSTEM BEFORE PRIVATE
        "${fastbed_curl_impersonate_include}")
    target_compile_definitions(fastbed PRIVATE FASTBED_HAS_CURL_IMPERSONATE=1)
    message(STATUS
        "Using verified curl 8.23 HTTP/2-only production prefix from ${FASTBED_CURL_IMPERSONATE_ROOT}")
elseif(FASTBED_CURL_IMPERSONATE_ARCHIVE)
    if(NOT EXISTS "${FASTBED_CURL_IMPERSONATE_ARCHIVE}")
        message(FATAL_ERROR
            "FASTBED_CURL_IMPERSONATE_ARCHIVE does not exist: ${FASTBED_CURL_IMPERSONATE_ARCHIVE}")
    endif()
    # curl_cffi's Linux artifact is a one-member mega-archive containing its
    # pinned curl, BoringSSL, HTTP/2, HTTP/3, compression, IDN, and resolver
    # dependencies. Referencing libcurl pulls that single aggregate object; no
    # whole-archive flag or host OpenSSL/zlib linkage is needed.
    target_link_libraries(fastbed PRIVATE
        "${FASTBED_CURL_IMPERSONATE_ARCHIVE}"
        stdc++ m dl
    )
    target_include_directories(fastbed PRIVATE ${CURL_INCLUDE_DIRS})
    target_compile_options(fastbed PRIVATE ${CURL_CFLAGS_OTHER})
    target_compile_definitions(fastbed PRIVATE FASTBED_HAS_CURL_IMPERSONATE=1)
    message(WARNING
        "Using vulnerable curl-impersonate v1.5.2 mega-archive control; do not deploy this build")
elseif(FASTBED_ALLOW_DYNAMIC_SYSTEM_CURL)
    target_link_libraries(fastbed PRIVATE
        PkgConfig::CURL OpenSSL::Crypto ZLIB::ZLIB)
    target_compile_definitions(fastbed PRIVATE FASTBED_HAS_CURL_IMPERSONATE=0)
    message(WARNING
        "Building with system libcurl: offline work is available, but faithful live Facebook transport is disabled")
endif()

if(FASTBED_CURL_IMPERSONATE_ROOT OR FASTBED_CURL_IMPERSONATE_ARCHIVE)
    if(NOT CMAKE_READELF OR NOT CMAKE_NM)
        message(FATAL_ERROR
            "Static bundled-dependency verification requires CMAKE_READELF and CMAKE_NM")
    endif()
    set(fastbed_linkage_verifier
        "${CMAKE_CURRENT_SOURCE_DIR}/cmake/VerifyBundledStaticLinkage.cmake")
    set_property(TARGET fastbed APPEND PROPERTY LINK_DEPENDS
        "${fastbed_linkage_verifier}")
    add_custom_command(TARGET fastbed POST_BUILD
        COMMAND "${CMAKE_COMMAND}"
            "-DFASTBED_BINARY=$<TARGET_FILE:fastbed>"
            "-DFASTBED_READELF=${CMAKE_READELF}"
            "-DFASTBED_NM=${CMAKE_NM}"
            "-DFASTBED_LINKAGE_REPORT=${CMAKE_CURRENT_BINARY_DIR}/fastbed-linkage-report.txt"
            -P "${fastbed_linkage_verifier}"
        COMMENT "Verifying bundled dependencies are statically embedded"
        VERBATIM)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(fastbed_yyjson PRIVATE
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-fno-semantic-interposition>
        $<$<CONFIG:Release>:-ffunction-sections>
        $<$<CONFIG:Release>:-fdata-sections>
        $<$<CONFIG:Release>:-fvisibility=hidden>
        -fno-common
    )
    if(NOT FASTBED_TOOLCHAIN_HAS_DEFAULT_FORTIFY)
        target_compile_definitions(fastbed_yyjson PRIVATE
            $<$<CONFIG:Release>:_FORTIFY_SOURCE=3>)
    endif()
endif()

target_compile_definitions(fastbed PRIVATE
    _FILE_OFFSET_BITS=64
    _GNU_SOURCE
    FASTBED_VERSION="${PROJECT_VERSION}"
)
if(FASTBED_VERIFICATION_BUILD)
    target_compile_definitions(fastbed PRIVATE FASTBED_VERIFICATION_BUILD=1)
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(fastbed PRIVATE
        -Wall -Wextra -Wpedantic -Wconversion -Wshadow
        -Wformat=2 -Wundef -Wstrict-prototypes -Wmissing-prototypes
        -Werror=implicit-function-declaration
        -fno-common
        $<$<CONFIG:Release>:-O3>
        $<$<CONFIG:Release>:-fno-plt>
        $<$<CONFIG:Release>:-fno-semantic-interposition>
        $<$<CONFIG:Release>:-ffunction-sections>
        $<$<CONFIG:Release>:-fdata-sections>
        $<$<CONFIG:Release>:-fvisibility=hidden>
        $<$<CONFIG:Release>:-fstack-protector-strong>
    )
    if(NOT FASTBED_TOOLCHAIN_HAS_DEFAULT_FORTIFY)
        target_compile_definitions(fastbed PRIVATE
            $<$<CONFIG:Release>:_FORTIFY_SOURCE=3>)
    endif()
    target_link_options(fastbed PRIVATE
        $<$<CONFIG:Release>:-Wl,--gc-sections>
        $<$<CONFIG:Release>:-Wl,-O2>
        $<$<CONFIG:Release>:-Wl,--as-needed>
        $<$<CONFIG:Release>:-Wl,-z,relro>
        $<$<CONFIG:Release>:-Wl,-z,now>
        $<$<CONFIG:Release>:-Wl,-z,noexecstack>
        $<$<CONFIG:Release>:-Wl,--build-id=sha1>
    )
endif()

if(FASTBED_PACK_RELR)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(FATAL_ERROR "FASTBED_PACK_RELR currently supports Linux ELF builds only")
    endif()
    check_linker_flag(C "-Wl,-z,pack-relative-relocs"
        fastbed_linker_has_pack_relative_relocs)
    if(NOT fastbed_linker_has_pack_relative_relocs)
        message(FATAL_ERROR
            "FASTBED_PACK_RELR requires linker support for -z pack-relative-relocs")
    endif()
    target_link_options(fastbed PRIVATE -Wl,-z,pack-relative-relocs)
endif()

if(FASTBED_NATIVE)
    target_compile_options(fastbed PRIVATE -march=native -mtune=native)
    target_compile_options(fastbed_yyjson PRIVATE -march=native -mtune=native)
elseif(FASTBED_X86_64_V3)
    if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64")
        message(FATAL_ERROR "FASTBED_X86_64_V3 requires an x86-64 target")
    endif()
    target_compile_options(fastbed PRIVATE -march=x86-64-v3 -mtune=generic)
    target_compile_options(fastbed_yyjson PRIVATE -march=x86-64-v3 -mtune=generic)
endif()

if(FASTBED_USE_LLD)
    target_link_options(fastbed PRIVATE -fuse-ld=lld)
    # Instrumented binaries are training artifacts. Folding their functions
    # adds no production benefit and can obscure per-function profile identity.
    if(NOT FASTBED_PGO_GENERATE)
        target_link_options(fastbed PRIVATE $<$<CONFIG:Release>:-Wl,--icf=safe>)
    endif()
    if(FASTBED_LTO AND CMAKE_C_COMPILER_ID MATCHES "Clang")
        target_link_options(fastbed PRIVATE $<$<CONFIG:Release>:-Wl,--lto-O3>)
    endif()
endif()

if(FASTBED_BOLT_READY)
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
        message(FATAL_ERROR
            "FASTBED_BOLT_READY currently supports Linux ELF builds only")
    endif()
    if(NOT CMAKE_SYSTEM_PROCESSOR MATCHES
       "x86_64|amd64|AMD64|aarch64|arm64|ARM64")
        message(FATAL_ERROR
            "FASTBED_BOLT_READY requires an x86-64 or AArch64 ELF target")
    endif()
    check_linker_flag(C "-Wl,--emit-relocs" fastbed_linker_has_emit_relocs)
    if(NOT fastbed_linker_has_emit_relocs)
        message(FATAL_ERROR
            "FASTBED_BOLT_READY requires linker support for --emit-relocs")
    endif()
    target_link_options(fastbed PRIVATE -Wl,--emit-relocs)
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        # BOLT cannot safely consume GCC's partitioned hot/cold functions.
        target_compile_options(fastbed PRIVATE
            -fno-reorder-blocks-and-partition)
        target_compile_options(fastbed_yyjson PRIVATE
            -fno-reorder-blocks-and-partition)
    endif()
endif()

if(FASTBED_SANITIZERS)
    target_compile_options(fastbed PRIVATE
        -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls
        -fsanitize=address,undefined
    )
    target_link_options(fastbed PRIVATE -fsanitize=address,undefined)
    target_compile_options(fastbed_yyjson PRIVATE
        -O1 -g3 -fno-omit-frame-pointer -fno-optimize-sibling-calls
        -fsanitize=address,undefined
    )
endif()

if(FASTBED_PGO_GENERATE)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        string(TOLOWER "${fastbed_clang_pgo_update_mode}"
               fastbed_clang_pgo_update_flag)
        string(REPLACE "_" "-" fastbed_clang_pgo_update_flag
               "${fastbed_clang_pgo_update_flag}")
        if(fastbed_clang_pgo_generate_mode STREQUAL "IR")
            set(fastbed_clang_pgo_generate_flag -fprofile-generate)
            set(fastbed_clang_pgo_link_flags -fprofile-generate)
        elseif(fastbed_clang_pgo_generate_mode STREQUAL "CSIR")
            set(fastbed_clang_pgo_generate_flag
                -fprofile-use=${FASTBED_PGO_USE}
                -fcs-profile-generate)
            set(fastbed_clang_pgo_link_flags
                -fprofile-use=${FASTBED_PGO_USE}
                -fcs-profile-generate)
        else()
            set(fastbed_clang_pgo_generate_flag -fprofile-instr-generate)
            set(fastbed_clang_pgo_link_flags -fprofile-instr-generate)
        endif()
        target_compile_options(fastbed PRIVATE
            ${fastbed_clang_pgo_generate_flag}
            -fprofile-update=${fastbed_clang_pgo_update_flag})
        target_compile_options(fastbed_yyjson PRIVATE
            ${fastbed_clang_pgo_generate_flag}
            -fprofile-update=${fastbed_clang_pgo_update_flag})
        target_link_options(fastbed PRIVATE ${fastbed_clang_pgo_link_flags})
    elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        target_compile_options(fastbed PRIVATE -fprofile-generate)
        target_compile_options(fastbed_yyjson PRIVATE -fprofile-generate)
        target_link_options(fastbed PRIVATE -fprofile-generate)
    else()
        message(FATAL_ERROR "PGO generation is supported only with Clang or GCC")
    endif()
elseif(FASTBED_PGO_USE)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        if(NOT EXISTS "${FASTBED_PGO_USE}" OR IS_DIRECTORY "${FASTBED_PGO_USE}")
            message(FATAL_ERROR
                "Clang FASTBED_PGO_USE must be a merged .profdata file: ${FASTBED_PGO_USE}")
        endif()
        target_compile_options(fastbed PRIVATE
            -fprofile-use=${FASTBED_PGO_USE}
        )
        target_link_options(fastbed PRIVATE -fprofile-use=${FASTBED_PGO_USE})
        target_compile_options(fastbed_yyjson PRIVATE
            -fprofile-use=${FASTBED_PGO_USE})
    elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        if(NOT IS_DIRECTORY "${FASTBED_PGO_USE}")
            message(FATAL_ERROR
                "GCC FASTBED_PGO_USE must be a directory containing .gcda files: ${FASTBED_PGO_USE}")
        endif()
        target_compile_options(fastbed PRIVATE
            -fprofile-use=${FASTBED_PGO_USE}
            -fprofile-correction
            -Wno-missing-profile
        )
        target_link_options(fastbed PRIVATE -fprofile-use=${FASTBED_PGO_USE})
        target_compile_options(fastbed_yyjson PRIVATE
            -fprofile-use=${FASTBED_PGO_USE}
            -fprofile-correction
            -Wno-missing-profile)
    else()
        message(FATAL_ERROR "PGO use is supported only with Clang or GCC")
    endif()
endif()

if(FASTBED_LTO AND NOT FASTBED_SANITIZERS AND NOT FASTBED_PGO_GENERATE)
    string(TOUPPER "${FASTBED_LTO_MODE}" fastbed_lto_mode)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND
       (fastbed_lto_mode STREQUAL "FULL" OR fastbed_lto_mode STREQUAL "THIN"))
        string(TOLOWER "${fastbed_lto_mode}" fastbed_clang_lto_mode)
        target_compile_options(fastbed PRIVATE -flto=${fastbed_clang_lto_mode})
        target_compile_options(fastbed_yyjson PRIVATE -flto=${fastbed_clang_lto_mode})
        target_link_options(fastbed PRIVATE -flto=${fastbed_clang_lto_mode})
    elseif(CMAKE_C_COMPILER_ID STREQUAL "GNU" AND
           NOT fastbed_lto_mode STREQUAL "AUTO")
        # GCC has no full/thin spelling; `auto` parallelizes its whole-program
        # LTRANS phase while retaining maximum interprocedural scope.
        target_compile_options(fastbed PRIVATE -flto=auto -fno-fat-lto-objects)
        target_compile_options(fastbed_yyjson PRIVATE -flto=auto -fno-fat-lto-objects)
        target_link_options(fastbed PRIVATE -flto=auto)
    elseif(fastbed_lto_mode STREQUAL "AUTO")
        check_ipo_supported(RESULT fastbed_ipo_supported OUTPUT fastbed_ipo_error)
        if(fastbed_ipo_supported)
            set_property(TARGET fastbed PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
            set_property(TARGET fastbed_yyjson PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
        else()
            message(WARNING "LTO unavailable: ${fastbed_ipo_error}")
        endif()
    else()
        message(FATAL_ERROR
            "FASTBED_LTO_MODE must be FULL, THIN, or AUTO (got ${FASTBED_LTO_MODE})")
    endif()
endif()

install(TARGETS fastbed RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES "${fastbed_embedded_manifest}"
    DESTINATION ${CMAKE_INSTALL_DATADIR}/fastbed)


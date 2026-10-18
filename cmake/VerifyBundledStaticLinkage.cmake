cmake_minimum_required(VERSION 3.24)

foreach(required IN ITEMS FASTBED_BINARY FASTBED_READELF FASTBED_NM)
    if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
        message(FATAL_ERROR "${required} is required")
    endif()
endforeach()
if(NOT EXISTS "${FASTBED_BINARY}")
    message(FATAL_ERROR "Fastbed binary does not exist: ${FASTBED_BINARY}")
endif()

execute_process(
    COMMAND "${FASTBED_READELF}" -dW "${FASTBED_BINARY}"
    RESULT_VARIABLE readelf_status
    OUTPUT_VARIABLE dynamic_table
    ERROR_VARIABLE readelf_error)
if(NOT readelf_status EQUAL 0)
    message(FATAL_ERROR
        "cannot inspect Fastbed dynamic table: ${readelf_error}")
endif()

execute_process(
    COMMAND "${FASTBED_READELF}" -lW "${FASTBED_BINARY}"
    RESULT_VARIABLE program_status
    OUTPUT_VARIABLE program_headers
    ERROR_VARIABLE program_error)
if(NOT program_status EQUAL 0)
    message(FATAL_ERROR
        "cannot inspect Fastbed program headers: ${program_error}")
endif()
string(REGEX MATCH "[[]Requesting program interpreter:[^]]+[]]"
       interpreter_entry "${program_headers}")

string(REGEX MATCHALL "Shared library: \\[[^]]+\\]"
       needed_entries "${dynamic_table}")
set(needed_libraries "")
foreach(entry IN LISTS needed_entries)
    string(REGEX REPLACE ".*\\[([^]]+)\\].*" "\\1" library "${entry}")
    list(APPEND needed_libraries "${library}")
    if(library MATCHES
       "^lib(curl|ssl|crypto|nghttp2|nghttp3|ngtcp2[^.]*|idn2|unistring|z|zstd|brotlidec|brotlicommon|yyjson|microhttpd|yaml[^.]*)\\.so(\\..*)?$")
        message(FATAL_ERROR
            "bundled dependency escaped into DT_NEEDED: ${library}")
    endif()
endforeach()

set(fully_static false)
if(DEFINED FASTBED_REQUIRE_FULLY_STATIC AND FASTBED_REQUIRE_FULLY_STATIC)
    if(needed_libraries)
        message(FATAL_ERROR
            "fully static Fastbed has DT_NEEDED entries: ${needed_libraries}")
    endif()
    if(NOT "${interpreter_entry}" STREQUAL "")
        message(FATAL_ERROR
            "fully static Fastbed has an ELF interpreter: ${interpreter_entry}")
    endif()
    set(fully_static true)
endif()

execute_process(
    COMMAND "${FASTBED_NM}" -a "${FASTBED_BINARY}"
    RESULT_VARIABLE nm_status
    OUTPUT_VARIABLE symbol_table
    ERROR_VARIABLE nm_error)
if(NOT nm_status EQUAL 0)
    message(FATAL_ERROR "cannot inspect Fastbed symbols: ${nm_error}")
endif()

set(required_static_symbols
    curl_easy_impersonate
    curl_easy_init
    yyjson_read_opts
    MHD_start_daemon
    yaml_parser_initialize
    fb_embedded_index_html
    fb_embedded_favicon_ico
    fb_embedded_banner_png
    fb_embedded_crawler_json)
foreach(symbol IN LISTS required_static_symbols)
    string(FIND "${symbol_table}" " T ${symbol}\n" global_index)
    string(FIND "${symbol_table}" " t ${symbol}\n" local_index)
    string(FIND "${symbol_table}" " R ${symbol}\n" ro_global_index)
    string(FIND "${symbol_table}" " r ${symbol}\n" ro_local_index)
    if(global_index EQUAL -1 AND local_index EQUAL -1 AND
       ro_global_index EQUAL -1 AND ro_local_index EQUAL -1)
        message(FATAL_ERROR
            "required statically embedded symbol is absent: ${symbol}")
    endif()
endforeach()

list(SORT needed_libraries)
list(JOIN needed_libraries "," needed_csv)
if(DEFINED FASTBED_LINKAGE_REPORT AND
   NOT "${FASTBED_LINKAGE_REPORT}" STREQUAL "")
    file(WRITE "${FASTBED_LINKAGE_REPORT}"
        "schema=1\n"
        "binary=${FASTBED_BINARY}\n"
        "fully_static=${fully_static}\n"
        "interpreter=${interpreter_entry}\n"
        "needed=${needed_csv}\n"
        "bundled_static_symbols=curl_easy_impersonate,curl_easy_init,yyjson_read_opts,MHD_start_daemon,yaml_parser_initialize,fb_embedded_index_html,fb_embedded_favicon_ico,fb_embedded_banner_png,fb_embedded_crawler_json\n")
endif()
if(fully_static)
    message(STATUS
        "verified fully static bundled linkage; no interpreter or DT_NEEDED entries")
else()
    message(STATUS
        "verified bundled static linkage; dynamic system libraries: ${needed_csv}")
endif()

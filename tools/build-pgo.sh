#!/bin/sh
set -eu

usage() {
    echo "usage: $0 [--ir|--csir] OUTPUT_DIR CURL_IMPERSONATE_ROOT -- TRAINER [ARGS...]" >&2
    echo "TRAINER must run FASTBED_PROFILE_BINARY and exit cleanly." >&2
    echo "--csir runs TRAINER twice with FASTBED_PROFILE_PHASE=ir and csir." >&2
    echo "A profile CFG/hash mismatch fails closed. A reviewed exception requires" >&2
    echo "FASTBED_ALLOW_PGO_PROFILE_MISMATCH=1 and a nonempty" >&2
    echo "FASTBED_PGO_PROFILE_MISMATCH_WAIVER_FILE." >&2
    exit 2
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "required tool not found: $1" >&2
        exit 2
    }
}

profile_kind=ir
case "${1-}" in
    --ir)
        shift
        ;;
    --csir)
        profile_kind=csir
        shift
        ;;
esac

[ "$#" -ge 4 ] || usage
output=$1
curl_root=$2
static_deps_root=${FASTBED_STATIC_DEPS_ROOT:-}
shift 2
[ "$1" = "--" ] || usage
shift
[ "$#" -ge 1 ] || usage
[ ! -e "$output" ] || {
    echo "output already exists: $output" >&2
    exit 2
}
[ -d "$curl_root" ] || {
    echo "curl-impersonate prefix not found: $curl_root" >&2
    exit 2
}
[ -d "$static_deps_root" ] || {
    echo "FASTBED_STATIC_DEPS_ROOT must name the verified libmicrohttpd/libyaml prefix" >&2
    exit 2
}
static_deps_root=$(CDPATH= cd -- "$static_deps_root" && pwd)
curl_root=$(CDPATH= cd -- "$curl_root" && pwd)
curl_manifest=$curl_root/share/fastbed-curl-impersonate/BUILD-MANIFEST.txt
curl_checksums=$curl_root/share/fastbed-curl-impersonate/SHA256SUMS
for curl_evidence in "$curl_manifest" "$curl_checksums"; do
    [ -f "$curl_evidence" ] || {
        echo "curl-impersonate prefix evidence not found: $curl_evidence" >&2
        exit 2
    }
done

cc=${CC:-clang}
profdata_tool=${LLVM_PROFDATA:-llvm-profdata}
cmake_tool=${CMAKE:-cmake}
readelf_tool=${READELF:-readelf}

case "${FASTBED_ALLOW_PGO_PROFILE_MISMATCH:-0}" in
    0|1)
        ;;
    *)
        echo "FASTBED_ALLOW_PGO_PROFILE_MISMATCH must be 0 or 1" >&2
        exit 2
        ;;
esac

require_command "$cc"
require_command "$profdata_tool"
require_command "$cmake_tool"
require_command ninja
require_command ld.lld
require_command "$readelf_tool"
require_command sha256sum
require_command find
require_command grep
require_command awk
require_command sed
require_command sort
require_command cat

cc_path=$(command -v "$cc")
profdata_path=$(command -v "$profdata_tool")
clang_major=$(
    "$cc_path" -dumpversion | sed -n '1{s/\..*//;p;q;}'
)
profdata_major=$(
    "$profdata_path" --version |
        sed -n 's/.*LLVM version \([0-9][0-9]*\).*/\1/p' |
        sed -n '1p'
)
[ -n "$clang_major" ] && [ "$clang_major" = "$profdata_major" ] || {
    echo "clang/llvm-profdata major-version mismatch: clang=$clang_major llvm-profdata=${profdata_major:-unknown}" >&2
    exit 2
}

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_abs=$(mkdir -p -- "$output" && CDPATH= cd -- "$output" && pwd)
instrumented="$output_abs/instrumented-ir"
cs_instrumented="$output_abs/instrumented-csir"
optimized="$output_abs/optimized"
optimized_build_log="$output_abs/optimized-build.log"
profile_mismatch_log="$output_abs/profile-mismatch-warnings.log"
profile_mismatch_count_file="$output_abs/profile-mismatch-warnings.count"
profile_mismatch_report="$output_abs/profile-mismatch-report.txt"
raw_ir="$output_abs/raw-ir"
raw_cs="$output_abs/raw-csir"
base_profile="$output_abs/fastbed.ir.profdata"
profile="$output_abs/fastbed.profdata"
mkdir -p -- "$raw_ir"

write_profile_mismatch_report() {
    {
        echo "schema=1"
        echo "gate=$(printf '%s' "$profile_mismatch_gate")"
        echo "profile_mismatch_warnings=$(printf '%s' "$profile_mismatch_warnings")"
        echo "profile_mismatch_log=$(sha256sum "$profile_mismatch_log" | awk '{print $1}')"
        echo "optimized_build_log=$(sha256sum "$optimized_build_log" | awk '{print $1}')"
        echo "waiver_requested=$(printf '%s' "$profile_mismatch_waiver_requested")"
        echo "waiver_file_sha256=$(printf '%s' "$profile_mismatch_waiver_hash")"
    } >"$profile_mismatch_report.tmp"
    mv -- "$profile_mismatch_report.tmp" "$profile_mismatch_report"
}

"$cmake_tool" -S "$root" -B "$instrumented" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$cc_path" \
    -DFASTBED_CURL_IMPERSONATE_ROOT="$curl_root" \
    -DFASTBED_STATIC_DEPS_ROOT="$static_deps_root" \
    -DFASTBED_USE_LLD=ON \
    -DFASTBED_VERIFICATION_BUILD=ON \
    -DFASTBED_LTO=OFF \
    -DFASTBED_PGO_GENERATE=ON \
    -DFASTBED_CLANG_PGO_GENERATE_MODE=IR \
    -DFASTBED_CLANG_PGO_UPDATE_MODE=ATOMIC
"$cmake_tool" --build "$instrumented" --parallel

export FASTBED_PROFILE_BINARY="$instrumented/fastbed"
export FASTBED_PROFILE_PHASE=ir
export LLVM_PROFILE_FILE="$raw_ir/fastbed-%m-%p.profraw"
"$@"

[ -n "$(find "$raw_ir" -type f -name '*.profraw' -print -quit)" ] || {
    echo "trainer produced no IR .profraw files" >&2
    exit 1
}

if [ "$profile_kind" = csir ]; then
    "$profdata_path" merge -output="$base_profile" "$raw_ir"
    mkdir -p -- "$raw_cs"
    "$cmake_tool" -S "$root" -B "$cs_instrumented" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER="$cc_path" \
        -DFASTBED_CURL_IMPERSONATE_ROOT="$curl_root" \
        -DFASTBED_STATIC_DEPS_ROOT="$static_deps_root" \
        -DFASTBED_USE_LLD=ON \
        -DFASTBED_VERIFICATION_BUILD=ON \
        -DFASTBED_LTO=OFF \
        -DFASTBED_PGO_GENERATE=ON \
        -DFASTBED_CLANG_PGO_GENERATE_MODE=CSIR \
        -DFASTBED_CLANG_PGO_UPDATE_MODE=ATOMIC \
        -DFASTBED_PGO_USE="$base_profile"
    "$cmake_tool" --build "$cs_instrumented" --parallel

    export FASTBED_PROFILE_BINARY="$cs_instrumented/fastbed"
    export FASTBED_PROFILE_PHASE=csir
    export LLVM_PROFILE_FILE="$raw_cs/fastbed-%m-%p.profraw"
    "$@"

    [ -n "$(find "$raw_cs" -type f -name '*.profraw' -print -quit)" ] || {
        echo "trainer produced no CSIR .profraw files" >&2
        exit 1
    }
    "$profdata_path" merge -output="$profile" "$raw_cs" "$base_profile"
else
    "$profdata_path" merge -output="$profile" "$raw_ir"
fi

"$profdata_path" show --detailed-summary --binary-ids "$profile" \
    >"$output_abs/profile-summary.txt"

"$cmake_tool" -S "$root" -B "$optimized" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$cc_path" \
    -DFASTBED_CURL_IMPERSONATE_ROOT="$curl_root" \
    -DFASTBED_STATIC_DEPS_ROOT="$static_deps_root" \
    -DFASTBED_USE_LLD=ON \
    -DFASTBED_LTO=ON \
    -DFASTBED_LTO_MODE=FULL \
    -DFASTBED_PGO_USE="$profile" \
    -DFASTBED_BOLT_READY=ON
optimized_build_status=0
if "$cmake_tool" --build "$optimized" --parallel \
        >"$optimized_build_log" 2>&1; then
    :
else
    optimized_build_status=$?
fi
awk 'index($0, "function control flow change detected (hash mismatch)") { print }' \
    "$optimized_build_log" >"$profile_mismatch_log.tmp"
profile_mismatch_warnings=$(
    awk 'END { print NR + 0 }' "$profile_mismatch_log.tmp"
)
mv -- "$profile_mismatch_log.tmp" "$profile_mismatch_log"
printf '%s\n' "$profile_mismatch_warnings" \
    >"$profile_mismatch_count_file.tmp"
mv -- "$profile_mismatch_count_file.tmp" "$profile_mismatch_count_file"

profile_mismatch_waiver_requested=${FASTBED_ALLOW_PGO_PROFILE_MISMATCH:-0}
profile_mismatch_waiver_hash=unprovided
if [ "$optimized_build_status" -ne 0 ]; then
    profile_mismatch_gate=optimized-build-failed
    write_profile_mismatch_report
    cat "$optimized_build_log" >&2
    exit "$optimized_build_status"
fi
cat "$optimized_build_log"

if [ "$profile_mismatch_warnings" -gt 0 ]; then
    if [ "$profile_mismatch_waiver_requested" -ne 1 ]; then
        profile_mismatch_gate=rejected
        write_profile_mismatch_report
        echo "optimized build rejected: $profile_mismatch_warnings profile CFG/hash mismatch warning(s)" >&2
        echo "review $profile_mismatch_log and $optimized_build_log" >&2
        echo "an independently justified waiver requires FASTBED_ALLOW_PGO_PROFILE_MISMATCH=1" >&2
        echo "and FASTBED_PGO_PROFILE_MISMATCH_WAIVER_FILE=/path/to/nonempty/review" >&2
        exit 1
    fi
    profile_mismatch_waiver_file=${FASTBED_PGO_PROFILE_MISMATCH_WAIVER_FILE:-}
    [ -f "$profile_mismatch_waiver_file" ] &&
        [ -s "$profile_mismatch_waiver_file" ] || {
            profile_mismatch_gate=rejected-invalid-waiver
            write_profile_mismatch_report
            echo "optimized build rejected: profile mismatch waiver file is missing, not a regular file, or empty" >&2
            exit 2
        }
    profile_mismatch_waiver_hash=$(
        sha256sum "$profile_mismatch_waiver_file" | awk '{print $1}'
    )
    profile_mismatch_gate=waived
    write_profile_mismatch_report
    echo "WARNING: accepting $profile_mismatch_warnings profile CFG/hash mismatch warning(s) under reviewed waiver $profile_mismatch_waiver_hash" >&2
else
    profile_mismatch_gate=clean
    write_profile_mismatch_report
fi

"$readelf_tool" -SW "$optimized/fastbed" |
    grep -Eq '[[:space:]]\.rela\.text([[:space:]]|$)' || {
        echo "optimized binary is missing the .rela.text section required by BOLT" >&2
        exit 1
    }

source_hash=$(
    CDPATH= cd -- "$root"
    find CMakeLists.txt assets include src third_party/yyjson \
        third_party/crawler-user-agents -type f -print |
        LC_ALL=C sort |
        while IFS= read -r source_path; do
            sha256sum "$source_path"
        done |
        sha256sum |
        awk '{print $1}'
)
trainer_command_hash=$(printf '%s\0' "$@" | sha256sum | awk '{print $1}')
training_manifest_hash=unprovided
if [ -n "${FASTBED_TRAINING_MANIFEST:-}" ]; then
    if [ -f "$FASTBED_TRAINING_MANIFEST" ]; then
        training_manifest_hash=$(sha256sum "$FASTBED_TRAINING_MANIFEST" | awk '{print $1}')
    elif [ -d "$FASTBED_TRAINING_MANIFEST" ]; then
        [ -n "$(find "$FASTBED_TRAINING_MANIFEST" -type f \( -name manifest.json -o -name SHA256SUMS \) -print -quit)" ] || {
            echo "FASTBED_TRAINING_MANIFEST directory has no manifests: $FASTBED_TRAINING_MANIFEST" >&2
            exit 2
        }
        training_manifest_hash=$(
            CDPATH= cd -- "$FASTBED_TRAINING_MANIFEST"
            find . -type f \( -name manifest.json -o -name SHA256SUMS \) -print |
                LC_ALL=C sort |
                while IFS= read -r manifest_path; do
                    sha256sum "$manifest_path"
                done |
                sha256sum |
                awk '{print $1}'
        )
    else
        echo "FASTBED_TRAINING_MANIFEST is not a file or directory: $FASTBED_TRAINING_MANIFEST" >&2
        exit 2
    fi
fi
binary_build_id=$(
    "$readelf_tool" -nW "$optimized/fastbed" |
        sed -n 's/.*Build ID: //p' |
        sed -n '1p'
)

{
    echo "schema=2"
    echo "kind=clang-${profile_kind}-pgo-full-lto-bolt-ready"
    echo "workflow=$(sha256sum "$root/tools/build-pgo.sh" | awk '{print $1}')"
    echo "source=$(printf '%s' "$source_hash")"
    echo "compiler_path=$(printf '%s' "$cc_path")"
    echo "compiler=$($cc_path --version | sed -n '1p')"
    echo "compiler_target=$($cc_path -print-target-triple)"
    echo "llvm_profdata_path=$(printf '%s' "$profdata_path")"
    echo "llvm_profdata=$($profdata_path --version | sed -n '2p')"
    echo "linker=$(ld.lld --version | sed -n '1p')"
    echo "cmake=$($cmake_tool --version | sed -n '1p')"
    echo "ninja=$(ninja --version)"
    echo "pgo_update=atomic"
    echo "training_command_sha256=$(printf '%s' "$trainer_command_hash")"
    echo "training_manifest_sha256=$(printf '%s' "$training_manifest_hash")"
    echo "profile=$(sha256sum "$profile" | awk '{print $1}')"
    echo "profile_summary=$(sha256sum "$output_abs/profile-summary.txt" | awk '{print $1}')"
    echo "profile_mismatch_warnings=$(printf '%s' "$profile_mismatch_warnings")"
    echo "profile_mismatch_gate=$(printf '%s' "$profile_mismatch_gate")"
    echo "profile_mismatch_log=$(sha256sum "$profile_mismatch_log" | awk '{print $1}')"
    echo "profile_mismatch_report=$(sha256sum "$profile_mismatch_report" | awk '{print $1}')"
    echo "profile_mismatch_waiver_file=$(printf '%s' "$profile_mismatch_waiver_hash")"
    echo "optimized_build_log=$(sha256sum "$optimized_build_log" | awk '{print $1}')"
    echo "binary=$(sha256sum "$optimized/fastbed" | awk '{print $1}')"
    echo "binary_build_id=$(printf '%s' "$binary_build_id")"
    echo "curl_build_manifest=$(sha256sum "$curl_manifest" | awk '{print $1}')"
    echo "curl_sha256sums=$(sha256sum "$curl_checksums" | awk '{print $1}')"
} >"$output_abs/manifest.txt.tmp"
mv -- "$output_abs/manifest.txt.tmp" "$output_abs/manifest.txt"

echo "$optimized/fastbed"

#!/bin/sh
set -eu

usage() {
    echo "usage: $0 OUTPUT_DIR INPUT_BINARY -- TRAINER [ARGS...]" >&2
    echo "TRAINER must run the binary named by FASTBED_BOLT_BINARY and exit cleanly." >&2
    exit 2
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "required tool not found: $1" >&2
        exit 2
    }
}

[ "$#" -ge 4 ] || usage
output=$1
input=$2
shift 2
[ "$1" = "--" ] || usage
shift
[ "$#" -ge 1 ] || usage
[ ! -e "$output" ] || {
    echo "output already exists: $output" >&2
    exit 2
}
[ -x "$input" ] || {
    echo "input binary is not executable: $input" >&2
    exit 2
}
bolt_tool=${LLVM_BOLT:-llvm-bolt}
merge_tool=${MERGE_FDATA:-merge-fdata}
readelf_tool=${READELF:-readelf}
require_command "$bolt_tool"
require_command "$merge_tool"
require_command "$readelf_tool"
require_command sha256sum
require_command tail
require_command find
require_command grep
require_command awk
require_command sed
require_command sort

bolt_path=$(command -v "$bolt_tool")
merge_path=$(command -v "$merge_tool")
readelf_path=$(command -v "$readelf_tool")
bolt_version=$("$bolt_path" --version)
merge_version=$("$merge_path" --version)
bolt_vendor=$(printf '%s\n' "$bolt_version" | sed -n '/./{p;q;}')
bolt_llvm_version=$(
    printf '%s\n' "$bolt_version" |
        sed -n '/^[[:space:]]*LLVM version[[:space:]]/{s/^[[:space:]]*//;s/[[:space:]]*$//;p;q;}'
)
merge_llvm_version=$(
    printf '%s\n' "$merge_version" |
        sed -n '/^[[:space:]]*LLVM version[[:space:]]/{s/^[[:space:]]*//;s/[[:space:]]*$//;p;q;}'
)
[ -n "$bolt_vendor" ] || {
    echo "llvm-bolt --version returned no vendor identity: $bolt_path" >&2
    exit 2
}
[ -n "$bolt_llvm_version" ] || {
    echo "llvm-bolt --version returned no LLVM version line: $bolt_path" >&2
    exit 2
}
[ -n "$merge_llvm_version" ] || {
    echo "merge-fdata --version returned no LLVM version line: $merge_path" >&2
    exit 2
}
bolt_hash=$(sha256sum "$bolt_path" | awk '{print $1}')
merge_hash=$(sha256sum "$merge_path" | awk '{print $1}')
readelf_hash=$(sha256sum "$readelf_path" | awk '{print $1}')
input_sections=$("$readelf_path" -SW "$input")
printf '%s\n' "$input_sections" |
    grep -Eq '[[:space:]]\.symtab([[:space:]]|$)' || {
        echo "BOLT input must retain its ELF symbol table: $input" >&2
        exit 2
    }
printf '%s\n' "$input_sections" |
    grep -Eq '[[:space:]]\.rela\.text([[:space:]]|$)' || {
        echo "BOLT input is missing .rela.text; rebuild with FASTBED_BOLT_READY=ON" >&2
        exit 2
    }
input_machine=$(
    "$readelf_path" -hW "$input" |
        sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p' |
        sed -n '1p'
)
case "$input_machine" in
    "Advanced Micro Devices X86-64"|AArch64)
        ;;
    *)
        echo "unsupported BOLT input machine: ${input_machine:-unknown}" >&2
        exit 2
        ;;
esac
input_build_id=$(
    "$readelf_path" -nW "$input" |
        sed -n 's/.*Build ID: //p' |
        sed -n '1p'
)
[ -n "$input_build_id" ] || {
    echo "BOLT input has no build ID: $input" >&2
    exit 2
}
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
input_manifest_hash=unprovided
if [ -n "${FASTBED_INPUT_MANIFEST:-}" ]; then
    [ -f "$FASTBED_INPUT_MANIFEST" ] || {
        echo "FASTBED_INPUT_MANIFEST is not a file: $FASTBED_INPUT_MANIFEST" >&2
        exit 2
    }
    input_manifest_hash=$(sha256sum "$FASTBED_INPUT_MANIFEST" | awk '{print $1}')
fi

output_abs=$(mkdir -p -- "$output/profiles" && CDPATH= cd -- "$output" && pwd)
instrumented="$output_abs/fastbed.instrumented"
profile_prefix="$output_abs/profiles/fastbed.fdata"
instrument_log="$output_abs/instrumentation.log"
optimize_log="$output_abs/optimization.log"

if ! "$bolt_path" "$input" \
        -instrument \
        -instrumentation-file="$profile_prefix" \
        -instrumentation-file-append-pid \
        -o "$instrumented" >"$instrument_log" 2>&1; then
    tail -n 200 "$instrument_log" >&2
    exit 1
fi
[ -x "$instrumented" ] || {
    echo "llvm-bolt did not produce an executable instrumented binary" >&2
    exit 1
}

export FASTBED_BOLT_BINARY="$instrumented"
"$@"

set -- "$profile_prefix".*
[ -f "$1" ] || {
    echo "trainer produced no BOLT instrumentation profiles" >&2
    exit 1
}
profile_file_count=$#
"$merge_path" "$@" >"$output_abs/fastbed.fdata"

if ! "$bolt_path" "$input" \
        -data="$output_abs/fastbed.fdata" \
        -reorder-blocks=ext-tsp \
        -reorder-functions=cdsort \
        -split-functions \
        -split-all-cold \
        -split-eh \
        -dyno-stats \
        -o "$output_abs/fastbed.bolt" >"$optimize_log" 2>&1; then
    tail -n 200 "$optimize_log" >&2
    exit 1
fi
[ -x "$output_abs/fastbed.bolt" ] || {
    echo "llvm-bolt did not produce an executable optimized binary" >&2
    exit 1
}
output_machine=$(
    "$readelf_path" -hW "$output_abs/fastbed.bolt" |
        sed -n 's/^[[:space:]]*Machine:[[:space:]]*//p' |
        sed -n '1p'
)
[ "$output_machine" = "$input_machine" ] || {
    echo "BOLT output machine changed: input=$input_machine output=$output_machine" >&2
    exit 1
}
output_build_id=$(
    "$readelf_path" -nW "$output_abs/fastbed.bolt" |
        sed -n 's/.*Build ID: //p' |
        sed -n '1p'
)
[ -n "$output_build_id" ] || {
    echo "BOLT output has no build ID" >&2
    exit 1
}
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

{
    echo "schema=2"
    echo "kind=bolt-instrumented-ext-tsp-cdsort"
    echo "workflow=$(sha256sum "$root/tools/build-bolt.sh" | awk '{print $1}')"
    echo "tool_path=$(printf '%s' "$bolt_path")"
    echo "tool=$(printf '%s' "$bolt_vendor")"
    echo "tool_llvm_version=$(printf '%s' "$bolt_llvm_version")"
    echo "tool_sha256=$(printf '%s' "$bolt_hash")"
    echo "merge_fdata_path=$(printf '%s' "$merge_path")"
    echo "merge_fdata_llvm_version=$(printf '%s' "$merge_llvm_version")"
    echo "merge_fdata_sha256=$(printf '%s' "$merge_hash")"
    echo "readelf_path=$(printf '%s' "$readelf_path")"
    echo "readelf_sha256=$(printf '%s' "$readelf_hash")"
    echo "machine=$(printf '%s' "$input_machine")"
    echo "flags=reorder-blocks=ext-tsp,reorder-functions=cdsort,split-functions,split-all-cold,split-eh,dyno-stats"
    echo "profile_mode=instrumentation"
    echo "profile_files=$(printf '%s' "$profile_file_count")"
    echo "training_command_sha256=$(printf '%s' "$trainer_command_hash")"
    echo "training_manifest_sha256=$(printf '%s' "$training_manifest_hash")"
    echo "input_manifest_sha256=$(printf '%s' "$input_manifest_hash")"
    echo "input=$(sha256sum "$input" | awk '{print $1}')"
    echo "input_build_id=$(printf '%s' "$input_build_id")"
    echo "profile=$(sha256sum "$output_abs/fastbed.fdata" | awk '{print $1}')"
    echo "binary=$(sha256sum "$output_abs/fastbed.bolt" | awk '{print $1}')"
    echo "binary_build_id=$(printf '%s' "$output_build_id")"
    echo "instrumentation_log=$(sha256sum "$instrument_log" | awk '{print $1}')"
    echo "optimization_log=$(sha256sum "$optimize_log" | awk '{print $1}')"
} >"$output_abs/manifest.txt.tmp"
mv -- "$output_abs/manifest.txt.tmp" "$output_abs/manifest.txt"

echo "$output_abs/fastbed.bolt"


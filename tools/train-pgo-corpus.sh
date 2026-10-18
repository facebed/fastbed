#!/bin/sh
set -eu

usage() {
    echo "usage: $0 CORPUS PYTHON_RESULTS OUTPUT_ROOT [LINES]" >&2
    echo "LINES is an optional comma-separated set of corpus source lines." >&2
    exit 2
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "required tool not found: $1" >&2
        exit 2
    }
}

[ "$#" -ge 3 ] && [ "$#" -le 4 ] || usage
[ -n "${FASTBED_PROFILE_BINARY:-}" ] || {
    echo "FASTBED_PROFILE_BINARY is not set" >&2
    exit 2
}
[ -x "$FASTBED_PROFILE_BINARY" ] || {
    echo "FASTBED_PROFILE_BINARY is not executable: $FASTBED_PROFILE_BINARY" >&2
    exit 2
}

corpus=$1
python_results=$2
output_root=$3
lines=${4-}
phase=${FASTBED_PROFILE_PHASE:-ir}
case "$phase" in
    *[!A-Za-z0-9_.-]*|'')
        echo "unsafe FASTBED_PROFILE_PHASE: $phase" >&2
        exit 2
        ;;
esac
[ -d "$corpus" ] || {
    echo "corpus directory not found: $corpus" >&2
    exit 2
}
[ -f "$python_results" ] || {
    echo "Python result file not found: $python_results" >&2
    exit 2
}
output="$output_root/$phase"
[ ! -e "$output" ] || {
    echo "training output already exists: $output" >&2
    exit 2
}

python=${PYTHON:-python3}
require_command "$python"
require_command unshare
require_command ip
require_command env
require_command openssl
require_command readlink

if [ "${FASTBED_TRAINER_NETNS_READY:-0}" != 1 ]; then
    parent_netns=$(readlink /proc/self/ns/net)
    exec unshare --user --map-root-user --net \
        env FASTBED_TRAINER_NETNS_READY=1 \
            FASTBED_TRAINER_PARENT_NETNS="$parent_netns" \
        sh "$0" "$@"
fi

parent_netns=${FASTBED_TRAINER_PARENT_NETNS:-}
[ -n "$parent_netns" ] || {
    echo "isolated trainer lost its parent network namespace identity" >&2
    exit 2
}
[ "$(readlink /proc/self/ns/net)" != "$parent_netns" ] || {
    echo "isolated trainer did not enter a new network namespace" >&2
    exit 2
}
ip link set dev lo up

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runner="$root/e2e/run_corpus_e2e.py"

if [ -n "$lines" ]; then
    exec "$python" "$runner" "$FASTBED_PROFILE_BINARY" "$corpus" \
        --output "$output" \
        --python-results "$python_results" \
        --lines "$lines" \
        --parent-netns "$parent_netns"
fi

exec "$python" "$runner" "$FASTBED_PROFILE_BINARY" "$corpus" \
    --output "$output" \
    --python-results "$python_results" \
    --parent-netns "$parent_netns"

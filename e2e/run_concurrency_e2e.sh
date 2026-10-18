#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
parent_netns=$(readlink /proc/self/ns/net)

exec unshare --user --map-root-user --net -- \
    sh -c 'set -e; ip link set lo up; exec "$@"' sh \
    python3 "$script_dir/run_concurrency_e2e.py" \
    "$@" --parent-netns "$parent_netns"

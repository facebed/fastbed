#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 OUTPUT_DIR" >&2
    exit 2
fi

case "$1" in
    /*) output=$1 ;;
    *) output=$PWD/$1 ;;
esac
if [ -e "$output" ]; then
    echo "output already exists: $output" >&2
    exit 2
fi

parent=$(dirname -- "$output")
mkdir -p -- "$parent"
work=$(mktemp -d "$parent/.fastbed-sbom-schemas.XXXXXX")
cleanup() {
    case "$work" in
        "$parent"/.fastbed-sbom-schemas.*) rm -rf -- "$work" ;;
        *) echo "refusing to remove unexpected directory: $work" >&2 ;;
    esac
}
trap cleanup EXIT HUP INT TERM

download() {
    name=$1
    url=$2
    expected=$3
    curl --proto '=https' --tlsv1.2 --fail --location --retry 3 \
        --silent --show-error \
        --output "$work/$name" "$url"
    printf '%s  %s\n' "$expected" "$work/$name" | sha256sum -c - >/dev/null
}

download bom-1.6.schema.json \
    https://cyclonedx.org/schema/bom-1.6.schema.json \
    1ebcb88a2c845ecb6ff7bee7aeabdff9422cb0347f3d6875b241bd444b7e098f
download spdx.schema.json \
    https://cyclonedx.org/schema/spdx.schema.json \
    33863a360fc4d348e183d89c1ca7aa0877f481e7eb55be2d4102a30386188a10
download jsf-0.82.schema.json \
    https://cyclonedx.org/schema/jsf-0.82.schema.json \
    2faf5eb3651f2ae5f46091a131770d8d847bbd121139d19c85fc7051bfa58c46
download spdx-2.3.schema.json \
    https://raw.githubusercontent.com/spdx/spdx-spec/v2.3/schemas/spdx-schema.json \
    239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b
download spdx-licenses-3.29.0.json \
    https://raw.githubusercontent.com/spdx/license-list-data/v3.29.0/json/licenses.json \
    47d1cc681abe31166b342b6cc4aab13a6ba8ea5c48794697fe3bf8b1dbaf509a
download spdx-exceptions-3.29.0.json \
    https://raw.githubusercontent.com/spdx/license-list-data/v3.29.0/json/exceptions.json \
    59ee7c150de521d635cbf9367b8cf543b8da6781ea3ac1c073d305524f84ada2

mv -- "$work" "$output"
trap - EXIT HUP INT TERM
printf '%s\n' "$output"

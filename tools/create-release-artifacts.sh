#!/bin/sh
set -eu

usage() {
    echo "usage: $0 SOURCE_DIR BUILD_DIR CURL_ROOT STATIC_DEPS_ROOT RUNTIME_ROOT ARTIFACT_ROOT TARGET_ARCH BASE_IMAGE" >&2
    exit 2
}

if [ "$#" -ne 8 ]; then
    usage
fi

source_dir=$1
build_dir=$2
curl_root=$3
static_deps_root=$4
runtime_root=$5
artifact_root=$6
target_arch=$7
base_image=$8

case "$target_arch" in
    amd64|arm64) ;;
    *) usage ;;
esac
for directory in "$source_dir" "$build_dir" "$curl_root" \
                 "$static_deps_root" "$runtime_root"; do
    case "$directory" in
        /*) ;;
        *) echo "directory must be absolute: $directory" >&2; exit 2 ;;
    esac
    test -d "$directory" || {
        echo "directory not found: $directory" >&2
        exit 2
    }
done
case "$artifact_root" in
    /*) ;;
    *) echo "artifact root must be absolute: $artifact_root" >&2; exit 2 ;;
esac

source_date_epoch=${SOURCE_DATE_EPOCH:-1774606016}
case "$source_date_epoch" in
    ''|*[!0-9]*) echo "invalid SOURCE_DATE_EPOCH: $source_date_epoch" >&2; exit 2 ;;
esac

for command in apk clang cmake cmp find gzip ld.lld ninja objcopy \
               python3 readelf sha256sum sort strip tar; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required release-artifact command not found: $command" >&2
        exit 2
    }
done

fastbed=$build_dir/fastbed
runtime_fastbed=$runtime_root/usr/local/bin/fastbed
for file in "$fastbed" "$runtime_fastbed" \
            "$build_dir/libfastbed_yyjson.a" \
            "$curl_root/share/fastbed-curl-impersonate/BUILD-MANIFEST.txt" \
            "$static_deps_root/lib/libmicrohttpd.a" \
            "$static_deps_root/lib/libyaml.a" \
            "$static_deps_root/share/fastbed-static-deps/BUILD-MANIFEST.txt"; do
    test -f "$file" || {
        echo "required release input not found: $file" >&2
        exit 2
    }
done

mkdir -p "$artifact_root/relink" "$artifact_root/debug"
relink_archive=$artifact_root/relink/fastbed-relink-$target_arch.tar.gz
debug_archive=$artifact_root/debug/fastbed-debug-$target_arch.tar.gz
for archive in "$relink_archive" "$debug_archive"; do
    test ! -e "$archive" || {
        echo "refusing to overwrite release artifact: $archive" >&2
        exit 2
    }
done

work=$(mktemp -d "${TMPDIR:-/tmp}/fastbed-release-artifacts.XXXXXX")
cleanup() {
    case "$work" in
        "${TMPDIR:-/tmp}"/fastbed-release-artifacts.*) rm -rf -- "$work" ;;
        *) echo "refusing to remove unexpected work directory: $work" >&2 ;;
    esac
}
trap cleanup EXIT HUP INT TERM

bundle_name=fastbed-relink-$target_arch
bundle=$work/$bundle_name
objects=$bundle/application-objects
mkdir -p "$objects" "$bundle/application-source" "$bundle/curl-prefix" \
    "$bundle/static-deps-prefix"

find "$build_dir/CMakeFiles/fastbed.dir" -type f -name '*.o' -print |
    LC_ALL=C sort |
    while IFS= read -r object; do
        relative=${object#"$build_dir/"}
        destination=$objects/$relative
        mkdir -p "$(dirname -- "$destination")"
        cp -- "$object" "$destination"
    done
cp -- "$build_dir/libfastbed_yyjson.a" "$objects/libfastbed_yyjson.a"
cp -R -- "$curl_root/include" "$curl_root/lib" "$curl_root/share" \
    "$bundle/curl-prefix/"
cp -R -- "$static_deps_root/include" "$static_deps_root/lib" \
    "$static_deps_root/share" "$bundle/static-deps-prefix/"
cp -- "$source_dir/CMakeLists.txt" "$source_dir/README.md" \
    "$bundle/application-source/"
cp -R -- "$source_dir/assets" "$source_dir/cmake" "$source_dir/include" \
    "$source_dir/src" \
    "$bundle/application-source/"
mkdir -p "$bundle/application-source/tools"
cp -- "$source_dir/tools/build-static-deps.sh" \
    "$source_dir/tools/embed-resources.py" \
    "$bundle/application-source/tools/"
mkdir -p "$bundle/application-source/third_party"
cp -R -- "$source_dir/third_party/yyjson" \
    "$source_dir/third_party/crawler-user-agents" \
    "$bundle/application-source/third_party/"

link_command=$bundle/ORIGINAL-LINK-COMMAND.txt
ninja -C "$build_dir" -t commands fastbed | tail -n 1 > "$link_command"
if ! grep -F -- "$curl_root/" "$link_command" >/dev/null; then
    echo "the captured link command does not reference $curl_root" >&2
    exit 1
fi
if ! grep -F -- "$static_deps_root/" "$link_command" >/dev/null; then
    echo "the captured link command does not reference $static_deps_root" >&2
    exit 1
fi
if ! grep -F -- ' -o fastbed ' "$link_command" >/dev/null; then
    echo "the captured link command has an unexpected output spelling" >&2
    exit 1
fi

python3 - "$link_command" "$bundle/relink-fastbed.sh" "$curl_root" \
    "$static_deps_root" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1])
destination = Path(sys.argv[2])
curl_root = sys.argv[3]
static_deps_root = sys.argv[4]
command = source.read_text(encoding="utf-8").strip()
if ("\n" in command or curl_root not in command
        or static_deps_root not in command):
    raise SystemExit("unsafe or incomplete captured link command")
link_command = command.split(" && cd ", 1)[0]
if " -o fastbed " not in link_command:
    raise SystemExit("cannot isolate the Fastbed compiler link command")
link_command = link_command.replace(
    curl_root, '"${bundle_root}/curl-prefix"')
link_command = link_command.replace(
    static_deps_root, '"${bundle_root}/static-deps-prefix"')
script = """#!/bin/sh
set -eu
bundle_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output_arg=${1:-"$bundle_root/fastbed.relinked"}
case "$output_arg" in
    /*) output=$output_arg ;;
    *) output=$PWD/$output_arg ;;
esac
for command in clang ld.lld; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required relink command not found: $command" >&2
        exit 2
    }
done
cd "$bundle_root/application-objects"
rm -f -- fastbed
(
""" + link_command + """
)
mv -- fastbed "$output"
printf 'relinked Fastbed: %s\\n' "$output"
"""
destination.write_text(script, encoding="utf-8")
PY
chmod 0755 "$bundle/relink-fastbed.sh"

{
    printf 'base_image=%s\n' "$base_image"
    printf 'target_arch=%s\n' "$target_arch"
    printf 'source_date_epoch=%s\n' "$source_date_epoch"
    printf 'alpine_release=%s\n' "$(cat /etc/alpine-release)"
    printf 'clang=%s\n' "$(clang --version | sed -n '1p')"
    printf 'lld=%s\n' "$(ld.lld --version | sed -n '1p')"
    printf 'cmake=%s\n' "$(cmake --version | sed -n '1p')"
    printf 'ninja=%s\n' "$(ninja --version)"
    printf 'libmicrohttpd=1.0.10-static\n'
    printf 'libyaml=0.2.5-static\n'
    printf 'libmicrohttpd_archive_sha256=%s\n' \
        "$(sha256sum "$static_deps_root/lib/libmicrohttpd.a" | awk '{print $1}')"
    printf 'libyaml_archive_sha256=%s\n' \
        "$(sha256sum "$static_deps_root/lib/libyaml.a" | awk '{print $1}')"
    printf 'libpcre2=%s\n' "$(pkg-config --modversion libpcre2-8)"
    printf '\n[apk-packages]\n'
    apk info -vv | LC_ALL=C sort
} > "$bundle/TOOLCHAIN.txt"

cat > "$bundle/README.txt" <<'EOF'
This is the release-time relinking material for Fastbed's statically linked
LGPL libmicrohttpd, libidn2, and libunistring libraries. It contains the
application objects, exact static dependency prefixes and licenses, the
corresponding application source used for this build, the original linker
command, and a portable relink script.

Extract the archive in the matching toolchain recorded in TOOLCHAIN.txt, replace
the LGPL archives under curl-prefix/lib or static-deps-prefix/lib if desired,
then run:

    ./relink-fastbed.sh ./fastbed.relinked

Fastbed's repository-level license is intentionally not inferred here. This
bundle is a technical relinking mechanism and source record, not a legal opinion.
EOF

relinked=$work/fastbed.relinked
"$bundle/relink-fastbed.sh" "$relinked"
if ! cmp -s "$fastbed" "$relinked"; then
    echo "relink verification did not reproduce the unstripped Fastbed binary" >&2
    sha256sum "$fastbed" "$relinked" >&2
    readelf -n "$fastbed" | sed -n '/Build ID:/p' >&2
    readelf -n "$relinked" | sed -n '/Build ID:/p' >&2
    cmp -l "$fastbed" "$relinked" | sed -n '1,20p' >&2 || true
    exit 1
fi
original_sha=$(sha256sum "$fastbed" | awk '{print $1}')
relinked_sha=$(sha256sum "$relinked" | awk '{print $1}')
printf 'original_unstripped_sha256=%s\nrelinked_sha256=%s\nbyte_identical=true\n' \
    "$original_sha" "$relinked_sha" > "$bundle/RELINK-VERIFICATION.txt"
printf 'curl_build_manifest_sha256=%s\n' \
    "$(sha256sum "$curl_root/share/fastbed-curl-impersonate/BUILD-MANIFEST.txt" | awk '{print $1}')" \
    > "$bundle/MANIFEST.txt"
printf 'static_deps_build_manifest_sha256=%s\n' \
    "$(sha256sum "$static_deps_root/share/fastbed-static-deps/BUILD-MANIFEST.txt" | awk '{print $1}')" \
    >> "$bundle/MANIFEST.txt"
(cd "$bundle" &&
    find . -type f ! -path './SHA256SUMS' -print | LC_ALL=C sort |
    while IFS= read -r file; do sha256sum "$file"; done) > "$bundle/SHA256SUMS"

relink_tar=$work/relink.tar
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 \
    --numeric-owner -C "$work" -cf "$relink_tar" "$bundle_name"
gzip -n -9 < "$relink_tar" > "$relink_archive"

debug_name=fastbed-debug-$target_arch
debug_bundle=$work/$debug_name
mkdir -p "$debug_bundle/usr/lib/debug/usr/local/bin"
debug_manifest=$debug_bundle/DEBUG-MANIFEST.tsv
printf 'runtime_path\tbuild_id\tunstripped_sha256\truntime_sha256\tdebug_sha256\tdebuglink\n' \
    > "$debug_manifest"

detach_debug() {
    runtime_path=$1
    debug_path=$2
    displayed_runtime=$3
    unstripped_sha=$(sha256sum "$runtime_path" | awk '{print $1}')
    build_id=$(readelf -n "$runtime_path" |
        awk '/Build ID:/ { print $3; found = 1; exit } END { if (!found) exit 1 }')
    objcopy --only-keep-debug "$runtime_path" "$debug_path"
    objcopy --compress-debug-sections=zlib "$debug_path"
    strip --strip-unneeded "$runtime_path"
    objcopy --add-gnu-debuglink="$debug_path" "$runtime_path"
    runtime_build_id=$(readelf -n "$runtime_path" |
        awk '/Build ID:/ { print $3; found = 1; exit } END { if (!found) exit 1 }')
    test "$build_id" = "$runtime_build_id" || {
        echo "build ID changed while detaching debug data: $displayed_runtime" >&2
        exit 1
    }
    runtime_sha=$(sha256sum "$runtime_path" | awk '{print $1}')
    debug_sha=$(sha256sum "$debug_path" | awk '{print $1}')
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$displayed_runtime" "$build_id" "$unstripped_sha" "$runtime_sha" \
        "$debug_sha" "$(basename -- "$debug_path")" >> "$debug_manifest"
}

detach_debug "$runtime_fastbed" \
    "$debug_bundle/usr/lib/debug/usr/local/bin/fastbed.debug" \
    /usr/local/bin/fastbed

cat > "$debug_bundle/README.txt" <<'EOF'
Detached debug data for the matching Fastbed runtime image. DEBUG-MANIFEST.tsv
binds each runtime ELF and debug file by GNU build ID and SHA-256. The production
ELFs contain .gnu_debuglink records; these debug files are intentionally absent
from the runtime image.
EOF
(cd "$debug_bundle" &&
    find . -type f ! -path './SHA256SUMS' -print | LC_ALL=C sort |
    while IFS= read -r file; do sha256sum "$file"; done) \
    > "$debug_bundle/SHA256SUMS"

debug_tar=$work/debug.tar
tar --sort=name --mtime="@$source_date_epoch" --owner=0 --group=0 \
    --numeric-owner -C "$work" -cf "$debug_tar" "$debug_name"
gzip -n -9 < "$debug_tar" > "$debug_archive"

# Seal the final post-link state only after the byte-identical relink check and
# runtime debug split.  This receipt is copied into both the release-artifact
# set and the runtime root so later image capture can bind the running payload
# to the exact prefix and LGPL relink closure without executing image code.
receipt_dir=$artifact_root/receipts
runtime_receipt_dir=$runtime_root/usr/local/share/fastbed
mkdir -p "$receipt_dir" "$runtime_receipt_dir"
receipt=$receipt_dir/fastbed-build-receipt-$target_arch.json
runtime_receipt=$runtime_receipt_dir/BUILD-RECEIPT.json
for file in "$receipt" "$runtime_receipt"; do
    test ! -e "$file" || {
        echo "refusing to overwrite build receipt: $file" >&2
        exit 2
    }
done

fastbed_build_id=$(readelf -n "$runtime_fastbed" |
    awk '/Build ID:/ { print $3; found = 1; exit } END { if (!found) exit 1 }')

python3 - "$source_dir" "$curl_root" "$static_deps_root" \
    "$link_command" "$bundle" \
    "$relink_archive" "$fastbed" "$runtime_fastbed" "$relinked" \
    "$target_arch" "$source_date_epoch" \
    "$fastbed_build_id" "$receipt" <<'PY'
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def regular(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    if not resolved.is_file() or resolved.is_symlink():
        raise SystemExit(f"{label} is not a regular file: {path}")
    return resolved


source = Path(sys.argv[1]).resolve(strict=True)
curl_prefix = Path(sys.argv[2]).resolve(strict=True)
static_prefix = Path(sys.argv[3]).resolve(strict=True)
link_file = regular(Path(sys.argv[4]), "link command")
bundle = Path(sys.argv[5]).resolve(strict=True)
relink_archive = regular(Path(sys.argv[6]), "relink archive")
release_root = relink_archive.parent.parent.resolve(strict=True)
unstripped = regular(Path(sys.argv[7]), "unstripped Fastbed")
runtime_fastbed = regular(Path(sys.argv[8]), "runtime Fastbed")
relinked = regular(Path(sys.argv[9]), "relinked Fastbed")
target_arch = sys.argv[10]
source_date_epoch = int(sys.argv[11])
fastbed_build_id = sys.argv[12]
output = Path(sys.argv[13])

source_paths = [
    "CMakeLists.txt",
    "assets",
    "cmake",
    "include",
    "src",
    "tools/build-static-deps.sh",
    "tools/embed-resources.py",
    "third_party/crawler-user-agents",
    "third_party/yyjson",
]
source_files: dict[str, Path] = {}
for relative in source_paths:
    unresolved = source
    for part in Path(relative).parts:
        unresolved /= part
        if unresolved.is_symlink():
            raise SystemExit(f"receipt source path is a symbolic link: {relative}")
    candidate = unresolved.resolve(strict=True)
    if candidate.is_dir():
        candidates = (item for item in candidate.rglob("*") if item.is_file())
    elif candidate.is_file():
        candidates = (candidate,)
    else:
        raise SystemExit(f"unsupported receipt source path: {relative}")
    for item in candidates:
        if item.is_symlink():
            raise SystemExit(f"receipt source path is a symbolic link: {item}")
        rel = item.relative_to(source).as_posix()
        source_files[rel] = item
if not source_files:
    raise SystemExit("receipt source allowlist is empty")
source_aggregate = hashlib.sha256()
for relative in sorted(source_files):
    source_aggregate.update(relative.encode("utf-8"))
    source_aggregate.update(b"\0")
    source_aggregate.update(digest(source_files[relative]).encode("ascii"))
    source_aggregate.update(b"\n")

metadata = curl_prefix / "share/fastbed-curl-impersonate"
sums_path = regular(metadata / "SHA256SUMS", "curl prefix SHA256SUMS")
manifest_path = regular(metadata / "BUILD-MANIFEST.txt", "curl build manifest")
manifest_values: dict[str, str] = {}
for number, line in enumerate(manifest_path.read_text(encoding="utf-8").splitlines(), 1):
    if "=" not in line:
        raise SystemExit(f"malformed curl build manifest line {number}")
    key, value = line.split("=", 1)
    if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or not value or key in manifest_values:
        raise SystemExit(f"malformed curl build manifest line {number}")
    manifest_values[key] = value
if (
    manifest_values.get("target_arch") != target_arch
    or manifest_values.get("source_date_epoch") != str(source_date_epoch)
):
    raise SystemExit("curl build manifest architecture/epoch differs from release build")
sums: dict[str, str] = {}
ordered_paths: list[str] = []
prefix_aggregate = hashlib.sha256()
for number, line in enumerate(sums_path.read_text(encoding="ascii").splitlines(), 1):
    match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
    if not match:
        raise SystemExit(f"malformed curl prefix SHA256SUMS line {number}")
    expected, relative = match.groups()
    pure = Path(relative)
    if pure.is_absolute() or ".." in pure.parts or relative in sums:
        raise SystemExit(f"unsafe or duplicate curl prefix path: {relative}")
    item = regular(curl_prefix / pure, "curl prefix member")
    try:
        item.relative_to(curl_prefix)
    except ValueError as exc:
        raise SystemExit(f"curl prefix member escapes prefix: {relative}") from exc
    if digest(item) != expected:
        raise SystemExit(f"curl prefix checksum mismatch: {relative}")
    sums[relative] = expected
    ordered_paths.append(relative)
    prefix_aggregate.update(relative.encode("utf-8"))
    prefix_aggregate.update(b"\0")
    prefix_aggregate.update(expected.encode("ascii"))
    prefix_aggregate.update(b"\n")
if ordered_paths != sorted(ordered_paths):
    raise SystemExit("curl prefix SHA256SUMS is not path-sorted")
actual_prefix_files: set[str] = set()
for item in curl_prefix.rglob("*"):
    if item.is_symlink():
        raise SystemExit(f"curl prefix contains a symbolic link: {item}")
    if item.is_file() and item != sums_path:
        actual_prefix_files.add(item.relative_to(curl_prefix).as_posix())
if set(sums) != actual_prefix_files:
    raise SystemExit("curl prefix SHA256SUMS does not close over the prefix")
prefix_aggregate.update(b"SHA256SUMS\0")
prefix_aggregate.update(digest(sums_path).encode("ascii"))

library_paths = [
    "lib/libcurl-impersonate.a",
    "lib/libnghttp2.a",
    "lib/libidn2.a",
    "lib/libunistring.a",
    "lib/libssl.a",
    "lib/libcrypto.a",
    "lib/libzstd.a",
    "lib/libbrotlidec.a",
    "lib/libbrotlicommon.a",
    "lib/libz.a",
]
link_command = link_file.read_text(encoding="utf-8").strip()
if not link_command or "\n" in link_command:
    raise SystemExit("captured link command is empty or multiline")
for relative in library_paths:
    absolute = str(curl_prefix / relative)
    if link_command.count(absolute) != 1:
        raise SystemExit(
            f"captured link command must reference exactly one {absolute}"
        )
for forbidden in ("libnghttp3.a", "libngtcp2.a", "libngtcp2_crypto_boringssl.a"):
    if forbidden in link_command or (curl_prefix / "lib" / forbidden).exists():
        raise SystemExit(f"HTTP/3 archive present in production receipt: {forbidden}")
libraries = [{"path": path, "sha256": sums[path]} for path in library_paths]

static_metadata = static_prefix / "share/fastbed-static-deps"
static_sums_path = regular(
    static_metadata / "SHA256SUMS", "static dependency prefix SHA256SUMS")
static_manifest_path = regular(
    static_metadata / "BUILD-MANIFEST.txt",
    "static dependency build manifest")
static_manifest_values: dict[str, str] = {}
for number, line in enumerate(
    static_manifest_path.read_text(encoding="utf-8").splitlines(), 1
):
    if "=" not in line:
        raise SystemExit(f"malformed static dependency manifest line {number}")
    key, value = line.split("=", 1)
    if (
        not re.fullmatch(r"[a-z][a-z0-9_]*", key)
        or not value
        or key in static_manifest_values
    ):
        raise SystemExit(f"malformed static dependency manifest line {number}")
    static_manifest_values[key] = value
if (
    static_manifest_values.get("profile") != "fastbed-static-deps-v1"
    or static_manifest_values.get("target_arch") != target_arch
    or static_manifest_values.get("source_date_epoch") != str(source_date_epoch)
    or static_manifest_values.get("libmicrohttpd_version") != "1.0.10"
    or static_manifest_values.get("libyaml_version") != "0.2.5"
):
    raise SystemExit("static dependency build manifest identity mismatch")

static_sums: dict[str, str] = {}
static_ordered_paths: list[str] = []
static_prefix_aggregate = hashlib.sha256()
for number, line in enumerate(
    static_sums_path.read_text(encoding="ascii").splitlines(), 1
):
    match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
    if not match:
        raise SystemExit(
            f"malformed static dependency SHA256SUMS line {number}")
    expected, relative = match.groups()
    pure = Path(relative)
    if pure.is_absolute() or ".." in pure.parts or relative in static_sums:
        raise SystemExit(
            f"unsafe or duplicate static dependency prefix path: {relative}")
    item = regular(static_prefix / pure, "static dependency prefix member")
    try:
        item.relative_to(static_prefix)
    except ValueError as exc:
        raise SystemExit(
            f"static dependency prefix member escapes prefix: {relative}"
        ) from exc
    if digest(item) != expected:
        raise SystemExit(
            f"static dependency prefix checksum mismatch: {relative}")
    static_sums[relative] = expected
    static_ordered_paths.append(relative)
    static_prefix_aggregate.update(relative.encode("utf-8"))
    static_prefix_aggregate.update(b"\0")
    static_prefix_aggregate.update(expected.encode("ascii"))
    static_prefix_aggregate.update(b"\n")
if static_ordered_paths != sorted(static_ordered_paths):
    raise SystemExit("static dependency SHA256SUMS is not path-sorted")
actual_static_files: set[str] = set()
for item in static_prefix.rglob("*"):
    if item.is_symlink():
        raise SystemExit(
            f"static dependency prefix contains a symbolic link: {item}")
    if item.is_file() and item != static_sums_path:
        actual_static_files.add(item.relative_to(static_prefix).as_posix())
if set(static_sums) != actual_static_files:
    raise SystemExit(
        "static dependency SHA256SUMS does not close over the prefix")
static_prefix_aggregate.update(b"SHA256SUMS\0")
static_prefix_aggregate.update(digest(static_sums_path).encode("ascii"))
static_library_paths = ["lib/libmicrohttpd.a", "lib/libyaml.a"]
for relative in static_library_paths:
    absolute = str(static_prefix / relative)
    if link_command.count(absolute) != 1:
        raise SystemExit(
            f"captured link command must reference exactly one {absolute}")
static_libraries = [
    {"path": path, "sha256": static_sums[path]}
    for path in static_library_paths
]

relink_sums = regular(bundle / "SHA256SUMS", "relink content SHA256SUMS")
relink_script = regular(bundle / "relink-fastbed.sh", "relink script")
lgpl_libraries = [
    {
        "path": "curl-prefix/lib/libidn2.a",
        "sha256": sums["lib/libidn2.a"],
    },
    {
        "path": "curl-prefix/lib/libunistring.a",
        "sha256": sums["lib/libunistring.a"],
    },
    {
        "path": "static-deps-prefix/lib/libmicrohttpd.a",
        "sha256": static_sums["lib/libmicrohttpd.a"],
    },
]
lgpl_source_paths = [
    "source/curl-impersonate/libidn2-2.3.8.tar.gz",
    "source/curl-impersonate/libidn2-2.3.8.tar.gz.sig",
    "source/curl-impersonate/libunistring-1.4.2.tar.xz",
    "source/curl-impersonate/libunistring-1.4.2.tar.xz.sig",
    "source/static-deps/libmicrohttpd-1.0.10.tar.gz",
]
lgpl_sources = [
    {"path": path, "sha256": digest(regular(release_root / path, "LGPL source archive"))}
    for path in lgpl_source_paths
]
command_sha = hashlib.sha256(link_command.encode("utf-8")).hexdigest()
if digest(unstripped) != digest(relinked):
    raise SystemExit("relink output is not byte-identical to unstripped Fastbed")
receipt = {
    "$schema": "build-receipt.schema.json",
    "schema_version": 2,
    "receipt_kind": "fastbed-post-link",
    "generator_sha256": digest(
        regular(source / "tools/create-release-artifacts.sh", "receipt generator")
    ),
    "source_date_epoch": source_date_epoch,
    "target_arch": target_arch,
    "source": {
        "tree_sha256": source_aggregate.hexdigest(),
        "paths": source_paths,
    },
    "fastbed": {
        "unstripped_sha256": digest(unstripped),
        "runtime_sha256": digest(runtime_fastbed),
        "relinked_sha256": digest(relinked),
        "build_id": fastbed_build_id,
    },
    "curl_prefix": {
        "checksum_aggregate_sha256": prefix_aggregate.hexdigest(),
        "sha256sums_sha256": digest(sums_path),
        "build_manifest_sha256": digest(manifest_path),
        "libraries": libraries,
    },
    "static_deps_prefix": {
        "checksum_aggregate_sha256": static_prefix_aggregate.hexdigest(),
        "sha256sums_sha256": digest(static_sums_path),
        "build_manifest_sha256": digest(static_manifest_path),
        "libraries": static_libraries,
        "source_archives": [
            {
                "path": "source/static-deps/libmicrohttpd-1.0.10.tar.gz",
                "sha256": digest(regular(
                    release_root
                    / "source/static-deps/libmicrohttpd-1.0.10.tar.gz",
                    "libmicrohttpd source archive",
                )),
            },
            {
                "path": "source/static-deps/yaml-0.2.5.tar.gz",
                "sha256": digest(regular(
                    release_root / "source/static-deps/yaml-0.2.5.tar.gz",
                    "libyaml source archive",
                )),
            },
        ],
    },
    "link": {"command": link_command, "sha256": command_sha},
    "lgpl_relink": {
        "archive_path": f"relink/fastbed-relink-{target_arch}.tar.gz",
        "archive_sha256": digest(relink_archive),
        "content_sha256s_sha256": digest(relink_sums),
        "relink_script_sha256": digest(relink_script),
        "link_command_sha256": command_sha,
        "byte_identical": True,
        "libraries": lgpl_libraries,
        "source_archives": lgpl_sources,
    },
}
with output.open("x", encoding="utf-8", newline="\n") as handle:
    json.dump(receipt, handle, sort_keys=True, indent=2)
    handle.write("\n")
PY
cp -- "$receipt" "$runtime_receipt"
cmp -s "$receipt" "$runtime_receipt" || {
    echo "runtime build receipt differs from release receipt" >&2
    exit 1
}

(cd "$artifact_root" &&
    find . -type f ! -path './SHA256SUMS' -print | LC_ALL=C sort |
    while IFS= read -r file; do sha256sum "$file"; done) \
    > "$artifact_root/SHA256SUMS"

trap - EXIT HUP INT TERM
cleanup
printf 'created release artifacts under %s\n' "$artifact_root"

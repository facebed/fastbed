#!/usr/bin/env python3
"""Capture only non-secret package and binary identity from a fresh image.

The command deliberately does not inspect image configuration, environment
variables, filesystem trees, layers, or a running service. It reads the fixed
scratch-runtime manifest, the build-package provenance for bytes copied or
linked into that runtime, and a fixed allowlist of production evidence from an
ephemeral, network-disabled container. The post-link receipt is parsed as data
and is never executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path


REQUIRED_FILES = (
    "/usr/local/bin/fastbed",
    "/etc/ssl/certs/ca-certificates.crt",
    "/usr/local/share/fastbed-runtime/RUNTIME-MANIFEST.txt",
    "/usr/local/share/fastbed-runtime/ALPINE-BUILD-PACKAGES",
    "/usr/local/share/fastbed/BUILD-RECEIPT.json",
    "/usr/local/share/fastbed/EMBEDDED-RESOURCES.json",
    "/usr/local/share/fastbed-curl-impersonate/BUILD-MANIFEST.txt",
    "/usr/local/share/fastbed-curl-impersonate/COMPONENTS.tsv",
    "/usr/local/share/fastbed-curl-impersonate/CURL-VERSION.txt",
    "/usr/local/share/fastbed-curl-impersonate/SHA256SUMS",
    "/usr/local/share/fastbed-curl-impersonate/SOURCE-OFFER.txt",
    "/usr/local/share/fastbed-curl-impersonate/licenses/curl-impersonate-LICENSE",
    "/usr/local/share/fastbed-curl-impersonate/licenses/curl-COPYING",
    "/usr/local/share/fastbed-curl-impersonate/licenses/boringssl-LICENSE",
    "/usr/local/share/fastbed-curl-impersonate/licenses/brotli-LICENSE",
    "/usr/local/share/fastbed-curl-impersonate/licenses/nghttp2-COPYING",
    "/usr/local/share/fastbed-curl-impersonate/licenses/zlib-LICENSE",
    "/usr/local/share/fastbed-curl-impersonate/licenses/zstd-LICENSE",
    "/usr/local/share/fastbed-curl-impersonate/licenses/libunistring-COPYING",
    "/usr/local/share/fastbed-curl-impersonate/licenses/libunistring-COPYING.LIB",
    "/usr/local/share/fastbed-curl-impersonate/licenses/libidn2-COPYING",
    "/usr/local/share/fastbed-curl-impersonate/licenses/libidn2-COPYING.LESSERv3",
    "/usr/local/share/fastbed-curl-impersonate/licenses/libidn2-COPYING.unicode",
    "/usr/local/share/fastbed-curl-impersonate/licenses/libidn2-COPYINGv2",
    "/usr/local/share/fastbed-curl-impersonate/rebuild/tools/build-curl-impersonate.sh",
    "/usr/local/share/fastbed-curl-impersonate/rebuild/third_party/curl-impersonate/patches/0001-curl-8.23.0-v1.5.2-production.patch",
    "/usr/local/share/fastbed-curl-impersonate/rebuild/third_party/curl-impersonate/patches/0002-boringssl-v1.5.2-base.patch",
    "/usr/local/share/fastbed-curl-impersonate/rebuild/third_party/curl-impersonate/patches/0003-boringssl-CVE-2026-35189.patch",
    "/usr/local/share/fastbed-curl-impersonate/rebuild/third_party/curl-impersonate/patches/0004-brotli-v1.5.2.patch",
    "/usr/local/share/fastbed-curl-impersonate/rebuild/third_party/curl-impersonate/patches/0005-nghttp2-1.68.1-outbound-priority-compat.patch",
    "/usr/local/share/fastbed-static-deps/BUILD-MANIFEST.txt",
    "/usr/local/share/fastbed-static-deps/COMPONENTS.tsv",
    "/usr/local/share/fastbed-static-deps/SHA256SUMS",
    "/usr/local/share/fastbed-static-deps/SOURCE-OFFER.txt",
    "/usr/local/share/fastbed-static-deps/licenses/libmicrohttpd-COPYING",
    "/usr/local/share/fastbed-static-deps/licenses/libyaml-License",
    "/usr/local/share/fastbed-static-deps/licenses/pcre2-COPYING",
    "/usr/local/share/fastbed-static-deps/rebuild/tools/build-static-deps.sh",
    "/usr/share/licenses/fastbed/yyjson-LICENSE",
    "/usr/share/licenses/fastbed/crawler-user-agents-LICENSE",
    "/usr/share/licenses/libmicrohttpd/COPYING",
    "/usr/share/licenses/libyaml/License",
    "/usr/share/licenses/pcre2/COPYING",
    "/usr/local/share/fastbed-source-offers/libmicrohttpd-1.0.10.tar.gz",
    "/usr/local/share/fastbed-source-offers/yaml-0.2.5.tar.gz",
    "/usr/local/share/fastbed-source-offers/pcre2-10.47.tar.bz2",
)
REQUIRED_FIELDS = {
    "P": "name",
    "V": "version",
    "A": "architecture",
    "L": "license",
    "o": "origin",
    "C": "apk_checksum",
}


class InventoryError(RuntimeError):
    pass


def run(argv: list[str]) -> str:
    try:
        completed = subprocess.run(
            argv,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = ""
        if isinstance(exc, subprocess.CalledProcessError):
            detail = exc.stderr.strip()
        raise InventoryError(f"command failed: {argv[0]} {detail}".rstrip()) from exc
    return completed.stdout


def parse_apk_database(raw: str) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    for paragraph in re.split(r"\n\s*\n", raw.strip()):
        record: dict[str, str] = {}
        for line in paragraph.splitlines():
            if len(line) >= 3 and line[1] == ":" and line[0] in REQUIRED_FIELDS:
                record[REQUIRED_FIELDS[line[0]]] = line[2:]
        if not record:
            continue
        missing = sorted(set(REQUIRED_FIELDS.values()) - record.keys())
        if missing:
            name = record.get("name", "<unknown>")
            raise InventoryError(
                f"Alpine package {name!r} lacks required fields: {', '.join(missing)}"
            )
        if any(not value or value.lower() in {"unknown", "noassertion"}
               for value in record.values()):
            raise InventoryError(f"Alpine package has unknown metadata: {record['name']}")
        if not re.fullmatch(r"Q1[0-9A-Za-z+/]+=*", record["apk_checksum"]):
            raise InventoryError(
                f"Alpine package has malformed checksum: {record['name']}"
            )
        packages.append(record)

    packages.sort(key=lambda package: package["name"])
    names = [package["name"] for package in packages]
    if not names or len(names) != len(set(names)):
        raise InventoryError("Alpine package inventory is empty or has duplicate names")
    return packages


def parse_manifest(raw: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, line in enumerate(raw.splitlines(), 1):
        if not line or "=" not in line:
            raise InventoryError(f"malformed runtime manifest line {number}")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or not value or key in values:
            raise InventoryError(f"malformed runtime manifest line {number}")
        values[key] = value
    return values


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def elf_build_id(path: Path, runtime_path: str) -> str:
    output = run(["readelf", "-nW", str(path)])
    values = re.findall(r"Build ID:\s*([0-9a-f]+)", output)
    if len(values) != 1 or not re.fullmatch(r"[0-9a-f]{16,128}", values[0]):
        raise InventoryError(
            f"runtime ELF has missing or ambiguous GNU build ID: {runtime_path}"
        )
    return values[0]


def copy_from_image(engine: str, container_id: str, source: str, target: Path) -> None:
    run([engine, "cp", f"{container_id}:{source}", str(target)])
    if not target.is_file() or target.is_symlink():
        raise InventoryError(f"runtime evidence is not a regular file: {source}")


def capture(engine: str, image: str, expected_alpine: str) -> dict[str, object]:
    image_id = run(
        [engine, "image", "inspect", "--format={{.Id}}", image]
    ).strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise InventoryError(f"unexpected image ID: {image_id!r}")
    image_architecture = run(
        [engine, "image", "inspect", "--format={{.Architecture}}", image_id]
    ).strip()
    if image_architecture not in {"amd64", "arm64"}:
        raise InventoryError(
            f"unsupported or unexpected image architecture: {image_architecture!r}"
        )

    container_id = run(
        [
            engine,
            "create",
            "--network=none",
            image_id,
            "--version",
        ]
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
        raise InventoryError(f"unexpected container ID: {container_id!r}")
    try:
        with tempfile.TemporaryDirectory(prefix="fastbed-runtime-inventory.") as temporary:
            temporary_path = Path(temporary)
            apk_path = temporary_path / "build-packages"
            copy_from_image(
                engine, container_id,
                "/usr/local/share/fastbed-runtime/ALPINE-BUILD-PACKAGES",
                apk_path,
            )
            apk_database = apk_path.read_text(encoding="utf-8")
            packages = parse_apk_database(apk_database)
            files: list[dict[str, str]] = []
            receipt_document: dict[str, object] | None = None
            receipt_digest: str | None = None
            embedded_document: dict[str, object] | None = None
            embedded_digest: str | None = None
            runtime_manifest: dict[str, str] | None = None
            runtime_manifest_digest: str | None = None
            ca_bundle_digest: str | None = None
            for index, runtime_path in enumerate(REQUIRED_FILES):
                local_path = temporary_path / f"evidence-{index:03d}"
                copy_from_image(engine, container_id, runtime_path, local_path)
                file_digest = sha256_file(local_path)
                record = {"path": runtime_path, "sha256": file_digest}
                if runtime_path == "/usr/local/bin/fastbed":
                    record["build_id"] = elf_build_id(local_path, runtime_path)
                files.append(record)
                if runtime_path == "/usr/local/share/fastbed/BUILD-RECEIPT.json":
                    try:
                        parsed = json.loads(local_path.read_text(encoding="utf-8"))
                    except (UnicodeError, json.JSONDecodeError) as exc:
                        raise InventoryError(
                            f"invalid runtime build receipt: {exc}"
                        ) from exc
                    if not isinstance(parsed, dict):
                        raise InventoryError("runtime build receipt is not an object")
                    receipt_document = parsed
                    receipt_digest = file_digest
                if runtime_path == "/usr/local/share/fastbed/EMBEDDED-RESOURCES.json":
                    try:
                        parsed = json.loads(local_path.read_text(encoding="utf-8"))
                    except (UnicodeError, json.JSONDecodeError) as exc:
                        raise InventoryError(
                            f"invalid embedded resource manifest: {exc}") from exc
                    if not isinstance(parsed, dict):
                        raise InventoryError(
                            "embedded resource manifest is not an object")
                    embedded_document = parsed
                    embedded_digest = file_digest
                if runtime_path == "/usr/local/share/fastbed-runtime/RUNTIME-MANIFEST.txt":
                    runtime_manifest = parse_manifest(
                        local_path.read_text(encoding="utf-8")
                    )
                    runtime_manifest_digest = file_digest
                if runtime_path == "/etc/ssl/certs/ca-certificates.crt":
                    ca_bundle_digest = file_digest
    finally:
        run([engine, "rm", container_id])

    if runtime_manifest is None or runtime_manifest_digest is None:
        raise InventoryError("scratch runtime manifest was not captured")
    if runtime_manifest.get("profile") != "fastbed-scratch-static-v1":
        raise InventoryError(
            f"unexpected runtime profile: {runtime_manifest.get('profile')!r}"
        )
    if runtime_manifest.get("target_arch") != image_architecture:
        raise InventoryError("scratch runtime architecture differs from image")
    base_image = runtime_manifest.get("base_image", "")
    if not base_image.startswith(f"alpine:{expected_alpine}@sha256:"):
        raise InventoryError(
            f"scratch build base mismatch: expected Alpine {expected_alpine}, got {base_image!r}"
        )
    if ca_bundle_digest is None or runtime_manifest.get("ca_bundle_sha256") != ca_bundle_digest:
        raise InventoryError("scratch CA bundle differs from runtime manifest")

    if receipt_document is None or receipt_digest is None:
        raise InventoryError("runtime build receipt was not captured")
    if embedded_document is None or embedded_digest is None:
        raise InventoryError("embedded resource manifest was not captured")

    return {
        "schema_version": 1,
        "image_id": image_id,
        "image_architecture": image_architecture,
        "image_reference": image,
        "runtime": {
            "kind": "scratch-static",
            "profile": runtime_manifest["profile"],
            "manifest_path": "/usr/local/share/fastbed-runtime/RUNTIME-MANIFEST.txt",
            "manifest_sha256": runtime_manifest_digest,
            "base_image": base_image,
            "ca_bundle_sha256": ca_bundle_digest,
        },
        "build_receipt": {
            "path": "/usr/local/share/fastbed/BUILD-RECEIPT.json",
            "sha256": receipt_digest,
            "document": receipt_document,
        },
        "embedded_resources": {
            "path": "/usr/local/share/fastbed/EMBEDDED-RESOURCES.json",
            "sha256": embedded_digest,
            "document": embedded_document,
        },
        "packages": packages,
        "files": files,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=("docker", "podman"), default="docker")
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-alpine", default="3.24.2")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if any(char in args.image for char in "\r\n\0"):
        parser.error("image reference contains a control character")
    if args.output.exists():
        parser.error(f"output already exists: {args.output}")

    try:
        inventory = capture(args.engine, args.image, args.expected_alpine)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(inventory, handle, sort_keys=True, indent=2)
            handle.write("\n")
    except (InventoryError, OSError) as exc:
        print(f"capture-runtime-inventory: {exc}", file=sys.stderr)
        return 1
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Generate deterministic Fastbed CycloneDX, SPDX, and VEX artifacts.

This is an intentionally manual, fail-closed generator.  It reads only the
explicit source allowlist, the source-built curl bundle metadata, and the
normalized runtime inventory.  It never walks the repository, image, process
environment, or container layers looking for credentials or dependencies.
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.parse
import uuid
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

try:
    import jsonschema
except ImportError as exc:  # pragma: no cover - explicit host prerequisite
    raise SystemExit("generate-sbom-vex requires Python jsonschema") from exc


class SupplyChainError(RuntimeError):
    pass


RUNTIME_RECEIPT_PATH = "/usr/local/share/fastbed/BUILD-RECEIPT.json"
LINKED_CURL_LIBRARIES = [
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
LINKED_STATIC_DEPS_LIBRARIES = [
    "lib/libmicrohttpd.a",
    "lib/libyaml.a",
    "lib/libpcre2-8.a",
]
LGPL_RELINK_LIBRARIES = [
    "curl-prefix/lib/libidn2.a",
    "curl-prefix/lib/libunistring.a",
    "static-deps-prefix/lib/libmicrohttpd.a",
]
LGPL_SOURCE_ARCHIVES = [
    "source/curl-impersonate/libidn2-2.3.8.tar.gz",
    "source/curl-impersonate/libidn2-2.3.8.tar.gz.sig",
    "source/curl-impersonate/libunistring-1.4.2.tar.xz",
    "source/curl-impersonate/libunistring-1.4.2.tar.xz.sig",
    "source/static-deps/libmicrohttpd-1.0.10.tar.gz",
]
FORBIDDEN_HTTP3_LIBRARIES = (
    "libnghttp3.a",
    "libngtcp2.a",
    "libngtcp2_crypto_boringssl.a",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SupplyChainError(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise SupplyChainError(f"top-level JSON value is not an object: {path}")
    return value


def validate_json_schema(instance: dict[str, Any], schema_path: Path) -> None:
    schema = read_json(schema_path)
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
    )
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if errors:
        first = errors[0]
        location = "/".join(str(item) for item in first.absolute_path) or "<root>"
        raise SupplyChainError(
            f"schema failure in {schema_path.name} at {location}: {first.message}"
        )


def safe_repo_path(root: Path, relative: str) -> Path:
    relative_path = Path(relative)
    if (
        not relative
        or relative_path.is_absolute()
        or ".." in relative_path.parts
        or "." in relative_path.parts
    ):
        raise SupplyChainError(f"repository path must be relative: {relative!r}")
    unresolved = root
    for part in relative_path.parts:
        unresolved /= part
        if unresolved.is_symlink():
            raise SupplyChainError(
                f"symbolic links are not accepted as evidence: {relative}"
            )
    path = unresolved.resolve(strict=True)
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise SupplyChainError(f"repository path escapes source root: {relative}") from exc
    return path


def hash_source_tree(root: Path, source_paths: list[str]) -> tuple[str, list[dict[str, str]]]:
    files: dict[str, Path] = {}
    for relative in source_paths:
        path = safe_repo_path(root, relative)
        candidates: Iterable[Path]
        if path.is_dir():
            candidates = (candidate for candidate in path.rglob("*") if candidate.is_file())
        elif path.is_file():
            candidates = (path,)
        else:
            raise SupplyChainError(f"unsupported source-tree entry: {relative}")
        for candidate in candidates:
            if candidate.is_symlink():
                raise SupplyChainError(f"source allowlist contains symlink: {candidate}")
            rel = candidate.relative_to(root).as_posix()
            files[rel] = candidate
    if not files:
        raise SupplyChainError("source allowlist resolved to no files")

    evidence: list[dict[str, str]] = []
    aggregate = hashlib.sha256()
    for relative in sorted(files):
        digest = sha256_file(files[relative])
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(digest.encode("ascii"))
        aggregate.update(b"\n")
        evidence.append({"path": relative, "sha256": digest})
    return aggregate.hexdigest(), evidence


def parse_key_value_manifest(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise SupplyChainError(f"cannot read curl build manifest: {exc}") from exc
    for number, line in enumerate(lines, 1):
        if not line or "=" not in line:
            raise SupplyChainError(f"malformed build manifest line {number}")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or not value:
            raise SupplyChainError(f"malformed build manifest line {number}")
        if key in result:
            raise SupplyChainError(f"duplicate build manifest key: {key}")
        result[key] = value
    return result


def parse_components(path: Path) -> dict[str, dict[str, str]]:
    expected_header = [
        "component", "version_or_revision", "source_sha256", "license_file"
    ]
    try:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            if reader.fieldnames != expected_header:
                raise SupplyChainError(
                    f"unexpected COMPONENTS.tsv header: {reader.fieldnames}"
                )
            rows = list(reader)
    except (OSError, UnicodeError, csv.Error) as exc:
        raise SupplyChainError(f"cannot read curl component manifest: {exc}") from exc
    result: dict[str, dict[str, str]] = {}
    for row in rows:
        name = row["component"]
        if (
            None in row
            or not name
            or name in result
            or any(not row[field] for field in expected_header)
        ):
            raise SupplyChainError(f"invalid or duplicate curl component row: {name!r}")
        if not re.fullmatch(r"[0-9a-f]{64}", row["source_sha256"]):
            raise SupplyChainError(f"invalid curl component source hash: {name}")
        result[name] = row
    return result


def parse_sha256sums(prefix: Path, path: Path) -> tuple[dict[str, str], str]:
    result: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise SupplyChainError(f"cannot read curl SHA256SUMS: {exc}") from exc
    aggregate = hashlib.sha256()
    for number, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise SupplyChainError(f"malformed curl SHA256SUMS line {number}")
        expected, relative = match.groups()
        pure = Path(relative)
        if pure.is_absolute() or ".." in pure.parts or relative in result:
            raise SupplyChainError(f"unsafe or duplicate curl checksum path: {relative}")
        target = (prefix / pure).resolve(strict=True)
        try:
            target.relative_to(prefix)
        except ValueError as exc:
            raise SupplyChainError(f"curl checksum path escapes prefix: {relative}") from exc
        actual = sha256_file(target)
        if actual != expected:
            raise SupplyChainError(
                f"curl checksum mismatch for {relative}: expected {expected}, got {actual}"
            )
        result[relative] = expected
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(expected.encode("ascii"))
        aggregate.update(b"\n")
    if not result:
        raise SupplyChainError("curl SHA256SUMS is empty")
    sums_relative = path.relative_to(prefix).as_posix()
    actual_files: set[str] = set()
    for candidate in prefix.rglob("*"):
        if candidate.is_symlink():
            raise SupplyChainError(
                f"curl prefix contains an unhashed symbolic link: {candidate.relative_to(prefix)}"
            )
        if candidate.is_file():
            relative = candidate.relative_to(prefix).as_posix()
            if relative != sums_relative:
                actual_files.add(relative)
    if set(result) != actual_files:
        missing = sorted(actual_files - result.keys())
        nonexistent = sorted(result.keys() - actual_files)
        raise SupplyChainError(
            "curl checksum closure is incomplete or stale; "
            f"unlisted={missing}, nonexistent={nonexistent}"
        )
    aggregate.update(b"SHA256SUMS\0")
    aggregate.update(sha256_file(path).encode("ascii"))
    return result, aggregate.hexdigest()


def validate_declared_inputs(root: Path, inventory: dict[str, Any]) -> None:
    product = inventory["product"]
    declared_components = inventory["components"] + inventory["curl_bundle"]["components"]
    identities = [product] + declared_components
    for field in ("id", "bom_ref", "purl"):
        values = [component[field] for component in identities]
        if len(values) != len(set(values)):
            raise SupplyChainError(f"duplicate declared component {field}")
    for component in identities:
        version = component["version"].strip().lower()
        if version in {"unknown", "noassertion", "none"}:
            raise SupplyChainError(
                f"declared component has unknown version: {component['id']}"
            )
    declared_ids = {component["id"] for component in identities}
    for record in inventory["patches"] + inventory["build_inputs"]:
        if record["component"] not in declared_ids:
            raise SupplyChainError(
                f"build/patch evidence references unknown component: {record['component']}"
            )
    patches_by_id = {record["id"]: record for record in inventory["patches"]}
    if len(patches_by_id) != len(inventory["patches"]):
        raise SupplyChainError("duplicate patch ID")
    vulnerability_ids = [record["id"] for record in inventory["vulnerabilities"]]
    if len(vulnerability_ids) != len(set(vulnerability_ids)):
        raise SupplyChainError("duplicate vulnerability ID")
    for vulnerability in inventory["vulnerabilities"]:
        if vulnerability["component"] not in declared_ids:
            raise SupplyChainError(
                f"VEX references unknown component: {vulnerability['component']}"
            )
        component = next(
            item for item in declared_components
            if item["id"] == vulnerability["component"]
        )
        resolution = vulnerability["resolution"]
        expected_disposition = (
            "fixed-by-verified-backport"
            if resolution == "verified-backport"
            else "fixed-by-upstream-version"
        )
        if component["security_disposition"] != expected_disposition:
            raise SupplyChainError(
                f"VEX/component disposition mismatch: {vulnerability['id']}"
            )
        if resolution == "verified-backport":
            patch_id = vulnerability.get("patch_id")
            patch = patches_by_id.get(patch_id)
            if (
                patch is None
                or patch["component"] != vulnerability["component"]
                or patch["upstream_commit"] != vulnerability["fixed_commit"]
            ):
                raise SupplyChainError(
                    f"VEX finding has no matching security patch: {vulnerability['id']}"
                )
        elif vulnerability["fixed_version"] not in component["version"]:
            raise SupplyChainError(
                f"upstream-fixed component does not identify fixed version: {vulnerability['id']}"
            )
    evidence = product["version_evidence"]
    evidence_path = safe_repo_path(root, evidence["path"])
    text = evidence_path.read_text(encoding="utf-8")
    if evidence["literal"] not in text:
        raise SupplyChainError(
            f"Fastbed version evidence missing from {evidence['path']}"
        )

    for component in inventory["components"]:
        for local in component["local_files"]:
            path = safe_repo_path(root, local["path"])
            actual = sha256_file(path)
            if actual != local["sha256"]:
                raise SupplyChainError(
                    f"local evidence mismatch for {local['path']}: "
                    f"expected {local['sha256']}, got {actual}"
                )
        declaration = component.get("declaration_evidence")
        if declaration:
            path = safe_repo_path(root, declaration["path"])
            declared_text = path.read_text(encoding="utf-8")
            for literal in declaration["literals"]:
                if literal not in declared_text:
                    raise SupplyChainError(
                        f"dependency declaration {literal!r} missing from {declaration['path']}"
                    )
    for vulnerability in inventory["vulnerabilities"]:
        artifact = vulnerability.get("evidence_artifact")
        if artifact:
            path = safe_repo_path(root, artifact["path"])
            if sha256_file(path) != artifact["sha256"]:
                raise SupplyChainError(
                    f"VEX evidence artifact hash mismatch: {artifact['path']}"
                )


def validate_curl_bundle(
    root: Path, prefix: Path, inventory: dict[str, Any]
) -> tuple[dict[str, str], str, dict[str, dict[str, str]], dict[str, str]]:
    prefix = prefix.resolve(strict=True)
    bundle = inventory["curl_bundle"]
    metadata = (prefix / bundle["metadata_relative_path"]).resolve(strict=True)
    try:
        metadata.relative_to(prefix)
    except ValueError as exc:
        raise SupplyChainError("curl metadata path escapes prefix") from exc
    manifest_path = metadata / "BUILD-MANIFEST.txt"
    components_path = metadata / "COMPONENTS.tsv"
    sums_path = metadata / "SHA256SUMS"
    for path in (manifest_path, components_path, sums_path):
        if not path.is_file():
            raise SupplyChainError(f"curl bundle metadata is missing: {path}")

    sums, bundle_digest = parse_sha256sums(prefix, sums_path)
    manifest = parse_key_value_manifest(manifest_path)
    components = parse_components(components_path)
    missing_libraries = sorted(set(LINKED_CURL_LIBRARIES) - sums.keys())
    if missing_libraries:
        raise SupplyChainError(
            f"curl checksum closure lacks linked libraries: {missing_libraries}"
        )
    forbidden_libraries = sorted(
        f"lib/{name}" for name in FORBIDDEN_HTTP3_LIBRARIES
        if f"lib/{name}" in sums
    )
    if forbidden_libraries:
        raise SupplyChainError(
            f"curl HTTP/2-only closure contains HTTP/3 archives: {forbidden_libraries}"
        )

    metadata_rel = Path(bundle["metadata_relative_path"])
    required_sum_paths = {
        (metadata_rel / "BUILD-MANIFEST.txt").as_posix(),
        (metadata_rel / "COMPONENTS.tsv").as_posix(),
    }
    missing_sum_paths = sorted(required_sum_paths - sums.keys())
    if missing_sum_paths:
        raise SupplyChainError(
            f"curl checksum closure omits metadata: {missing_sum_paths}"
        )

    for key, expected in bundle["manifest_expectations"].items():
        actual = manifest.get(key)
        if actual != expected:
            raise SupplyChainError(
                f"curl manifest {key} mismatch: expected {expected!r}, got {actual!r}"
            )
    for key, relative in {
        "libcurl_sha256": "lib/libcurl-impersonate.a",
        "libnghttp2_sha256": "lib/libnghttp2.a",
        "libssl_sha256": "lib/libssl.a",
        "libcrypto_sha256": "lib/libcrypto.a",
    }.items():
        if manifest.get(key) != sums[relative]:
            raise SupplyChainError(
                f"curl manifest library digest mismatch: {key}"
            )

    declared_rows = {item["manifest_name"]: item for item in bundle["components"]}
    if set(components) != set(declared_rows):
        missing = sorted(set(declared_rows) - components.keys())
        unknown = sorted(components.keys() - set(declared_rows))
        raise SupplyChainError(
            f"curl component set mismatch; missing={missing}, unknown={unknown}"
        )
    for name, declared in declared_rows.items():
        row = components[name]
        expected_values = {
            "version_or_revision": declared["manifest_version"],
            "source_sha256": declared["source_sha256"],
            "license_file": declared["license_file"],
        }
        for field, expected in expected_values.items():
            if row[field] != expected:
                raise SupplyChainError(
                    f"curl component {name} {field} mismatch: "
                    f"expected {expected!r}, got {row[field]!r}"
                )
        license_relative = (
            metadata_rel / "licenses" / declared["license_file"]
        ).as_posix()
        if sums.get(license_relative) != declared["license_sha256"]:
            raise SupplyChainError(
                f"curl license digest mismatch: {license_relative}"
            )
        if (prefix / license_relative).stat().st_size == 0:
            raise SupplyChainError(f"empty curl license file: {license_relative}")
    for notice in bundle["additional_license_files"]:
        relative = (metadata_rel / "licenses" / notice["path"]).as_posix()
        if sums.get(relative) != notice["sha256"]:
            raise SupplyChainError(f"curl additional notice digest mismatch: {relative}")

    curl_component_ids = {
        component["id"] for component in bundle["components"]
    }
    for build_input in inventory["build_inputs"]:
        if build_input["component"] not in curl_component_ids:
            continue
        path = safe_repo_path(root, build_input["path"])
        actual = sha256_file(path)
        if actual != build_input["sha256"]:
            raise SupplyChainError(f"build input hash mismatch: {build_input['path']}")
        if manifest.get(build_input["manifest_hash_key"]) != actual:
            raise SupplyChainError(
                f"curl manifest does not bind build input {build_input['id']}"
            )
        bundled_relative = (
            metadata_rel / build_input["runtime_relative_path"]
        ).as_posix()
        if sums.get(bundled_relative) != actual:
            raise SupplyChainError(
                f"curl rebuild bundle does not contain trusted build input {build_input['id']}"
            )

    for patch in inventory["patches"]:
        path = safe_repo_path(root, patch["path"])
        actual = sha256_file(path)
        if actual != patch["sha256"]:
            raise SupplyChainError(f"security patch hash mismatch: {patch['path']}")
        if manifest.get(patch["manifest_hash_key"]) != actual:
            raise SupplyChainError(
                f"curl manifest does not bind security patch {patch['id']}"
            )
        if manifest.get(patch["fix_commit_manifest_key"]) != patch["upstream_commit"]:
            raise SupplyChainError(
                f"curl manifest does not bind security fix commit {patch['id']}"
            )
        for prerequisite in patch.get("prerequisites", []):
            if manifest.get(prerequisite["manifest_key"]) != prerequisite["commit"]:
                raise SupplyChainError(
                    f"curl manifest does not bind prerequisite for {patch['id']}"
                )
        bundled_relative = (
            metadata_rel
            / "rebuild/third_party/curl-impersonate/patches"
            / Path(patch["path"]).name
        ).as_posix()
        if sums.get(bundled_relative) != actual:
            raise SupplyChainError(
                f"curl rebuild bundle does not contain trusted security patch {patch['id']}"
            )
        patched_hash = manifest.get(patch["patched_file_manifest_key"])
        if not patched_hash or not re.fullmatch(r"[0-9a-f]{64}", patched_hash):
            raise SupplyChainError(
                f"curl manifest lacks patched-source evidence for {patch['id']}"
            )

    required_vex_keys = {
        key
        for vulnerability in inventory["vulnerabilities"]
        for key in vulnerability["evidence_manifest_keys"]
    }
    for key in sorted(required_vex_keys):
        if key not in manifest or not manifest[key]:
            raise SupplyChainError(f"curl manifest lacks VEX evidence key: {key}")
    for vulnerability in inventory["vulnerabilities"]:
        key = vulnerability["version_evidence_manifest_key"]
        expected = vulnerability["version_evidence_value"]
        if manifest.get(key) != expected:
            raise SupplyChainError(
                f"VEX version evidence mismatch for {vulnerability['id']}: "
                f"expected {expected!r}, got {manifest.get(key)!r}"
            )
    return manifest, bundle_digest, components, sums


def validate_static_deps_bundle(
    root: Path, prefix: Path, inventory: dict[str, Any]
) -> tuple[dict[str, str], str, dict[str, str]]:
    prefix = prefix.resolve(strict=True)
    bundle = inventory["static_deps_bundle"]
    metadata = (prefix / bundle["metadata_relative_path"]).resolve(strict=True)
    try:
        metadata.relative_to(prefix)
    except ValueError as exc:
        raise SupplyChainError(
            "static dependency metadata path escapes prefix"
        ) from exc
    manifest_path = metadata / "BUILD-MANIFEST.txt"
    components_path = metadata / "COMPONENTS.tsv"
    sums_path = metadata / "SHA256SUMS"
    for path in (manifest_path, components_path, sums_path):
        if not path.is_file():
            raise SupplyChainError(
                f"static dependency bundle metadata is missing: {path}")

    sums, bundle_digest = parse_sha256sums(prefix, sums_path)
    manifest = parse_key_value_manifest(manifest_path)
    for key, expected in bundle["manifest_expectations"].items():
        if manifest.get(key) != expected:
            raise SupplyChainError(
                f"static dependency manifest {key} mismatch: "
                f"expected {expected!r}, got {manifest.get(key)!r}"
            )
    missing_libraries = sorted(set(bundle["libraries"]) - sums.keys())
    if missing_libraries:
        raise SupplyChainError(
            "static dependency checksum closure lacks linked libraries: "
            f"{missing_libraries}"
        )
    digest_keys = {
        "lib/libmicrohttpd.a": "libmicrohttpd_archive_sha256",
        "lib/libyaml.a": "libyaml_archive_sha256",
        "lib/libpcre2-8.a": "pcre2_archive_sha256",
    }
    for relative, key in digest_keys.items():
        if manifest.get(key) != sums[relative]:
            raise SupplyChainError(
                f"static dependency manifest library digest mismatch: {key}"
            )
    metadata_rel = Path(bundle["metadata_relative_path"])
    for relative in (
        (metadata_rel / "BUILD-MANIFEST.txt").as_posix(),
        (metadata_rel / "COMPONENTS.tsv").as_posix(),
        (metadata_rel / "SOURCE-OFFER.txt").as_posix(),
        (metadata_rel / "licenses/libmicrohttpd-COPYING").as_posix(),
        (metadata_rel / "licenses/libyaml-License").as_posix(),
        (metadata_rel / "licenses/pcre2-COPYING").as_posix(),
    ):
        if relative not in sums:
            raise SupplyChainError(
                f"static dependency checksum closure omits {relative}")

    with components_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if reader.fieldnames != [
            "component", "version", "source_sha256", "license_file", "archive"
        ]:
            raise SupplyChainError("unexpected static dependency component header")
        rows = {row["component"]: row for row in reader}
    expected_rows = {
        "libmicrohttpd": {
            "version": "1.0.10",
            "source_sha256": inventory["static_deps_bundle"]
                ["manifest_expectations"]["libmicrohttpd_source_sha256"],
            "license_file": "libmicrohttpd-COPYING",
            "archive": "lib/libmicrohttpd.a",
        },
        "libyaml": {
            "version": "0.2.5",
            "source_sha256": inventory["static_deps_bundle"]
                ["manifest_expectations"]["libyaml_source_sha256"],
            "license_file": "libyaml-License",
            "archive": "lib/libyaml.a",
        },
        "pcre2": {
            "version": "10.47",
            "source_sha256": inventory["static_deps_bundle"]
                ["manifest_expectations"]["pcre2_source_sha256"],
            "license_file": "pcre2-COPYING",
            "archive": "lib/libpcre2-8.a",
        },
    }
    if set(rows) != set(expected_rows):
        raise SupplyChainError("static dependency component set mismatch")
    for name, expected in expected_rows.items():
        observed = {key: rows[name][key] for key in expected}
        if observed != expected:
            raise SupplyChainError(
                f"static dependency component metadata mismatch: {name}")

    static_component_ids = {"libmicrohttpd", "libyaml", "pcre2"}
    for build_input in inventory["build_inputs"]:
        if build_input["component"] not in static_component_ids:
            continue
        path = safe_repo_path(root, build_input["path"])
        actual = sha256_file(path)
        if actual != build_input["sha256"]:
            raise SupplyChainError(
                f"static dependency build input hash mismatch: {build_input['path']}"
            )
        if manifest.get(build_input["manifest_hash_key"]) != actual:
            raise SupplyChainError(
                f"static dependency manifest does not bind {build_input['id']}"
            )
        bundled_relative = (
            metadata_rel / build_input["runtime_relative_path"]
        ).as_posix()
        if sums.get(bundled_relative) != actual:
            raise SupplyChainError(
                f"static dependency rebuild bundle omits {build_input['id']}"
            )
    return manifest, bundle_digest, sums


def expected_runtime_files(inventory: dict[str, Any]) -> set[str]:
    metadata = inventory["curl_bundle"]["metadata_relative_path"].strip("/")
    static_metadata = inventory["static_deps_bundle"][
        "metadata_relative_path"
    ].strip("/")
    paths = {
        "/usr/local/bin/fastbed",
        "/etc/ssl/certs/ca-certificates.crt",
        "/usr/local/share/fastbed-runtime/RUNTIME-MANIFEST.txt",
        "/usr/local/share/fastbed-runtime/ALPINE-BUILD-PACKAGES",
        RUNTIME_RECEIPT_PATH,
        "/usr/local/share/fastbed/EMBEDDED-RESOURCES.json",
        f"/usr/local/{metadata}/BUILD-MANIFEST.txt",
        f"/usr/local/{metadata}/COMPONENTS.tsv",
        f"/usr/local/{metadata}/CURL-VERSION.txt",
        f"/usr/local/{metadata}/SHA256SUMS",
        f"/usr/local/{metadata}/SOURCE-OFFER.txt",
        f"/usr/local/{metadata}/rebuild/tools/build-curl-impersonate.sh",
        f"/usr/local/{static_metadata}/BUILD-MANIFEST.txt",
        f"/usr/local/{static_metadata}/COMPONENTS.tsv",
        f"/usr/local/{static_metadata}/SHA256SUMS",
        f"/usr/local/{static_metadata}/SOURCE-OFFER.txt",
        f"/usr/local/{static_metadata}/licenses/libmicrohttpd-COPYING",
        f"/usr/local/{static_metadata}/licenses/libyaml-License",
        f"/usr/local/{static_metadata}/licenses/pcre2-COPYING",
        f"/usr/local/{static_metadata}/rebuild/tools/build-static-deps.sh",
    }
    paths.update(
        f"/usr/local/{metadata}/licenses/{component['license_file']}"
        for component in inventory["curl_bundle"]["components"]
    )
    paths.update(
        f"/usr/local/{metadata}/licenses/{notice['path']}"
        for notice in inventory["curl_bundle"]["additional_license_files"]
    )
    paths.update(
        f"/usr/local/{metadata}/rebuild/third_party/curl-impersonate/patches/{Path(record['path']).name}"
        for record in inventory["patches"]
    )
    curl_component_ids = {
        component["id"] for component in inventory["curl_bundle"]["components"]
    }
    paths.update(
        f"/usr/local/{metadata}/{record['runtime_relative_path']}"
        for record in inventory["build_inputs"]
        if record["component"] in curl_component_ids
    )
    paths.update(
        f"/usr/local/{static_metadata}/{record['runtime_relative_path']}"
        for record in inventory["build_inputs"]
        if record["component"] in {"libmicrohttpd", "libyaml", "pcre2"}
    )
    paths.update(
        component["runtime_license"]["path"]
        for component in inventory["components"]
        if "runtime_license" in component
    )
    paths.update(
        record["path"]
        for component in inventory["components"]
        for record in component.get("runtime_evidence", [])
    )
    return paths


def validate_runtime(
    runtime: dict[str, Any], inventory: dict[str, Any]
) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    if runtime.get("schema_version") != 1:
        raise SupplyChainError("unsupported runtime inventory schema version")
    image_id = runtime.get("image_id")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise SupplyChainError("runtime inventory has an invalid image ID")
    runtime_profile = runtime.get("runtime")
    if (
        not isinstance(runtime_profile, dict)
        or runtime_profile.get("kind") != "scratch-static"
        or runtime_profile.get("profile") != "fastbed-scratch-static-v1"
        or not re.fullmatch(
            r"alpine:[^@]+@sha256:[0-9a-f]{64}",
            str(runtime_profile.get("base_image", "")),
        )
    ):
        raise SupplyChainError("runtime inventory is not the scratch-static profile")

    packages: dict[str, dict[str, str]] = {}
    required_fields = (
        "name", "version", "architecture", "license", "origin", "apk_checksum"
    )
    for package in runtime.get("packages", []):
        if not isinstance(package, dict) or any(
            not isinstance(package.get(field), str) or not package[field]
            for field in required_fields
        ):
            raise SupplyChainError("runtime package has incomplete metadata")
        name = package["name"]
        if name in packages:
            raise SupplyChainError(f"duplicate runtime package: {name}")
        if package["version"].lower() in {"unknown", "noassertion"}:
            raise SupplyChainError(f"runtime package has unknown version: {name}")
        packages[name] = package
    missing = sorted(set(inventory["required_runtime_packages"]) - packages.keys())
    if missing:
        raise SupplyChainError(f"runtime inventory lacks required packages: {missing}")

    files: dict[str, str] = {}
    elf_paths = {"/usr/local/bin/fastbed"}
    for record in runtime.get("files", []):
        if not isinstance(record, dict):
            raise SupplyChainError("runtime file record is not an object")
        path, digest = record.get("path"), record.get("sha256")
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or path in files
        ):
            raise SupplyChainError("runtime file record is malformed or duplicate")
        files[path] = digest
        build_id = record.get("build_id")
        if path in elf_paths:
            if not isinstance(build_id, str) or not re.fullmatch(
                r"[0-9a-f]{16,128}", build_id
            ):
                raise SupplyChainError(f"runtime ELF lacks a valid build ID: {path}")
        elif build_id is not None:
            raise SupplyChainError(f"non-ELF runtime evidence has a build ID: {path}")
    expected_files = expected_runtime_files(inventory)
    if set(files) != expected_files:
        raise SupplyChainError(
            f"runtime file evidence mismatch: expected {sorted(expected_files)}, "
            f"got {sorted(files)}"
        )
    for component in inventory["components"]:
        license_record = component.get("runtime_license")
        if license_record and files[license_record["path"]] != license_record["sha256"]:
            raise SupplyChainError(
                f"runtime license digest mismatch for {component['id']}: "
                f"{license_record['path']}"
            )
        for evidence in component.get("runtime_evidence", []):
            if files[evidence["path"]] != evidence["sha256"]:
                raise SupplyChainError(
                    f"runtime evidence digest mismatch for {component['id']}: "
                    f"{evidence['path']}"
                )
    return packages, files


def runtime_alpine_version(runtime: dict[str, Any]) -> str:
    base_image = runtime["runtime"]["base_image"]
    match = re.fullmatch(r"alpine:([^@]+)@sha256:[0-9a-f]{64}", base_image)
    if not match:
        raise SupplyChainError("runtime base image is not a pinned Alpine image")
    return match.group(1)


def validate_runtime_bundle_binding(
    runtime_files: dict[str, str],
    prefix: Path,
    inventory: dict[str, Any],
    curl_sums: dict[str, str],
) -> None:
    metadata = inventory["curl_bundle"]["metadata_relative_path"].strip("/")
    for runtime_path, runtime_digest in runtime_files.items():
        prefix_marker = f"/usr/local/{metadata}/"
        if not runtime_path.startswith(prefix_marker):
            continue
        relative = runtime_path.removeprefix("/usr/local/")
        if relative.endswith("/SHA256SUMS"):
            expected = sha256_file(prefix / relative)
        else:
            expected = curl_sums.get(relative)
            if expected is None:
                raise SupplyChainError(
                    f"runtime curl metadata is outside the bundle checksum closure: {relative}"
                )
        if runtime_digest != expected:
            raise SupplyChainError(
                f"runtime curl metadata differs from supplied bundle: {runtime_path}"
            )


def validate_runtime_static_deps_binding(
    runtime_files: dict[str, str],
    prefix: Path,
    inventory: dict[str, Any],
    static_sums: dict[str, str],
) -> None:
    metadata = inventory["static_deps_bundle"][
        "metadata_relative_path"
    ].strip("/")
    for runtime_path, runtime_digest in runtime_files.items():
        prefix_marker = f"/usr/local/{metadata}/"
        if not runtime_path.startswith(prefix_marker):
            continue
        relative = runtime_path.removeprefix("/usr/local/")
        if relative.endswith("/SHA256SUMS"):
            expected = sha256_file(prefix / relative)
        else:
            expected = static_sums.get(relative)
            if expected is None:
                raise SupplyChainError(
                    "runtime static dependency metadata is outside the "
                    f"checksum closure: {relative}"
                )
        if runtime_digest != expected:
            raise SupplyChainError(
                "runtime static dependency metadata differs from supplied "
                f"bundle: {runtime_path}"
            )


def validate_runtime_payload_binding(
    runtime: dict[str, Any],
    runtime_files: dict[str, str],
    source_evidence: list[dict[str, str]],
    inventory: dict[str, Any],
) -> None:
    source_hashes = {item["path"]: item["sha256"] for item in source_evidence}
    record = runtime["embedded_resources"]
    path = "/usr/local/share/fastbed/EMBEDDED-RESOURCES.json"
    if (
        record.get("path") != path
        or record.get("sha256") != runtime_files.get(path)
    ):
        raise SupplyChainError("embedded resource manifest digest binding mismatch")
    document = record.get("document")
    if (
        not isinstance(document, dict)
        or document.get("schema") != "fastbed-embedded-resources-v1"
        or document.get("generator_sha256")
        != source_hashes["tools/embed-resources.py"]
    ):
        raise SupplyChainError("embedded resource manifest identity mismatch")
    expected = [
        ("index_html", "assets/index.html"),
        ("favicon_ico", "assets/favicon.ico"),
        ("banner_png", "assets/banner.png"),
        (
            "crawler_json",
            "third_party/crawler-user-agents/crawler-user-agents.json",
        ),
    ]
    resources = document.get("resources")
    if not isinstance(resources, list) or len(resources) != len(expected):
        raise SupplyChainError("embedded resource manifest set is incomplete")
    for resource, (name, source_path) in zip(resources, expected, strict=True):
        if (
            not isinstance(resource, dict)
            or resource.get("name") != name
            or resource.get("sha256") != source_hashes[source_path]
            or not isinstance(resource.get("bytes"), int)
            or resource["bytes"] <= 0
        ):
            raise SupplyChainError(
                f"embedded resource differs from source evidence: {source_path}")


def validate_target_architecture(
    manifest: dict[str, str],
    static_manifest: dict[str, str],
    runtime: dict[str, Any],
    runtime_packages: dict[str, dict[str, str]],
) -> None:
    runtime_arch = runtime_packages["musl"]["architecture"]
    mapped = {"x86_64": "amd64", "aarch64": "arm64"}.get(runtime_arch)
    if mapped is None:
        raise SupplyChainError(f"unsupported runtime architecture: {runtime_arch}")
    image_arch = runtime.get("image_architecture")
    if image_arch != mapped:
        raise SupplyChainError(
            f"runtime image/package architecture mismatch: image={image_arch!r}, package={runtime_arch!r}"
        )
    if manifest.get("target_arch") != image_arch:
        raise SupplyChainError(
            "curl target architecture does not match runtime: "
            f"curl={manifest.get('target_arch')!r}, runtime={image_arch!r}"
        )
    if static_manifest.get("target_arch") != image_arch:
        raise SupplyChainError(
            "static dependency target architecture does not match runtime: "
            f"static={static_manifest.get('target_arch')!r}, "
            f"runtime={image_arch!r}"
        )
    expected_host = {"amd64": "x86_64", "arm64": "aarch64"}[image_arch]
    if manifest.get("host_machine") != expected_host:
        raise SupplyChainError(
            "curl host machine does not match target architecture: "
            f"host={manifest.get('host_machine')!r}, target={image_arch!r}"
        )
    if static_manifest.get("host_machine") != expected_host:
        raise SupplyChainError(
            "static dependency host machine does not match target architecture: "
            f"static={static_manifest.get('host_machine')!r}, "
            f"expected={expected_host!r}"
        )


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def validate_relink_archive(
    release_root: Path, receipt: dict[str, Any]
) -> str:
    release_root = release_root.resolve(strict=True)
    relink = receipt["lgpl_relink"]
    relative = PurePosixPath(relink["archive_path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise SupplyChainError("unsafe LGPL relink archive path in receipt")
    archive = (release_root / Path(*relative.parts)).resolve(strict=True)
    try:
        archive.relative_to(release_root)
    except ValueError as exc:
        raise SupplyChainError("LGPL relink archive escapes release root") from exc
    archive_digest = sha256_file(archive)
    if archive_digest != relink["archive_sha256"]:
        raise SupplyChainError("LGPL relink archive digest differs from receipt")

    top = f"fastbed-relink-{receipt['target_arch']}"
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(archive, mode="r:gz") as handle:
            for member in handle.getmembers():
                pure = PurePosixPath(member.name)
                if (
                    pure.is_absolute()
                    or ".." in pure.parts
                    or not pure.parts
                    or pure.parts[0] != top
                ):
                    raise SupplyChainError(
                        f"unsafe member in LGPL relink archive: {member.name}"
                    )
                if member.isdir():
                    continue
                key = PurePosixPath(*pure.parts[1:]).as_posix()
                if not member.isfile() or key in files:
                    raise SupplyChainError(
                        f"non-regular or duplicate LGPL relink member: {member.name}"
                    )
                extracted = handle.extractfile(member)
                if extracted is None:
                    raise SupplyChainError(
                        f"cannot read LGPL relink member: {member.name}"
                    )
                files[key] = extracted.read()
    except (tarfile.TarError, OSError) as exc:
        raise SupplyChainError(f"cannot inspect LGPL relink archive: {exc}") from exc

    sums_name = "SHA256SUMS"
    if sums_name not in files:
        raise SupplyChainError("LGPL relink archive lacks SHA256SUMS")
    sums_bytes = files[sums_name]
    if sha256_bytes(sums_bytes) != relink["content_sha256s_sha256"]:
        raise SupplyChainError("LGPL relink internal checksum digest mismatch")
    declared: dict[str, str] = {}
    for number, raw_line in enumerate(sums_bytes.decode("ascii").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  \./(.+)", raw_line)
        if not match:
            raise SupplyChainError(
                f"malformed LGPL relink SHA256SUMS line {number}"
            )
        expected, name = match.groups()
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or name in declared:
            raise SupplyChainError(f"unsafe LGPL relink checksum path: {name}")
        declared[name] = expected
    actual_names = set(files) - {sums_name}
    if set(declared) != actual_names:
        raise SupplyChainError("LGPL relink checksum closure is incomplete or stale")
    for name, expected in declared.items():
        if sha256_bytes(files[name]) != expected:
            raise SupplyChainError(f"LGPL relink member digest mismatch: {name}")

    required = {
        "ORIGINAL-LINK-COMMAND.txt",
        "RELINK-VERIFICATION.txt",
        "relink-fastbed.sh",
        "application-objects/libfastbed_yyjson.a",
    }
    if not required.issubset(files) or not any(
        name.startswith("application-objects/CMakeFiles/fastbed.dir/")
        and name.endswith(".o")
        for name in files
    ):
        raise SupplyChainError("LGPL relink archive lacks required application material")
    link_command = files["ORIGINAL-LINK-COMMAND.txt"].decode("utf-8").strip()
    command_digest = sha256_bytes(link_command.encode("utf-8"))
    if (
        link_command != receipt["link"]["command"]
        or command_digest != relink["link_command_sha256"]
        or sha256_bytes(files["relink-fastbed.sh"])
        != relink["relink_script_sha256"]
    ):
        raise SupplyChainError("LGPL relink command/script binding mismatch")
    for record in relink["libraries"]:
        name = record["path"]
        if name not in files or sha256_bytes(files[name]) != record["sha256"]:
            raise SupplyChainError(f"LGPL relink library mismatch: {record['path']}")
    verification: dict[str, str] = {}
    for line in files["RELINK-VERIFICATION.txt"].decode("ascii").splitlines():
        if "=" not in line:
            raise SupplyChainError("malformed RELINK-VERIFICATION.txt")
        key, value = line.split("=", 1)
        if key in verification or not key or not value:
            raise SupplyChainError("malformed RELINK-VERIFICATION.txt")
        verification[key] = value
    if verification != {
        "original_unstripped_sha256": receipt["fastbed"]["unstripped_sha256"],
        "relinked_sha256": receipt["fastbed"]["relinked_sha256"],
        "byte_identical": "true",
    }:
        raise SupplyChainError("LGPL relink verification differs from receipt")
    return archive_digest


def validate_build_receipt(
    runtime: dict[str, Any],
    inventory: dict[str, Any],
    source_digest: str,
    prefix: Path,
    bundle_digest: str,
    curl_sums: dict[str, str],
    static_prefix: Path,
    static_bundle_digest: str,
    static_sums: dict[str, str],
    release_root: Path,
) -> tuple[dict[str, Any], str, str]:
    record = runtime["build_receipt"]
    receipt = record["document"]
    receipt_digest = sha256_bytes(canonical_json_bytes(receipt))
    runtime_records = {item["path"]: item for item in runtime["files"]}
    if (
        record["path"] != RUNTIME_RECEIPT_PATH
        or record["sha256"] != receipt_digest
        or runtime_records[RUNTIME_RECEIPT_PATH]["sha256"] != receipt_digest
    ):
        raise SupplyChainError("runtime build receipt hash binding mismatch")
    if (
        receipt["source"]["tree_sha256"] != source_digest
        or receipt["source"]["paths"] != inventory["product"]["source_paths"]
        or receipt["source_date_epoch"]
        != int(inventory["curl_bundle"]["manifest_expectations"]["source_date_epoch"])
    ):
        raise SupplyChainError("build receipt source-tree binding mismatch")
    if receipt["generator_sha256"] != sha256_file(
        Path(__file__).resolve().parent / "create-release-artifacts.sh"
    ):
        raise SupplyChainError("build receipt generator digest mismatch")
    if (
        receipt["fastbed"]["runtime_sha256"]
        != runtime_records["/usr/local/bin/fastbed"]["sha256"]
        or receipt["fastbed"]["build_id"]
        != runtime_records["/usr/local/bin/fastbed"]["build_id"]
        or receipt["fastbed"]["unstripped_sha256"]
        != receipt["fastbed"]["relinked_sha256"]
    ):
        raise SupplyChainError("build receipt Fastbed binding mismatch")
    prefix = prefix.resolve(strict=True)
    metadata = prefix / inventory["curl_bundle"]["metadata_relative_path"]
    sums_path = metadata / "SHA256SUMS"
    manifest_path = metadata / "BUILD-MANIFEST.txt"
    prefix_receipt = receipt["curl_prefix"]
    if (
        prefix_receipt["checksum_aggregate_sha256"] != bundle_digest
        or prefix_receipt["sha256sums_sha256"] != sha256_file(sums_path)
        or prefix_receipt["build_manifest_sha256"] != sha256_file(manifest_path)
    ):
        raise SupplyChainError("build receipt curl-prefix aggregate mismatch")
    expected_libraries = [
        {"path": path, "sha256": curl_sums[path]}
        for path in LINKED_CURL_LIBRARIES
    ]
    if prefix_receipt["libraries"] != expected_libraries:
        raise SupplyChainError("build receipt linked-library set/hash mismatch")

    static_prefix = static_prefix.resolve(strict=True)
    static_metadata = (
        static_prefix / inventory["static_deps_bundle"]["metadata_relative_path"]
    )
    static_sums_path = static_metadata / "SHA256SUMS"
    static_manifest_path = static_metadata / "BUILD-MANIFEST.txt"
    static_receipt = receipt["static_deps_prefix"]
    if (
        static_receipt["checksum_aggregate_sha256"] != static_bundle_digest
        or static_receipt["sha256sums_sha256"]
        != sha256_file(static_sums_path)
        or static_receipt["build_manifest_sha256"]
        != sha256_file(static_manifest_path)
    ):
        raise SupplyChainError(
            "build receipt static-dependency prefix aggregate mismatch")
    expected_static_libraries = [
        {"path": path, "sha256": static_sums[path]}
        for path in LINKED_STATIC_DEPS_LIBRARIES
    ]
    if static_receipt["libraries"] != expected_static_libraries:
        raise SupplyChainError(
            "build receipt static-dependency library set/hash mismatch")
    expected_static_sources = []
    for relative in inventory["static_deps_bundle"]["source_archives"]:
        candidate = release_root.resolve(strict=True) / relative
        expected_static_sources.append(
            {"path": relative, "sha256": sha256_file(candidate)}
        )
    if static_receipt["source_archives"] != expected_static_sources:
        raise SupplyChainError(
            "build receipt static-dependency source closure mismatch")
    command = receipt["link"]["command"]
    command_digest = sha256_bytes(command.encode("utf-8"))
    if receipt["link"]["sha256"] != command_digest or "\n" in command:
        raise SupplyChainError("build receipt link-command digest mismatch")
    for relative in LINKED_CURL_LIBRARIES:
        if command.count("/" + relative) != 1:
            raise SupplyChainError(
                f"build receipt link command does not bind exactly one {relative}"
            )
    for relative in LINKED_STATIC_DEPS_LIBRARIES:
        if command.count("/" + relative) != 1:
            raise SupplyChainError(
                "build receipt link command does not bind exactly one "
                f"static dependency {relative}"
            )
    if any(name in command for name in FORBIDDEN_HTTP3_LIBRARIES):
        raise SupplyChainError("build receipt link command contains HTTP/3 archive")
    expected_lgpl = [
        {
            "path": "curl-prefix/lib/libidn2.a",
            "sha256": curl_sums["lib/libidn2.a"],
        },
        {
            "path": "curl-prefix/lib/libunistring.a",
            "sha256": curl_sums["lib/libunistring.a"],
        },
        {
            "path": "static-deps-prefix/lib/libmicrohttpd.a",
            "sha256": static_sums["lib/libmicrohttpd.a"],
        },
    ]
    if receipt["lgpl_relink"]["libraries"] != expected_lgpl:
        raise SupplyChainError("build receipt LGPL library closure mismatch")
    expected_sources = []
    release_root = release_root.resolve(strict=True)
    for relative in LGPL_SOURCE_ARCHIVES:
        candidate = release_root / relative
        if candidate.is_symlink():
            raise SupplyChainError(f"LGPL source archive is a symlink: {relative}")
        source = candidate.resolve(strict=True)
        try:
            source.relative_to(release_root)
        except ValueError as exc:
            raise SupplyChainError("LGPL source archive escapes release root") from exc
        if not source.is_file():
            raise SupplyChainError(f"LGPL source archive is absent: {relative}")
        expected_sources.append({"path": relative, "sha256": sha256_file(source)})
    if receipt["lgpl_relink"]["source_archives"] != expected_sources:
        raise SupplyChainError("build receipt LGPL source-archive closure mismatch")
    source_by_path = {item["path"]: item["sha256"] for item in expected_sources}
    component_by_id = {
        item["id"]: item for item in inventory["curl_bundle"]["components"]
    }
    if (
        source_by_path["source/curl-impersonate/libidn2-2.3.8.tar.gz"]
        != component_by_id["libidn2"]["source_sha256"]
        or source_by_path["source/curl-impersonate/libunistring-1.4.2.tar.xz"]
        != component_by_id["libunistring"]["source_sha256"]
    ):
        raise SupplyChainError("LGPL source archives differ from component identity")
    mhd_component = next(
        item for item in inventory["components"]
        if item["id"] == "libmicrohttpd"
    )
    if (
        source_by_path["source/static-deps/libmicrohttpd-1.0.10.tar.gz"]
        != mhd_component["source_sha256"]
    ):
        raise SupplyChainError(
            "libmicrohttpd LGPL source archive differs from component identity")
    archive_digest = validate_relink_archive(release_root, receipt)
    return receipt, receipt_digest, archive_digest


def apk_sha1(encoded: str) -> str:
    if not re.fullmatch(r"Q1[0-9A-Za-z+/]+=*", encoded):
        raise SupplyChainError(f"malformed APK checksum: {encoded!r}")
    try:
        raw = base64.b64decode(encoded[2:], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise SupplyChainError(f"malformed APK checksum: {encoded!r}") from exc
    if len(raw) != 20:
        raise SupplyChainError(f"APK checksum is not SHA-1 sized: {encoded!r}")
    return raw.hex()


def component_properties(component: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {
            "name": "fastbed:source-archive-sha256",
            "value": component["source_sha256"],
        },
        {
            "name": "fastbed:security-disposition",
            "value": component["security_disposition"],
        },
    ]


def evidence_output_name(finding: dict[str, Any]) -> str:
    artifact = finding["evidence_artifact"]
    suffix = "".join(Path(artifact["path"]).suffixes)
    return f"evidence-{finding['id'].lower()}{suffix}"


def cdx_component(
    component: dict[str, Any], patches: list[dict[str, Any]]
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": component["type"],
        "bom-ref": component["bom_ref"],
        "name": component["name"],
        "version": component["version"],
        "hashes": [{"alg": "SHA-256", "content": component["source_sha256"]}],
        "licenses": [{"expression": component["license"]}],
        "purl": component["purl"],
        "externalReferences": [
            {"type": "website", "url": component["source_url"]},
            {
                "type": "distribution",
                "url": component["download_url"],
                "hashes": [
                    {"alg": "SHA-256", "content": component["source_sha256"]}
                ],
            },
        ],
        "properties": component_properties(component),
    }
    if component.get("description"):
        result["description"] = component["description"]
    component_patches = [patch for patch in patches if patch["component"] == component["id"]]
    if component_patches:
        result["pedigree"] = {
            "patches": [
                {
                    "type": "backport",
                    "diff": {"url": patch["upstream_url"]},
                    "resolves": [
                        {
                            "type": "security",
                            "id": patch["id"],
                            "description": patch["purpose"],
                        }
                    ],
                }
                for patch in component_patches
            ]
        }
        result["properties"].extend(
            item
            for patch in component_patches
            for item in (
                {
                    "name": f"fastbed:patch-sha256:{patch['id']}",
                    "value": patch["sha256"],
                },
                {
                    "name": f"fastbed:upstream-patch-sha256:{patch['id']}",
                    "value": patch["upstream_patch_sha256"],
                },
            )
        )
        for patch in component_patches:
            for prerequisite in patch.get("prerequisites", []):
                result["properties"].extend(
                    [
                        {
                            "name": f"fastbed:prerequisite-commit:{patch['id']}",
                            "value": prerequisite["commit"],
                        },
                        {
                            "name": f"fastbed:prerequisite-patch-sha256:{patch['id']}",
                            "value": prerequisite["patch_sha256"],
                        },
                    ]
                )
    return result


def apk_purl(package: dict[str, str], alpine_version: str) -> str:
    name = urllib.parse.quote(package["name"], safe=".-_+")
    version = urllib.parse.quote(package["version"], safe=".-_+")
    qualifiers = urllib.parse.urlencode(
        {
            "arch": package["architecture"],
            "distro": f"alpine-{alpine_version}",
        }
    )
    return f"pkg:apk/alpine/{name}@{version}?{qualifiers}"


def runtime_cdx_component(package: dict[str, str], alpine_version: str) -> dict[str, Any]:
    sha1 = apk_sha1(package["apk_checksum"])
    purl = apk_purl(package, alpine_version)
    query = urllib.parse.urlencode(
        {
            "name": package["name"],
            "branch": f"v{alpine_version.rsplit('.', 1)[0]}",
            "arch": package["architecture"],
        }
    )
    return {
        "type": "library",
        "bom-ref": f"runtime:{package['name']}",
        "group": "alpine",
        "name": package["name"],
        "version": package["version"],
        "hashes": [{"alg": "SHA-1", "content": sha1}],
        "licenses": [{"expression": package["license"]}],
        "purl": purl,
        "externalReferences": [
            {
                "type": "distribution",
                "url": f"https://pkgs.alpinelinux.org/packages?{query}",
            }
        ],
        "properties": [
            {"name": "fastbed:apk-origin", "value": package["origin"]},
            {"name": "fastbed:apk-checksum", "value": package["apk_checksum"]},
            {
                "name": "fastbed:security-disposition",
                "value": "no-named-finding-in-this-vex",
            },
        ],
    }


def dependency_records(
    relationships: list[dict[str, str]], ref_by_id: dict[str, str]
) -> list[dict[str, Any]]:
    children: dict[str, set[str]] = {ref: set() for ref in ref_by_id.values()}
    for relation in relationships:
        parent_id, child_id = relation["from"], relation["to"]
        if parent_id not in ref_by_id or child_id not in ref_by_id:
            raise SupplyChainError(
                f"relationship references unknown component: {parent_id} -> {child_id}"
            )
        children[ref_by_id[parent_id]].add(ref_by_id[child_id])
    return [
        {"ref": ref, "dependsOn": sorted(children[ref])}
        for ref in sorted(children)
    ]


def make_cyclonedx(
    inventory: dict[str, Any],
    runtime_packages: dict[str, dict[str, str]],
    runtime_files: dict[str, str],
    source_digest: str,
    source_evidence: list[dict[str, str]],
    manifest: dict[str, str],
    bundle_digest: str,
    static_bundle_digest: str,
    alpine_version: str,
    serial: str,
    timestamp: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    product = inventory["product"]
    all_declared = inventory["components"] + inventory["curl_bundle"]["components"]
    ref_by_id = {product["id"]: product["bom_ref"]}
    components = [cdx_component(component, inventory["patches"]) for component in all_declared]
    for component in all_declared:
        if component["id"] in ref_by_id:
            raise SupplyChainError(f"duplicate component ID: {component['id']}")
        ref_by_id[component["id"]] = component["bom_ref"]
    cdx_by_ref = {item["bom-ref"]: item for item in components}
    for build_input in inventory["build_inputs"]:
        owner = next(
            component
            for component in all_declared
            if component["id"] == build_input["component"]
        )
        cdx_by_ref[owner["bom_ref"]]["properties"].append(
            {
                "name": f"fastbed:build-input-sha256:{build_input['id']}",
                "value": build_input["sha256"],
            }
        )
    for static_component_id in ("libmicrohttpd", "libyaml", "pcre2"):
        static_ref = next(
            component["bom_ref"]
            for component in inventory["components"]
            if component["id"] == static_component_id
        )
        next(
            item for item in components if item["bom-ref"] == static_ref
        )["properties"].append(
            {"name": "fastbed:linkage", "value": "static"}
        )

    for package in runtime_packages.values():
        component_id = f"runtime:{package['name']}"
        if component_id in ref_by_id:
            raise SupplyChainError(f"duplicate runtime component ID: {component_id}")
        ref_by_id[component_id] = component_id
        components.append(runtime_cdx_component(package, alpine_version))

    source_manifest_digest = sha256_bytes(
        "".join(
            f"{item['path']}\0{item['sha256']}\n" for item in source_evidence
        ).encode("utf-8")
    )
    metadata_component = {
        "type": "application",
        "bom-ref": product["bom_ref"],
        "name": product["name"],
        "version": product["version"],
        "hashes": [
            {
                "alg": "SHA-256",
                "content": runtime_files["/usr/local/bin/fastbed"],
            }
        ],
        "purl": product["purl"],
        "properties": [
            {"name": "fastbed:source-tree-sha256", "value": source_digest},
            {
                "name": "fastbed:source-file-aggregate-sha256",
                "value": source_manifest_digest,
            },
            {"name": "fastbed:libmicrohttpd-linkage", "value": "static"},
            {"name": "fastbed:libyaml-linkage", "value": "static"},
            {"name": "fastbed:resolver-backend", "value": manifest["resolver_backend"]},
            {
                "name": "fastbed:curl-profile",
                "value": manifest["profile"],
            },
            {
                "name": "fastbed:curl-protocols",
                "value": manifest["protocols"],
            },
            {
                "name": "fastbed:http3",
                "value": manifest["http3"],
            },
        ],
    }
    if product["license"] not in {"NOASSERTION", "NONE"}:
        metadata_component["licenses"] = [{"expression": product["license"]}]
    return (
        {
            "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{serial}",
            "version": 1,
            "metadata": {
                "timestamp": timestamp,
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": "fastbed-manual-sbom",
                            "version": "1",
                        }
                    ]
                },
                "component": metadata_component,
                "properties": [
                    {
                        "name": "fastbed:inventory-scope",
                        "value": "application-source,post-link-receipt,linked-libraries,curl-static-closure,lgpl-relink-closure,runtime-image-packages",
                    },
                    {
                        "name": "fastbed:resolver-note",
                        "value": "curl threaded resolver; no c-ares archive is present; getaddrinfo is provided by runtime musl",
                    },
                    {
                        "name": "fastbed:target-architecture",
                        "value": manifest["target_arch"],
                    },
                    {
                        "name": "fastbed:curl-bundle-sha256",
                        "value": bundle_digest,
                    },
                    {
                        "name": "fastbed:static-deps-bundle-sha256",
                        "value": static_bundle_digest,
                    },
                    {
                        "name": "fastbed:release-status",
                        "value": inventory["release_status"],
                    },
                    {
                        "name": "fastbed:release-reason",
                        "value": inventory["release_reason"],
                    },
                ],
            },
            "components": sorted(components, key=lambda item: item["bom-ref"]),
            "dependencies": dependency_records(inventory["relationships"], ref_by_id),
        },
        ref_by_id,
    )


def spdx_id(component_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.-]", "-", component_id)
    return f"SPDXRef-{cleaned}"


def make_spdx(
    inventory: dict[str, Any],
    runtime_packages: dict[str, dict[str, str]],
    runtime_files: dict[str, str],
    source_digest: str,
    alpine_version: str,
    serial: str,
    timestamp: str,
) -> dict[str, Any]:
    product = inventory["product"]
    declared = inventory["components"] + inventory["curl_bundle"]["components"]
    packages: list[dict[str, Any]] = []
    by_id: dict[str, dict[str, Any]] = {}

    product_package = {
        "name": product["name"],
        "SPDXID": spdx_id(product["id"]),
        "versionInfo": product["version"],
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "checksums": [
            {
                "algorithm": "SHA256",
                "checksumValue": runtime_files["/usr/local/bin/fastbed"],
            }
        ],
        "licenseConcluded": product["license"],
        "licenseDeclared": product["license"],
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": product["purl"],
            },
            {
                "referenceCategory": "OTHER",
                "referenceType": "fastbed:source-tree-sha256",
                "referenceLocator": source_digest,
            },
        ],
    }
    packages.append(product_package)
    by_id[product["id"]] = product_package

    for component in declared:
        package = {
            "name": component["name"],
            "SPDXID": spdx_id(component["id"]),
            "versionInfo": component["version"],
            "downloadLocation": component["download_url"],
            "filesAnalyzed": False,
            "checksums": [
                {"algorithm": "SHA256", "checksumValue": component["source_sha256"]}
            ],
            "licenseConcluded": component["license"],
            "licenseDeclared": component["license"],
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": (
                "FILE" if component["type"] == "data" else "LIBRARY"
            ),
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": component["purl"],
                },
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "fastbed:security-disposition",
                    "referenceLocator": component["security_disposition"],
                },
            ],
        }
        packages.append(package)
        by_id[component["id"]] = package
        for record_kind, records in (
            ("patch", inventory["patches"]),
            ("build-input", inventory["build_inputs"]),
        ):
            for patch_record in records:
                if patch_record["component"] != component["id"]:
                    continue
                package["externalRefs"].append(
                    {
                        "referenceCategory": "OTHER",
                        "referenceType": (
                            f"urn:fastbed:{record_kind}-sha256:"
                            + re.sub(r"[^A-Za-z0-9.-]", "-", patch_record["id"]).lower()
                        ),
                        "referenceLocator": patch_record["sha256"],
                    }
                )
        if component["id"] == "libmicrohttpd":
            package["externalRefs"].append(
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "urn:fastbed:linkage",
                    "referenceLocator": "static",
                }
            )
        if component["id"] == "libyaml":
            package["externalRefs"].append(
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "urn:fastbed:linkage",
                    "referenceLocator": "static",
                }
            )

    for runtime in runtime_packages.values():
        component_id = f"runtime:{runtime['name']}"
        package = {
            "name": runtime["name"],
            "SPDXID": spdx_id(component_id),
            "versionInfo": runtime["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "checksums": [
                {"algorithm": "SHA1", "checksumValue": apk_sha1(runtime["apk_checksum"])}
            ],
            "licenseConcluded": runtime["license"],
            "licenseDeclared": runtime["license"],
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": apk_purl(runtime, alpine_version),
                },
                {
                    "referenceCategory": "OTHER",
                    "referenceType": "fastbed:apk-checksum",
                    "referenceLocator": runtime["apk_checksum"],
                },
            ],
        }
        packages.append(package)
        by_id[component_id] = package

    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": product_package["SPDXID"],
        }
    ]
    for relation in inventory["relationships"]:
        if relation["from"] not in by_id or relation["to"] not in by_id:
            raise SupplyChainError(
                f"SPDX relationship references unknown component: {relation}"
            )
        relationships.append(
            {
                "spdxElementId": by_id[relation["from"]]["SPDXID"],
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": by_id[relation["to"]]["SPDXID"],
            }
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"fastbed-{product['version']}-production-{inventory['schema_version']}",
        "comment": inventory["release_reason"],
        "documentNamespace": f"https://fastbed.invalid/spdx/{serial}",
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: fastbed-manual-sbom-1"],
            "licenseListVersion": "3.29.0",
        },
        "documentDescribes": [product_package["SPDXID"]],
        "packages": sorted(packages, key=lambda item: item["SPDXID"]),
        "relationships": sorted(
            relationships,
            key=lambda item: (
                item["spdxElementId"],
                item["relationshipType"],
                item["relatedSpdxElement"],
            ),
        ),
    }


def make_vex(
    inventory: dict[str, Any],
    manifest: dict[str, str],
    ref_by_id: dict[str, str],
    serial: str,
    timestamp: str,
) -> dict[str, Any]:
    component_by_id = {
        component["id"]: component
        for component in inventory["components"] + inventory["curl_bundle"]["components"]
    }
    vulnerabilities: list[dict[str, Any]] = []
    affected_components: dict[str, dict[str, Any]] = {}
    for finding in inventory["vulnerabilities"]:
        component_id = finding["component"]
        if component_id not in component_by_id or component_id not in ref_by_id:
            raise SupplyChainError(
                f"VEX finding references unknown component: {component_id}"
            )
        evidence = ", ".join(
            f"{key}={manifest[key]}" for key in finding["evidence_manifest_keys"]
        )
        vulnerability: dict[str, Any] = {
            "id": finding["id"],
            "source": {"name": "CVE", "url": finding["advisory_url"]},
            "ratings": [
                {
                    "source": {"name": "upstream advisory"},
                    "severity": finding["severity"],
                }
            ],
            "description": finding["description"],
            "advisories": [{"url": finding["advisory_url"]}],
            "affects": [{"ref": ref_by_id[component_id]}],
            "analysis": {
                "state": finding["state"],
                "response": finding["response"],
                "detail": f"{finding['detail']} Evidence: {evidence}",
            },
            "properties": [
                {"name": "fastbed:resolution", "value": finding["resolution"]},
                {"name": "fastbed:fixed-version", "value": finding["fixed_version"]},
                {"name": "fastbed:fixed-commit", "value": finding["fixed_commit"]},
            ],
        }
        evidence_artifact = finding.get("evidence_artifact")
        if evidence_artifact:
            vulnerability["properties"].extend(
                [
                    {
                        "name": "fastbed:evidence-artifact",
                        "value": evidence_output_name(finding),
                    },
                    {
                        "name": "fastbed:evidence-artifact-sha256",
                        "value": evidence_artifact["sha256"],
                    },
                ]
            )
        if "score" in finding:
            vulnerability["ratings"][0]["score"] = finding["score"]
        if "vector" in finding:
            vulnerability["ratings"][0]["vector"] = finding["vector"]
            vulnerability["ratings"][0]["method"] = "CVSSv31"
        if "cwe" in finding:
            vulnerability["cwes"] = [finding["cwe"]]
        vulnerabilities.append(vulnerability)
        affected_components[component_id] = component_by_id[component_id]

    return {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.UUID(serial), 'vex')}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "fastbed-manual-vex",
                        "version": "1",
                    }
                ]
            },
            "properties": [
                {
                    "name": "fastbed:vex-scope",
                    "value": "Named findings only; absence from this VEX is not an assertion of no vulnerability",
                },
                {
                    "name": "fastbed:release-status",
                    "value": inventory["release_status"],
                },
                {
                    "name": "fastbed:release-reason",
                    "value": inventory["release_reason"],
                },
            ],
        },
        "components": sorted(
            [
                cdx_component(component, inventory["patches"])
                for component in affected_components.values()
            ],
            key=lambda item: item["bom-ref"],
        ),
        "vulnerabilities": sorted(vulnerabilities, key=lambda item: item["id"]),
    }


def write_json(path: Path, value: Any) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, sort_keys=True, indent=2, ensure_ascii=False)
        handle.write("\n")


def write_artifacts(
    output: Path,
    source_root: Path,
    inventory: dict[str, Any],
    runtime: dict[str, Any],
    runtime_inventory_digest: str,
    source_digest: str,
    source_evidence: list[dict[str, str]],
    manifest: dict[str, str],
    bundle_digest: str,
    static_bundle_digest: str,
    inventory_digest: str,
    build_receipt: dict[str, Any],
    build_receipt_digest: str,
    relink_archive_digest: str,
) -> None:
    timestamp = inventory.get("document_created")
    if not isinstance(timestamp, str):
        raise SupplyChainError("inventory lacks document_created")
    try:
        parsed_timestamp = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SupplyChainError("inventory document_created is not ISO 8601") from exc
    if parsed_timestamp.tzinfo != dt.timezone.utc or not timestamp.endswith("Z"):
        raise SupplyChainError("inventory document_created must be UTC with a Z suffix")
    seed = "\n".join(
        [
            sha256_bytes(
                json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ),
            runtime_inventory_digest,
            source_digest,
            bundle_digest,
            static_bundle_digest,
            build_receipt_digest,
            relink_archive_digest,
        ]
    )
    serial = str(uuid.uuid5(uuid.NAMESPACE_URL, seed))
    runtime_packages, runtime_files = validate_runtime(runtime, inventory)
    alpine_version = runtime_alpine_version(runtime)
    cyclone, refs = make_cyclonedx(
        inventory,
        runtime_packages,
        runtime_files,
        source_digest,
        source_evidence,
        manifest,
        bundle_digest,
        static_bundle_digest,
        alpine_version,
        serial,
        timestamp,
    )
    spdx = make_spdx(
        inventory,
        runtime_packages,
        runtime_files,
        source_digest,
        alpine_version,
        serial,
        timestamp,
    )
    vex = make_vex(inventory, manifest, refs, serial, timestamp)

    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=f".{output.name}.tmp-", dir=output.parent
    ) as temporary:
        stage = Path(temporary) / "artifact"
        stage.mkdir()
        documents = [
            ("cyclonedx-sbom.json", "CycloneDX-1.6", cyclone),
            ("spdx-sbom.json", "SPDX-2.3", spdx),
            ("cyclonedx-vex.json", "CycloneDX-VEX-1.6", vex),
        ]
        for name, _format, content in documents:
            write_json(stage / name, content)

        source_files = {
            "$schema": "../artifact-schema/source-files.schema.json",
            "schema_version": 1,
            "source_tree_sha256": source_digest,
            "files": source_evidence,
        }
        write_json(stage / "source-files.json", source_files)
        write_json(stage / "build-receipt.json", build_receipt)
        if sha256_file(stage / "build-receipt.json") != build_receipt_digest:
            raise SupplyChainError("generated build receipt digest changed")

        evidence_records: list[dict[str, str]] = []
        for finding in inventory["vulnerabilities"]:
            evidence_artifact = finding.get("evidence_artifact")
            if not evidence_artifact:
                continue
            name = evidence_output_name(finding)
            source = safe_repo_path(source_root, evidence_artifact["path"])
            target = stage / name
            shutil.copyfile(source, target)
            actual = sha256_file(target)
            if actual != evidence_artifact["sha256"]:
                raise SupplyChainError(f"copied VEX evidence digest mismatch: {name}")
            evidence_records.append(
                {"id": finding["id"], "path": name, "sha256": actual}
            )

        document_records = [
            {"path": name, "format": format_name, "sha256": sha256_file(stage / name)}
            for name, format_name, _content in documents
        ]
        provenance = {
            "$schema": "../artifact-schema/sbom-output-profile.schema.json",
            "schema_version": 1,
            "generator": "tools/generate-sbom-vex.py",
            "generator_sha256": sha256_file(
                source_root / "tools/generate-sbom-vex.py"
            ),
            "verifier_sha256": sha256_file(
                source_root / "tools/verify-sbom-vex.py"
            ),
            "inventory_sha256": inventory_digest,
            "source_tree_sha256": source_digest,
            "source_files_sha256": sha256_file(stage / "source-files.json"),
            "curl_bundle_sha256": bundle_digest,
            "static_deps_bundle_sha256": static_bundle_digest,
            "runtime_inventory_sha256": runtime_inventory_digest,
            "build_receipt_sha256": build_receipt_digest,
            "lgpl_relink_archive_sha256": relink_archive_digest,
            "image_id": runtime["image_id"],
            "target_arch": manifest["target_arch"],
            "release_status": inventory["release_status"],
            "release_reason": inventory["release_reason"],
            "evidence": evidence_records,
            "documents": document_records,
        }
        write_json(stage / "provenance.json", provenance)
        with (stage / "SHA256SUMS").open("x", encoding="ascii", newline="\n") as handle:
            names = [item[0] for item in documents] + [
                "provenance.json",
                "source-files.json",
                "build-receipt.json",
            ] + [record["path"] for record in evidence_records]
            for name in sorted(names):
                handle.write(f"{sha256_file(stage / name)}  {name}\n")
        os.rename(stage, output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--curl-prefix", type=Path, required=True)
    parser.add_argument("--static-deps-prefix", type=Path, required=True)
    parser.add_argument("--release-artifact-root", type=Path, required=True)
    parser.add_argument("--runtime-inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if args.output.exists():
        parser.error(f"output already exists: {args.output}")
    try:
        source_root = args.source_root.resolve(strict=True)
        inventory_path = args.inventory.resolve(strict=True)
        inventory = read_json(inventory_path)
        runtime_path = args.runtime_inventory.resolve(strict=True)
        runtime = read_json(runtime_path)
        validate_json_schema(
            inventory, inventory_path.parent / "supply-chain-inventory.schema.json"
        )
        validate_json_schema(
            runtime, inventory_path.parent / "runtime-inventory.schema.json"
        )
        validate_json_schema(
            runtime["build_receipt"]["document"],
            inventory_path.parent / "build-receipt.schema.json",
        )
        if inventory.get("schema_version") != 1:
            raise SupplyChainError("unsupported supply-chain inventory schema version")
        validate_declared_inputs(source_root, inventory)
        source_digest, source_evidence = hash_source_tree(
            source_root, inventory["product"]["source_paths"]
        )
        manifest, bundle_digest, _components, curl_sums = validate_curl_bundle(
            source_root, args.curl_prefix, inventory
        )
        static_manifest, static_bundle_digest, static_sums = (
            validate_static_deps_bundle(
                source_root, args.static_deps_prefix, inventory
            )
        )
        runtime_packages, runtime_files = validate_runtime(runtime, inventory)
        validate_runtime_bundle_binding(
            runtime_files,
            args.curl_prefix.resolve(strict=True),
            inventory,
            curl_sums,
        )
        validate_runtime_static_deps_binding(
            runtime_files,
            args.static_deps_prefix.resolve(strict=True),
            inventory,
            static_sums,
        )
        validate_runtime_payload_binding(
            runtime, runtime_files, source_evidence, inventory)
        validate_target_architecture(
            manifest, static_manifest, runtime, runtime_packages)
        receipt, receipt_digest, relink_archive_digest = validate_build_receipt(
            runtime,
            inventory,
            source_digest,
            args.curl_prefix.resolve(strict=True),
            bundle_digest,
            curl_sums,
            args.static_deps_prefix.resolve(strict=True),
            static_bundle_digest,
            static_sums,
            args.release_artifact_root.resolve(strict=True),
        )
        if receipt["target_arch"] != runtime["image_architecture"]:
            raise SupplyChainError("build receipt target architecture mismatch")
        write_artifacts(
            args.output,
            source_root,
            inventory,
            runtime,
            sha256_file(runtime_path),
            source_digest,
            source_evidence,
            manifest,
            bundle_digest,
            static_bundle_digest,
            sha256_file(inventory_path),
            receipt,
            receipt_digest,
            relink_archive_digest,
        )
    except (
        KeyError,
        OSError,
        SupplyChainError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        print(f"generate-sbom-vex: {exc}", file=sys.stderr)
        return 1
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

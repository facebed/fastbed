#!/usr/bin/env python3
"""Validate a generated Fastbed SBOM/VEX artifact set and its hash closure."""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import re
import sys
import tarfile
import urllib.parse
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import jsonschema
except ImportError as exc:  # pragma: no cover - an explicit host prerequisite
    raise SystemExit("verify-sbom-vex requires Python jsonschema") from exc


class VerificationError(RuntimeError):
    pass


OFFICIAL_SCHEMA_SHA256 = {
    "bom-1.6.schema.json": "1ebcb88a2c845ecb6ff7bee7aeabdff9422cb0347f3d6875b241bd444b7e098f",
    "spdx.schema.json": "33863a360fc4d348e183d89c1ca7aa0877f481e7eb55be2d4102a30386188a10",
    "jsf-0.82.schema.json": "2faf5eb3651f2ae5f46091a131770d8d847bbd121139d19c85fc7051bfa58c46",
    "spdx-2.3.schema.json": "239208b7ac287b3cf5d9a9af23f9d69863971102a5e1587a27a398b43490b89b",
    "spdx-licenses-3.29.0.json": "47d1cc681abe31166b342b6cc4aab13a6ba8ea5c48794697fe3bf8b1dbaf509a",
    "spdx-exceptions-3.29.0.json": "59ee7c150de521d635cbf9367b8cf543b8da6781ea3ac1c073d305524f84ada2",
}

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
LINKED_STATIC_DEPS_LIBRARIES = ["lib/libmicrohttpd.a", "lib/libyaml.a"]
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


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_output_name(finding: dict[str, Any]) -> str:
    artifact = finding["evidence_artifact"]
    suffix = "".join(Path(artifact["path"]).suffixes)
    return f"evidence-{finding['id'].lower()}{suffix}"


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"invalid JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError(f"top-level value is not an object: {path}")
    return value


def validate_schema(instance: dict[str, Any], schema_path: Path) -> None:
    schema = load_json(schema_path)
    try:
        validator = jsonschema.Draft202012Validator(
            schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
        )
        validator.check_schema(schema)
        errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    except jsonschema.SchemaError as exc:
        raise VerificationError(f"invalid JSON schema {schema_path}: {exc.message}") from exc
    if errors:
        first = errors[0]
        location = "/".join(str(item) for item in first.absolute_path) or "<root>"
        raise VerificationError(
            f"schema failure in {schema_path.name} at {location}: {first.message}"
        )


def validate_official_documents(
    cyclone: dict[str, Any],
    vex: dict[str, Any],
    spdx: dict[str, Any],
    schema_dir: Path,
) -> tuple[set[str], set[str]]:
    actual_files = {
        path.name
        for path in schema_dir.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    if actual_files != set(OFFICIAL_SCHEMA_SHA256):
        raise VerificationError("official schema directory has an unexpected file set")
    for name, expected in OFFICIAL_SCHEMA_SHA256.items():
        path = schema_dir / name
        if path.is_symlink() or sha256_file(path) != expected:
            raise VerificationError(f"official schema digest mismatch: {name}")
    paths = {
        "cyclonedx": schema_dir / "bom-1.6.schema.json",
        "cyclonedx_spdx": schema_dir / "spdx.schema.json",
        "jsf": schema_dir / "jsf-0.82.schema.json",
        "spdx": schema_dir / "spdx-2.3.schema.json",
        "license_list": schema_dir / "spdx-licenses-3.29.0.json",
        "exception_list": schema_dir / "spdx-exceptions-3.29.0.json",
    }
    schemas = {name: load_json(path) for name, path in paths.items()}
    store: dict[str, dict[str, Any]] = {}
    for schema in schemas.values():
        schema_id = schema.get("$id") or schema.get("id")
        if isinstance(schema_id, str):
            store[schema_id] = schema
    # CycloneDX 1.6 uses relative references whose absolute forms are these
    # HTTP identifiers. The explicit store prevents validation from fetching
    # mutable network content after the schema bundle has been hash-verified.
    def deny_network(uri: str) -> Any:
        raise VerificationError(f"official schema attempted network resolution: {uri}")

    resolver = jsonschema.RefResolver.from_schema(
        schemas["cyclonedx"],
        store=store,
        handlers={"http": deny_network, "https": deny_network},
    )
    for name, document in (("cyclonedx-sbom", cyclone), ("cyclonedx-vex", vex)):
        errors = sorted(
            jsonschema.Draft7Validator(
                schemas["cyclonedx"],
                resolver=resolver,
                format_checker=jsonschema.Draft7Validator.FORMAT_CHECKER,
            ).iter_errors(document),
            key=lambda error: list(error.path),
        )
        if errors:
            first = errors[0]
            location = "/".join(str(item) for item in first.absolute_path) or "<root>"
            raise VerificationError(
                f"official {name} schema failure at {location}: {first.message}"
            )
    spdx_errors = sorted(
        jsonschema.Draft7Validator(
            schemas["spdx"],
            format_checker=jsonschema.Draft7Validator.FORMAT_CHECKER,
        ).iter_errors(spdx),
        key=lambda error: list(error.path),
    )
    if spdx_errors:
        first = spdx_errors[0]
        location = "/".join(str(item) for item in first.absolute_path) or "<root>"
        raise VerificationError(
            f"official SPDX schema failure at {location}: {first.message}"
        )
    license_ids = {
        item.get("licenseId") for item in schemas["license_list"].get("licenses", [])
    }
    exception_ids = {
        item.get("licenseExceptionId")
        for item in schemas["exception_list"].get("exceptions", [])
    }
    if None in license_ids or None in exception_ids or not license_ids or not exception_ids:
        raise VerificationError("pinned SPDX license/exception lists are malformed")
    return license_ids, exception_ids


def validate_license_expression(
    expression: str, license_ids: set[str], exception_ids: set[str]
) -> None:
    tokens: list[str] = []
    position = 0
    token_re = re.compile(r"\s*(\(|\)|AND\b|OR\b|WITH\b|[A-Za-z0-9][A-Za-z0-9.+-]*)")
    while position < len(expression):
        match = token_re.match(expression, position)
        if not match:
            raise VerificationError(f"invalid SPDX license expression: {expression!r}")
        tokens.append(match.group(1))
        position = match.end()
    index = 0

    def parse_factor() -> None:
        nonlocal index
        if index >= len(tokens):
            raise VerificationError(f"incomplete SPDX license expression: {expression!r}")
        token = tokens[index]
        if token == "(":
            index += 1
            parse_expression()
            if index >= len(tokens) or tokens[index] != ")":
                raise VerificationError(
                    f"unbalanced SPDX license expression: {expression!r}"
                )
            index += 1
        elif token in license_ids:
            index += 1
        else:
            raise VerificationError(
                f"unknown SPDX license identifier {token!r} in {expression!r}"
            )
        if index < len(tokens) and tokens[index] == "WITH":
            index += 1
            if index >= len(tokens) or tokens[index] not in exception_ids:
                raise VerificationError(
                    f"unknown SPDX exception in expression: {expression!r}"
                )
            index += 1

    def parse_expression() -> None:
        nonlocal index
        parse_factor()
        while index < len(tokens) and tokens[index] in {"AND", "OR"}:
            index += 1
            parse_factor()

    parse_expression()
    if index != len(tokens):
        raise VerificationError(f"invalid SPDX license expression: {expression!r}")


def validate_license_inventory(
    inventory: dict[str, Any],
    runtime: dict[str, Any],
    license_ids: set[str],
    exception_ids: set[str],
) -> None:
    for component in inventory["components"] + inventory["curl_bundle"]["components"]:
        validate_license_expression(component["license"], license_ids, exception_ids)
    for package in runtime["packages"]:
        validate_license_expression(package["license"], license_ids, exception_ids)


def verify_spdx_external_reference_types(spdx: dict[str, Any]) -> None:
    for package in spdx.get("packages", []):
        for reference in package.get("externalRefs", []):
            if reference.get("referenceCategory") != "OTHER":
                continue
            reference_type = reference.get("referenceType", "")
            if not urllib.parse.urlparse(reference_type).scheme:
                raise VerificationError(
                    f"SPDX OTHER referenceType is not a URI: {reference_type!r}"
                )


def verify_sha256sums(artifact: Path, inventory: dict[str, Any]) -> None:
    sums_path = artifact / "SHA256SUMS"
    try:
        lines = sums_path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise VerificationError(f"cannot read SHA256SUMS: {exc}") from exc
    expected_names = {
        "build-receipt.json",
        "cyclonedx-sbom.json",
        "cyclonedx-vex.json",
        "spdx-sbom.json",
        "provenance.json",
        "source-files.json",
    }
    expected_names.update(
        evidence_output_name(finding)
        for finding in inventory["vulnerabilities"]
        if "evidence_artifact" in finding
    )
    actual_names: set[str] = set()
    for path in artifact.iterdir():
        if path.is_symlink() or not path.is_file():
            raise VerificationError(f"artifact contains non-regular entry: {path.name}")
        actual_names.add(path.name)
    if actual_names != expected_names | {"SHA256SUMS"}:
        raise VerificationError(
            f"artifact file set mismatch: expected {sorted(expected_names | {'SHA256SUMS'})}, "
            f"got {sorted(actual_names)}"
        )
    found: set[str] = set()
    for number, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match:
            raise VerificationError(f"malformed SHA256SUMS line {number}")
        expected, name = match.groups()
        if name in found:
            raise VerificationError(f"duplicate SHA256SUMS entry: {name}")
        path = artifact / name
        if not path.is_file():
            raise VerificationError(f"SHA256SUMS target missing: {name}")
        actual = sha256_file(path)
        if actual != expected:
            raise VerificationError(
                f"artifact digest mismatch for {name}: expected {expected}, got {actual}"
            )
        found.add(name)
    if found != expected_names:
        raise VerificationError(
            f"SHA256SUMS file set mismatch: expected {sorted(expected_names)}, got {sorted(found)}"
        )


def verify_cyclonedx(sbom: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], set[str]]:
    if sbom.get("bomFormat") != "CycloneDX" or sbom.get("specVersion") != "1.6":
        raise VerificationError("CycloneDX SBOM does not declare specVersion 1.6")
    metadata_component = sbom.get("metadata", {}).get("component")
    if not isinstance(metadata_component, dict):
        raise VerificationError("CycloneDX SBOM has no metadata component")
    components: dict[str, dict[str, Any]] = {
        metadata_component.get("bom-ref", ""): metadata_component
    }
    for component in sbom.get("components", []):
        ref = component.get("bom-ref")
        if not isinstance(ref, str) or not ref or ref in components:
            raise VerificationError(f"invalid or duplicate CycloneDX bom-ref: {ref!r}")
        version = component.get("version")
        if not isinstance(version, str) or not version or version.lower() in {
            "unknown", "noassertion"
        }:
            raise VerificationError(f"unknown CycloneDX component version: {ref}")
        if not component.get("hashes"):
            raise VerificationError(f"CycloneDX component lacks a hash: {ref}")
        if not component.get("licenses"):
            raise VerificationError(f"CycloneDX component lacks a license: {ref}")
        components[ref] = component
    dependency_refs: set[str] = set()
    for dependency in sbom.get("dependencies", []):
        ref = dependency.get("ref")
        if ref not in components or ref in dependency_refs:
            raise VerificationError(f"invalid/duplicate dependency ref: {ref!r}")
        dependency_refs.add(ref)
        for child in dependency.get("dependsOn", []):
            if child not in components:
                raise VerificationError(f"dependency target does not exist: {child}")
    if dependency_refs != set(components):
        raise VerificationError("CycloneDX dependency graph does not cover every component")
    purls = {
        component["purl"]
        for component in components.values()
        if isinstance(component.get("purl"), str)
    }
    return components, purls


def verify_vex(
    vex: dict[str, Any], inventory: dict[str, Any], sbom_components: dict[str, dict[str, Any]]
) -> None:
    if vex.get("bomFormat") != "CycloneDX" or vex.get("specVersion") != "1.6":
        raise VerificationError("CycloneDX VEX does not declare specVersion 1.6")
    expected = {item["id"]: item for item in inventory["vulnerabilities"]}
    declared_components = {
        item["id"]: item
        for item in inventory["components"] + inventory["curl_bundle"]["components"]
    }
    vex_components = {
        component.get("bom-ref"): component for component in vex.get("components", [])
    }
    expected_vex_refs = {
        declared_components[item["component"]]["bom_ref"]
        for item in expected.values()
    }
    if (
        len(vex.get("components", [])) != len(vex_components)
        or set(vex_components) != expected_vex_refs
    ):
        raise VerificationError("VEX component set mismatch")
    findings = vex.get("vulnerabilities", [])
    actual_ids = [finding.get("id") for finding in findings]
    if set(actual_ids) != set(expected) or len(actual_ids) != len(set(actual_ids)):
        raise VerificationError(
            f"VEX finding set mismatch: expected {sorted(expected)}, got {sorted(actual_ids)}"
        )
    for finding in findings:
        finding_id = finding["id"]
        expected_finding = expected[finding_id]
        analysis = finding.get("analysis", {})
        if analysis.get("state") != expected_finding["state"]:
            raise VerificationError(f"VEX finding state mismatch: {finding_id}")
        if analysis.get("response") != ["update"]:
            raise VerificationError(f"VEX finding lacks update response: {finding_id}")
        affected = finding.get("affects", [])
        expected_component = declared_components[expected_finding["component"]]
        expected_ref = expected_component["bom_ref"]
        if (
            len(affected) != 1
            or affected[0].get("ref") != expected_ref
            or expected_ref not in sbom_components
            or expected_ref not in vex_components
        ):
            raise VerificationError(f"VEX finding has invalid affected component: {finding_id}")
        ratings = finding.get("ratings", [])
        if len(ratings) != 1:
            raise VerificationError(f"VEX finding has invalid rating count: {finding_id}")
        rating = ratings[0]
        if (
            finding.get("description") != expected_finding["description"]
            or finding.get("source", {}).get("url") != expected_finding["advisory_url"]
            or finding.get("advisories") != [{"url": expected_finding["advisory_url"]}]
            or rating.get("severity") != expected_finding["severity"]
            or rating.get("score") != expected_finding.get("score")
            or rating.get("vector") != expected_finding.get("vector")
            or finding.get("cwes", [])
            != ([expected_finding["cwe"]] if "cwe" in expected_finding else [])
        ):
            raise VerificationError(f"VEX advisory/rating mismatch: {finding_id}")
        if (
            finding.get("source", {}).get("name") != "CVE"
            or rating.get("source", {}).get("name") != "upstream advisory"
            or rating.get("method")
            != ("CVSSv31" if "vector" in expected_finding else None)
        ):
            raise VerificationError(f"VEX rating source/method mismatch: {finding_id}")
        evidence_text = ", ".join(
            f"{key}={inventory['curl_bundle']['manifest_expectations'][key]}"
            for key in expected_finding["evidence_manifest_keys"]
        )
        expected_detail = f"{expected_finding['detail']} Evidence: {evidence_text}"
        if analysis.get("detail") != expected_detail:
            raise VerificationError(f"VEX structured evidence detail mismatch: {finding_id}")
        property_records = finding.get("properties", [])
        properties = {
            item.get("name"): item.get("value")
            for item in property_records
        }
        if len(property_records) != len(properties):
            raise VerificationError(f"VEX duplicate finding property: {finding_id}")
        if (
            properties.get("fastbed:resolution") != expected_finding["resolution"]
            or properties.get("fastbed:fixed-version")
            != expected_finding["fixed_version"]
            or properties.get("fastbed:fixed-commit")
            != expected_finding["fixed_commit"]
        ):
            raise VerificationError(f"VEX fixed commit mismatch: {finding_id}")
        component_property_records = vex_components[expected_ref].get("properties", [])
        component_properties = {
            item.get("name"): item.get("value")
            for item in component_property_records
        }
        if len(component_property_records) != len(component_properties):
            raise VerificationError(f"VEX duplicate component property: {finding_id}")
        vex_component = vex_components[expected_ref]
        if (
            vex_component.get("name") != expected_component["name"]
            or vex_component.get("version") != expected_component["version"]
            or vex_component.get("purl") != expected_component["purl"]
        ):
            raise VerificationError(f"VEX component identity mismatch: {finding_id}")
        pedigree_patches = vex_component.get("pedigree", {}).get("patches", [])
        if expected_finding["resolution"] == "verified-backport":
            patch = next(
                (
                    item for item in inventory["patches"]
                    if item["id"] == expected_finding["patch_id"]
                ),
                None,
            )
            if patch is None:
                raise VerificationError(f"VEX patch is absent: {finding_id}")
            patch_key = f"fastbed:patch-sha256:{patch['id']}"
            if component_properties.get(patch_key) != patch["sha256"]:
                raise VerificationError(f"VEX patch digest mismatch: {finding_id}")
            if (
                component_properties.get(
                    f"fastbed:upstream-patch-sha256:{patch['id']}"
                )
                != patch["upstream_patch_sha256"]
            ):
                raise VerificationError(
                    f"VEX upstream patch digest mismatch: {finding_id}"
                )
            for prerequisite in patch.get("prerequisites", []):
                if (
                    component_properties.get(
                        f"fastbed:prerequisite-commit:{patch['id']}"
                    )
                    != prerequisite["commit"]
                    or component_properties.get(
                        f"fastbed:prerequisite-patch-sha256:{patch['id']}"
                    )
                    != prerequisite["patch_sha256"]
                ):
                    raise VerificationError(
                        f"VEX prerequisite patch evidence mismatch: {finding_id}"
                    )
            matching_pedigree = [
                item
                for item in pedigree_patches
                if item.get("diff", {}).get("url") == patch["upstream_url"]
                and any(
                    issue.get("type") == "security"
                    and issue.get("id") == finding_id
                    for issue in item.get("resolves", [])
                )
            ]
            if len(matching_pedigree) != 1:
                raise VerificationError(f"VEX patch pedigree mismatch: {finding_id}")
        elif pedigree_patches:
            raise VerificationError(
                f"upstream-version VEX finding has local patch pedigree: {finding_id}"
            )
        evidence_artifact = expected_finding.get("evidence_artifact")
        if evidence_artifact:
            if (
                properties.get("fastbed:evidence-artifact")
                != evidence_output_name(expected_finding)
                or properties.get("fastbed:evidence-artifact-sha256")
                != evidence_artifact["sha256"]
            ):
                raise VerificationError(
                    f"VEX behavioral evidence mismatch: {finding_id}"
                )


def verify_spdx(spdx: dict[str, Any], cdx_purls: set[str]) -> None:
    if spdx.get("spdxVersion") != "SPDX-2.3" or spdx.get("dataLicense") != "CC0-1.0":
        raise VerificationError("SPDX document does not declare SPDX-2.3/CC0-1.0")
    packages: dict[str, dict[str, Any]] = {}
    purls: set[str] = set()
    for package in spdx.get("packages", []):
        spdx_id = package.get("SPDXID")
        if not isinstance(spdx_id, str) or spdx_id in packages:
            raise VerificationError(f"invalid or duplicate SPDX package ID: {spdx_id!r}")
        version = package.get("versionInfo")
        if not isinstance(version, str) or not version or version.lower() in {
            "unknown", "noassertion"
        }:
            raise VerificationError(f"unknown SPDX package version: {spdx_id}")
        if not package.get("checksums"):
            raise VerificationError(f"SPDX package lacks checksum: {spdx_id}")
        for external in package.get("externalRefs", []):
            if external.get("referenceType") == "purl":
                purls.add(external.get("referenceLocator", ""))
        packages[spdx_id] = package
    if purls != cdx_purls:
        raise VerificationError("CycloneDX and SPDX purl sets differ")
    valid_ids = set(packages) | {"SPDXRef-DOCUMENT"}
    for relationship in spdx.get("relationships", []):
        if relationship.get("spdxElementId") not in valid_ids:
            raise VerificationError("SPDX relationship has an unknown source")
        if relationship.get("relatedSpdxElement") not in valid_ids:
            raise VerificationError("SPDX relationship has an unknown target")


def expected_spdx_id(component_id: str) -> str:
    return "SPDXRef-" + re.sub(r"[^A-Za-z0-9.-]", "-", component_id)


def apk_sha1(encoded: str) -> str:
    try:
        raw = base64.b64decode(encoded[2:], validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise VerificationError(f"invalid APK checksum: {encoded!r}") from exc
    if not encoded.startswith("Q1") or len(raw) != 20:
        raise VerificationError(f"invalid APK checksum: {encoded!r}")
    return raw.hex()


def runtime_purl(package: dict[str, str], alpine_version: str) -> str:
    name = urllib.parse.quote(package["name"], safe=".-_+")
    version = urllib.parse.quote(package["version"], safe=".-_+")
    qualifiers = urllib.parse.urlencode(
        {
            "arch": package["architecture"],
            "distro": f"alpine-{alpine_version}",
        }
    )
    return f"pkg:apk/alpine/{name}@{version}?{qualifiers}"


def verify_spdx_bindings(
    spdx: dict[str, Any], inventory: dict[str, Any], runtime: dict[str, Any]
) -> None:
    packages = {package["SPDXID"]: package for package in spdx["packages"]}
    product = inventory["product"]
    declared = inventory["components"] + inventory["curl_bundle"]["components"]
    runtime_packages = {item["name"]: item for item in runtime["packages"]}
    runtime_files = {item["path"]: item["sha256"] for item in runtime["files"]}
    expected_ids = {expected_spdx_id(product["id"])}
    expected_ids.update(expected_spdx_id(item["id"]) for item in declared)
    expected_ids.update(expected_spdx_id(f"runtime:{name}") for name in runtime_packages)
    if set(packages) != expected_ids:
        raise VerificationError("SPDX package identity set mismatch")

    def purl_of(package: dict[str, Any]) -> str | None:
        values = [
            item.get("referenceLocator")
            for item in package.get("externalRefs", [])
            if item.get("referenceType") == "purl"
        ]
        return values[0] if len(values) == 1 else None

    def checksum_of(package: dict[str, Any], algorithm: str) -> str | None:
        values = [
            item.get("checksumValue")
            for item in package.get("checksums", [])
            if item.get("algorithm") == algorithm
        ]
        return values[0] if len(values) == 1 else None

    product_package = packages[expected_spdx_id(product["id"])]
    if (
        product_package.get("name") != product["name"]
        or product_package.get("versionInfo") != product["version"]
        or product_package.get("licenseDeclared") != product["license"]
        or product_package.get("licenseConcluded") != product["license"]
        or purl_of(product_package) != product["purl"]
        or checksum_of(product_package, "SHA256")
        != runtime_files["/usr/local/bin/fastbed"]
    ):
        raise VerificationError("SPDX product binding mismatch")
    for expected in declared:
        package = packages[expected_spdx_id(expected["id"])]
        if (
            package.get("name") != expected["name"]
            or package.get("versionInfo") != expected["version"]
            or package.get("licenseDeclared") != expected["license"]
            or package.get("licenseConcluded") != expected["license"]
            or purl_of(package) != expected["purl"]
            or checksum_of(package, "SHA256") != expected["source_sha256"]
        ):
            raise VerificationError(f"SPDX declared component mismatch: {expected['id']}")
    alpine_version = runtime_packages["alpine-release"]["version"].removesuffix("-r0")
    for name, expected in runtime_packages.items():
        package = packages[expected_spdx_id(f"runtime:{name}")]
        if (
            package.get("name") != name
            or package.get("versionInfo") != expected["version"]
            or package.get("licenseDeclared") != expected["license"]
            or package.get("licenseConcluded") != expected["license"]
            or purl_of(package) != runtime_purl(expected, alpine_version)
            or checksum_of(package, "SHA1") != apk_sha1(expected["apk_checksum"])
        ):
            raise VerificationError(f"SPDX runtime package mismatch: {name}")

    expected_relationships = {
        ("SPDXRef-DOCUMENT", "DESCRIBES", expected_spdx_id(product["id"]))
    }
    expected_relationships.update(
        (
            expected_spdx_id(relation["from"]),
            "DEPENDS_ON",
            expected_spdx_id(relation["to"]),
        )
        for relation in inventory["relationships"]
    )
    actual_relationships = [
        (
            item.get("spdxElementId"),
            item.get("relationshipType"),
            item.get("relatedSpdxElement"),
        )
        for item in spdx.get("relationships", [])
    ]
    if (
        len(actual_relationships) != len(set(actual_relationships))
        or set(actual_relationships) != expected_relationships
    ):
        raise VerificationError("SPDX relationship graph mismatch")


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n"
    ).encode("utf-8")


def verify_prefix_closure(prefix: Path, metadata_relative: str) -> tuple[dict[str, str], str]:
    prefix = prefix.resolve(strict=True)
    sums_path = prefix / metadata_relative / "SHA256SUMS"
    sums: dict[str, str] = {}
    ordered: list[str] = []
    aggregate = hashlib.sha256()
    for number, line in enumerate(sums_path.read_text(encoding="ascii").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise VerificationError(f"malformed curl SHA256SUMS line {number}")
        expected, relative = match.groups()
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or relative in sums:
            raise VerificationError(f"unsafe curl checksum path: {relative}")
        path = prefix / Path(*pure.parts)
        if path.is_symlink() or not path.is_file() or sha256_file(path) != expected:
            raise VerificationError(f"curl prefix checksum mismatch: {relative}")
        sums[relative] = expected
        ordered.append(relative)
        aggregate.update(relative.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(expected.encode("ascii"))
        aggregate.update(b"\n")
    if ordered != sorted(ordered):
        raise VerificationError("curl SHA256SUMS is not path-sorted")
    sums_relative = sums_path.relative_to(prefix).as_posix()
    actual: set[str] = set()
    for path in prefix.rglob("*"):
        if path.is_symlink():
            raise VerificationError(f"curl prefix contains symlink: {path}")
        if path.is_file() and path.relative_to(prefix).as_posix() != sums_relative:
            actual.add(path.relative_to(prefix).as_posix())
    if set(sums) != actual:
        raise VerificationError("curl checksum closure is incomplete or stale")
    aggregate.update(b"SHA256SUMS\0")
    aggregate.update(sha256_file(sums_path).encode("ascii"))
    return sums, aggregate.hexdigest()


def verify_relink_archive(
    release_root: Path, receipt: dict[str, Any]
) -> str:
    release_root = release_root.resolve(strict=True)
    relink = receipt["lgpl_relink"]
    relative = PurePosixPath(relink["archive_path"])
    if relative.is_absolute() or ".." in relative.parts:
        raise VerificationError("unsafe LGPL relink archive path")
    archive = (release_root / Path(*relative.parts)).resolve(strict=True)
    try:
        archive.relative_to(release_root)
    except ValueError as exc:
        raise VerificationError("LGPL relink archive escapes release root") from exc
    archive_digest = sha256_file(archive)
    if archive_digest != relink["archive_sha256"]:
        raise VerificationError("LGPL relink archive digest mismatch")
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
                    raise VerificationError(
                        f"unsafe LGPL relink member: {member.name}"
                    )
                if member.isdir():
                    continue
                key = PurePosixPath(*pure.parts[1:]).as_posix()
                if not member.isfile() or key in files:
                    raise VerificationError(
                        f"non-regular or duplicate LGPL relink member: {member.name}"
                    )
                stream = handle.extractfile(member)
                if stream is None:
                    raise VerificationError(f"unreadable LGPL relink member: {key}")
                files[key] = stream.read()
    except (tarfile.TarError, OSError) as exc:
        raise VerificationError(f"cannot inspect LGPL relink archive: {exc}") from exc
    if "SHA256SUMS" not in files:
        raise VerificationError("LGPL relink archive lacks SHA256SUMS")
    sums_bytes = files["SHA256SUMS"]
    if sha256_bytes(sums_bytes) != relink["content_sha256s_sha256"]:
        raise VerificationError("LGPL relink checksum-file digest mismatch")
    declared: dict[str, str] = {}
    for number, line in enumerate(sums_bytes.decode("ascii").splitlines(), 1):
        match = re.fullmatch(r"([0-9a-f]{64})  \./(.+)", line)
        if not match:
            raise VerificationError(
                f"malformed LGPL relink SHA256SUMS line {number}"
            )
        expected, name = match.groups()
        pure = PurePosixPath(name)
        if pure.is_absolute() or ".." in pure.parts or name in declared:
            raise VerificationError(f"unsafe LGPL relink checksum path: {name}")
        declared[name] = expected
    if set(declared) != set(files) - {"SHA256SUMS"}:
        raise VerificationError("LGPL relink checksum closure is incomplete")
    for name, expected in declared.items():
        if sha256_bytes(files[name]) != expected:
            raise VerificationError(f"LGPL relink member digest mismatch: {name}")
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
        raise VerificationError("LGPL relink archive lacks required material")
    command = files["ORIGINAL-LINK-COMMAND.txt"].decode("utf-8").strip()
    if (
        command != receipt["link"]["command"]
        or sha256_bytes(command.encode("utf-8")) != relink["link_command_sha256"]
        or sha256_bytes(files["relink-fastbed.sh"])
        != relink["relink_script_sha256"]
    ):
        raise VerificationError("LGPL relink command/script binding mismatch")
    for item in relink["libraries"]:
        name = item["path"]
        if name not in files or sha256_bytes(files[name]) != item["sha256"]:
            raise VerificationError(f"LGPL relink library mismatch: {item['path']}")
    verification = {}
    for line in files["RELINK-VERIFICATION.txt"].decode("ascii").splitlines():
        if "=" not in line:
            raise VerificationError("malformed RELINK-VERIFICATION.txt")
        key, value = line.split("=", 1)
        if not key or not value or key in verification:
            raise VerificationError("malformed RELINK-VERIFICATION.txt")
        verification[key] = value
    if verification != {
        "original_unstripped_sha256": receipt["fastbed"]["unstripped_sha256"],
        "relinked_sha256": receipt["fastbed"]["relinked_sha256"],
        "byte_identical": "true",
    }:
        raise VerificationError("LGPL relink verification mismatch")
    return archive_digest


def verify_build_receipt(
    output_receipt: dict[str, Any],
    output_receipt_path: Path,
    runtime: dict[str, Any],
    inventory: dict[str, Any],
    provenance: dict[str, Any],
    curl_prefix: Path,
    static_deps_prefix: Path,
    release_root: Path,
) -> None:
    runtime_receipt = runtime["build_receipt"]
    if output_receipt != runtime_receipt["document"]:
        raise VerificationError("artifact/runtime build receipt differs")
    receipt_digest = sha256_bytes(canonical_json_bytes(output_receipt))
    files = {item["path"]: item for item in runtime["files"]}
    if (
        sha256_file(output_receipt_path) != receipt_digest
        or runtime_receipt["path"] != RUNTIME_RECEIPT_PATH
        or runtime_receipt["sha256"] != receipt_digest
        or files[RUNTIME_RECEIPT_PATH]["sha256"] != receipt_digest
        or provenance["build_receipt_sha256"] != receipt_digest
    ):
        raise VerificationError("build receipt digest binding mismatch")
    if (
        output_receipt["source"]["tree_sha256"]
        != provenance["source_tree_sha256"]
        or output_receipt["source"]["paths"]
        != inventory["product"]["source_paths"]
        or output_receipt["source_date_epoch"]
        != int(inventory["curl_bundle"]["manifest_expectations"]["source_date_epoch"])
    ):
        raise VerificationError("build receipt source binding mismatch")
    repository_root = Path(__file__).resolve().parent.parent
    if output_receipt["generator_sha256"] != sha256_file(
        repository_root / "tools/create-release-artifacts.sh"
    ):
        raise VerificationError("build receipt generator digest mismatch")
    if (
        output_receipt["fastbed"]["runtime_sha256"]
        != files["/usr/local/bin/fastbed"]["sha256"]
        or output_receipt["fastbed"]["build_id"]
        != files["/usr/local/bin/fastbed"]["build_id"]
        or output_receipt["fastbed"]["unstripped_sha256"]
        != output_receipt["fastbed"]["relinked_sha256"]
    ):
        raise VerificationError("build receipt runtime ELF binding mismatch")
    if output_receipt["target_arch"] != runtime["image_architecture"]:
        raise VerificationError("build receipt architecture mismatch")

    metadata = inventory["curl_bundle"]["metadata_relative_path"]
    sums, aggregate = verify_prefix_closure(curl_prefix, metadata)
    prefix = curl_prefix.resolve(strict=True)
    manifest: dict[str, str] = {}
    for number, line in enumerate(
        (prefix / metadata / "BUILD-MANIFEST.txt")
        .read_text(encoding="utf-8")
        .splitlines(),
        1,
    ):
        if "=" not in line:
            raise VerificationError(f"malformed curl manifest line {number}")
        key, value = line.split("=", 1)
        if (
            not re.fullmatch(r"[a-z][a-z0-9_]*", key)
            or not value
            or key in manifest
        ):
            raise VerificationError(f"malformed curl manifest line {number}")
        manifest[key] = value
    for key, expected in inventory["curl_bundle"]["manifest_expectations"].items():
        if manifest.get(key) != expected:
            raise VerificationError(f"curl manifest inventory mismatch: {key}")
    expected_host = {
        "amd64": "x86_64",
        "arm64": "aarch64",
    }[output_receipt["target_arch"]]
    if (
        manifest.get("target_arch") != output_receipt["target_arch"]
        or manifest.get("host_machine") != expected_host
    ):
        raise VerificationError("curl manifest architecture mismatch")
    for key, relative in {
        "libcurl_sha256": "lib/libcurl-impersonate.a",
        "libnghttp2_sha256": "lib/libnghttp2.a",
        "libssl_sha256": "lib/libssl.a",
        "libcrypto_sha256": "lib/libcrypto.a",
    }.items():
        if manifest.get(key) != sums[relative]:
            raise VerificationError(f"curl manifest library digest mismatch: {key}")

    components_path = prefix / metadata / "COMPONENTS.tsv"
    with components_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        if reader.fieldnames != [
            "component",
            "version_or_revision",
            "source_sha256",
            "license_file",
        ]:
            raise VerificationError("unexpected curl component manifest header")
        component_rows = {row["component"]: row for row in reader}
    declared_rows = {
        item["manifest_name"]: item
        for item in inventory["curl_bundle"]["components"]
    }
    if len(component_rows) != len(declared_rows) or set(component_rows) != set(declared_rows):
        raise VerificationError("curl component identity set mismatch")
    for name, declared in declared_rows.items():
        row = component_rows[name]
        if (
            row.get("version_or_revision") != declared["manifest_version"]
            or row.get("source_sha256") != declared["source_sha256"]
            or row.get("license_file") != declared["license_file"]
            or sums.get(f"{metadata}/licenses/{declared['license_file']}")
            != declared["license_sha256"]
        ):
            raise VerificationError(f"curl component evidence mismatch: {name}")
    for notice in inventory["curl_bundle"]["additional_license_files"]:
        if sums.get(f"{metadata}/licenses/{notice['path']}") != notice["sha256"]:
            raise VerificationError(
                f"curl additional license digest mismatch: {notice['path']}"
            )
    prefix_receipt = output_receipt["curl_prefix"]
    if (
        aggregate != prefix_receipt["checksum_aggregate_sha256"]
        or aggregate != provenance["curl_bundle_sha256"]
        or prefix_receipt["sha256sums_sha256"]
        != sha256_file(prefix / metadata / "SHA256SUMS")
        or prefix_receipt["build_manifest_sha256"]
        != sha256_file(prefix / metadata / "BUILD-MANIFEST.txt")
    ):
        raise VerificationError("build receipt curl-prefix binding mismatch")
    expected_libraries = [
        {"path": path, "sha256": sums[path]} for path in LINKED_CURL_LIBRARIES
    ]
    if prefix_receipt["libraries"] != expected_libraries:
        raise VerificationError("build receipt linked-library set mismatch")

    static_metadata = inventory["static_deps_bundle"]["metadata_relative_path"]
    static_sums, static_aggregate = verify_prefix_closure(
        static_deps_prefix, static_metadata
    )
    static_prefix = static_deps_prefix.resolve(strict=True)
    static_manifest: dict[str, str] = {}
    for number, line in enumerate(
        (static_prefix / static_metadata / "BUILD-MANIFEST.txt")
        .read_text(encoding="utf-8")
        .splitlines(),
        1,
    ):
        if "=" not in line:
            raise VerificationError(
                f"malformed static dependency manifest line {number}")
        key, value = line.split("=", 1)
        if (
            not re.fullmatch(r"[a-z][a-z0-9_]*", key)
            or not value
            or key in static_manifest
        ):
            raise VerificationError(
                f"malformed static dependency manifest line {number}")
        static_manifest[key] = value
    for key, expected in inventory["static_deps_bundle"][
        "manifest_expectations"
    ].items():
        if static_manifest.get(key) != expected:
            raise VerificationError(
                f"static dependency manifest inventory mismatch: {key}")
    if (
        static_manifest.get("target_arch") != output_receipt["target_arch"]
        or static_manifest.get("host_machine") != expected_host
    ):
        raise VerificationError("static dependency manifest architecture mismatch")
    for key, relative in {
        "libmicrohttpd_archive_sha256": "lib/libmicrohttpd.a",
        "libyaml_archive_sha256": "lib/libyaml.a",
    }.items():
        if static_manifest.get(key) != static_sums[relative]:
            raise VerificationError(
                f"static dependency archive digest mismatch: {key}")
    static_receipt = output_receipt["static_deps_prefix"]
    if (
        static_aggregate != static_receipt["checksum_aggregate_sha256"]
        or static_aggregate != provenance["static_deps_bundle_sha256"]
        or static_receipt["sha256sums_sha256"]
        != sha256_file(static_prefix / static_metadata / "SHA256SUMS")
        or static_receipt["build_manifest_sha256"]
        != sha256_file(static_prefix / static_metadata / "BUILD-MANIFEST.txt")
    ):
        raise VerificationError(
            "build receipt static-dependency prefix binding mismatch")
    expected_static_libraries = [
        {"path": path, "sha256": static_sums[path]}
        for path in LINKED_STATIC_DEPS_LIBRARIES
    ]
    if static_receipt["libraries"] != expected_static_libraries:
        raise VerificationError(
            "build receipt static-dependency library set mismatch")
    expected_static_sources = [
        {
            "path": relative,
            "sha256": sha256_file(release_root.resolve(strict=True) / relative),
        }
        for relative in inventory["static_deps_bundle"]["source_archives"]
    ]
    if static_receipt["source_archives"] != expected_static_sources:
        raise VerificationError(
            "build receipt static-dependency source set mismatch")
    command = output_receipt["link"]["command"]
    if (
        output_receipt["link"]["sha256"]
        != sha256_bytes(command.encode("utf-8"))
        or "\n" in command
        or any(command.count("/" + path) != 1 for path in LINKED_CURL_LIBRARIES)
        or any(
            command.count("/" + path) != 1
            for path in LINKED_STATIC_DEPS_LIBRARIES
        )
        or any(name in command for name in FORBIDDEN_HTTP3_LIBRARIES)
    ):
        raise VerificationError("build receipt link command is not exact H2 closure")
    expected_lgpl = [
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
    if output_receipt["lgpl_relink"]["libraries"] != expected_lgpl:
        raise VerificationError("build receipt LGPL library set mismatch")
    expected_sources = []
    release_root = release_root.resolve(strict=True)
    for relative in LGPL_SOURCE_ARCHIVES:
        candidate = release_root / relative
        if candidate.is_symlink():
            raise VerificationError(f"LGPL source archive is a symlink: {relative}")
        path = candidate.resolve(strict=True)
        try:
            path.relative_to(release_root)
        except ValueError as exc:
            raise VerificationError("LGPL source archive escapes release root") from exc
        if not path.is_file():
            raise VerificationError(f"LGPL source archive is absent: {relative}")
        expected_sources.append({"path": relative, "sha256": sha256_file(path)})
    if output_receipt["lgpl_relink"]["source_archives"] != expected_sources:
        raise VerificationError("build receipt LGPL source-archive set mismatch")
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
        raise VerificationError("LGPL source archives differ from component identity")
    mhd_component = next(
        item for item in inventory["components"]
        if item["id"] == "libmicrohttpd"
    )
    if (
        source_by_path["source/static-deps/libmicrohttpd-1.0.10.tar.gz"]
        != mhd_component["source_sha256"]
    ):
        raise VerificationError(
            "libmicrohttpd LGPL source archive differs from component identity")
    archive_digest = verify_relink_archive(release_root, output_receipt)
    if provenance["lgpl_relink_archive_sha256"] != archive_digest:
        raise VerificationError("provenance LGPL relink archive digest mismatch")


def verify_provenance(
    artifact: Path,
    provenance: dict[str, Any],
    runtime_path: Path,
    runtime: dict[str, Any],
    inventory: dict[str, Any],
    inventory_path: Path,
) -> None:
    records = provenance.get("documents", [])
    expected_documents = {
        "cyclonedx-sbom.json": "CycloneDX-1.6",
        "spdx-sbom.json": "SPDX-2.3",
        "cyclonedx-vex.json": "CycloneDX-VEX-1.6",
    }
    record_map = {record.get("path"): record for record in records}
    if len(records) != len(record_map) or {
        path: record.get("format") for path, record in record_map.items()
    } != expected_documents:
        raise VerificationError("provenance document path/format map is invalid")
    for record in records:
        path = artifact / record.get("path", "")
        if not path.is_file() or sha256_file(path) != record.get("sha256"):
            raise VerificationError(f"provenance document digest mismatch: {path.name}")
    expected_evidence = [
        {
            "id": finding["id"],
            "path": evidence_output_name(finding),
            "sha256": finding["evidence_artifact"]["sha256"],
        }
        for finding in inventory["vulnerabilities"]
        if "evidence_artifact" in finding
    ]
    if provenance.get("evidence") != expected_evidence:
        raise VerificationError("provenance VEX evidence records mismatch")
    for record in expected_evidence:
        if sha256_file(artifact / record["path"]) != record["sha256"]:
            raise VerificationError(
                f"portable VEX evidence digest mismatch: {record['path']}"
            )
    if provenance.get("runtime_inventory_sha256") != sha256_file(runtime_path):
        raise VerificationError("provenance runtime inventory digest mismatch")
    tool_dir = Path(__file__).resolve().parent
    if (
        provenance.get("inventory_sha256") != sha256_file(inventory_path)
        or provenance.get("generator_sha256")
        != sha256_file(tool_dir / "generate-sbom-vex.py")
        or provenance.get("verifier_sha256")
        != sha256_file(tool_dir / "verify-sbom-vex.py")
    ):
        raise VerificationError("provenance inventory/tool digest mismatch")
    if provenance.get("image_id") != runtime.get("image_id"):
        raise VerificationError("provenance image ID does not match runtime inventory")
    if (
        provenance.get("release_status") != inventory["release_status"]
        or provenance.get("release_reason") != inventory["release_reason"]
    ):
        raise VerificationError("provenance release block mismatch")
    packages = {item.get("name"): item for item in runtime.get("packages", [])}
    runtime_arch = packages.get("musl", {}).get("architecture")
    expected_target = {"x86_64": "amd64", "aarch64": "arm64"}.get(runtime_arch)
    if (
        expected_target is None
        or runtime.get("image_architecture") != expected_target
        or provenance.get("target_arch") != expected_target
    ):
        raise VerificationError("provenance target architecture mismatch")


def verify_source_files(
    source_files: dict[str, Any],
    source_files_path: Path,
    provenance: dict[str, Any],
    product_component: dict[str, Any],
    runtime: dict[str, Any],
) -> None:
    records = source_files.get("files", [])
    paths = [record.get("path") for record in records]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise VerificationError("source file manifest is unsorted or has duplicate paths")
    aggregate = hashlib.sha256()
    for record in records:
        path, digest = record.get("path"), record.get("sha256")
        if (
            not isinstance(path, str)
            or not path
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise VerificationError("source file manifest contains an invalid record")
        aggregate.update(path.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(digest.encode("ascii"))
        aggregate.update(b"\n")
    tree_digest = aggregate.hexdigest()
    product_properties = property_map(product_component)
    if (
        source_files.get("source_tree_sha256") != tree_digest
        or provenance.get("source_tree_sha256") != tree_digest
        or provenance.get("source_files_sha256") != sha256_file(source_files_path)
        or product_properties.get("fastbed:source-tree-sha256") != tree_digest
        or product_properties.get("fastbed:source-file-aggregate-sha256")
        != tree_digest
    ):
        raise VerificationError("source file/tree digest binding mismatch")
    source_hashes = {
        record["path"]: record["sha256"] for record in records
    }
    embedded = runtime.get("embedded_resources", {})
    document = embedded.get("document")
    if (
        embedded.get("path")
        != "/usr/local/share/fastbed/EMBEDDED-RESOURCES.json"
        or not isinstance(document, dict)
        or document.get("schema") != "fastbed-embedded-resources-v1"
        or document.get("generator_sha256")
        != source_hashes.get("tools/embed-resources.py")
    ):
        raise VerificationError("embedded resource manifest identity mismatch")
    expected = [
        ("index_html", "assets/index.html"),
        ("favicon_ico", "assets/favicon.ico"),
        ("banner_png", "assets/banner.png"),
        (
            "crawler_json",
            "third_party/crawler-user-agents/crawler-user-agents.json",
        ),
    ]
    embedded_records = document.get("resources")
    if not isinstance(embedded_records, list) or len(embedded_records) != 4:
        raise VerificationError("embedded resource manifest set mismatch")
    for record, (name, source_path) in zip(
        embedded_records, expected, strict=True
    ):
        if (
            not isinstance(record, dict)
            or record.get("name") != name
            or record.get("sha256") != source_hashes.get(source_path)
            or not isinstance(record.get("bytes"), int)
            or record["bytes"] <= 0
        ):
            raise VerificationError(
                f"embedded resource source binding mismatch: {source_path}")


def property_map(component: dict[str, Any]) -> dict[str, str]:
    return {
        item.get("name"): item.get("value")
        for item in component.get("properties", [])
        if isinstance(item, dict)
    }


def verify_inventory_bindings(
    components: dict[str, dict[str, Any]],
    cyclone: dict[str, Any],
    inventory: dict[str, Any],
    runtime: dict[str, Any],
) -> None:
    product = inventory["product"]
    declared = inventory["components"] + inventory["curl_bundle"]["components"]
    expected_refs = {product["bom_ref"]}
    expected_refs.update(item["bom_ref"] for item in declared)
    expected_refs.update(f"runtime:{item['name']}" for item in runtime["packages"])
    if set(components) != expected_refs:
        raise VerificationError(
            "CycloneDX component identity set differs from inventory/runtime"
        )
    runtime_files = {item["path"]: item["sha256"] for item in runtime["files"]}
    product_component = components[product["bom_ref"]]
    if (
        product_component.get("name") != product["name"]
        or product_component.get("version") != product["version"]
        or product_component.get("purl") != product["purl"]
        or product_component.get("hashes")
        != [
            {
                "alg": "SHA-256",
                "content": runtime_files["/usr/local/bin/fastbed"],
            }
        ]
    ):
        raise VerificationError("CycloneDX product identity/binary hash mismatch")
    if product["license"] in {"NOASSERTION", "NONE"} and "licenses" in product_component:
        raise VerificationError("CycloneDX product must omit an unknown license")
    for expected in declared:
        actual = components[expected["bom_ref"]]
        properties = property_map(actual)
        if (
            actual.get("name") != expected["name"]
            or actual.get("version") != expected["version"]
            or actual.get("purl") != expected["purl"]
            or properties.get("fastbed:source-archive-sha256")
            != expected["source_sha256"]
            or properties.get("fastbed:security-disposition")
            != expected["security_disposition"]
            or actual.get("hashes")
            != [{"alg": "SHA-256", "content": expected["source_sha256"]}]
            or actual.get("licenses") != [{"expression": expected["license"]}]
        ):
            raise VerificationError(
                f"CycloneDX declared component mismatch: {expected['id']}"
            )
        if expected["id"] in {"libmicrohttpd", "libyaml"} and (
            properties.get("fastbed:linkage") != "static"
        ):
            raise VerificationError(
                f"CycloneDX {expected['id']} linkage mismatch")
    runtime_by_name = {item["name"]: item for item in runtime["packages"]}
    alpine_version = runtime_by_name["alpine-release"]["version"].removesuffix("-r0")
    for name, expected in runtime_by_name.items():
        actual = components[f"runtime:{name}"]
        properties = property_map(actual)
        if (
            actual.get("name") != name
            or actual.get("version") != expected["version"]
            or actual.get("purl") != runtime_purl(expected, alpine_version)
            or actual.get("hashes")
            != [{"alg": "SHA-1", "content": apk_sha1(expected["apk_checksum"])}]
            or actual.get("licenses") != [{"expression": expected["license"]}]
            or properties.get("fastbed:apk-origin") != expected["origin"]
            or properties.get("fastbed:apk-checksum") != expected["apk_checksum"]
            or properties.get("fastbed:security-disposition")
            != "no-named-finding-in-this-vex"
        ):
            raise VerificationError(f"CycloneDX runtime package mismatch: {name}")

    ref_by_id = {product["id"]: product["bom_ref"]}
    ref_by_id.update({item["id"]: item["bom_ref"] for item in declared})
    ref_by_id.update({f"runtime:{name}": f"runtime:{name}" for name in runtime_by_name})
    expected_edges = {
        (ref_by_id[relation["from"]], ref_by_id[relation["to"]])
        for relation in inventory["relationships"]
    }
    actual_edges: set[tuple[str, str]] = set()
    dependency_refs: list[str] = []
    for dependency in cyclone.get("dependencies", []):
        dependency_refs.append(dependency["ref"])
        actual_edges.update(
            (dependency["ref"], target) for target in dependency.get("dependsOn", [])
        )
    if (
        len(dependency_refs) != len(set(dependency_refs))
        or set(dependency_refs) != set(components)
        or actual_edges != expected_edges
    ):
        raise VerificationError("CycloneDX dependency graph mismatch")


def verify_release_block(
    cyclone: dict[str, Any],
    vex: dict[str, Any],
    spdx: dict[str, Any],
    provenance: dict[str, Any],
    inventory: dict[str, Any],
) -> None:
    expected = {
        "fastbed:release-status": inventory["release_status"],
        "fastbed:release-reason": inventory["release_reason"],
    }
    for name, document in (("CycloneDX", cyclone), ("VEX", vex)):
        properties = {
            item.get("name"): item.get("value")
            for item in document.get("metadata", {}).get("properties", [])
        }
        if any(properties.get(key) != value for key, value in expected.items()):
            raise VerificationError(f"{name} release block mismatch")
    if spdx.get("comment") != inventory["release_reason"]:
        raise VerificationError("SPDX release block mismatch")
    cyclone_properties = {
        item.get("name"): item.get("value")
        for item in cyclone.get("metadata", {}).get("properties", [])
    }
    if (
        cyclone_properties.get("fastbed:curl-bundle-sha256")
        != provenance.get("curl_bundle_sha256")
    ):
        raise VerificationError("CycloneDX/provenance curl bundle digest mismatch")
    if (
        cyclone_properties.get("fastbed:static-deps-bundle-sha256")
        != provenance.get("static_deps_bundle_sha256")
    ):
        raise VerificationError(
            "CycloneDX/provenance static dependency bundle digest mismatch")
    if (
        provenance.get("release_status") != inventory["release_status"]
        or provenance.get("release_reason") != inventory["release_reason"]
    ):
        raise VerificationError("provenance release block mismatch")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--runtime-inventory", type=Path, required=True)
    parser.add_argument("--curl-prefix", type=Path, required=True)
    parser.add_argument("--static-deps-prefix", type=Path, required=True)
    parser.add_argument("--release-artifact-root", type=Path, required=True)
    parser.add_argument("--schema-dir", type=Path, required=True)
    parser.add_argument("--official-schema-dir", type=Path, required=True)
    args = parser.parse_args()

    try:
        artifact = args.artifact.resolve(strict=True)
        inventory_path = args.inventory.resolve(strict=True)
        inventory = load_json(inventory_path)
        runtime_path = args.runtime_inventory.resolve(strict=True)
        runtime = load_json(runtime_path)
        provenance = load_json(artifact / "provenance.json")
        source_files_path = artifact / "source-files.json"
        source_files = load_json(source_files_path)
        receipt_path = artifact / "build-receipt.json"
        receipt = load_json(receipt_path)
        validate_schema(
            inventory, args.schema_dir / "supply-chain-inventory.schema.json"
        )
        validate_schema(runtime, args.schema_dir / "runtime-inventory.schema.json")
        validate_schema(receipt, args.schema_dir / "build-receipt.schema.json")
        validate_schema(
            runtime["build_receipt"]["document"],
            args.schema_dir / "build-receipt.schema.json",
        )
        validate_schema(provenance, args.schema_dir / "sbom-output-profile.schema.json")
        validate_schema(source_files, args.schema_dir / "source-files.schema.json")
        verify_sha256sums(artifact, inventory)
        verify_provenance(
            artifact,
            provenance,
            runtime_path,
            runtime,
            inventory,
            inventory_path,
        )
        verify_build_receipt(
            receipt,
            receipt_path,
            runtime,
            inventory,
            provenance,
            args.curl_prefix,
            args.static_deps_prefix,
            args.release_artifact_root,
        )
        cyclone = load_json(artifact / "cyclonedx-sbom.json")
        vex = load_json(artifact / "cyclonedx-vex.json")
        spdx = load_json(artifact / "spdx-sbom.json")
        license_ids, exception_ids = validate_official_documents(
            cyclone,
            vex,
            spdx,
            args.official_schema_dir.resolve(strict=True),
        )
        validate_license_inventory(
            inventory, runtime, license_ids, exception_ids
        )
        components, purls = verify_cyclonedx(cyclone)
        verify_inventory_bindings(components, cyclone, inventory, runtime)
        verify_source_files(
            source_files,
            source_files_path,
            provenance,
            components[inventory["product"]["bom_ref"]],
            runtime,
        )
        verify_vex(vex, inventory, components)
        verify_spdx(spdx, purls)
        verify_spdx_bindings(spdx, inventory, runtime)
        verify_spdx_external_reference_types(spdx)
        verify_release_block(cyclone, vex, spdx, provenance, inventory)
    except (
        KeyError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        VerificationError,
        jsonschema.ValidationError,
    ) as exc:
        print(f"verify-sbom-vex: {exc}", file=sys.stderr)
        return 1
    print("verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

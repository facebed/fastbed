#!/usr/bin/env python3
"""Exhaustive process-level crawler classification contract for Fastbed.

The runner seals the candidate binary and every reference input into the
artifact, enters a loopback-only network namespace, evaluates all cases with
an independently compiled per-pattern PCRE2 oracle, then sends the exact user
agent bytes through Fastbed's real HTTP listener.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback
from typing import Any


SUITE_VERSION = "fastbed-crawler-contract-process-e2e-v1"
VENDOR_NAME = "crawler-user-agents"
VENDOR_VERSION = "1.59.0"
VENDOR_SHA256 = "4e414e18ed3f64b9b8298a9f042c83e1ccf54414d8a742fb1f0ec9441d5170e4"
VENDOR_PATTERN_COUNT = 1498
VENDOR_CHUNK_COUNT = 60
VENDOR_INSTANCE_PATTERN_COUNT = 1453
VENDOR_SYNTHETIC_PATTERN_COUNT = 45
PINNED_PCRE2_VERSION = "10.47"
# crawler-user-agents 1.59.0 implements case_sensitive=False by lowercasing the
# regex source. That turns the uppercase class escape \\S into \\s in these
# three expressions, so their published instances no longer match. Preserve
# that observable compatibility and add a whitespace-only positive witness so
# every compiled pattern is still exercised independently.
LOWERED_ESCAPE_WITNESSES = {
    704: (r"ContextualBot[\s\S]*outcomes\.net", "ContextualBot outcomes.net"),
    710: (r"Current[\s\S]*RSS Reader", "Current RSS Reader"),
    810: (r"Spider[\s\S]*spider\.com", "Spider spider.com"),
}
COMMON_UNFURLERS = (
    "discordbot",
    "facebookexternalhit",
    "facebot",
    "twitterbot",
    "slackbot",
    "telegrambot",
    "whatsapp",
    "linkedinbot",
)
SANITIZER_MARKERS = (
    "ERROR: AddressSanitizer",
    "AddressSanitizer:DEADLYSIGNAL",
    "ERROR: LeakSanitizer",
    "runtime error:",
    "UndefinedBehaviorSanitizer",
    "ThreadSanitizer: data race",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def write_new(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(data)


def copy_new(source: Path, destination: Path, executable: bool = False) -> str:
    before = sha256_file(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as input_stream, destination.open("xb") as output_stream:
        shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
    after = sha256_file(source)
    copied = sha256_file(destination)
    if before != after or before != copied:
        raise RuntimeError(f"input changed while sealing: {source}")
    if executable:
        destination.chmod(0o755)
    return copied


def assertion(name: str, passed: bool,
              expected: object, observed: object) -> dict[str, Any]:
    return {
        "name": name,
        "passed": bool(passed),
        "expected": expected,
        "observed": observed,
    }


def ascii_swapcase(data: bytes) -> bytes:
    output = bytearray(data)
    for index, value in enumerate(output):
        if ord("a") <= value <= ord("z"):
            output[index] = value - (ord("a") - ord("A"))
        elif ord("A") <= value <= ord("Z"):
            output[index] = value + (ord("a") - ord("A"))
    return bytes(output)


def literal_witness(pattern: str) -> str:
    """Derive a witness only for the known literal no-instance entries."""
    output: list[str] = []
    index = 0
    regex_meta = set(".*+?[]{}|^$")
    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            if index + 1 >= len(pattern):
                raise ValueError(f"trailing escape in no-instance pattern {pattern!r}")
            output.append(pattern[index + 1])
            index += 2
            continue
        if character in regex_meta:
            raise ValueError(
                f"no safe literal witness for no-instance pattern {pattern!r}")
        output.append(character)
        index += 1
    witness = "".join(output)
    # HTTP parsers remove optional whitespace at the end of a field value.
    # Keep a regex-significant trailing space internal to the User-Agent.
    if witness.endswith((" ", "\t")):
        witness += "contract"
    return witness


def add_case(cases: list[dict[str, Any]], case_id: str, group: str,
             user_agent: bytes, *, header_mode: str = "value",
             target_pattern_index: int | None = None,
             instance_source: str | None = None,
             expected_oracle: bool | None = None,
             allow_http_reject: bool = False) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", case_id):
        raise ValueError(f"unsafe case id: {case_id}")
    if header_mode not in {"value", "empty", "missing"}:
        raise ValueError(f"invalid header mode: {header_mode}")
    if header_mode == "value" and not user_agent:
        raise ValueError(f"value case has an empty user agent: {case_id}")
    if header_mode != "value" and user_agent:
        raise ValueError(f"headerless case has user-agent bytes: {case_id}")
    if any(value in user_agent for value in (b"\0", b"\r", b"\n")):
        raise ValueError(f"unsafe HTTP header bytes in {case_id}")
    cases.append({
        "id": case_id,
        "group": group,
        "user_agent": user_agent,
        "header_mode": header_mode,
        "target_pattern_index": target_pattern_index,
        "instance_source": instance_source,
        "expected_oracle": expected_oracle,
        "allow_http_reject": allow_http_reject,
    })


def make_cases(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    published = 0
    synthetic = 0
    for index, entry in enumerate(entries):
        pattern = entry["pattern"]
        instances = entry.get("instances")
        if isinstance(instances, list) and instances:
            published_text = instances[0]
            witness_text = published_text
            source = "vendor-instance-0"
            published += 1
        else:
            published_text = None
            witness_text = literal_witness(pattern)
            source = "literal-witness-no-published-instance"
            synthetic += 1
        lowered_override = LOWERED_ESCAPE_WITNESSES.get(index)
        if lowered_override is not None:
            expected_pattern, witness_text = lowered_override
            if pattern != expected_pattern or published_text is None:
                raise ValueError(
                    f"lowered-escape witness metadata drift at pattern {index}")
        if not isinstance(witness_text, str):
            raise ValueError(f"pattern {index} witness is not a string")
        witness = witness_text.encode("utf-8")
        if lowered_override is not None:
            add_case(
                cases, f"pattern-{index:04d}-published-instance",
                "vendor-published-known-nonmatch",
                published_text.encode("utf-8"),
                instance_source="vendor-instance-0-lowercase-class-escape-nonmatch",
                expected_oracle=False,
            )
        add_case(
            cases, f"pattern-{index:04d}-representative",
            ("compatibility-target-witness" if lowered_override is not None
             else "vendor-representative"),
            witness, target_pattern_index=index,
            instance_source=(
                "lowered-uppercase-class-escape-whitespace-witness"
                if lowered_override is not None else source),
            expected_oracle=True,
        )
        if isinstance(instances, list) and lowered_override is None:
            for instance_index, additional_text in enumerate(instances[1:], 1):
                if not isinstance(additional_text, str):
                    raise ValueError(
                        f"pattern {index} instance {instance_index} is not a string")
                add_case(
                    cases,
                    f"pattern-{index:04d}-instance-{instance_index:03d}",
                    "vendor-additional-instance",
                    additional_text.encode("utf-8"),
                    target_pattern_index=index,
                    instance_source=f"vendor-instance-{instance_index}",
                    expected_oracle=True,
                )
        add_case(
            cases, f"pattern-{index:04d}-casefold",
            "vendor-casefold", ascii_swapcase(witness),
            target_pattern_index=index, instance_source=source,
            expected_oracle=True,
        )
    if published != VENDOR_INSTANCE_PATTERN_COUNT:
        raise ValueError(
            f"published-instance count {published} != {VENDOR_INSTANCE_PATTERN_COUNT}")
    if synthetic != VENDOR_SYNTHETIC_PATTERN_COUNT:
        raise ValueError(
            f"synthetic-witness count {synthetic} != {VENDOR_SYNTHETIC_PATTERN_COUNT}")

    near_miss = {
        "discordbot": "discordbo",
        "facebookexternalhit": "facebookexternalhi",
        "facebot": "facebo",
        "twitterbot": "twitterbo",
        "slackbot": "slackbo",
        "telegrambot": "telegrambo",
        "whatsapp": "whatsap",
        "linkedinbot": "linkedinbo",
    }
    for token in COMMON_UNFURLERS:
        add_case(cases, f"unfurler-{token}-exact", "common-unfurler",
                 token.encode("ascii"), expected_oracle=True)
        add_case(cases, f"unfurler-{token}-upper", "common-unfurler-casefold",
                 token.upper().encode("ascii"), expected_oracle=True)
        add_case(cases, f"unfurler-{token}-noisy", "common-unfurler-boundary",
                 f"Mozilla/5.0 compatible {token}/contract".encode("ascii"),
                 expected_oracle=True)
        add_case(cases, f"near-miss-{token}", "deterministic-near-miss",
                 near_miss[token].encode("ascii"), expected_oracle=False)

    strict_negatives = (
        ("chrome", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"),
        ("firefox", "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:142.0) "
                    "Gecko/20100101 Firefox/142.0"),
        ("safari", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                   "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 "
                   "Safari/605.1.15"),
        ("botanical", "botanical-browser/1.0"),
        ("robotics", "robotics-lab/1.0"),
        ("spiderplant", "spiderplant/1.0"),
        ("crawlerless", "crawlerless/1.0"),
        ("discord-hyphen", "discord-bot/1.0"),
    )
    for label, value in strict_negatives:
        add_case(cases, f"ordinary-{label}", "deterministic-near-miss",
                 value.encode("ascii"), expected_oracle=False)
    add_case(cases, "missing-user-agent", "header-boundary", b"",
             header_mode="missing", expected_oracle=False)
    add_case(cases, "empty-user-agent", "header-boundary", b"",
             header_mode="empty", expected_oracle=False)
    add_case(cases, "invalid-utf8-prefix-positive", "invalid-utf-boundary",
             b"\xffDISCORDBOT", expected_oracle=True)
    add_case(cases, "invalid-utf8-suffix-positive", "invalid-utf-boundary",
             b"DISCORDBOT\xff", expected_oracle=True)
    add_case(cases, "invalid-utf8-near-miss", "invalid-utf-boundary",
             b"\xffdiscordbo\xfe", expected_oracle=False)

    for length in (511, 512, 513, 4096, 16384, 30000, 48000):
        allow_reject = length >= 30000
        negative = b"z" * length
        token = b"DISCORDBOT"
        positive = b"z" * (length - len(token)) + token
        add_case(cases, f"oversize-{length:05d}-negative",
                 "resource-boundary", negative, expected_oracle=False,
                 allow_http_reject=allow_reject)
        add_case(cases, f"oversize-{length:05d}-positive",
                 "resource-boundary", positive, expected_oracle=True,
                 allow_http_reject=allow_reject)
    return cases


def validate_vendor(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    digest = sha256_file(path)
    if digest != VENDOR_SHA256:
        raise RuntimeError(
            f"vendor SHA-256 mismatch: {digest} != {VENDOR_SHA256}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"cannot parse vendor database: {exc}") from exc
    if not isinstance(data, list) or len(data) != VENDOR_PATTERN_COUNT:
        raise RuntimeError(
            f"vendor pattern count mismatch: "
            f"{len(data) if isinstance(data, list) else 'not-an-array'}")
    for index, entry in enumerate(data):
        if not isinstance(entry, dict) or not isinstance(entry.get("pattern"), str):
            raise RuntimeError(f"vendor entry {index} has no string pattern")
        instances = entry.get("instances")
        if instances is not None and (
                not isinstance(instances, list) or
                any(not isinstance(value, str) for value in instances)):
            raise RuntimeError(f"vendor entry {index} has invalid instances")
    with_instances = sum(bool(entry.get("instances")) for entry in data)
    total_instances = sum(len(entry.get("instances") or []) for entry in data)
    metadata = {
        "name": VENDOR_NAME,
        "version": VENDOR_VERSION,
        "sha256": digest,
        "pattern_count": len(data),
        "expected_chunk_count": VENDOR_CHUNK_COUNT,
        "patterns_with_instances": with_instances,
        "patterns_without_instances": len(data) - with_instances,
        "total_instances": total_instances,
    }
    if (with_instances != VENDOR_INSTANCE_PATTERN_COUNT or
            len(data) - with_instances != VENDOR_SYNTHETIC_PATTERN_COUNT):
        raise RuntimeError(f"vendor instance coverage mismatch: {metadata}")
    return data, metadata


def raw_request(target: bytes, user_agent: bytes, header_mode: str) -> bytes:
    lines = [
        b"GET " + target + b" HTTP/1.1",
        b"Host: 127.0.0.1",
    ]
    if header_mode == "value":
        lines.append(b"User-Agent: " + user_agent)
    elif header_mode == "empty":
        lines.append(b"User-Agent:")
    lines.extend((b"Accept: */*", b"Connection: close"))
    return b"\r\n".join(lines) + b"\r\n\r\n"


def parse_response(raw: bytes) -> tuple[int | None, dict[str, str], bytes]:
    split = raw.find(b"\r\n\r\n")
    if split < 0:
        return None, {}, b""
    head = raw[:split].split(b"\r\n")
    try:
        status = int(head[0].split(b" ", 2)[1])
    except (IndexError, ValueError):
        return None, {}, raw[split + 4:]
    headers: dict[str, str] = {}
    for line in head[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        key = name.decode("ascii", "replace").lower()
        decoded = value.strip().decode("latin-1")
        headers[key] = decoded if key not in headers else headers[key] + ", " + decoded
    return status, headers, raw[split + 4:]


def exchange_raw(port: int, request: bytes,
                 timeout: float = 15.0,
                 receive_limit: int = 2 * 1024 * 1024) -> tuple[bytes, str | None]:
    result = bytearray()
    transport_error: str | None = None
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as client:
            client.settimeout(timeout)
            try:
                client.sendall(request)
                client.shutdown(socket.SHUT_WR)
            except OSError as exc:
                transport_error = f"send:{type(exc).__name__}:{exc}"
            while len(result) < receive_limit:
                try:
                    chunk = client.recv(min(65536, receive_limit - len(result)))
                except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError) as exc:
                    if transport_error is None:
                        transport_error = f"receive:{type(exc).__name__}:{exc}"
                    break
                if not chunk:
                    break
                result.extend(chunk)
                header_end = result.find(b"\r\n\r\n")
                if header_end >= 0:
                    header = bytes(result[:header_end]).lower()
                    match = re.search(
                        br"\r\ncontent-length:\s*([0-9]+)\s*\r\n",
                        b"\r\n" + header + b"\r\n")
                    if match is not None:
                        expected = header_end + 4 + int(match.group(1))
                        if len(result) >= expected:
                            break
    except OSError as exc:
        transport_error = f"connect:{type(exc).__name__}:{exc}"
    return bytes(result), transport_error


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_health(port: int, process: subprocess.Popen[bytes],
                timeout: float = 20.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last = "no response"
    request = raw_request(b"/healthz", b"crawler-contract-health/1.0", "value")
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"Fastbed exited during readiness: {process.returncode}")
        raw, error = exchange_raw(port, request, timeout=1.0)
        status, _headers, body = parse_response(raw)
        if status == 200:
            try:
                payload = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                last = str(exc)
            else:
                if payload.get("status") == "ok":
                    return payload
                last = repr(payload)
        else:
            last = error or f"HTTP {status}"
        time.sleep(0.05)
    raise RuntimeError(f"Fastbed was not healthy: {last}")


def health_once(port: int) -> dict[str, Any]:
    raw, error = exchange_raw(
        port, raw_request(b"/healthz", b"crawler-contract-health/1.0", "value"),
        timeout=3.0)
    status, _headers, body = parse_response(raw)
    if status != 200:
        raise RuntimeError(error or f"health returned HTTP {status}")
    payload = json.loads(body)
    if payload.get("status") != "ok":
        raise RuntimeError(f"invalid health response: {payload}")
    return payload


def terminate(process: subprocess.Popen[bytes] | None,
              timeout: float = 35.0) -> int | None:
    if process is None:
        return None
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5.0)
    return process.returncode


def facebed_url_attribute(value: str) -> str:
    replacements = {
        "<": "%3C", ">": "%3E", '"': "%22", "'": "%27",
        "#": "%23", "%": "%25", "{": "%7B", "}": "%7D",
        "[": "%5B", "]": "%5D", "|": "%7C", "\\": "%5C",
        "^": "%5E", "`": "%60", "&": "&amp;",
    }
    return "".join(replacements.get(character, character) for character in value)


def fallback_body(original_url: str) -> bytes:
    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"\">\n"
        "    <head>\n"
        "        <meta charset=\"UTF-8\" />\n"
        "        <meta name=\"theme-color\" content=\"#2c3048f\" />\n"
        "        <meta property=\"og:title\" content=\"Log in or sign up to view\"/>\n"
        "        <meta property=\"og:description\" content=\"See posts, photos and more on Facebook.\"/>\n"
        "        <meta http-equiv=\"refresh\" content=\"0;url="
        + facebed_url_attribute(original_url)
        + "\"/>\n"
        "    </head>\n"
        "</html>"
    ).encode("utf-8")


def browser_redirect_body(location: str) -> bytes:
    json_url = json.dumps(location, ensure_ascii=True, separators=(",", ":"))
    return (
        "<!DOCTYPE HTML>\n"
        "<html lang=\"en-US\">\n"
        "    <head>\n"
        "        <meta charset=\"UTF-8\">\n"
        "        <meta http-equiv=\"refresh\" content=\"0; url="
        + facebed_url_attribute(location)
        + "\">\n"
        "        <script type=\"text/javascript\">\n"
        "            window.location.href = " + json_url + "\n"
        "        </script>\n"
        "        <title>\n"
        "            redirecting...\n"
        "        </title>\n"
        "    </head>\n"
        "    <body></body>\n"
        "</html>"
    ).encode("utf-8")


def command_output(command: list[str]) -> str:
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {shlex.join(command)}\n"
            + result.stdout.decode("utf-8", "replace"))
    return result.stdout.decode("utf-8", "replace").strip()


def shared_objects(binary: Path, log_path: Path) -> list[dict[str, Any]]:
    output = command_output(["ldd", str(binary)])
    write_new(log_path, (output + "\n").encode("utf-8"))
    paths: set[Path] = set()
    for line in output.splitlines():
        match = re.search(r"=>\s+(/[^ ]+)", line)
        if match is None:
            match = re.match(r"\s*(/[^ ]+)", line)
        if match is not None:
            path = Path(match.group(1))
            if path.is_file():
                paths.add(path.resolve())
    return [
        {"path": str(path), "sha256": sha256_file(path), "bytes": path.stat().st_size}
        for path in sorted(paths)
    ]


def pcre2_shared_hash(objects: list[dict[str, Any]]) -> str | None:
    matches = [entry["sha256"] for entry in objects
               if "libpcre2-8" in Path(entry["path"]).name]
    if len(matches) > 1:
        raise RuntimeError(f"multiple PCRE2 runtime libraries found: {matches}")
    return matches[0] if matches else None


def compile_oracle(oracle_dir: Path, runtime: Path) -> tuple[Path, dict[str, Any]]:
    pcre2_version = command_output(["pcre2-config", "--version"])
    if pcre2_version != PINNED_PCRE2_VERSION:
        raise RuntimeError(
            f"PCRE2 version {pcre2_version!r} != pinned {PINNED_PCRE2_VERSION!r}")
    pkg_flags = shlex.split(command_output(
        ["pkg-config", "--cflags", "--libs", "libpcre2-8"]))
    pcre2_include_dir = Path(command_output(
        ["pkg-config", "--variable=includedir", "libpcre2-8"]))
    pcre2_header = pcre2_include_dir / "pcre2.h"
    if not pcre2_header.is_file():
        raise RuntimeError(f"PCRE2 header not found: {pcre2_header}")
    compiler = shutil.which(os.environ.get("CC", "cc"))
    if compiler is None:
        raise RuntimeError("C compiler not found")
    binary = runtime / "crawler-pcre2-oracle"
    command = [
        compiler, "-std=c17", "-O2", "-fno-lto",
        "-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wshadow",
        "-I", str(oracle_dir),
        str(oracle_dir / "crawler_pcre2_oracle.c"),
        str(oracle_dir / "yyjson.c"),
        *pkg_flags,
        "-o", str(binary),
    ]
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    write_new(runtime / "oracle-build.log", result.stdout)
    write_new(runtime / "oracle-build-command.json", canonical_json(command))
    if result.returncode != 0:
        raise RuntimeError(
            f"oracle build failed ({result.returncode}); see oracle-build.log")
    binary.chmod(0o755)
    compiler_version = command_output([compiler, "--version"]).splitlines()[0]
    return binary, {
        "compiler": compiler,
        "compiler_version": compiler_version,
        "command": command,
        "pcre2_config_version": pcre2_version,
        "pcre2_header": str(pcre2_header.resolve()),
        "pcre2_header_sha256": sha256_file(pcre2_header),
        "binary_sha256": sha256_file(binary),
        "binary_bytes": binary.stat().st_size,
    }


def run_oracle(binary: Path, vendor: Path, cases_tsv: Path,
               output: Path, metadata: Path, log_path: Path) -> None:
    result = subprocess.run(
        [str(binary), str(vendor), str(cases_tsv), str(output), str(metadata)],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    write_new(log_path, result.stdout)
    if result.returncode != 0:
        raise RuntimeError(
            f"reference oracle failed ({result.returncode}); see {log_path.name}")


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"invalid JSONL {path}:{line_number}: {exc}") from exc
            if not isinstance(row, dict):
                raise RuntimeError(f"non-object JSONL row {path}:{line_number}")
            rows.append(row)
    return rows


def enter_network_namespace(args: argparse.Namespace) -> None:
    if args.inside_netns:
        result = subprocess.run(
            ["ip", "link", "set", "lo", "up"], check=False,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode != 0:
            raise RuntimeError(
                "cannot enable loopback in isolated namespace: "
                + result.stdout.decode("utf-8", "replace"))
        interfaces = sorted(name for _index, name in socket.if_nameindex())
        current = os.readlink("/proc/self/ns/net")
        if interfaces != ["lo"] or current == args.parent_netns:
            raise RuntimeError(
                f"network isolation failed: interfaces={interfaces} "
                f"namespace={current}")
        return
    unshare = shutil.which("unshare")
    if unshare is None:
        raise RuntimeError("unshare is required for loopback-only execution")
    parent = os.readlink("/proc/self/ns/net")
    command = [
        unshare, "--user", "--map-root-user", "--net", "--",
        sys.executable, str(Path(__file__).resolve()), *sys.argv[1:],
        "--inside-netns", "--parent-netns", parent,
    ]
    os.execv(unshare, command)


def write_sha256s(output: Path) -> None:
    checksum_path = output / "SHA256SUMS"
    lines: list[str] = []
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path == checksum_path:
            continue
        relative = path.relative_to(output).as_posix()
        lines.append(f"{sha256_file(path)}  {relative}\n")
    checksum_path.write_text("".join(lines), encoding="utf-8")
    for line in lines:
        expected, relative = line.rstrip("\n").split("  ", 1)
        observed = sha256_file(output / relative)
        if observed != expected:
            raise RuntimeError(f"artifact checksum verification failed: {relative}")


def validate_http_case(case: dict[str, Any], oracle: dict[str, Any],
                       status: int | None, headers: dict[str, str], body: bytes,
                       transport_error: str | None) -> tuple[list[dict[str, Any]], bool | None]:
    checks: list[dict[str, Any]] = []
    oracle_bot = bool(oracle["is_crawler"])
    rejected = status is None or (status is not None and 400 <= status <= 499)
    if rejected and case["allow_http_reject"]:
        checks.append(assertion(
            "resource-bound-http-outcome", True,
            "oracle classification or explicit HTTP rejection",
            status if status is not None else transport_error or "connection-close"))
        return checks, None
    checks.append(assertion(
        "transport-complete", transport_error is None,
        None, transport_error))
    expected_status = 200 if oracle_bot else 302
    checks.append(assertion("classification-status", status == expected_status,
                            expected_status, status))
    expected_content_type = "text/html; charset=UTF-8"
    checks.append(assertion(
        "content-type", headers.get("content-type") == expected_content_type,
        expected_content_type, headers.get("content-type")))
    checks.append(assertion(
        "cache-control", headers.get("cache-control") == "no-store",
        "no-store", headers.get("cache-control")))
    checks.append(assertion(
        "vary-user-agent", headers.get("vary") == "User-Agent",
        "User-Agent", headers.get("vary")))
    target = f"/__crawler_contract__/{case['id']}"
    facebook_url = "https://www.facebook.com" + target
    if oracle_bot:
        expected_body = fallback_body(facebook_url)
        checks.append(assertion("no-location", "location" not in headers,
                                "absent", headers.get("location")))
    else:
        expected_body = browser_redirect_body(facebook_url)
        checks.append(assertion(
            "location", headers.get("location") == facebook_url,
            facebook_url, headers.get("location")))
    checks.append(assertion(
        "exact-body", body == expected_body,
        sha256_bytes(expected_body), sha256_bytes(body)))
    observed_bot = True if status == 200 else False if status == 302 else None
    checks.append(assertion(
        "oracle-classification", observed_bot == oracle_bot,
        oracle_bot, observed_bot))
    return checks, observed_bot


def run(args: argparse.Namespace) -> int:
    enter_network_namespace(args)
    source_root = Path(__file__).resolve().parent.parent
    binary_source = args.binary.resolve()
    vendor_source = (args.vendor.resolve() if args.vendor is not None
                     else source_root / "third_party/crawler-user-agents/crawler-user-agents.json")
    assets_source = (args.assets.resolve() if args.assets is not None
                     else source_root / "assets")
    oracle_source = (args.oracle_source.resolve() if args.oracle_source is not None
                     else Path(__file__).with_name("crawler_pcre2_oracle.c"))
    audit_source = (args.audit_doc.resolve() if args.audit_doc is not None
                    else Path(__file__).with_name("CRAWLER_CONTRACT_E2E.md"))
    yyjson_source = (args.yyjson_dir.resolve() if args.yyjson_dir is not None
                     else source_root / "third_party/yyjson")
    output = args.output.resolve()
    if output.exists():
        raise RuntimeError(f"output already exists: {output}")
    if not binary_source.is_file() or not os.access(binary_source, os.X_OK):
        raise RuntimeError(f"Fastbed binary is not executable: {binary_source}")
    for required in (
        vendor_source, oracle_source, audit_source, yyjson_source / "yyjson.c",
        yyjson_source / "yyjson.h", assets_source / "index.html",
        assets_source / "banner.png", assets_source / "favicon.ico",
    ):
        if not required.is_file():
            raise RuntimeError(f"required input is missing: {required}")
    output.mkdir(parents=True)
    started = datetime.now(timezone.utc)
    failures: list[str] = []
    results: list[dict[str, Any]] = []
    fastbed: subprocess.Popen[bytes] | None = None
    fastbed_log_stream = None
    fastbed_exit: int | None = None
    process_start_error: str | None = None
    input_fingerprint = ""
    binary_sha = ""
    vendor_metadata: dict[str, Any] = {}
    oracle_metadata: dict[str, Any] = {}
    oracle_build: dict[str, Any] = {}
    oracle_coverage: dict[str, Any] = {}
    environment_metadata: dict[str, Any] = {}
    cases: list[dict[str, Any]] = []
    oracle_rows: list[dict[str, Any]] = []
    fastbed_port: int | None = None

    try:
        inputs = output / "inputs"
        oracle_inputs = inputs / "oracle"
        runtime = output / "runtime"
        runtime.mkdir(parents=True)
        sealed_binary = inputs / "fastbed"
        binary_sha = copy_new(binary_source, sealed_binary, executable=True)
        if args.expected_binary_sha256 and binary_sha != args.expected_binary_sha256:
            raise RuntimeError(
                f"binary SHA-256 mismatch: {binary_sha} != "
                f"{args.expected_binary_sha256}")
        sealed_vendor = inputs / f"crawler-user-agents-{VENDOR_VERSION}.json"
        copy_new(vendor_source, sealed_vendor)
        sealed_assets = inputs / "assets"
        for name in ("index.html", "banner.png", "favicon.ico"):
            copy_new(assets_source / name, sealed_assets / name)
        sealed_oracle_source = oracle_inputs / "crawler_pcre2_oracle.c"
        copy_new(oracle_source, sealed_oracle_source)
        copy_new(yyjson_source / "yyjson.c", oracle_inputs / "yyjson.c")
        copy_new(yyjson_source / "yyjson.h", oracle_inputs / "yyjson.h")
        sealed_runner = inputs / "run_crawler_contract_e2e.py"
        copy_new(Path(__file__).resolve(), sealed_runner, executable=True)
        sealed_audit = inputs / "CRAWLER_CONTRACT_E2E.md"
        copy_new(audit_source, sealed_audit)

        entries, vendor_metadata = validate_vendor(sealed_vendor)
        cases = make_cases(entries)
        raw_request_dir = output / "raw_requests"
        raw_request_dir.mkdir()
        case_manifest: list[dict[str, Any]] = []
        oracle_case_lines: list[str] = []
        seen_ids: set[str] = set()
        for index, case in enumerate(cases):
            if case["id"] in seen_ids:
                raise RuntimeError(f"duplicate case id: {case['id']}")
            seen_ids.add(case["id"])
            target = f"/__crawler_contract__/{case['id']}".encode("ascii")
            request_bytes = raw_request(
                target, case["user_agent"], case["header_mode"])
            request_path = raw_request_dir / f"{index:04d}-{case['id']}.request.bin"
            write_new(request_path, request_bytes)
            case["index"] = index
            case["request_path"] = str(request_path.relative_to(output))
            case["request_sha256"] = sha256_bytes(request_bytes)
            oracle_case_lines.append(
                f"{case['id']}\t{case['user_agent'].hex()}\n")
            case_manifest.append({
                "index": index,
                "id": case["id"],
                "group": case["group"],
                "header_mode": case["header_mode"],
                "user_agent_bytes": len(case["user_agent"]),
                "user_agent_sha256": sha256_bytes(case["user_agent"]),
                "user_agent_hex": case["user_agent"].hex(),
                "target_pattern_index": case["target_pattern_index"],
                "instance_source": case["instance_source"],
                "expected_oracle": case["expected_oracle"],
                "allow_http_reject": case["allow_http_reject"],
                "request_path": case["request_path"],
                "request_bytes": len(request_bytes),
                "request_sha256": case["request_sha256"],
            })
        oracle_cases_path = output / "oracle-cases.tsv"
        write_new(oracle_cases_path, "".join(oracle_case_lines).encode("ascii"))

        asset_hashes = {
            name: sha256_file(sealed_assets / name)
            for name in ("index.html", "banner.png", "favicon.ico")
        }
        deterministic_input = {
            "schema": 1,
            "suite": SUITE_VERSION,
            "vendor": vendor_metadata,
            "pinned_pcre2_version": PINNED_PCRE2_VERSION,
            "candidate_binary_sha256": binary_sha,
            "allow_stock_curl": args.allow_stock_curl,
            "runner_sha256": sha256_file(sealed_runner),
            "audit_doc_sha256": sha256_file(sealed_audit),
            "oracle_source_sha256": sha256_file(sealed_oracle_source),
            "yyjson_source_sha256": sha256_file(oracle_inputs / "yyjson.c"),
            "yyjson_header_sha256": sha256_file(oracle_inputs / "yyjson.h"),
            "asset_sha256": asset_hashes,
            "oracle_cases_sha256": sha256_file(oracle_cases_path),
            "cases": case_manifest,
        }
        input_fingerprint = sha256_bytes(canonical_json(deterministic_input))
        deterministic_input["input_fingerprint"] = input_fingerprint
        write_new(output / "input-manifest.json", canonical_json(deterministic_input))
        if (args.expected_input_fingerprint and
                input_fingerprint != args.expected_input_fingerprint):
            raise RuntimeError(
                f"input fingerprint mismatch: {input_fingerprint} != "
                f"{args.expected_input_fingerprint}")

        oracle_binary, oracle_build = compile_oracle(oracle_inputs, runtime)
        if (args.expected_pcre2_header_sha256 and
                oracle_build["pcre2_header_sha256"] !=
                args.expected_pcre2_header_sha256):
            raise RuntimeError(
                "PCRE2 header SHA-256 mismatch: "
                f"{oracle_build['pcre2_header_sha256']} != "
                f"{args.expected_pcre2_header_sha256}")
        oracle_output = output / "oracle-results.jsonl"
        oracle_metadata_path = output / "oracle-metadata.json"
        run_oracle(
            oracle_binary, sealed_vendor, oracle_cases_path,
            oracle_output, oracle_metadata_path, output / "oracle.log")
        oracle_metadata = json.loads(oracle_metadata_path.read_text(encoding="utf-8"))
        runtime_version = str(oracle_metadata.get("pcre2_runtime_version", ""))
        header_version = str(oracle_metadata.get("pcre2_header_version", ""))
        if header_version != PINNED_PCRE2_VERSION:
            raise RuntimeError(
                f"oracle header PCRE2 is not pinned version: {header_version!r}")
        if not (runtime_version == PINNED_PCRE2_VERSION or
                runtime_version.startswith(PINNED_PCRE2_VERSION + " ")):
            raise RuntimeError(
                f"oracle runtime PCRE2 is not pinned version: {runtime_version!r}")
        if oracle_metadata.get("pattern_count") != VENDOR_PATTERN_COUNT:
            raise RuntimeError(f"oracle pattern count mismatch: {oracle_metadata}")
        if oracle_metadata.get("oracle_error_count") != 0:
            raise RuntimeError(f"oracle reported match errors: {oracle_metadata}")
        oracle_rows = load_jsonl(oracle_output)
        if len(oracle_rows) != len(cases):
            raise RuntimeError(
                f"oracle result coverage {len(oracle_rows)} != {len(cases)}")
        oracle_by_id: dict[str, dict[str, Any]] = {}
        target_coverage: set[int] = set()
        target_casefold_coverage: set[int] = set()
        for case, row in zip(cases, oracle_rows, strict=True):
            if row.get("case_id") != case["id"]:
                raise RuntimeError(
                    f"oracle ordering mismatch: {row.get('case_id')} != {case['id']}")
            if row["case_id"] in oracle_by_id:
                raise RuntimeError(f"duplicate oracle row: {row['case_id']}")
            oracle_by_id[row["case_id"]] = row
            matching = row.get("matching_pattern_indices")
            if (not isinstance(matching, list) or
                    row.get("match_count") != len(matching) or
                    bool(row.get("is_crawler")) != bool(matching)):
                raise RuntimeError(f"invalid oracle result: {row}")
            target = case["target_pattern_index"]
            if target is not None:
                if target not in matching:
                    raise RuntimeError(
                        f"representative {case['id']} does not match target pattern {target}")
                if case["group"] == "vendor-casefold":
                    target_casefold_coverage.add(target)
                else:
                    target_coverage.add(target)
            expected_oracle = case["expected_oracle"]
            if (expected_oracle is not None and
                    bool(row["is_crawler"]) != expected_oracle):
                raise RuntimeError(
                    f"case {case['id']} oracle={row['is_crawler']} expected="
                    f"{expected_oracle}; input contract is invalid")
        if target_coverage != set(range(VENDOR_PATTERN_COUNT)):
            raise RuntimeError("representative target pattern coverage is incomplete")
        if target_casefold_coverage != set(range(VENDOR_PATTERN_COUNT)):
            raise RuntimeError("casefold target pattern coverage is incomplete")
        base_target_rows: list[dict[str, Any]] = []
        for case in cases:
            target = case["target_pattern_index"]
            if target is None or case["group"] not in {
                    "vendor-representative", "compatibility-target-witness"}:
                continue
            row = oracle_by_id[case["id"]]
            base_target_rows.append({
                "case_id": case["id"],
                "target_pattern_index": target,
                "matching_pattern_indices": row["matching_pattern_indices"],
                "unique_to_target": row["matching_pattern_indices"] == [target],
            })
        overlapping_targets = [
            row for row in base_target_rows if not row["unique_to_target"]
        ]
        oracle_coverage = {
            "pattern_count": VENDOR_PATTERN_COUNT,
            "positive_target_witnesses": len(base_target_rows),
            "unique_target_witnesses": len(base_target_rows) - len(overlapping_targets),
            "overlapping_target_witnesses": len(overlapping_targets),
            "max_patterns_matching_one_target_witness": max(
                len(row["matching_pattern_indices"]) for row in base_target_rows),
            "overlapping_targets": overlapping_targets,
        }
        write_new(output / "oracle-coverage.json", canonical_json(oracle_coverage))

        candidate_objects = shared_objects(
            sealed_binary, output / "candidate-ldd.txt")
        oracle_objects = shared_objects(
            oracle_binary, output / "oracle-ldd.txt")
        candidate_pcre2 = pcre2_shared_hash(candidate_objects)
        oracle_pcre2 = pcre2_shared_hash(oracle_objects)
        if candidate_pcre2 is not None and oracle_pcre2 is not None and \
                candidate_pcre2 != oracle_pcre2:
            raise RuntimeError(
                "candidate and oracle resolve different dynamic PCRE2 libraries: "
                f"{candidate_pcre2} != {oracle_pcre2}")
        if (args.expected_pcre2_library_sha256 and
                oracle_pcre2 != args.expected_pcre2_library_sha256):
            raise RuntimeError(
                "PCRE2 runtime library SHA-256 mismatch: "
                f"{oracle_pcre2} != {args.expected_pcre2_library_sha256}")
        environment_metadata = {
            "platform": platform.platform(),
            "python": sys.version,
            "uname": list(os.uname()),
            "network_namespace": os.readlink("/proc/self/ns/net"),
            "interfaces": sorted(name for _index, name in socket.if_nameindex()),
            "candidate_shared_objects": candidate_objects,
            "oracle_shared_objects": oracle_objects,
            "candidate_pcre2_sha256": candidate_pcre2,
            "oracle_pcre2_sha256": oracle_pcre2,
            "oracle_build": oracle_build,
        }
        write_new(output / "environment.json", canonical_json(environment_metadata))

        fastbed_port = reserve_port()
        config = output / "config.yaml"
        write_new(
            config,
            ("host: 127.0.0.1\n"
             f"port: {fastbed_port}\n"
             "timezone: 7\n"
             "banned_users: []\n"
             "notifier_webhook: ''\n").encode("utf-8"))
        environment = dict(os.environ)
        environment["FASTBED_ASSET_DIR"] = str(sealed_assets)
        environment["FASTBED_CRAWLER_DB"] = str(sealed_vendor)
        fastbed_log_stream = (output / "fastbed.log").open("xb")
        fastbed_command = [
            str(sealed_binary), "--config", str(config),
            "--workers", "1",
        ]
        if args.allow_stock_curl:
            fastbed_command.append("--allow-stock-curl")
        write_new(output / "fastbed-command.json", canonical_json(fastbed_command))
        fastbed = subprocess.Popen(fastbed_command, env=environment,
            stdout=fastbed_log_stream,
            stderr=subprocess.STDOUT)
        wait_health(fastbed_port, fastbed)

        result_stream = (output / "case-results.jsonl").open("x", encoding="utf-8")
        try:
            for index, case in enumerate(cases):
                if fastbed.poll() is not None:
                    failures.append(
                        f"fastbed-exited-before-{case['id']}-{fastbed.returncode}")
                    break
                request_path = output / case["request_path"]
                request_bytes = request_path.read_bytes()
                began = time.monotonic()
                raw_response, transport_error = exchange_raw(
                    fastbed_port, request_bytes, timeout=args.case_timeout)
                elapsed = time.monotonic() - began
                status, headers, body = parse_response(raw_response)
                response_path = (output / "raw_responses" /
                                 f"{index:04d}-{case['id']}.response.bin")
                write_new(response_path, raw_response)
                oracle = oracle_by_id[case["id"]]
                checks, observed_classification = validate_http_case(
                    case, oracle, status, headers, body, transport_error)
                checks.append(assertion(
                    "process-running", fastbed.poll() is None,
                    "running", fastbed.poll()))
                health_payload: dict[str, Any] | None = None
                if index % args.health_interval == 0 or \
                        case["allow_http_reject"] or index + 1 == len(cases):
                    try:
                        health_payload = health_once(fastbed_port)
                        checks.append(assertion("process-health", True, "ok", "ok"))
                    except Exception as exc:
                        checks.append(assertion(
                            "process-health", False, "ok",
                            f"{type(exc).__name__}: {exc}"))
                passed = all(check["passed"] for check in checks)
                if not passed:
                    failures.append(case["id"])
                result = {
                    "index": index,
                    "id": case["id"],
                    "group": case["group"],
                    "passed": passed,
                    "elapsed_seconds": round(elapsed, 6),
                    "user_agent_bytes": len(case["user_agent"]),
                    "user_agent_sha256": sha256_bytes(case["user_agent"]),
                    "header_mode": case["header_mode"],
                    "target_pattern_index": case["target_pattern_index"],
                    "instance_source": case["instance_source"],
                    "oracle": oracle,
                    "observed_classification": observed_classification,
                    "status": status,
                    "headers": headers,
                    "body_bytes": len(body),
                    "body_sha256": sha256_bytes(body),
                    "transport_error": transport_error,
                    "request_path": case["request_path"],
                    "request_sha256": case["request_sha256"],
                    "response_path": str(response_path.relative_to(output)),
                    "response_sha256": sha256_bytes(raw_response),
                    "health": health_payload,
                    "assertions": checks,
                }
                results.append(result)
                result_stream.write(
                    json.dumps(result, sort_keys=True, ensure_ascii=True) + "\n")
                result_stream.flush()
        finally:
            result_stream.close()
    except Exception:
        failures.append("harness-error")
        process_start_error = traceback.format_exc()
        (output / "harness-error.txt").write_text(
            process_start_error, encoding="utf-8")
    finally:
        fastbed_exit = terminate(fastbed)
        if fastbed_log_stream is not None:
            fastbed_log_stream.close()

    if fastbed_exit not in {None, 0}:
        failures.append(f"fastbed-exit-{fastbed_exit}")
    sanitizer_findings: list[str] = []
    startup_record: dict[str, Any] | None = None
    fastbed_log = output / "fastbed.log"
    if fastbed_log.exists():
        log_text = fastbed_log.read_text(encoding="utf-8", errors="replace")
        sanitizer_findings = [marker for marker in SANITIZER_MARKERS if marker in log_text]
        if sanitizer_findings:
            failures.append("sanitizer-finding")
        startup_match = re.search(
            r"crawler database patterns=(\d+) chunks=(\d+) jit=(\d+) combined=(\S+)",
            log_text)
        if startup_match is None:
            failures.append("missing-crawler-startup-record")
        else:
            startup_record = {
                "patterns": int(startup_match.group(1)),
                "chunks": int(startup_match.group(2)),
                "jit_chunks": int(startup_match.group(3)),
                "combined": startup_match.group(4),
            }
            if startup_record["patterns"] != VENDOR_PATTERN_COUNT:
                failures.append("wrong-startup-pattern-count")
            if startup_record["chunks"] != VENDOR_CHUNK_COUNT:
                failures.append("wrong-startup-chunk-count")

    if len(results) != len(cases):
        failures.append(f"incomplete-case-run-{len(results)}-of-{len(cases)}")
    groups: dict[str, dict[str, int]] = {}
    for result in results:
        group = groups.setdefault(result["group"], {"passed": 0, "failed": 0})
        group["passed" if result["passed"] else "failed"] += 1
    unique_failures = list(dict.fromkeys(failures))
    strict_classifications = sum(
        result["observed_classification"] is not None for result in results)
    resource_rejections = sum(
        result["observed_classification"] is None for result in results)
    finished = datetime.now(timezone.utc)
    summary = {
        "schema": 1,
        "suite": SUITE_VERSION,
        "success": not unique_failures,
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "input_fingerprint": input_fingerprint,
        "binary_source": str(binary_source),
        "binary_snapshot": "inputs/fastbed",
        "binary_sha256": binary_sha,
        "vendor": vendor_metadata,
        "oracle": {
            "metadata": oracle_metadata,
            "build": oracle_build,
            "coverage": oracle_coverage,
            "results_sha256": (sha256_file(output / "oracle-results.jsonl")
                               if (output / "oracle-results.jsonl").exists() else None),
        },
        "environment": environment_metadata,
        "network_namespace": (os.readlink("/proc/self/ns/net")
                              if Path("/proc/self/ns/net").exists() else None),
        "interfaces": sorted(name for _index, name in socket.if_nameindex()),
        "fastbed_port": fastbed_port,
        "fastbed_exit": fastbed_exit,
        "startup_crawler_record": startup_record,
        "sanitizer_findings": sanitizer_findings,
        "cases_planned": len(cases),
        "cases_completed": len(results),
        "cases_passed": sum(int(result["passed"]) for result in results),
        "cases_failed": sum(int(not result["passed"]) for result in results),
        "strict_classifications_compared": strict_classifications,
        "resource_bound_rejections": resource_rejections,
        "groups": groups,
        "coverage": {
            "vendor_patterns": VENDOR_PATTERN_COUNT,
            "vendor_patterns_with_published_instances": VENDOR_INSTANCE_PATTERN_COUNT,
            "vendor_patterns_with_synthetic_witnesses": VENDOR_SYNTHETIC_PATTERN_COUNT,
            "positive_target_cases": sum(
                case["target_pattern_index"] is not None and
                case["group"] != "vendor-casefold" for case in cases),
            "casefold_target_cases": sum(
                case["group"] == "vendor-casefold" for case in cases),
            "published_instance_known_nonmatches": sum(
                case["group"] == "vendor-published-known-nonmatch"
                for case in cases),
            "oracle_negative_cases": sum(
                case["expected_oracle"] is False for case in cases),
            "deterministic_near_miss_cases": sum(
                case["group"] == "deterministic-near-miss" for case in cases),
            "common_unfurler_cases": sum(
                case["group"].startswith("common-unfurler") for case in cases),
            "resource_boundary_cases": sum(
                case["group"] == "resource-boundary" for case in cases),
        },
        "failures": unique_failures,
        "harness_error": process_start_error is not None,
    }
    (output / "artifact-manifest.json").write_bytes(canonical_json(summary))
    if input_fingerprint and binary_sha and (output / "inputs/fastbed").exists():
        replay_output = output.parent / (output.name + "-replay")
        replay_command = [
            sys.executable,
            str(output / "inputs/run_crawler_contract_e2e.py"),
            str(output / "inputs/fastbed"),
            "--output", str(replay_output),
            "--vendor", str(output / f"inputs/crawler-user-agents-{VENDOR_VERSION}.json"),
            "--assets", str(output / "inputs/assets"),
            "--oracle-source", str(output / "inputs/oracle/crawler_pcre2_oracle.c"),
            "--audit-doc", str(output / "inputs/CRAWLER_CONTRACT_E2E.md"),
            "--yyjson-dir", str(output / "inputs/oracle"),
            "--expected-binary-sha256", binary_sha,
            "--expected-input-fingerprint", input_fingerprint,
            "--expected-pcre2-header-sha256",
            str(oracle_build.get("pcre2_header_sha256", "")),
            "--expected-pcre2-library-sha256",
            str(environment_metadata.get("oracle_pcre2_sha256", "")),
            "--case-timeout", str(args.case_timeout),
            "--health-interval", str(args.health_interval),
        ]
        if args.allow_stock_curl:
            replay_command.append("--allow-stock-curl")
        (output / "REPLAY.txt").write_text(
            shlex.join(replay_command) + "\n", encoding="utf-8")
    write_sha256s(output)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"artifact: {output}")
    if input_fingerprint:
        print(f"input fingerprint: {input_fingerprint}")
    return 0 if summary["success"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--vendor", type=Path)
    parser.add_argument("--assets", type=Path)
    parser.add_argument("--oracle-source", type=Path)
    parser.add_argument("--audit-doc", type=Path)
    parser.add_argument("--yyjson-dir", type=Path)
    parser.add_argument("--expected-input-fingerprint")
    parser.add_argument("--expected-binary-sha256")
    parser.add_argument("--expected-pcre2-header-sha256")
    parser.add_argument("--expected-pcre2-library-sha256")
    parser.add_argument("--case-timeout", type=float, default=15.0)
    parser.add_argument("--health-interval", type=int, default=128)
    parser.add_argument("--allow-stock-curl", action="store_true")
    parser.add_argument("--inside-netns", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--parent-netns", default="", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.case_timeout < 1.0 or args.case_timeout > 120.0:
        parser.error("--case-timeout must be between 1 and 120 seconds")
    if args.health_interval < 1 or args.health_interval > 10000:
        parser.error("--health-interval must be between 1 and 10000")
    try:
        return run(args)
    except Exception as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())

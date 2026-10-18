#!/usr/bin/env python3
"""Run deterministic process-level robustness E2E against a real Fastbed.

The suite re-executes itself in a fresh user/network namespace, brings up only
the loopback interface, starts a programmable saved-fixture broker, and then
drives the Fastbed binary over raw HTTP.  It emits raw requests/responses,
exact oracle bodies, broker events, logs, a manifest, and SHA256SUMS.

Example:
  python3 e2e/run_adversarial_e2e.py build-sanitize/fastbed \
      --output artifacts/adversarial-0x5eed --seed 0x5eed \
      --sanitizers required
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import traceback
from typing import Any
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


GENERATOR_VERSION = "fastbed-adversarial-e2e-v1"
DEFAULT_SEED = 0xF45BED5EED
BOT_UA = "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"
FACEBOOK_HOSTS = {
    "facebook.com", "www.facebook.com", "web.facebook.com",
    "m.facebook.com", "mbasic.facebook.com",
}
SANITIZER_MARKERS = (
    "ERROR: AddressSanitizer",
    "AddressSanitizer:DEADLYSIGNAL",
    "ERROR: LeakSanitizer",
    "runtime error:",
    "UndefinedBehaviorSanitizer",
)


def parse_seed(text: str) -> int:
    value = int(text, 0)
    if value < 0 or value >= 1 << 64:
        raise argparse.ArgumentTypeError("seed must fit in an unsigned 64-bit integer")
    return value


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


def deterministic_bytes(seed: int, label: str, length: int) -> bytes:
    output = bytearray()
    counter = 0
    prefix = seed.to_bytes(8, "big") + label.encode("utf-8") + b"\0"
    while len(output) < length:
        output.extend(hashlib.sha256(prefix + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(output[:length])


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


def html_json(payload: bytes) -> bytes:
    return (b"<!doctype html><html><body><script type=\"application/json\">" +
            payload + b"</script></body></html>")


def raw_request(target: bytes, user_agent: bytes = b"Browser/1.0",
                extra_headers: list[bytes] | None = None) -> bytes:
    headers = [
        b"GET " + target + b" HTTP/1.1",
        b"Host: 127.0.0.1",
        b"User-Agent: " + user_agent,
        b"Accept: */*",
        b"Connection: close",
    ]
    if extra_headers:
        headers.extend(extra_headers)
    return b"\r\n".join(headers) + b"\r\n\r\n"


def reserve_ports(count: int) -> list[int]:
    listeners: list[socket.socket] = []
    try:
        for _index in range(count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listeners.append(listener)
        return [int(listener.getsockname()[1]) for listener in listeners]
    finally:
        for listener in listeners:
            listener.close()


def terminate(process: subprocess.Popen[bytes] | None, timeout: float = 35.0) -> int | None:
    if process is None:
        return None
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    return process.returncode


def control_json(port: int, path: str, payload: object | None = None,
                 timeout: float = 5.0) -> dict[str, Any]:
    url = f"http://127.0.0.1:{port}{path}"
    if payload is None:
        request = Request(url)
    else:
        data = canonical_json(payload)
        request = Request(url, data=data, method="POST",
                          headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def wait_ready(port: int, path: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            control_json(port, path, timeout=1.0)
            return
        except Exception as exc:
            error = exc
        time.sleep(0.05)
    raise RuntimeError(f"service on port {port} was not ready: {error}")


def exchange_raw(port: int, request: bytes, timeout: float = 60.0,
                 receive_limit: int = 16 * 1024 * 1024) -> bytes:
    result = bytearray()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as client:
        client.settimeout(timeout)
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        while len(result) < receive_limit:
            try:
                chunk = client.recv(min(65536, receive_limit - len(result)))
            except (ConnectionResetError, socket.timeout):
                break
            if not chunk:
                break
            result.extend(chunk)
            header_end = result.find(b"\r\n\r\n")
            if header_end >= 0:
                header = bytes(result[:header_end]).lower()
                match = re.search(br"\r\ncontent-length:\s*([0-9]+)\s*\r\n", b"\r\n" + header + b"\r\n")
                if match is not None:
                    expected = header_end + 4 + int(match.group(1))
                    if len(result) >= expected:
                        break
    return bytes(result)


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


def health(port: int) -> dict[str, Any]:
    response = exchange_raw(port, raw_request(b"/healthz"), timeout=3.0)
    status, _headers, body = parse_response(response)
    if status != 200:
        raise RuntimeError(f"health check returned {status}")
    payload = json.loads(body)
    if payload.get("status") != "ok":
        raise RuntimeError(f"invalid health payload: {payload}")
    return payload


def sanitizer_instrumented(binary: Path) -> bool:
    evidence = bytearray()
    for command in (["ldd", str(binary)], ["nm", "-an", str(binary)]):
        executable = shutil.which(command[0])
        if executable is None:
            continue
        result = subprocess.run([executable, *command[1:]], check=False,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        evidence.extend(result.stdout)
    lowered = bytes(evidence).lower()
    return b"libasan" in lowered and (b"libubsan" in lowered or b"__ubsan_" in lowered)


def assertion(name: str, passed: bool, expected: object,
              observed: object) -> dict[str, Any]:
    return {"name": name, "passed": bool(passed),
            "expected": expected, "observed": observed}


def exact_headers(headers: dict[str, str], expected: dict[str, str]) -> list[dict[str, Any]]:
    return [assertion(f"header:{name}", headers.get(name) == value,
                      value, headers.get(name))
            for name, value in expected.items()]


def make_fixture_inputs(output: Path, seed: int) -> tuple[dict[str, Any], dict[str, bytes]]:
    fixtures = output / "fixtures"
    fixtures.mkdir()
    token = hashlib.sha256(seed.to_bytes(8, "big")).hexdigest()[:12]

    nested_within = b'"leaf"'
    for index in range(240):
        nested_within = (b'{"n' + str(index).encode("ascii") + b'":' +
                         nested_within + b'}')
    nested_over = b'"leaf"'
    for index in range(270):
        nested_over = (b'{"n' + str(index).encode("ascii") + b'":' +
                       nested_over + b'}')

    huge_records = []
    for index in range(7600):
        value = int.from_bytes(
            hashlib.sha256(
                seed.to_bytes(8, "big") + b"huge-record" +
                index.to_bytes(8, "big")
            ).digest()[:8],
            "big",
        )
        huge_records.append(
            f'{{"index":{index},"dup":"first-{value:016x}",'
            f'"dup":"last-{value ^ seed:016x}","items":[1,2,3,4]}}'.encode("ascii")
        )
    huge_json = b'{"require":[],"data":[' + b",".join(huge_records) + b"]}"

    bodies: dict[str, bytes] = {
        "truncated-html.bin": b"<!doctype html><html><head><meta property=\"og:url\" content=\"https://www.facebook.com/watch?v=1\"",
        "truncated-script-json.bin": b"<!doctype html><script type=\"application/json\">{\"require\":[{\"x\":",
        "truncated-script-utf8.bin": b"<!doctype html><script type=\"application/json\">{\"text\":\"" + b"\xe2\x82",
        "duplicate-first.bin": html_json(
            b'{"node":{"id":"111","id":"222","feedback":{}},'
            b'"node":{"id":"333","actors":[]},"require":[]}'),
        "duplicate-last.bin": html_json(
            b'{"require":[],"node":{"id":"333","actors":[]},'
            b'"node":{"id":"222","id":"111","feedback":{}}}'),
        "deep-within.bin": html_json(nested_within),
        "deep-over.bin": html_json(nested_over),
        "huge-within.bin": html_json(huge_json),
        "wire-truncate.bin": html_json(
            b'{"require":[],"data":{"id":"wire-' + token.encode("ascii") + b'"}}'),
        "safe-redirect-end.bin": b"<!doctype html><script type=\"application/json\">{\"safe\":true",
        "body-cap.bin": b"<!doctype html><body>" + b"A" * (1152 * 1024) + b"</body>",
        "slow-body.bin": b"<!doctype html><body>" +
                         deterministic_bytes(seed, "slow", 384 * 1024) + b"</body>",
    }
    for name, body in bodies.items():
        write_new(fixtures / name, body)

    crawler = [
        {"pattern": "(a+)+$"},
        {"pattern": "(?:a|aa)+$"},
        {"pattern": "adversarial-safe-bot/"},
    ]
    crawler_bytes = json.dumps(crawler, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    write_new(fixtures / "crawler-db.json", crawler_bytes)
    bodies["crawler-db.json"] = crawler_bytes

    def response(body_name: str | None = None, *, status: int = 200,
                 headers: dict[str, str] | None = None,
                 mode: str = "normal", **extra: object) -> dict[str, Any]:
        result: dict[str, Any] = {
            "status": status,
            "headers": headers or {"Content-Type": "text/html; charset=utf-8"},
            "mode": mode,
        }
        if body_name is not None:
            result["body_path"] = f"fixtures/{body_name}"
        result.update(extra)
        return result

    standard = {
        "truncated-html": response("truncated-html.bin"),
        "truncated-script-json": response("truncated-script-json.bin"),
        "truncated-script-utf8": response("truncated-script-utf8.bin"),
        "duplicate-json-first": response("duplicate-first.bin"),
        "duplicate-json-last": response("duplicate-last.bin"),
        "deep-json-within": response("deep-within.bin"),
        "deep-json-over": response("deep-over.bin"),
        "huge-json-within": response("huge-within.bin"),
        "body-cap": response("body-cap.bin"),
        "query-duplicates": response("truncated-script-json.bin"),
        "query-4096": response("truncated-html.bin"),
        "query-4097": response("truncated-html.bin"),
    }
    plan_cases: dict[str, Any] = {
        "idle": {"default": response(None, status=404)},
        **{name: {"default": spec} for name, spec in standard.items()},
        "wire-truncate": {"default": response(
            "wire-truncate.bin", mode="truncate",
            declared_length=len(bodies["wire-truncate.bin"]) + 257,
            write_limit=max(1, len(bodies["wire-truncate.bin"]) // 2))},
        "unsafe-ip": {"default": response(
            None, status=302, headers={"Location": "http://127.0.0.1:9/not-facebook"})},
        "unsafe-userinfo": {"default": response(
            None, status=302,
            headers={"Location": "https://www.facebook.com@127.0.0.1:9/ambiguous"})},
        "unsafe-scheme": {"default": response(
            None, status=302, headers={"Location": "file:///etc/passwd"})},
        "redirect-loop": {"default": response(
            None, status=302, headers={"Location": f"https://www.facebook.com/watch?v=loop-{token}"})},
        "slow-disconnect": {"default": response(
            "slow-body.bin", mode="slow", chunk_size=4096,
            chunk_delay_seconds=0.01)},
    }
    safe_start = f"https://www.facebook.com/watch?v=safe-{token}"
    safe_end = f"https://m.facebook.com/permalink.php?story_fbid={int(seed % 900000) + 100000}&id=42"
    plan_cases["safe-redirect"] = {
        "rules": [
            {"url": safe_start,
             "response": response(None, status=302, headers={"Location": safe_end})},
            {"url": safe_end,
             "response": response("safe-redirect-end.bin")},
        ],
        "default": response(None, status=404),
    }
    plan = {"schema": 1, "seed": seed, "cases": plan_cases,
            "safe_redirect": {"start": safe_start, "end": safe_end}}
    write_new(output / "broker-plan.json", canonical_json(plan))
    return plan, bodies


def make_cases(output: Path, seed: int, plan: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    token = hashlib.sha256(seed.to_bytes(8, "big")).hexdigest()[:12]
    cases: list[dict[str, Any]] = []

    def add(case_id: str, group: str, request_bytes: bytes,
            oracle: dict[str, Any], broker_case: str = "idle",
            expected_events: dict[str, Any] | None = None,
            disconnect: bool = False) -> None:
        cases.append({
            "id": case_id,
            "group": group,
            "request": request_bytes,
            "oracle": oracle,
            "broker_case": broker_case,
            "expected_events": expected_events or {},
            "disconnect": disconnect,
        })

    malformed_targets = [
        b"/watch?v=42%",
        b"/watch?v=42%2",
        b"/watch?v=%GG&v=second",
        b"/watch?v=%C0%AF&id=7&id=8",
        b"/watch?v=%ED%A0%80&q=%E2%28%A1",
    ]
    for index, target in enumerate(malformed_targets):
        location = "https://www.facebook.com" + target.decode("ascii")
        add(
            f"browser-malformed-percent-{index:02d}", "url-percent-utf8",
            raw_request(target),
            {"kind": "redirect", "location": location},
            expected_events={"exact": 0},
        )

    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    percent_fragments = ["%", "%0", "%xz", "%c0%af", "%ed%a0%80",
                         "%f4%90%80%80", "%e2%28%a1"]
    for index in range(24):
        entropy = hashlib.sha512(
            (seed ^ 0xA5A55A5AF00DFACE).to_bytes(8, "big") +
            b"seeded-url-fuzz" + index.to_bytes(4, "big")
        ).digest()
        word = "".join(
            alphabet[entropy[offset] % len(alphabet)]
            for offset in range(18 + index % 13)
        )
        fragment = percent_fragments[entropy[40] % len(percent_fragments)]
        first = 10**8 + int.from_bytes(entropy[41:45], "big") % (9 * 10**8)
        second = 10**8 + int.from_bytes(entropy[45:49], "big") % (9 * 10**8)
        target_text = (
            f"/fuzz/{index:02d}-{word}/{fragment}?v={first}&v={second}"
            f"&empty=&flag&id={second}&id={first}&payload={fragment}"
        )
        location = "https://www.facebook.com" + target_text
        add(
            f"seeded-url-fuzz-{index:02d}", "seeded-url-fuzz",
            raw_request(target_text.encode("ascii")),
            {"kind": "redirect", "location": location},
            expected_events={"exact": 0},
        )

    crawler_ua = (b"a" * 10000) + b"! bounded-regex-subject"
    target = b"/crawler-regex-stress?dup=1&dup=2"
    add("crawler-regex-resource-bound", "crawler-regex", raw_request(target, crawler_ua),
        {"kind": "redirect", "location": "https://www.facebook.com" + target.decode()},
        expected_events={"exact": 0})

    fixture_routes = [
        ("truncated-html", "html-script-truncation"),
        ("truncated-script-json", "html-script-truncation"),
        ("truncated-script-utf8", "html-script-truncation"),
        ("duplicate-json-first", "json-duplicates"),
        ("duplicate-json-last", "json-duplicates"),
        ("deep-json-within", "json-resource-bounds"),
        ("deep-json-over", "json-resource-bounds"),
        ("huge-json-within", "json-resource-bounds"),
        ("wire-truncate", "transport-truncation"),
        ("body-cap", "transport-resource-bound"),
    ]
    for case_id, group in fixture_routes:
        target_text = f"/watch?v={case_id}-{token}"
        add(case_id, group, raw_request(target_text.encode(), BOT_UA.encode()),
            {"kind": "fallback", "original_url": "https://www.facebook.com" + target_text},
            broker_case=case_id, expected_events={"minimum": 1})

    query = "v=111&v=222&story_fbid=333&id=444&id=555&bad=%2&bad=%GG"
    target_text = "/watch?" + query
    add("query-duplicates", "url-query-duplicates",
        raw_request(target_text.encode(), BOT_UA.encode()),
        {"kind": "fallback", "original_url": "https://www.facebook.com" + target_text},
        broker_case="query-duplicates", expected_events={"minimum": 1})

    query_4096 = "&".join(["v=4096"] + [f"x{i % 17}={i}" for i in range(4095)])
    target_4096 = "/watch?" + query_4096
    add("query-pair-limit-4096", "url-query-resource-bound",
        raw_request(target_4096.encode(), BOT_UA.encode()),
        {"kind": "fallback", "original_url": "https://www.facebook.com" + target_4096},
        broker_case="query-4096")
    query_4097 = query_4096 + "&overflow=1"
    target_4097 = "/watch?" + query_4097
    add("query-pair-limit-4097", "url-query-resource-bound",
        raw_request(target_4097.encode(), BOT_UA.encode()),
        {"kind": "fallback", "original_url": "https://www.facebook.com" + target_4097},
        broker_case="query-4097")

    redirect_cases = [
        ("unsafe-ip", "unsafe-ip"),
        ("unsafe-userinfo", "unsafe-userinfo"),
        ("unsafe-scheme", "unsafe-scheme"),
        ("redirect-loop", "redirect-loop"),
    ]
    for case_id, broker_case in redirect_cases:
        target_text = (f"/watch?v=loop-{token}" if case_id == "redirect-loop"
                       else f"/watch?v={case_id}-{token}")
        add(case_id, "redirect-validation",
            raw_request(target_text.encode(), BOT_UA.encode()),
            {"kind": "fallback", "original_url": "https://www.facebook.com" + target_text},
            broker_case=broker_case, expected_events={"exact": 1})

    safe_start = plan["safe_redirect"]["start"]
    safe_target = urlsplit(safe_start).path + "?" + urlsplit(safe_start).query
    add("safe-redirect", "redirect-validation",
        raw_request(safe_target.encode(), BOT_UA.encode()),
        {"kind": "fallback", "original_url": safe_start},
        broker_case="safe-redirect", expected_events={"exact": 2})

    malformed_requests = [
        # HTTP/0.9 tolerance and whitespace recovery differ across supported
        # libmicrohttpd versions, so these two are survival contracts rather
        # than parser-version change detectors.
        ("request-line-missing-version", b"GET /healthz\r\nHost: 127.0.0.1\r\n\r\n", "survival"),
        ("request-line-double-space", b"GET  /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", "survival"),
        ("request-line-bad-version", b"GET /healthz HTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", "malformed"),
        ("header-missing-colon", b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nBroken-Header\r\n\r\n", "survival"),
        ("request-target-raw-invalid-utf8", raw_request(b"/raw-\xff-utf8"), "survival"),
        ("header-value-invalid-utf8", raw_request(b"/header-invalid-utf8", extra_headers=[b"X-Raw: \xff\xfe"]), "survival"),
        ("header-duplicate-user-agent", raw_request(
            b"/duplicate-user-agent", extra_headers=[b"User-Agent: " + BOT_UA.encode()]), "survival"),
        ("header-obsolete-fold", raw_request(
            b"/folded-header", extra_headers=[b"X-Folded: first", b" second"]), "survival"),
        ("header-resource-bound", raw_request(b"/large-header", extra_headers=[b"X-Bounded: " + b"z" * 48_000]), "survival"),
        ("request-target-over-limit", raw_request(b"/" + b"q" * 66_000), "malformed"),
    ]
    for case_id, request_bytes, kind in malformed_requests:
        event_expectation = ({}
                             if case_id == "header-duplicate-user-agent"
                             else {"exact": 0})
        add(case_id, "raw-http-malformed", request_bytes, {"kind": kind},
            expected_events=event_expectation)

    disconnect_target = f"/watch?v=disconnect-{token}"
    add("client-disconnect-during-upstream", "client-disconnect",
        raw_request(disconnect_target.encode(), BOT_UA.encode()),
        {"kind": "disconnect"}, broker_case="slow-disconnect",
        expected_events={"minimum": 1}, disconnect=True)
    reuse_target = f"/watch?v=900000{seed % 100000:05d}"
    add("post-disconnect-worker-reuse", "client-disconnect",
        raw_request(reuse_target.encode(), BOT_UA.encode()),
        {"kind": "fallback",
         "original_url": "https://www.facebook.com" + reuse_target},
        broker_case="truncated-html", expected_events={"minimum": 1})

    raw_dir = output / "raw_cases"
    oracle_dir = output / "oracles"
    raw_dir.mkdir()
    oracle_dir.mkdir()
    manifest_cases: list[dict[str, Any]] = []
    for index, case in enumerate(cases):
        stem = f"{index:03d}-{case['id']}"
        request_path = raw_dir / f"{stem}.request.bin"
        write_new(request_path, case["request"])
        case["request_path"] = str(request_path.relative_to(output))
        oracle = case["oracle"]
        oracle_body: bytes | None = None
        if oracle["kind"] == "fallback":
            oracle_body = fallback_body(oracle["original_url"])
        elif oracle["kind"] == "redirect":
            oracle_body = browser_redirect_body(oracle["location"])
        if oracle_body is not None:
            oracle_path = oracle_dir / f"{stem}.body"
            write_new(oracle_path, oracle_body)
            case["oracle_body"] = oracle_body
            case["oracle_path"] = str(oracle_path.relative_to(output))
        manifest_cases.append({
            "id": case["id"], "group": case["group"],
            "broker_case": case["broker_case"],
            "disconnect": case["disconnect"],
            "request_path": case["request_path"],
            "request_sha256": sha256_bytes(case["request"]),
            "request_bytes": len(case["request"]),
            "oracle": oracle,
            "oracle_path": case.get("oracle_path"),
            "oracle_sha256": (sha256_bytes(oracle_body)
                              if oracle_body is not None else None),
        })
    deterministic = {
        "schema": 1,
        "generator": GENERATOR_VERSION,
        "seed": seed,
        "seed_hex": f"0x{seed:016x}",
        "cases": manifest_cases,
        "broker_plan_sha256": sha256_file(output / "broker-plan.json"),
        "fixture_sha256": {
            str(path.relative_to(output)): sha256_file(path)
            for path in sorted((output / "fixtures").iterdir()) if path.is_file()
        },
    }
    fingerprint = sha256_bytes(canonical_json(deterministic))
    deterministic["input_fingerprint"] = fingerprint
    write_new(output / "input-manifest.json", canonical_json(deterministic))
    return cases, fingerprint


def validate_case(case: dict[str, Any], status: int | None,
                  headers: dict[str, str], body: bytes,
                  events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    kind = case["oracle"]["kind"]
    if kind == "fallback":
        checks.append(assertion("status", status == 200, 200, status))
        checks.extend(exact_headers(headers, {
            "content-type": "text/html; charset=UTF-8",
            "cache-control": "no-store",
            "vary": "User-Agent",
        }))
        expected = case["oracle_body"]
        checks.append(assertion("exact-body", body == expected,
                                sha256_bytes(expected), sha256_bytes(body)))
    elif kind == "redirect":
        checks.append(assertion("status", status == 302, 302, status))
        checks.extend(exact_headers(headers, {
            "content-type": "text/html; charset=UTF-8",
            "cache-control": "no-store",
            "vary": "User-Agent",
            "location": case["oracle"]["location"],
        }))
        expected = case["oracle_body"]
        checks.append(assertion("exact-body", body == expected,
                                sha256_bytes(expected), sha256_bytes(body)))
    elif kind == "malformed":
        rejected = status is None or 400 <= status <= 599
        checks.append(assertion("malformed-request-rejected", rejected,
                                "connection close or HTTP 4xx/5xx", status))
    elif kind == "survival":
        checks.append(assertion("bounded-response", len(body) <= 2 * 1024 * 1024,
                                "<=2097152", len(body)))
    elif kind == "disconnect":
        checks.append(assertion(
            "upstream-work-observed-after-client-rst", len(events) >= 1,
            ">=1 broker event", len(events)))
    else:
        checks.append(assertion("known-oracle", False, "known kind", kind))

    expectation = case["expected_events"]
    if "exact" in expectation:
        checks.append(assertion("broker-event-count",
                                len(events) == int(expectation["exact"]),
                                int(expectation["exact"]), len(events)))
    if "minimum" in expectation:
        checks.append(assertion("broker-event-count",
                                len(events) >= int(expectation["minimum"]),
                                f">={expectation['minimum']}", len(events)))
    for event in events:
        parsed = urlsplit(str(event.get("logical_url", "")))
        safe = (parsed.scheme in {"http", "https"} and
                (parsed.hostname or "").lower() in FACEBOOK_HOSTS)
        checks.append(assertion(
            f"broker-url-safe:{event.get('sequence')}", safe,
            "http(s) Facebook host", event.get("logical_url")))
        checks.append(assertion(
            f"broker-event-terminal:{event.get('sequence')}",
            event.get("outcome") != "started", "terminal outcome",
            event.get("outcome")))
    return checks


def write_sha256s(output: Path) -> None:
    checksum_path = output / "SHA256SUMS"
    lines = []
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path == checksum_path:
            continue
        relative = path.relative_to(output)
        lines.append(f"{sha256_file(path)}  {relative.as_posix()}\n")
    checksum_path.write_text("".join(lines), encoding="utf-8")
    for line in lines:
        expected, relative = line.rstrip("\n").split("  ", 1)
        observed = sha256_file(output / relative)
        if observed != expected:
            raise RuntimeError(f"artifact checksum verification failed: {relative}")


def enter_network_namespace(args: argparse.Namespace) -> None:
    if args.inside_netns:
        result = subprocess.run(["ip", "link", "set", "lo", "up"], check=False,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if result.returncode != 0:
            raise RuntimeError("cannot enable loopback in isolated namespace: " +
                               result.stdout.decode("utf-8", "replace"))
        interfaces = sorted(name for _index, name in socket.if_nameindex())
        current = os.readlink("/proc/self/ns/net")
        if interfaces != ["lo"] or current == args.parent_netns:
            raise RuntimeError(
                f"network isolation failed: interfaces={interfaces} namespace={current}")
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


def run(args: argparse.Namespace) -> int:
    enter_network_namespace(args)
    root = Path(__file__).resolve().parent.parent
    binary = args.binary.resolve()
    output = args.output.resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"Fastbed binary is not executable: {binary}")
    sanitizer_detected = sanitizer_instrumented(binary)
    if args.sanitizers == "required" and not sanitizer_detected:
        raise RuntimeError("--sanitizers required, but ASan+UBSan instrumentation was not detected")
    if output.exists():
        raise RuntimeError(f"output already exists: {output}")
    output.mkdir(parents=True)

    started = datetime.now(timezone.utc)
    failures: list[str] = []
    results: list[dict[str, Any]] = []
    broker: subprocess.Popen[bytes] | None = None
    fastbed: subprocess.Popen[bytes] | None = None
    broker_log = None
    fastbed_log = None
    broker_exit: int | None = None
    fastbed_exit: int | None = None
    plan: dict[str, Any] = {}
    fingerprint = ""
    sanitizer_enabled = args.sanitizers != "off" and sanitizer_detected

    try:
        plan, _bodies = make_fixture_inputs(output, args.seed)
        cases, fingerprint = make_cases(output, args.seed, plan)
        if args.expected_input_fingerprint and fingerprint != args.expected_input_fingerprint:
            raise RuntimeError(
                f"input fingerprint mismatch: {fingerprint} != "
                f"{args.expected_input_fingerprint}")

        http_port, https_port, fastbed_port = reserve_ports(3)
        config = output / "config.yaml"
        config.write_text(
            "host: 127.0.0.1\n"
            f"port: {fastbed_port}\n"
            "timezone: 7\n"
            "banned_users: []\n"
            "notifier_webhook: ''\n",
            encoding="utf-8",
        )
        runtime = output / "runtime"
        runtime.mkdir()
        cert = runtime / "fixture-cert.pem"
        key = runtime / "fixture-key.pem"
        openssl = subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost",
        ], check=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if openssl.returncode != 0:
            raise RuntimeError("openssl certificate generation failed: " +
                               openssl.stdout.decode("utf-8", "replace"))

        broker_log = (output / "broker.log").open("wb")
        fastbed_log = (output / "fastbed.log").open("wb")
        broker = subprocess.Popen([
            sys.executable, str(Path(__file__).with_name("adversarial_fixture_broker.py")),
            str(output), str(output / "broker-plan.json"),
            "--http-port", str(http_port), "--https-port", str(https_port),
            "--cert", str(cert), "--key", str(key),
        ], stdout=broker_log, stderr=subprocess.STDOUT)
        wait_ready(http_port, "/__ready")

        environment = dict(os.environ)
        environment["FASTBED_ASSET_DIR"] = str(root / "assets")
        environment["FASTBED_CRAWLER_DB"] = str(output / "fixtures/crawler-db.json")
        environment["FASTBED_TRACE_PARSER"] = "1"
        if sanitizer_enabled:
            environment["ASAN_OPTIONS"] = (
                "abort_on_error=1:halt_on_error=1:detect_leaks=1:"
                "allocator_may_return_null=0:strict_string_checks=1")
            environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        fastbed = subprocess.Popen([
            str(binary), "--config", str(config), "--workers", "1",
            "--max-body-mib", "1",
            "--replay-http-port", str(http_port),
            "--replay-https-port", str(https_port),
        ], env=environment, stdout=fastbed_log, stderr=subprocess.STDOUT)
        wait_ready(fastbed_port, "/healthz")

        result_stream = (output / "case-results.jsonl").open("x", encoding="utf-8")
        try:
            for index, case in enumerate(cases):
                if fastbed.poll() is not None:
                    failures.append(f"Fastbed exited before case {case['id']}: {fastbed.returncode}")
                    break
                before = control_json(http_port, "/__report")
                control_json(http_port, "/__select", {"case": case["broker_case"]})
                began = time.monotonic()
                raw_response = b""
                if case["disconnect"]:
                    client = socket.create_connection(("127.0.0.1", fastbed_port), timeout=5)
                    client.sendall(case["request"])
                    deadline = time.monotonic() + 10.0
                    while time.monotonic() < deadline:
                        report = control_json(http_port, "/__report")
                        new_events = report["events"][len(before["events"]):]
                        if new_events:
                            break
                        time.sleep(0.02)
                    linger = struct.pack("ii", 1, 0)
                    client.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                    client.close()
                    deadline = time.monotonic() + 10.0
                    while time.monotonic() < deadline:
                        report = control_json(http_port, "/__report")
                        new_events = report["events"][len(before["events"]):]
                        if new_events and all(event["outcome"] != "started"
                                              for event in new_events):
                            break
                        time.sleep(0.02)
                else:
                    exchange_timeout = (min(args.case_timeout, 8.0)
                                        if case["group"] == "raw-http-malformed"
                                        else args.case_timeout)
                    raw_response = exchange_raw(fastbed_port, case["request"],
                                                timeout=exchange_timeout)
                elapsed = time.monotonic() - began
                report = control_json(http_port, "/__report")
                events = report["events"][len(before["events"]):]
                status, headers, body = parse_response(raw_response)
                response_path = output / "raw_cases" / f"{index:03d}-{case['id']}.response.bin"
                write_new(response_path, raw_response)
                checks = validate_case(case, status, headers, body, events)
                try:
                    health_payload = health(fastbed_port)
                    checks.append(assertion("process-health", True, "ok", "ok"))
                except Exception as exc:
                    health_payload = None
                    checks.append(assertion("process-health", False, "ok", str(exc)))
                passed = all(check["passed"] for check in checks)
                if not passed:
                    failures.append(case["id"])
                result = {
                    "index": index,
                    "id": case["id"],
                    "group": case["group"],
                    "passed": passed,
                    "elapsed_seconds": round(elapsed, 6),
                    "status": status,
                    "headers": headers,
                    "body_bytes": len(body),
                    "body_sha256": sha256_bytes(body),
                    "raw_response_path": str(response_path.relative_to(output)),
                    "raw_response_sha256": sha256_bytes(raw_response),
                    "broker_events": events,
                    "health": health_payload,
                    "assertions": checks,
                }
                results.append(result)
                result_stream.write(json.dumps(result, ensure_ascii=True, sort_keys=True) + "\n")
                result_stream.flush()
        finally:
            result_stream.close()

        final_report = control_json(http_port, "/__report")
        with (output / "broker-events.jsonl").open("x", encoding="utf-8") as stream:
            for event in final_report["events"]:
                stream.write(json.dumps(event, ensure_ascii=True, sort_keys=True) + "\n")
    except Exception:
        failures.append("harness-error")
        (output / "harness-error.txt").write_text(traceback.format_exc(), encoding="utf-8")
    finally:
        fastbed_exit = terminate(fastbed)
        broker_exit = terminate(broker, timeout=8.0)
        if fastbed_log is not None:
            fastbed_log.close()
        if broker_log is not None:
            broker_log.close()

    if fastbed_exit not in {None, 0}:
        failures.append(f"fastbed-exit-{fastbed_exit}")
    if broker_exit not in {None, 0}:
        failures.append(f"broker-exit-{broker_exit}")
    sanitizer_findings: list[str] = []
    fastbed_log_path = output / "fastbed.log"
    if fastbed_log_path.exists():
        log_text = fastbed_log_path.read_text(encoding="utf-8", errors="replace")
        sanitizer_findings = [marker for marker in SANITIZER_MARKERS if marker in log_text]
        if sanitizer_findings:
            failures.append("sanitizer-finding")

    finished = datetime.now(timezone.utc)
    groups: dict[str, dict[str, int]] = {}
    for result in results:
        group = groups.setdefault(result["group"], {"passed": 0, "failed": 0})
        group["passed" if result["passed"] else "failed"] += 1
    planned_cases = (len(json.loads((output / "input-manifest.json").read_text())["cases"])
                     if (output / "input-manifest.json").exists() else 0)
    if len(results) != planned_cases:
        failures.append(
            f"incomplete-case-run-{len(results)}-of-{planned_cases}")
    summary = {
        "schema": 1,
        "suite": GENERATOR_VERSION,
        "success": not failures,
        "seed": args.seed,
        "seed_hex": f"0x{args.seed:016x}",
        "input_fingerprint": fingerprint,
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "binary": str(binary),
        "binary_sha256": sha256_file(binary),
        "network_namespace": os.readlink("/proc/self/ns/net"),
        "interfaces": sorted(name for _index, name in socket.if_nameindex()),
        "sanitizers": {
            "mode": args.sanitizers,
            "detected": sanitizer_detected,
            "enabled": sanitizer_enabled,
            "findings": sanitizer_findings,
        },
        "cases_planned": planned_cases,
        "cases_completed": len(results),
        "cases_passed": sum(int(result["passed"]) for result in results),
        "cases_failed": sum(int(not result["passed"]) for result in results),
        "groups": groups,
        "failures": failures,
        "fastbed_exit": fastbed_exit,
        "broker_exit": broker_exit,
    }
    (output / "artifact-manifest.json").write_bytes(canonical_json(summary))
    replay_command = (
        f"{shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} "
        f"{shlex.quote(str(binary))} --output REPLACE_WITH_NEW_OUTPUT "
        f"--seed {args.seed:#x} --sanitizers {args.sanitizers} "
        f"--expected-input-fingerprint {fingerprint}\n"
    )
    (output / "REPLAY.txt").write_text(replay_command, encoding="utf-8")
    write_sha256s(output)
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"artifact: {output}")
    print(f"input fingerprint: {fingerprint}")
    return 0 if summary["success"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=parse_seed, default=DEFAULT_SEED)
    parser.add_argument("--sanitizers", choices=("auto", "required", "off"),
                        default="auto")
    parser.add_argument("--expected-input-fingerprint")
    parser.add_argument("--case-timeout", type=float, default=60.0)
    parser.add_argument("--inside-netns", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--parent-netns", default="", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.case_timeout < 1.0 or args.case_timeout > 300.0:
        parser.error("--case-timeout must be between 1 and 300 seconds")
    try:
        return run(args)
    except Exception as exc:
        parser.exit(2, f"error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())

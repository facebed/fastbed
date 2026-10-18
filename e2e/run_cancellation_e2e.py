#!/usr/bin/env python3
"""Exercise CPU-phase request deadlines and forced shutdown end to end."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from urllib.request import urlopen


CRAWLER_UA = "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"
TARGET = "/123/posts/456"
DEADLINE_BODY = b"request timed out\n"
SHUTDOWN_BODY = b"server shutting down\n"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_http(port: int, path: str, timeout: float = 30.0) -> dict:
    deadline = time.monotonic() + timeout
    failure: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{port}{path}", timeout=1) as response:
                return json.loads(response.read())
        except Exception as exc:
            failure = exc
            time.sleep(0.02)
    raise RuntimeError(f"HTTP service {port}{path} not ready: {failure}")


def control(port: int, path: str, payload: dict | None = None) -> dict:
    body = None if payload is None else json.dumps(payload).encode()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    connection.request(
        "GET" if body is None else "POST",
        path,
        body=body,
        headers={} if body is None else {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        },
    )
    response = connection.getresponse()
    data = response.read()
    status = response.status
    connection.close()
    if status != 200:
        raise RuntimeError(f"control {path} returned {status}: {data!r}")
    return json.loads(data)


def request(port: int, timeout: float = 30.0) -> dict:
    began = time.monotonic_ns()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    connection.request("GET", TARGET, headers={"User-Agent": CRAWLER_UA})
    response = connection.getresponse()
    body = response.read()
    result = {
        "status": response.status,
        "headers": {name.lower(): value for name, value in response.getheaders()},
        "body": body,
        "elapsed_seconds": round((time.monotonic_ns() - began) / 1e9, 6),
    }
    connection.close()
    return result


def write_heavy_document(path: Path) -> int:
    item = b'{"id":"12345678901234567890"}'
    count_per_script = 1_000_000
    with path.open("xb") as stream:
        stream.write(
            b'<html><head><link rel="canonical" '
            b'href="https://www.facebook.com/123/posts/456"></head><body>'
        )
        for _script in range(2):
            stream.write(b'<script type="application/json">{"payload":[')
            for index in range(count_per_script):
                if index:
                    stream.write(b",")
                stream.write(item)
            stream.write(b"]}</script>")
        stream.write(b"</body></html>")
    return path.stat().st_size


def start_fastbed(
    binary: Path,
    root: Path,
    directory: Path,
    broker_http: int,
    broker_https: int,
    request_timeout: int,
    graceful: int,
    notifier_url: str,
    sanitizer: bool,
) -> tuple[subprocess.Popen[bytes], int, object]:
    port = free_port()
    config = directory / "config.yaml"
    config.write_text(
        "host: 127.0.0.1\n"
        f"port: {port}\n"
        "timezone: 7\n"
        "banned_users: []\n"
        f"notifier_webhook: '{notifier_url}'\n",
        encoding="utf-8",
    )
    log = (directory / "fastbed.log").open("wb")
    environment = dict(os.environ)
    environment["FASTBED_ASSET_DIR"] = str(root / "assets")
    environment["FASTBED_CRAWLER_DB"] = str(
        root / "third_party/crawler-user-agents/crawler-user-agents.json")
    environment["FASTBED_TRACE_PARSER"] = "1"
    if sanitizer:
        environment["ASAN_OPTIONS"] = (
            "abort_on_error=1:halt_on_error=1:detect_leaks=1:"
            "allocator_may_return_null=0:strict_string_checks=1")
        environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    process = subprocess.Popen(
        [
            str(binary), "--config", str(config), "--workers", "1",
            "--max-body-mib", "64", "--replay-http-port", str(broker_http),
            "--replay-https-port", str(broker_https),
            "--request-timeout-seconds", str(request_timeout),
            "--graceful-shutdown-seconds", str(graceful),
        ],
        cwd=root,
        env=environment,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    wait_http(port, "/healthz")
    return process, port, log


def stop(process: subprocess.Popen[bytes], timeout: float = 15.0) -> int:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(timeout=5)


def wait_event(port: int, previous: int, timeout: float = 20.0) -> list[dict]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events = control(port, "/__report")["events"][previous:]
        if events and all(event["outcome"] != "started" for event in events):
            return events
        time.sleep(0.005)
    raise RuntimeError("upstream response did not finish")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--sanitizers", action="store_true")
    parser.add_argument("--parent-netns", required=True)
    args = parser.parse_args()

    if sorted(name for _index, name in socket.if_nameindex()) != ["lo"]:
        parser.error("run in a loopback-only network namespace")
    if os.readlink("/proc/self/ns/net") == args.parent_netns:
        parser.error("network namespace isolation was not established")

    root = Path(__file__).resolve().parent.parent
    binary = args.binary.resolve()
    output = args.output.resolve()
    if output.exists():
        parser.error(f"output exists: {output}")
    output.mkdir(parents=True)
    (output / "deadline").mkdir()
    (output / "shutdown").mkdir()

    body_path = output / "heavy.html"
    body_bytes = write_heavy_document(body_path)
    if body_bytes >= 64 * 1024 * 1024:
        raise RuntimeError(f"fixture exceeds body cap: {body_bytes}")

    plan = {
        "schema": 1,
        "cases": {
            "deadline": {"default": {
                "status": 200,
                "headers": {"Content-Type": "text/html; charset=utf-8"},
                "body_path": "heavy.html",
                "mode": "slow",
                "chunk_size": body_bytes - 1,
                "chunk_delay_seconds": 0.35,
            }},
            "shutdown": {"default": {
                "status": 200,
                "headers": {"Content-Type": "text/html; charset=utf-8"},
                "body_path": "heavy.html",
            }},
        },
    }
    plan_path = output / "broker-plan.json"
    plan_path.write_text(json.dumps(plan, sort_keys=True), encoding="utf-8")

    cert = output / "fixture-cert.pem"
    key = output / "fixture-key.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=localhost"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    http_port, https_port = free_port(), free_port()
    broker_log = (output / "broker.log").open("wb")
    broker = subprocess.Popen(
        [sys.executable, str(root / "e2e/adversarial_fixture_broker.py"),
         str(output), str(plan_path), "--http-port", str(http_port),
         "--https-port", str(https_port), "--cert", str(cert),
         "--key", str(key)],
        stdout=broker_log,
        stderr=subprocess.STDOUT,
    )
    wait_http(http_port, "/__ready")
    notifier_url = f"http://127.0.0.1:{http_port}/webhook"
    results: dict[str, object] = {}
    failures: list[str] = []

    try:
        # Deadline after full body delivery: the remaining work is document/
        # parser CPU, and a cancelled parse must not affect metrics/notifier.
        before = len(control(http_port, "/__report")["events"])
        control(http_port, "/__select", {"case": "deadline"})
        process, port, log = start_fastbed(
            binary, root, output / "deadline", http_port, https_port,
            1, 1, notifier_url, args.sanitizers)
        try:
            deadline_result = request(port, timeout=20)
            events = wait_event(http_port, before)
            health = wait_http(port, "/healthz")
            webhook_events = [event for event in events
                              if event["method"] == "POST"]
            passed = (
                deadline_result["status"] == 504 and
                deadline_result["body"] == DEADLINE_BODY and
                int(health["requests"]) == 0 and
                int(health["errors"]) == 0 and
                not webhook_events and
                any(event["bytes_written"] == body_bytes for event in events)
            )
            results["deadline"] = {
                "passed": passed,
                "status": deadline_result["status"],
                "body_sha256": sha256_bytes(deadline_result["body"]),
                "elapsed_seconds": deadline_result["elapsed_seconds"],
                "health": health,
                "events": events,
                "webhook_events": len(webhook_events),
            }
            if not passed:
                failures.append("deadline")
        finally:
            exit_status = stop(process)
            log.close()
            if exit_status != 0:
                failures.append(f"deadline-exit-{exit_status}")

        # Forced shutdown after complete upstream delivery must cancel CPU work,
        # return the shutdown contract, and join the request worker cleanly.
        before = len(control(http_port, "/__report")["events"])
        control(http_port, "/__select", {"case": "shutdown"})
        process, port, log = start_fastbed(
            binary, root, output / "shutdown", http_port, https_port,
            60, 1, notifier_url, args.sanitizers)
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(request, port, 20)
                events = wait_event(http_port, before)
                signal_ns = time.monotonic_ns()
                process.send_signal(signal.SIGTERM)
                shutdown_result = future.result(timeout=15)
                exit_status = process.wait(timeout=15)
                exit_elapsed = round((time.monotonic_ns() - signal_ns) / 1e9, 6)
            webhook_events = [event for event in events
                              if event["method"] == "POST"]
            passed = (
                shutdown_result["status"] == 503 and
                shutdown_result["body"] == SHUTDOWN_BODY and
                shutdown_result["headers"].get("retry-after") == "1" and
                exit_status == 0 and
                not webhook_events and
                any(event["bytes_written"] == body_bytes for event in events)
            )
            results["shutdown"] = {
                "passed": passed,
                "status": shutdown_result["status"],
                "body_sha256": sha256_bytes(shutdown_result["body"]),
                "elapsed_seconds": shutdown_result["elapsed_seconds"],
                "exit_elapsed_seconds": exit_elapsed,
                "exit_status": exit_status,
                "events": events,
                "webhook_events": len(webhook_events),
            }
            if not passed:
                failures.append("shutdown")
        finally:
            stop(process)
            log.close()
    finally:
        broker_status = stop(broker)
        broker_log.close()
        if broker_status != 0:
            failures.append(f"broker-exit-{broker_status}")

    markers = (
        "ERROR: AddressSanitizer", "runtime error:",
        "LeakSanitizer", "UndefinedBehaviorSanitizer",
    )
    sanitizer_findings: list[str] = []
    for path in output.glob("*/fastbed.log"):
        text = path.read_text(encoding="utf-8", errors="replace")
        sanitizer_findings.extend(marker for marker in markers if marker in text)
    if sanitizer_findings:
        failures.append("sanitizer-findings")

    manifest = {
        "schema": 1,
        "suite": "fastbed-cpu-cancellation-e2e-v1",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "success": not failures,
        "failures": failures,
        "binary": str(binary),
        "binary_sha256": sha256_file(binary),
        "body_bytes": body_bytes,
        "body_sha256": sha256_file(body_path),
        "sanitizers": args.sanitizers,
        "sanitizer_findings": sorted(set(sanitizer_findings)),
        "network_namespace": os.readlink("/proc/self/ns/net"),
        "results": results,
    }
    manifest_path = output / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (output / "REPLAY.txt").write_text(
        f"python3 {Path(__file__).resolve()} {binary} --output NEW_OUTPUT "
        f"{'--sanitizers ' if args.sanitizers else ''}"
        "--parent-netns PARENT_NETNS\n",
        encoding="utf-8",
    )
    checksums = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            checksums.append(f"{sha256_file(path)}  {path.relative_to(output)}")
    (output / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())

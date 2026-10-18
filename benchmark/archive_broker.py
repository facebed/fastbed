#!/usr/bin/env python3
"""Serve hash-verified archived Facebook responses for service benchmarks.

The mixed-workload broker is intentionally narrower than the full corpus replay
broker.  Every selected oracle row must perform exactly one successful GET with
no recorded redirect, retry, transport error, or reused response.  That makes
the endpoint mapping immutable and safe to serve concurrently to both Facebed
and Fastbed without request-local selection state.
"""

from __future__ import annotations

import argparse
from collections import Counter
import compression.zstd
from datetime import datetime, timezone
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import threading
import time
from typing import Any
from urllib.parse import unquote, urlsplit


BUNDLE_SCHEMA = "fastbed-archive-broker-bundle-v1"
REPORT_SCHEMA = "fastbed-archive-broker-report-v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def copy_verified(source: Path, destination: Path) -> dict[str, Any]:
    if not source.is_file():
        raise ValueError(f"input is not a file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    source_hash = sha256_file(source)
    copied_hash = sha256_file(destination)
    if copied_hash != source_hash:
        raise RuntimeError(f"input changed while copying: {source}")
    return {
        "source": str(source),
        "snapshot": str(destination),
        "bytes": destination.stat().st_size,
        "sha256": copied_hash,
    }


def url_key(url: str) -> tuple[str, str, str, str]:
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    if host in {"facebook.com", "www.facebook.com"}:
        host = "www.facebook.com"
    return (
        parsed.scheme.lower(),
        host,
        unquote(parsed.path).rstrip("/") or "/",
        parsed.query,
    )


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def selected_oracle_rows(path: Path, wanted: set[int]) -> dict[int, dict[str, Any]]:
    rows: dict[int, dict[str, Any]] = {}
    with path.open(encoding="utf-8") as stream:
        for text in stream:
            row = json.loads(text)
            line = int(row["line"])
            if line not in wanted:
                continue
            if line in rows:
                raise ValueError(f"duplicate oracle line {line}")
            rows[line] = row
    missing = sorted(wanted - rows.keys())
    if missing:
        raise ValueError(f"oracle is missing selected lines: {missing}")
    return rows


def body_container(archive: Path, digest: str) -> Path:
    candidates = [
        archive / "html" / f"{digest}.html.zst",
        archive / "non_html" / f"{digest}.bin.zst",
    ]
    found = [path for path in candidates if path.is_file()]
    if len(found) != 1:
        raise ValueError(
            f"archive body {digest} resolved to {len(found)} containers"
        )
    return found[0]


def verify_decompress(path: Path, expected_sha256: str,
                      expected_bytes: int) -> tuple[bytes, dict[str, Any]]:
    compressed = path.read_bytes()
    body = compression.zstd.decompress(compressed)
    observed_hash = sha256_bytes(body)
    if observed_hash != expected_sha256 or len(body) != expected_bytes:
        raise ValueError(
            f"archive body integrity mismatch {path}: "
            f"sha256={observed_hash}/{expected_sha256} "
            f"bytes={len(body)}/{expected_bytes}"
        )
    return body, {
        "compressed_bytes": len(compressed),
        "compressed_sha256": sha256_bytes(compressed),
        "body_bytes": len(body),
        "body_sha256": observed_hash,
    }


def build_bundle(oracle_results: Path, archive: Path,
                 workload_manifest: Path, cert: Path, key: Path,
                 output: Path) -> Path:
    if output.exists():
        raise ValueError(f"bundle output already exists: {output}")
    workload = load_json(workload_manifest)
    if workload.get("schema") != "fastbed-http-workload-manifest-v1":
        raise ValueError("unsupported workload manifest schema")
    if sha256_file(oracle_results) != workload.get("python_results_sha256"):
        raise ValueError("workload manifest does not pin this oracle results file")
    workload_path = Path(str(workload.get("workload", "")))
    if not workload_path.is_file():
        workload_path = workload_manifest.with_name(
            workload_manifest.name.removesuffix(".manifest.json")
        )
    if (
        not workload_path.is_file()
        or sha256_file(workload_path) != workload.get("workload_sha256")
    ):
        raise ValueError("workload bytes do not match its manifest")
    selected_lines = [int(line) for line in workload.get("selected_lines", [])]
    if not selected_lines or len(set(selected_lines)) != len(selected_lines):
        raise ValueError("workload selected_lines must be nonempty and unique")
    manifest_rows = workload.get("rows", [])
    if not isinstance(manifest_rows, list) or {
        int(row["line"]) for row in manifest_rows
    } != set(selected_lines):
        raise ValueError("workload rows do not match selected_lines")
    row_by_line = selected_oracle_rows(oracle_results, set(selected_lines))

    output.mkdir(parents=True)
    (output / "bodies").mkdir()
    input_receipts = {
        "oracle_selected": str(output / "oracle-selected.jsonl"),
        "workload": copy_verified(workload_path, output / "workload.tsv"),
        "workload_manifest": copy_verified(
            workload_manifest, output / "workload.tsv.manifest.json"
        ),
        "archive_manifest": copy_verified(
            archive / "archive.json", output / "archive.json"
        ),
        "certificate": copy_verified(cert, output / "fixture-cert.pem"),
        "private_key": copy_verified(key, output / "fixture-key.pem"),
    }
    os.chmod(output / "fixture-key.pem", 0o600)

    endpoints: list[dict[str, Any]] = []
    selected_records: list[str] = []
    exact_seen: dict[tuple[str, str], tuple[Any, ...]] = {}
    normalized_seen: dict[tuple[str, tuple[str, str, str, str]], tuple[Any, ...]] = {}
    copied_bodies: dict[str, dict[str, Any]] = {}
    workload_rows = {int(row["line"]): row for row in manifest_rows}
    for line in selected_lines:
        row = row_by_line[line]
        selected_records.append(json.dumps(row, sort_keys=True) + "\n")
        if (
            row.get("outcome") != "parsed"
            or int(row.get("http_status", 0)) != 200
            or row.get("fixture_misses")
            or row.get("integrity_errors")
        ):
            raise ValueError(f"line {line} is not a clean parsed oracle row")
        requests = row.get("requests")
        if not isinstance(requests, list) or len(requests) != 1:
            raise ValueError(
                f"line {line} has {len(requests) if isinstance(requests, list) else 'invalid'} "
                "upstream operations; mixed broker requires exactly one"
            )
        request = requests[0]
        method = str(request.get("method", "")).upper()
        requested_url = str(request.get("requested_url", ""))
        status = int(request.get("status", 0))
        body_hash = str(request.get("body_sha256", ""))
        body_bytes = int(request.get("bytes", -1))
        if (
            method != "GET"
            or status != 200
            or not requested_url
            or request.get("error_type")
            or int(request.get("recorded_redirect_count", 0)) != 0
            or request.get("reused_last_response")
            or len(body_hash) != 64
            or body_bytes < 0
        ):
            raise ValueError(
                f"line {line} is not a single successful immutable GET"
            )
        expected_output = workload_rows[line]
        if (
            str(expected_output.get("digest")) != str(row.get("output_sha256"))
            or int(expected_output.get("status", 0)) != 200
        ):
            raise ValueError(f"line {line} workload output does not match oracle")
        container = body_container(archive, body_hash)
        body, evidence = verify_decompress(container, body_hash, body_bytes)
        destination = output / "bodies" / container.name
        if body_hash not in copied_bodies:
            copy_receipt = copy_verified(container, destination)
            copy_receipt.update(evidence)
            copied_bodies[body_hash] = copy_receipt
        else:
            prior = copied_bodies[body_hash]
            if prior["body_bytes"] != len(body):
                raise ValueError(f"body {body_hash} changed across endpoints")
        endpoint = {
            "line": line,
            "source_url": row["url"],
            "method": method,
            "requested_url": requested_url,
            "status": status,
            "final_url": str(request.get("final_url") or requested_url),
            "content_type": str(
                row.get("upstream_response_content_type")
                or "application/octet-stream"
            ),
            "body_path": f"bodies/{container.name}",
            "body_sha256": body_hash,
            "body_bytes": body_bytes,
            "output_sha256": str(row["output_sha256"]),
            "output_bytes": int(expected_output["bytes"]),
        }
        identity = (
            status, endpoint["final_url"], endpoint["content_type"],
            body_hash, body_bytes,
        )
        exact_key = (method, requested_url)
        normalized_key = (method, url_key(requested_url))
        if exact_key in exact_seen and exact_seen[exact_key] != identity:
            raise ValueError(f"ambiguous exact endpoint {exact_key}")
        if normalized_key in normalized_seen and normalized_seen[normalized_key] != identity:
            raise ValueError(f"ambiguous normalized endpoint {normalized_key}")
        exact_seen[exact_key] = identity
        normalized_seen[normalized_key] = identity
        endpoints.append(endpoint)

    selected_path = output / "oracle-selected.jsonl"
    with selected_path.open("x", encoding="utf-8") as stream:
        stream.writelines(selected_records)
        stream.flush()
        os.fsync(stream.fileno())
    input_receipts["oracle_selected"] = {
        "snapshot": str(selected_path),
        "bytes": selected_path.stat().st_size,
        "sha256": sha256_file(selected_path),
        "source": str(oracle_results),
        "source_sha256": sha256_file(oracle_results),
    }
    bundle = {
        "schema": BUNDLE_SCHEMA,
        "created_utc": utc_now(),
        "selection_policy": "one-successful-get-no-redirect-retry-or-error-v1",
        "selected_lines": selected_lines,
        "endpoints": endpoints,
        "bodies": copied_bodies,
        "inputs": input_receipts,
    }
    manifest_path = output / "manifest.json"
    atomic_json(manifest_path, bundle)
    return manifest_path


class ReplayState:
    def __init__(self, bundle: Path) -> None:
        self.bundle_path = bundle.resolve()
        self.bundle = load_json(self.bundle_path)
        if self.bundle.get("schema") != BUNDLE_SCHEMA:
            raise ValueError("unsupported archive broker bundle schema")
        self.root = self.bundle_path.parent
        self.exact: dict[tuple[str, str], dict[str, Any]] = {}
        self.normalized: dict[
            tuple[str, tuple[str, str, str, str]], dict[str, Any]
        ] = {}
        self.bodies: dict[str, bytes] = {}
        for endpoint in self.bundle.get("endpoints", []):
            digest = str(endpoint["body_sha256"])
            relative = Path(str(endpoint["body_path"]))
            path = (self.root / relative).resolve()
            path.relative_to(self.root)
            if digest not in self.bodies:
                body, _evidence = verify_decompress(
                    path, digest, int(endpoint["body_bytes"])
                )
                self.bodies[digest] = body
            exact_key = (str(endpoint["method"]), str(endpoint["requested_url"]))
            normalized_key = (
                str(endpoint["method"]), url_key(str(endpoint["requested_url"]))
            )
            if exact_key in self.exact and self.exact[exact_key] != endpoint:
                raise ValueError(f"ambiguous exact bundle endpoint {exact_key}")
            if (
                normalized_key in self.normalized
                and self.normalized[normalized_key] != endpoint
            ):
                raise ValueError(
                    f"ambiguous normalized bundle endpoint {normalized_key}"
                )
            self.exact[exact_key] = endpoint
            self.normalized[normalized_key] = endpoint
        if not self.exact:
            raise ValueError("archive broker bundle has no endpoints")
        self.lock = threading.RLock()
        self.generation = 0
        self.started_ns = time.monotonic_ns()
        self.active = 0
        self.calls: Counter[str] = Counter()
        self.match_modes: Counter[str] = Counter()
        self.misses: list[dict[str, Any]] = []
        self.malformed_logical_urls: list[dict[str, Any]] = []
        self.write_errors: list[dict[str, Any]] = []

    def reset(self) -> dict[str, Any]:
        with self.lock:
            if self.active != 0:
                raise RuntimeError(
                    f"cannot reset archive broker with {self.active} active requests"
                )
            self.generation += 1
            self.started_ns = time.monotonic_ns()
            self.calls = Counter()
            self.match_modes = Counter()
            self.misses = []
            self.malformed_logical_urls = []
            self.write_errors = []
            return self.report()

    def begin(self) -> None:
        with self.lock:
            self.active += 1

    def finish(self) -> None:
        with self.lock:
            self.active -= 1

    def find(self, method: str, requested_url: str) -> tuple[dict[str, Any] | None, str]:
        with self.lock:
            endpoint = self.exact.get((method, requested_url))
            mode = "exact"
            if endpoint is None:
                endpoint = self.normalized.get((method, url_key(requested_url)))
                mode = "normalized"
            if endpoint is None:
                self.misses.append({
                    "method": method,
                    "requested_url": requested_url,
                    "monotonic_ns": time.monotonic_ns(),
                })
                return None, "miss"
            self.calls[f"line-{int(endpoint['line'])}"] += 1
            self.match_modes[mode] += 1
            return endpoint, mode

    def malformed(self, value: str, error: Exception) -> None:
        with self.lock:
            self.malformed_logical_urls.append({
                "value": value[:512],
                "error": f"{type(error).__name__}: {error}",
                "monotonic_ns": time.monotonic_ns(),
            })

    def write_error(self, endpoint: dict[str, Any], error: Exception) -> None:
        with self.lock:
            self.write_errors.append({
                "line": endpoint["line"],
                "error": f"{type(error).__name__}: {error}",
                "monotonic_ns": time.monotonic_ns(),
            })

    def report(self) -> dict[str, Any]:
        with self.lock:
            return {
                "schema": REPORT_SCHEMA,
                "generation": self.generation,
                "started_monotonic_ns": self.started_ns,
                "reported_monotonic_ns": time.monotonic_ns(),
                "active": self.active,
                "calls": dict(sorted(self.calls.items())),
                "call_count": sum(self.calls.values()),
                "match_modes": dict(sorted(self.match_modes.items())),
                "misses": list(self.misses),
                "malformed_logical_urls": list(self.malformed_logical_urls),
                "write_errors": list(self.write_errors),
                "bundle": str(self.bundle_path),
                "bundle_sha256": sha256_file(self.bundle_path),
            }


class ReplayHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state: ReplayState
    upstream_scheme: str

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def json_response(self, status: int, value: Any) -> None:
        body = (json.dumps(value, sort_keys=True) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def is_control(self) -> bool:
        host = self.headers.get("Host", "").partition(":")[0]
        return host in {"127.0.0.1", "localhost"}

    def serve_control(self) -> bool:
        if not self.is_control():
            return False
        path = urlsplit(self.path).path
        if path == "/__archive_replay_health":
            self.json_response(200, {
                "status": "ok",
                "endpoints": len(self.state.exact),
                "bundle_sha256": sha256_file(self.state.bundle_path),
            })
            return True
        if path == "/__archive_replay_report":
            self.json_response(200, self.state.report())
            return True
        if path == "/__archive_replay_reset":
            try:
                self.json_response(200, self.state.reset())
            except RuntimeError as error:
                self.json_response(409, {"error": str(error)})
            return True
        return False

    def serve_replay(self) -> None:
        if self.serve_control():
            return
        logical_hex = self.headers.get("X-Fastbed-Fixture-Requested-Hex", "")
        if logical_hex:
            try:
                requested_url = bytes.fromhex(logical_hex).decode("utf-8")
            except (ValueError, UnicodeDecodeError) as error:
                self.state.malformed(logical_hex, error)
                self.send_error(400, "malformed logical URL")
                return
        else:
            host = self.headers.get("Host", "")
            requested_url = f"{self.upstream_scheme}://{host}{self.path}"
        self.state.begin()
        try:
            endpoint, match_mode = self.state.find(self.command, requested_url)
            if endpoint is None:
                self.send_response(598)
                self.send_header("X-Fastbed-Fixture-Miss", "1")
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            body = self.state.bodies[str(endpoint["body_sha256"])]
            self.send_response(int(endpoint["status"]))
            self.send_header("Content-Type", str(endpoint["content_type"]))
            self.send_header(
                "X-Fastbed-Fixture-Final-Url", str(endpoint["final_url"])
            )
            self.send_header("X-Fastbed-Archive-Match", match_mode)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, OSError) as error:
                    self.state.write_error(endpoint, error)
        finally:
            self.state.finish()

    do_GET = serve_replay
    do_HEAD = serve_replay
    do_POST = serve_replay


def make_server(state: ReplayState, address: str, port: int, scheme: str,
                cert: Path | None = None, key: Path | None = None):
    handler = type(
        f"{scheme.upper()}ArchiveReplayHandler",
        (ReplayHandler,),
        {"state": state, "upstream_scheme": scheme},
    )
    instance = http.server.ThreadingHTTPServer((address, port), handler)
    instance.daemon_threads = True
    if scheme == "https":
        assert cert is not None and key is not None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        instance.socket = context.wrap_socket(instance.socket, server_side=True)
    return instance


def serve(args: argparse.Namespace) -> int:
    if args.bundle_input is not None:
        if any(value is not None for value in (
            args.oracle_results, args.archive, args.workload_manifest,
            args.cert, args.key, args.bundle_output,
        )):
            raise ValueError("--bundle-input cannot be combined with source inputs")
        bundle_manifest = args.bundle_input.resolve() / "manifest.json"
        cert = args.bundle_input.resolve() / "fixture-cert.pem"
        key = args.bundle_input.resolve() / "fixture-key.pem"
    else:
        required = {
            "oracle_results": args.oracle_results,
            "archive": args.archive,
            "workload_manifest": args.workload_manifest,
            "cert": args.cert,
            "key": args.key,
            "bundle_output": args.bundle_output,
        }
        missing = sorted(name for name, value in required.items() if value is None)
        if missing:
            raise ValueError(f"missing source inputs: {missing}")
        bundle_manifest = build_bundle(
            args.oracle_results.resolve(), args.archive.resolve(),
            args.workload_manifest.resolve(), args.cert.resolve(),
            args.key.resolve(), args.bundle_output.resolve(),
        )
        cert = bundle_manifest.parent / "fixture-cert.pem"
        key = bundle_manifest.parent / "fixture-key.pem"
    state = ReplayState(bundle_manifest)
    receipt = (
        args.receipt.resolve()
        if args.receipt is not None
        else bundle_manifest.parent / "final-report.json"
    )
    servers = [
        make_server(state, args.address, args.http_port, "http"),
        make_server(state, args.address, args.https_port, "https", cert, key),
    ]
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in servers
    ]
    stopped = threading.Event()

    def request_stop(_signum: int, _frame: Any) -> None:
        stopped.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    for thread in threads:
        thread.start()
    try:
        stopped.wait()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=10)
        report = state.report()
        report.update({
            "status": "passed" if (
                report["active"] == 0
                and not report["misses"]
                and not report["malformed_logical_urls"]
                and not report["write_errors"]
            ) else "failed",
            "finished_utc": utc_now(),
        })
        atomic_json(receipt, report)
    return 0 if report["status"] == "passed" else 1


def control(args: argparse.Namespace) -> int:
    path = {
        "health": "/__archive_replay_health",
        "reset": "/__archive_replay_reset",
        "report": "/__archive_replay_report",
        "assert-clean": "/__archive_replay_report",
    }[args.action]
    connection = http.client.HTTPConnection(args.host, args.port, timeout=args.timeout)
    try:
        connection.request("GET", path, headers={"Connection": "close"})
        response = connection.getresponse()
        body = response.read()
    finally:
        connection.close()
    if response.status != 200:
        raise RuntimeError(f"archive broker control returned HTTP {response.status}")
    value = json.loads(body)
    if args.action == "assert-clean":
        failures: list[str] = []
        if int(value.get("active", -1)) != 0:
            failures.append(f"active={value.get('active')}")
        if int(value.get("call_count", 0)) < args.min_calls:
            failures.append(
                f"call_count={value.get('call_count')} < {args.min_calls}"
            )
        for key in ("misses", "malformed_logical_urls", "write_errors"):
            if value.get(key):
                failures.append(f"{key}={len(value[key])}")
        if failures:
            print(json.dumps(value, indent=2, sort_keys=True))
            raise RuntimeError("archive broker assertion failed: " + ", ".join(failures))
    print(json.dumps(value, indent=2, sort_keys=True))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve_parser = subparsers.add_parser("serve")
    serve_parser.add_argument("--oracle-results", type=Path)
    serve_parser.add_argument("--archive", type=Path)
    serve_parser.add_argument("--workload-manifest", type=Path)
    serve_parser.add_argument("--cert", type=Path)
    serve_parser.add_argument("--key", type=Path)
    serve_parser.add_argument("--bundle-output", type=Path)
    serve_parser.add_argument("--bundle-input", type=Path)
    serve_parser.add_argument("--receipt", type=Path)
    serve_parser.add_argument("--address", default="127.0.0.1")
    serve_parser.add_argument("--http-port", type=int, required=True)
    serve_parser.add_argument("--https-port", type=int, required=True)

    control_parser = subparsers.add_parser("control")
    control_parser.add_argument(
        "action", choices=("health", "reset", "report", "assert-clean")
    )
    control_parser.add_argument("--host", default="127.0.0.1")
    control_parser.add_argument("--port", type=int, required=True)
    control_parser.add_argument("--timeout", type=float, default=10.0)
    control_parser.add_argument("--min-calls", type=int, default=1)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    return serve(args) if args.command == "serve" else control(args)


if __name__ == "__main__":
    raise SystemExit(main())

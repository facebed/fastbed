#!/usr/bin/env python3
"""Loopback-only programmable upstream for Fastbed robustness E2E.

The runner writes an immutable response plan and selects one case at a time.
Every request is served from saved bytes below the artifact root; this process
never resolves or connects to a non-loopback address.
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import threading
import time
from typing import Any
from urllib.parse import urlsplit


class BrokerState:
    def __init__(self, root: Path, plan_path: Path) -> None:
        self.root = root.resolve()
        plan_path = plan_path.resolve()
        plan_path.relative_to(self.root)
        plan = json.loads(plan_path.read_text(encoding="utf-8"))
        if plan.get("schema") != 1 or not isinstance(plan.get("cases"), dict):
            raise ValueError("unsupported broker plan")
        self.cases: dict[str, dict[str, Any]] = plan["cases"]
        self.lock = threading.RLock()
        self.selected: str | None = None
        self.selection = 0
        self.events: list[dict[str, Any]] = []

    def select(self, case_id: str) -> dict[str, Any]:
        if case_id not in self.cases:
            raise KeyError(f"unknown broker case: {case_id}")
        with self.lock:
            self.selected = case_id
            self.selection += 1
            return {"case": case_id, "selection": self.selection}

    def report(self) -> dict[str, Any]:
        with self.lock:
            return {
                "selected": self.selected,
                "selection": self.selection,
                "events": [dict(event) for event in self.events],
            }

    def response_for(self, logical_url: str) -> tuple[str, dict[str, Any]]:
        with self.lock:
            case_id = self.selected
            if case_id is None:
                raise KeyError("no broker case selected")
            case = self.cases[case_id]
            for rule in case.get("rules", []):
                if rule.get("url") == logical_url:
                    return case_id, rule["response"]
            return case_id, case["default"]

    def body(self, response: dict[str, Any]) -> bytes:
        relative = response.get("body_path")
        if relative is None:
            return b""
        candidate = (self.root / str(relative)).resolve()
        candidate.relative_to(self.root)
        return candidate.read_bytes()

    def event_start(self, case_id: str, method: str, logical_url: str,
                    response: dict[str, Any], body_bytes: int) -> int:
        event = {
            "sequence": 0,
            "case": case_id,
            "method": method,
            "logical_url": logical_url,
            "status": int(response.get("status", 200)),
            "mode": str(response.get("mode", "normal")),
            "body_bytes": body_bytes,
            "bytes_written": 0,
            "outcome": "started",
        }
        with self.lock:
            event["sequence"] = len(self.events) + 1
            self.events.append(event)
            return len(self.events) - 1

    def event_finish(self, index: int, bytes_written: int, outcome: str) -> None:
        with self.lock:
            self.events[index]["bytes_written"] = bytes_written
            self.events[index]["outcome"] = outcome


class FixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "FastbedAdversarialFixture/1"
    state: BrokerState
    upstream_scheme: str

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _send_json(self, status: int, payload: object) -> None:
        body = (json.dumps(payload, sort_keys=True) + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _control(self) -> bool:
        host = self.headers.get("Host", "").partition(":")[0]
        path = urlsplit(self.path).path
        if host not in {"127.0.0.1", "localhost"}:
            return False
        if path == "/__ready" and self.command == "GET":
            self._send_json(200, {"status": "ok"})
            return True
        if path == "/__report" and self.command == "GET":
            self._send_json(200, self.state.report())
            return True
        if path == "/__select" and self.command == "POST":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 4096:
                    raise ValueError("invalid control body length")
                payload = json.loads(self.rfile.read(length))
                self._send_json(200, self.state.select(str(payload["case"])))
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})
            return True
        return False

    def _logical_url(self) -> str:
        encoded = self.headers.get("X-Fastbed-Fixture-Requested-Hex")
        if encoded:
            try:
                return bytes.fromhex(encoded).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                pass
        return f"{self.upstream_scheme}://{self.headers.get('Host', '')}{self.path}"

    def _serve(self) -> None:
        if self._control():
            return
        logical_url = self._logical_url()
        try:
            case_id, response = self.state.response_for(logical_url)
            body = self.state.body(response)
        except Exception as exc:
            self._send_json(503, {"error": str(exc)})
            return

        status = int(response.get("status", 200))
        headers = response.get("headers", {})
        if not isinstance(headers, dict):
            self._send_json(500, {"error": "invalid response headers"})
            return
        mode = str(response.get("mode", "normal"))
        declared_length = int(response.get("declared_length", len(body)))
        write_limit = int(response.get("write_limit", len(body)))
        write_limit = max(0, min(write_limit, len(body)))
        event = self.state.event_start(
            case_id, self.command, logical_url, response, len(body))
        written = 0
        outcome = "complete"
        try:
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(str(name), str(value))
            self.send_header("Content-Length", str(declared_length))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                if mode == "slow":
                    chunk_size = int(response.get("chunk_size", 4096))
                    delay = float(response.get("chunk_delay_seconds", 0.005))
                    for offset in range(0, write_limit, chunk_size):
                        chunk = body[offset:min(offset + chunk_size, write_limit)]
                        self.wfile.write(chunk)
                        self.wfile.flush()
                        written += len(chunk)
                        time.sleep(delay)
                else:
                    payload = body[:write_limit]
                    self.wfile.write(payload)
                    self.wfile.flush()
                    written = len(payload)
                if mode == "truncate":
                    outcome = "truncated"
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
            outcome = "peer_closed"
        finally:
            self.close_connection = True
            self.state.event_finish(event, written, outcome)

    do_GET = _serve
    do_HEAD = _serve
    do_POST = _serve


def make_server(state: BrokerState, port: int, scheme: str,
                cert: Path | None, key: Path | None) -> FixtureServer:
    handler = type(
        f"{scheme.upper()}FixtureHandler",
        (FixtureHandler,),
        {"state": state, "upstream_scheme": scheme},
    )
    server = FixtureServer(("127.0.0.1", port), handler)
    if scheme == "https":
        if cert is None or key is None:
            raise ValueError("HTTPS fixture server requires a certificate and key")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("plan", type=Path)
    parser.add_argument("--http-port", type=int, required=True)
    parser.add_argument("--https-port", type=int, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    args = parser.parse_args()

    interfaces = sorted(name for _index, name in socket.if_nameindex())
    if interfaces != ["lo"]:
        parser.error(f"broker requires an isolated loopback-only namespace: {interfaces}")
    state = BrokerState(args.root, args.plan)
    httpd = make_server(state, args.http_port, "http", None, None)
    httpsd = make_server(state, args.https_port, "https", args.cert, args.key)
    threads = [
        threading.Thread(target=httpd.serve_forever, name="fixture-http", daemon=True),
        threading.Thread(target=httpsd.serve_forever, name="fixture-https", daemon=True),
    ]
    for thread in threads:
        thread.start()
    print(json.dumps({
        "event": "ready",
        "pid": os.getpid(),
        "http_port": args.http_port,
        "https_port": args.https_port,
    }, sort_keys=True), flush=True)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda _sig, _frame: stop.set())
    signal.signal(signal.SIGINT, lambda _sig, _frame: stop.set())
    while not stop.wait(0.25):
        pass
    httpd.shutdown()
    httpsd.shutdown()
    httpd.server_close()
    httpsd.server_close()
    for thread in threads:
        thread.join(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

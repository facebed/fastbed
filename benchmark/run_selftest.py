#!/usr/bin/env python3
"""Process-level self-test for the independent HTTP load generator.

This starts a real HTTP/1.1 server, compiles the C program, exercises closed and
open schedules, keep-alive, FIN, RST, chunked framing, explicit source binding,
and a negative digest control, then seals a replayable artifact.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time
from typing import Any


SCHEMA = "fastbed-loadgen-process-selftest-v1"
FIXED_BODY = ("fastbed-loadgen-fixed-\u2603-" * 37).encode()
CHUNKED_BODY = bytes(range(256)) * 7 + b"chunk-boundary"


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "fastbed-loadgen-selftest"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def setup(self) -> None:
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _fragmented(self, *pieces: bytes) -> None:
        for piece in pieces:
            self.wfile.write(piece)
            self.wfile.flush()
            time.sleep(0.0001)

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        self.server.record_peer(self.client_address[0])
        if self.path == "/fixed":
            body = FIXED_BODY
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/chunked":
            self.send_response(201)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            pieces = (CHUNKED_BODY[:13], CHUNKED_BODY[13:777], CHUNKED_BODY[777:])
            for piece in pieces:
                size = f"{len(piece):x};selftest=yes".encode()
                midpoint = max(1, len(piece) // 2)
                self._fragmented(
                    size[:1], size[1:], b"\r", b"\n",
                    piece[:midpoint], piece[midpoint:], b"\r", b"\n",
                )
            self._fragmented(
                b"0", b"\r", b"\n", b"X-Selftest:", b" yes\r\n", b"\r\n"
            )
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.expected_peer_resets = 0
        self._reset_lock = threading.Lock()
        self.observed_sources: dict[str, int] = {}

    def record_peer(self, address: str) -> None:
        with self._reset_lock:
            self.observed_sources[address] = (
                self.observed_sources.get(address, 0) + 1
            )

    def handle_error(self, request: socket.socket,
                     client_address: tuple[str, int]) -> None:
        error = sys.exception()
        if isinstance(error, (BrokenPipeError, ConnectionResetError)):
            with self._reset_lock:
                self.expected_peer_resets += 1
            return
        super().handle_error(request, client_address)


def read_records(path: Path) -> list[dict[str, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    header = next(line for line in lines if line and not line.startswith("#"))
    keys = header.split("\t")
    records: list[dict[str, str]] = []
    past_header = False
    for line in lines:
        if not past_header:
            if line == header:
                past_header = True
            continue
        if line:
            values = line.split("\t")
            if len(values) != len(keys):
                raise RuntimeError(f"malformed raw record: {line!r}")
            records.append(dict(zip(keys, values, strict=True)))
    return records


def assert_success_artifact(records_path: Path, summary_path: Path,
                            expected: int, mode: str) -> dict[str, Any]:
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    records = read_records(records_path)
    if summary["clock"] != "CLOCK_MONOTONIC_RAW":
        raise RuntimeError("load generator used the wrong clock")
    if summary["requests_completed"] != expected or len(records) != expected:
        raise RuntimeError("raw record count does not match completed requests")
    if summary["ok"] != expected or summary["errors"] != 0:
        raise RuntimeError(f"successful run reported errors: {summary}")
    for row in records:
        scheduled = int(row["scheduled_ns"])
        started = int(row["started_ns"])
        first_byte = int(row["first_byte_ns"])
        ended = int(row["end_ns"])
        if not (0 < scheduled <= started <= first_byte <= ended):
            raise RuntimeError(f"invalid timestamp order: {row}")
        if row["outcome"] != "ok" or len(row["actual_sha256"]) != 64:
            raise RuntimeError(f"unverified successful record: {row}")
        if mode == "fin" and row["reuse_ordinal"] != "0":
            raise RuntimeError("FIN mode unexpectedly reused a connection")
    if summary["mode"] == "open":
        scheduled = [int(row["scheduled_ns"]) for row in records]
        if any(right <= left for left, right in zip(scheduled, scheduled[1:])):
            raise RuntimeError("open-loop schedule is not strictly increasing")
        if summary["max_pending"] < 1:
            raise RuntimeError("open-loop stress did not exercise pending arrivals")
    if mode == "keepalive" and expected > summary["concurrency"]:
        if summary["connections_opened"] > summary["concurrency"]:
            raise RuntimeError("keep-alive opened more than the slot count")
        if not any(int(row["reuse_ordinal"]) > 0 for row in records):
            raise RuntimeError("keep-alive case did not reuse a connection")
    return summary


def run_command(command: list[str], stdout: Path, stderr: Path,
                expect: int = 0) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30
    )
    stdout.write_bytes(result.stdout)
    stderr.write_bytes(result.stderr)
    if result.returncode != expect:
        raise RuntimeError(
            f"command exited {result.returncode}, expected {expect}: {command}"
        )
    return result


def seal(output: Path) -> None:
    rows: list[str] = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            relative = path.relative_to(output).as_posix()
            rows.append(f"{sha256_file(path)}  {relative}\n")
    (output / "SHA256SUMS").write_text("".join(rows), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument(
        "--sanitize", action="store_true",
        help="compile the process E2E binary with ASan and UBSan",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parent
    source = root / "http_loadgen.c"
    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"output already exists: {output}")
    output.mkdir(parents=True)

    started = datetime.now(timezone.utc)
    binary = output / "http_loadgen"
    workload = output / "workload.tsv"
    workload.write_text(
        "# fastbed-http-workload-v1\n"
        f"/fixed\t200:{sha256_bytes(FIXED_BODY)}\tfixed\n"
        f"/chunked\t201:{sha256_bytes(CHUNKED_BODY)}\tchunked\n",
        encoding="utf-8",
    )

    compile_base = [
        args.cc, "-std=c17", "-D_GNU_SOURCE", "-Wall", "-Wextra",
        "-Wpedantic", "-Wconversion", "-Wshadow", "-Wformat=2",
        "-Werror=implicit-function-declaration",
    ]
    run_command(
        compile_base + ["-fsyntax-only", str(source)],
        output / "syntax.stdout", output / "syntax.stderr",
    )
    build_flags = ["-O1", "-g"] if args.sanitize else ["-O2", "-g"]
    if args.sanitize:
        build_flags.extend([
            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        ])
    run_command(
        compile_base + build_flags + [str(source), "-o", str(binary), "-lcrypto"],
        output / "compile.stdout", output / "compile.stderr",
    )

    server = Server(("127.0.0.1", 0), Handler)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cases: list[dict[str, Any]] = []
    common = [
        str(binary), "--host", "127.0.0.1", "--port", str(port),
        "--requests-file", str(workload), "--timeout-ms", "3000",
        "--max-body-bytes", str(1024 * 1024), "--seed", "3735928559",
    ]
    try:
        plans = [
            ("closed-keepalive", 257, [
                "--mode", "closed", "--concurrency", "8",
                "--connection-mode", "keepalive",
                "--source-address", "127.0.0.2",
            ], "keepalive"),
            ("open-keepalive", 173, [
                "--mode", "open", "--rate", "800", "--concurrency", "16",
                "--connection-mode", "keepalive",
            ], "keepalive"),
            ("closed-fin", 53, [
                "--mode", "closed", "--concurrency", "7",
                "--connection-mode", "fin",
            ], "fin"),
        ]
        for name, count, extra, connection_mode in plans:
            records = output / f"{name}.records.tsv"
            summary = output / f"{name}.summary.json"
            command = common + [
                "--requests", str(count), "--records", str(records),
                "--summary", str(summary), *extra,
            ]
            run_command(
                command, output / f"{name}.stdout", output / f"{name}.stderr"
            )
            parsed = assert_success_artifact(records, summary, count, connection_mode)
            if name == "closed-keepalive":
                rows = read_records(records)
                if any(row["source_index"] != "0" for row in rows):
                    raise RuntimeError("explicit source bind attribution was lost")
            cases.append({"name": name, "command": command, "summary": parsed})

        rst_name = "closed-rst"
        rst_records = output / f"{rst_name}.records.tsv"
        rst_summary = output / f"{rst_name}.summary.json"
        rst_command = common + [
            "--requests", "41", "--records", str(rst_records),
            "--summary", str(rst_summary), "--mode", "closed",
            "--concurrency", "5", "--connection-mode", "rst",
        ]
        run_command(
            rst_command, output / f"{rst_name}.stdout", output / f"{rst_name}.stderr"
        )
        parsed_rst = json.loads(rst_summary.read_text(encoding="utf-8"))
        rst_rows = read_records(rst_records)
        if parsed_rst["client_rst"] != 41 or len(rst_rows) != 41:
            raise RuntimeError("RST mode did not retain every abort record")
        if any(row["outcome"] != "client_rst" for row in rst_rows):
            raise RuntimeError("RST mode emitted a non-RST outcome")
        cases.append({"name": rst_name, "command": rst_command, "summary": parsed_rst})

        bad_workload = output / "bad-workload.tsv"
        bad_workload.write_text(
            "# fastbed-http-workload-v1\n"
            f"/fixed\t200:{'0' * 64}\tnegative-digest-control\n",
            encoding="utf-8",
        )
        bad_records = output / "negative.records.tsv"
        bad_summary = output / "negative.summary.json"
        bad_command = [
            str(binary), "--host", "127.0.0.1", "--port", str(port),
            "--requests-file", str(bad_workload), "--requests", "1",
            "--concurrency", "1", "--mode", "closed",
            "--connection-mode", "fin", "--records", str(bad_records),
            "--summary", str(bad_summary),
        ]
        run_command(
            bad_command, output / "negative.stdout", output / "negative.stderr",
            expect=1,
        )
        parsed_bad = json.loads(bad_summary.read_text(encoding="utf-8"))
        if parsed_bad["hash_mismatch"] != 1 or parsed_bad["errors"] != 1:
            raise RuntimeError("negative digest control did not fail closed")
        cases.append({"name": "negative-digest", "command": bad_command,
                      "summary": parsed_bad})
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    if server.expected_peer_resets != 41:
        raise RuntimeError(
            "server did not externally observe every requested RST: "
            f"{server.expected_peer_resets}/41"
        )
    if server.observed_sources.get("127.0.0.2") != 257:
        raise RuntimeError(
            "server did not observe the explicit 127.0.0.2 source address "
            "for every source-bind request"
        )

    finished = datetime.now(timezone.utc)
    manifest = {
        "schema": SCHEMA,
        "status": "passed",
        "started_utc": started.isoformat(),
        "finished_utc": finished.isoformat(),
        "source": {"path": str(source), "sha256": sha256_file(source)},
        "binary_sha256": sha256_file(binary),
        "compiler": args.cc,
        "sanitizers": "address,undefined" if args.sanitize else None,
        "server": {"address": "127.0.0.1", "port": port},
        "expected_peer_resets_from_rst_case": server.expected_peer_resets,
        "server_observed_source_counts": server.observed_sources,
        "cases": cases,
    }
    atomic_json(output / "manifest.json", manifest)
    seal(output)
    print(json.dumps({
        "status": "passed", "artifact": str(output),
        "manifest_sha256": sha256_file(output / "manifest.json"),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

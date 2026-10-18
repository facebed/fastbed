#!/usr/bin/env python3
"""Process-level lifecycle verifier for a built Fastbed binary."""

from __future__ import annotations

import argparse
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone


WATCHDOG_SECONDS = 75.0
WATCHDOG_EXIT = 124
CRAWLER_USER_AGENT = (
    "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"
)
ACTIVE_REQUEST_TARGET = (
    "/0jikop/posts/"
    "pfbid03K4RToDUWrXFDATPFYpwuyrHkzsQoCmbx4gxnfX7mBYxBQRchua1L6JpGjoWpxhHl"
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def write_config(path: Path, port: int) -> None:
    path.write_text(
        "host: 127.0.0.1\n"
        f"port: {port}\n"
        "timezone: 7\n"
        "banned_users: []\n"
        "notifier_webhook: ''\n",
        encoding="utf-8",
    )


def command(binary: Path, config: Path, assets: Path,
            crawler_database: Path, replay_http_port: int = 0,
            replay_https_port: int = 0) -> list[str]:
    arguments = [
        str(binary), "--config", str(config),
        "--assets", str(assets),
        "--crawler-db", str(crawler_database),
        "--workers", "2",
        "--allow-stock-curl",
    ]
    if replay_http_port != 0 or replay_https_port != 0:
        if replay_http_port == 0 or replay_https_port == 0:
            raise ValueError("both replay ports are required")
        arguments.extend([
            "--replay-http-port", str(replay_http_port),
            "--replay-https-port", str(replay_https_port),
        ])
    return arguments


class SlowUpstream:
    def __init__(self, certificate: Path, private_key: Path) -> None:
        self.stop_event = threading.Event()
        self.accepted_event = threading.Event()
        self.schemes: list[str] = []
        self._lock = threading.Lock()
        self._connections: list[socket.socket] = []
        self._listeners: list[socket.socket] = []
        self._threads: list[threading.Thread] = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, private_key)
        self.http_port = self._start_listener("http", None)
        self.https_port = self._start_listener("https", context)

    def _start_listener(self, scheme: str,
                        context: ssl.SSLContext | None) -> int:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        listener.settimeout(0.25)
        self._listeners.append(listener)
        thread = threading.Thread(
            target=self._serve, args=(listener, scheme, context),
            name=f"slow-upstream-{scheme}", daemon=True)
        self._threads.append(thread)
        thread.start()
        return int(listener.getsockname()[1])

    def _serve(self, listener: socket.socket, scheme: str,
               context: ssl.SSLContext | None) -> None:
        connection: socket.socket | None = None
        try:
            while not self.stop_event.is_set():
                try:
                    connection, _address = listener.accept()
                    break
                except TimeoutError:
                    continue
            if connection is None:
                return
            connection.settimeout(1.0)
            if context is not None:
                connection = context.wrap_socket(connection, server_side=True)
                connection.settimeout(0.25)
            with self._lock:
                self._connections.append(connection)
            request = bytearray()
            while (b"\r\n\r\n" not in request and
                   not self.stop_event.is_set()):
                try:
                    block = connection.recv(4096)
                except TimeoutError:
                    continue
                if not block:
                    return
                request.extend(block)
                if len(request) > 65536:
                    return
            if b"\r\n\r\n" in request:
                with self._lock:
                    self.schemes.append(scheme)
                self.accepted_event.set()
            self.stop_event.wait(60.0)
        except (OSError, ssl.SSLError):
            if not self.stop_event.is_set():
                return
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass

    def close(self) -> None:
        self.stop_event.set()
        for listener in self._listeners:
            try:
                listener.close()
            except OSError:
                pass
        with self._lock:
            connections = list(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass
        for thread in self._threads:
            thread.join(timeout=2.0)


def wait_ready(process: subprocess.Popen[bytes], port: int,
               timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    last_error = "not attempted"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"Fastbed exited during startup with {process.returncode}")
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.5)
        try:
            connection.request("GET", "/healthz")
            response = connection.getresponse()
            body = response.read()
            if response.status == 200 and body:
                return
            last_error = f"HTTP {response.status}, {len(body)} bytes"
        except OSError as exc:
            last_error = repr(exc)
        finally:
            connection.close()
        time.sleep(0.05)
    raise RuntimeError(f"Fastbed did not become ready: {last_error}")


def mem_open_result(pid: int) -> dict[str, object]:
    try:
        descriptor = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    except OSError as exc:
        return {
            "opened": False,
            "errno": exc.errno,
            "error": exc.strerror,
        }
    else:
        os.close(descriptor)
        return {"opened": True, "errno": 0, "error": ""}


def inspect_linux_security(pid: int) -> dict[str, object]:
    limits_text = Path(f"/proc/{pid}/limits").read_text(encoding="utf-8")
    core_fields: list[str] | None = None
    for line in limits_text.splitlines():
        if line.startswith("Max core file size"):
            core_fields = line.split()
            break
    if core_fields is None or len(core_fields) < 7:
        raise RuntimeError("/proc limits has no Max core file size row")
    core_soft, core_hard = core_fields[-3], core_fields[-2]

    sleep = shutil.which("sleep")
    if sleep is None:
        raise RuntimeError("sleep executable is unavailable for dumpable control")
    control = subprocess.Popen([sleep, "30"])
    try:
        control_access = mem_open_result(control.pid)
    finally:
        control.terminate()
        control.wait(timeout=5)
    fastbed_access = mem_open_result(pid)
    status_text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    core_dumping = re.search(r"^CoreDumping:\s+(\d+)$", status_text,
                             flags=re.MULTILINE)
    result: dict[str, object] = {
        "core_soft": core_soft,
        "core_hard": core_hard,
        "dumpable_control_mem": control_access,
        "fastbed_mem": fastbed_access,
        "core_dumping": (
            int(core_dumping.group(1)) if core_dumping is not None else None
        ),
    }
    if core_soft != "0" or core_hard != "0":
        raise RuntimeError(
            f"core limits are not zero: {(core_soft, core_hard)}")
    if not bool(control_access["opened"]):
        raise RuntimeError(
            "dumpable child control was not readable through /proc/PID/mem: "
            f"{control_access}")
    if bool(fastbed_access["opened"]) or fastbed_access["errno"] not in {
        errno.EACCES, errno.EPERM
    }:
        raise RuntimeError(
            "Fastbed /proc/PID/mem was not denied as non-dumpable: "
            f"{fastbed_access}")
    return result


def launch_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment["ASAN_OPTIONS"] = (
        "abort_on_error=1:halt_on_error=1:detect_leaks=1:"
        "allocator_may_return_null=0:strict_string_checks=1"
    )
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    return environment


def normal_term_case(binary: Path, assets: Path, crawler_database: Path,
                     output: Path) -> dict[str, object]:
    case_directory = output / "normal-term"
    case_directory.mkdir()
    port = reserve_port()
    config = case_directory / "config.yaml"
    log_path = case_directory / "fastbed.log"
    write_config(config, port)
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            command(binary, config, assets, crawler_database),
            stdout=log,
            stderr=subprocess.STDOUT,
            env=launch_environment(),
        )
        try:
            wait_ready(process, port)
            security = inspect_linux_security(process.pid)
            started = time.monotonic()
            process.send_signal(signal.SIGTERM)
            exit_code = process.wait(timeout=20)
            elapsed = time.monotonic() - started
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    if exit_code != 0:
        raise RuntimeError(f"normal SIGTERM exited {exit_code}")
    if "[INFO] shutting down" not in log_text:
        raise RuntimeError("normal SIGTERM log has no shutdown marker")
    if "AddressSanitizer" in log_text or "runtime error:" in log_text:
        raise RuntimeError("sanitizer diagnostic detected during normal SIGTERM")
    return {
        "name": "normal-term-and-proc-hardening",
        "passed": True,
        "exit_code": exit_code,
        "shutdown_elapsed_seconds": round(elapsed, 6),
        "security": security,
        "log": str(log_path.relative_to(output)),
    }


def active_request_term_case(binary: Path, assets: Path,
                             crawler_database: Path,
                             output: Path) -> dict[str, object]:
    case_directory = output / "active-request-term"
    case_directory.mkdir()
    port = reserve_port()
    config = case_directory / "config.yaml"
    log_path = case_directory / "fastbed.log"
    certificate = case_directory / "fixture-cert.pem"
    private_key = case_directory / "fixture-key.pem"
    openssl_log = case_directory / "openssl.log"
    write_config(config, port)
    with openssl_log.open("wb") as log:
        generated = subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(private_key), "-out", str(certificate),
            "-days", "1", "-subj", "/CN=localhost",
        ], stdout=log, stderr=subprocess.STDOUT, check=False)
    if generated.returncode != 0:
        raise RuntimeError(
            f"openssl certificate generation exited {generated.returncode}")

    upstream = SlowUpstream(certificate, private_key)
    client_result: dict[str, object] = {"completed": False}

    def request() -> None:
        connection = http.client.HTTPConnection(
            "127.0.0.1", port, timeout=60.0)
        try:
            connection.request(
                "GET", ACTIVE_REQUEST_TARGET,
                headers={"User-Agent": CRAWLER_USER_AGENT})
            response = connection.getresponse()
            body = response.read()
            client_result.update({
                "completed": True,
                "status": response.status,
                "body_bytes": len(body),
            })
        except Exception as exc:
            client_result.update({
                "completed": True,
                "error": f"{type(exc).__name__}: {exc}",
            })
        finally:
            connection.close()

    client = threading.Thread(
        target=request, name="active-request-client", daemon=True)
    client_started = False
    exit_code: int | None = None
    elapsed = 0.0
    security: dict[str, object] = {}
    with log_path.open("wb") as log:
        process = subprocess.Popen(
            command(binary, config, assets, crawler_database,
                    upstream.http_port, upstream.https_port),
            stdout=log,
            stderr=subprocess.STDOUT,
            env=launch_environment(),
        )
        try:
            wait_ready(process, port)
            security = inspect_linux_security(process.pid)
            client.start()
            client_started = True
            if not upstream.accepted_event.wait(timeout=10.0):
                raise RuntimeError(
                    "active request never reached the slow upstream")
            time.sleep(0.1)
            if not client.is_alive() or process.poll() is not None:
                raise RuntimeError(
                    "active request was not outstanding at SIGTERM")
            started = time.monotonic()
            process.send_signal(signal.SIGTERM)
            exit_code = process.wait(timeout=45.0)
            elapsed = time.monotonic() - started
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            upstream.close()
            if client_started:
                client.join(timeout=5.0)
    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    if exit_code != 0:
        raise RuntimeError(f"active-request SIGTERM exited {exit_code}")
    if client.is_alive():
        raise RuntimeError("active request client remained blocked after exit")
    if "https" not in upstream.schemes:
        raise RuntimeError(
            f"active request did not reach TLS upstream: {upstream.schemes}")
    if "[INFO] shutting down" not in log_text:
        raise RuntimeError("active-request log has no shutdown marker")
    if "AddressSanitizer" in log_text or "runtime error:" in log_text:
        raise RuntimeError(
            "sanitizer diagnostic detected during active-request shutdown")
    return {
        "name": "active-request-term",
        "passed": True,
        "exit_code": exit_code,
        "shutdown_elapsed_seconds": round(elapsed, 6),
        "upstream_schemes": list(upstream.schemes),
        "client": client_result,
        "security": security,
        "log": str(log_path.relative_to(output)),
    }


def fill_fifo(write_descriptor: int) -> int:
    payload = b"stuck-local-sink\n" * 4096
    total = 0
    while True:
        try:
            written = os.write(write_descriptor, payload)
        except BlockingIOError:
            return total
        if written <= 0:
            raise RuntimeError("FIFO filler made no progress")
        total += written


def stuck_sink_case(binary: Path, assets: Path, crawler_database: Path,
                    output: Path) -> dict[str, object]:
    case_directory = output / "stuck-local-sink"
    case_directory.mkdir()
    port = reserve_port()
    config = case_directory / "config.yaml"
    fifo_path = case_directory / "stderr.fifo"
    captured_path = case_directory / "stuck-sink-bytes.bin"
    write_config(config, port)
    os.mkfifo(fifo_path, 0o600)
    read_descriptor = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
    child_writer = os.open(fifo_path, os.O_WRONLY)
    filler = -1
    process: subprocess.Popen[bytes] | None = None
    security: dict[str, object] = {}
    filled_bytes = 0
    elapsed = 0.0
    exit_code: int | None = None
    captured = bytearray()
    try:
        process = subprocess.Popen(
            command(binary, config, assets, crawler_database),
            stdout=child_writer,
            stderr=subprocess.STDOUT,
            env=launch_environment(),
        )
        os.close(child_writer)
        child_writer = -1
        wait_ready(process, port)
        security = inspect_linux_security(process.pid)
        filler = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)
        filled_bytes = fill_fifo(filler)
        started = time.monotonic()
        process.send_signal(signal.SIGTERM)
        exit_code = process.wait(timeout=WATCHDOG_SECONDS + 15.0)
        elapsed = time.monotonic() - started
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if child_writer >= 0:
            os.close(child_writer)
        if filler >= 0:
            os.close(filler)
        while True:
            try:
                block = os.read(read_descriptor, 65536)
            except BlockingIOError:
                break
            if not block:
                break
            captured.extend(block)
        os.close(read_descriptor)
        fifo_path.unlink(missing_ok=True)
        captured_path.write_bytes(captured)
    if exit_code != WATCHDOG_EXIT:
        raise RuntimeError(
            f"stuck local sink exited {exit_code}, expected {WATCHDOG_EXIT}")
    if elapsed < WATCHDOG_SECONDS - 1.0 or elapsed > WATCHDOG_SECONDS + 8.0:
        raise RuntimeError(
            f"watchdog elapsed {elapsed:.3f}s, expected about {WATCHDOG_SECONDS}s")
    if b"[INFO] shutting down\n" in captured:
        raise RuntimeError(
            "stuck sink unexpectedly accepted the post-signal shutdown log")
    return {
        "name": "stuck-local-sink-hard-watchdog",
        "passed": True,
        "exit_code": exit_code,
        "shutdown_elapsed_seconds": round(elapsed, 6),
        "watchdog_seconds": WATCHDOG_SECONDS,
        "fifo_fill_bytes": filled_bytes,
        "captured_sink_bytes": len(captured),
        "security": security,
        "capture": str(captured_path.relative_to(output)),
    }


def write_checksums(output: Path) -> None:
    checksum_path = output / "SHA256SUMS"
    lines = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path != checksum_path:
            lines.append(f"{sha256(path)}  {path.relative_to(output)}")
    checksum_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--crawler-db", required=True, type=Path)
    parser.add_argument("--skip-watchdog", action="store_true")
    parser.add_argument("--require-sanitizers", action="store_true")
    args = parser.parse_args()

    binary = args.binary.resolve()
    output = args.output.resolve()
    assets = args.assets.resolve()
    crawler_database = args.crawler_db.resolve()
    if output.exists():
        parser.error(f"output already exists: {output}")
    for path, label in ((binary, "binary"), (assets, "assets"),
                        (crawler_database, "crawler database")):
        if not path.exists():
            parser.error(f"{label} does not exist: {path}")
    binary_bytes = binary.read_bytes()
    shared_sanitizers = (
        b"libasan.so" in binary_bytes and b"libubsan.so" in binary_bytes)
    static_sanitizers = (
        b"__asan_init" in binary_bytes and
        b"__ubsan_handle_type_mismatch_v1" in binary_bytes)
    sanitizers_detected = shared_sanitizers or static_sanitizers
    sanitizer_linkage = (
        "shared" if shared_sanitizers else
        "static" if static_sanitizers else
        "none"
    )
    if args.require_sanitizers and not sanitizers_detected:
        parser.error(
            "--require-sanitizers needs ASan+UBSan instrumentation")
    output.mkdir(parents=True)
    runner_source = Path(__file__).resolve()
    runner_copy = output / "runner.py"
    binary_copy = output / "fastbed"
    assets_copy = output / "assets"
    crawler_copy = output / "crawler-user-agents.json"
    shutil.copy2(runner_source, runner_copy)
    shutil.copy2(binary, binary_copy)
    shutil.copytree(assets, assets_copy)
    shutil.copy2(crawler_database, crawler_copy)

    source_hashes: dict[str, str] = {}
    source_root = runner_source.parent.parent
    for relative in (
        "src/main.c", "src/server.c", "src/app.c", "src/notifier.c",
        "include/fastbed/server.h",
    ):
        source_path = source_root / relative
        if source_path.is_file():
            source_hashes[relative] = sha256(source_path)

    invocation = [
        "python3", "runner.py", "--binary", "./fastbed",
        "--output", "./replay-output", "--assets", "./assets",
        "--crawler-db", "./crawler-user-agents.json",
    ]
    if args.skip_watchdog:
        invocation.append("--skip-watchdog")
    if args.require_sanitizers:
        invocation.append("--require-sanitizers")
    (output / "REPLAY.txt").write_text(
        "Run from this artifact directory (the output path must not exist):\n\n"
        f"{shlex.join(invocation)}\n",
        encoding="utf-8",
    )

    manifest: dict[str, object] = {
        "schema": 1,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "source_binary": str(binary),
        "binary": "fastbed",
        "binary_sha256": sha256(binary_copy),
        "source_sha256": source_hashes,
        "skip_watchdog": args.skip_watchdog,
        "sanitizers_detected": sanitizers_detected,
        "sanitizer_linkage": sanitizer_linkage,
        "sanitizers_required": args.require_sanitizers,
        "kernel": " ".join(os.uname()),
        "cases": [],
        "passed": False,
    }
    exit_code = 1
    try:
        cases = manifest["cases"]
        assert isinstance(cases, list)
        cases.append(normal_term_case(
            binary_copy, assets_copy, crawler_copy, output))
        cases.append(active_request_term_case(
            binary_copy, assets_copy, crawler_copy, output))
        if not args.skip_watchdog:
            cases.append(stuck_sink_case(
                binary_copy, assets_copy, crawler_copy, output))
        manifest["passed"] = True
        exit_code = 0
    except Exception as exc:  # Preserve a replayable artifact on any failure.
        manifest["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        manifest["finished_at"] = datetime.now(timezone.utc).isoformat()
        (output / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        write_checksums(output)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())

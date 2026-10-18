#!/usr/bin/env python3
"""Exercise Fastbed cache, saturation, disconnect, and shutdown behavior E2E.

The runner must execute inside an isolated user/network namespace with only
loopback enabled.  It launches the real Fastbed binary and a separately gated
HTTP/HTTPS saved-corpus broker, drives deterministic seeded client races from
multiple 127/8 source addresses, and emits a self-verifying artifact bundle.
"""

from __future__ import annotations

import argparse
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import math
import os
from pathlib import Path
import random
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
from urllib.parse import quote, urlencode, urlsplit


CRAWLER_USER_AGENT = (
    "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"
)
BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "Chrome/131.0 Safari/537.36"
)
RELEVANT_HEADERS = {
    "cache-control",
    "connection",
    "content-type",
    "location",
    "retry-after",
    "vary",
}
SHUTDOWN_BODY = b"server shutting down\n"
BUSY_BODY = b"server busy\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1)
    return round(ordered[max(0, index)], 6)


def expected_forced_attempts(grace_seconds: float,
                             attempt_timeout_seconds: float,
                             retry_delay_seconds: float,
                             max_attempts: int) -> int:
    interval = attempt_timeout_seconds + retry_delay_seconds
    attempts = 1
    while attempts < max_attempts and attempts * interval < grace_seconds:
        attempts += 1
    return attempts


def assert_forced_retry_timeline(report: dict, workers: int,
                                 expected_attempts: int,
                                 attempt_timeout_seconds: float,
                                 retry_delay_seconds: float,
                                 tolerance_seconds: float) -> list[dict]:
    events = sorted(
        report["gate"].get("events", []),
        key=lambda item: int(item["arrival_monotonic_ns"]),
    )
    expected_events = workers * expected_attempts
    if len(events) != expected_events:
        raise RuntimeError(
            f"forced upstream attempts {len(events)} != exact configured "
            f"expectation {expected_events}"
        )
    waves: list[dict] = []
    interval = attempt_timeout_seconds + retry_delay_seconds
    first_midpoint_ns: int | None = None
    for attempt_index in range(expected_attempts):
        wave = events[attempt_index * workers:(attempt_index + 1) * workers]
        arrivals_ns = [int(item["arrival_monotonic_ns"]) for item in wave]
        midpoint_ns = sum(arrivals_ns) // len(arrivals_ns)
        if first_midpoint_ns is None:
            first_midpoint_ns = midpoint_ns
        observed_offset = (midpoint_ns - first_midpoint_ns) / 1e9
        expected_offset = attempt_index * interval
        spread = (max(arrivals_ns) - min(arrivals_ns)) / 1e9
        if abs(observed_offset - expected_offset) > tolerance_seconds:
            raise RuntimeError(
                f"forced retry wave {attempt_index + 1} arrived at "
                f"{observed_offset:.6f}s, expected {expected_offset:.6f}s "
                f"+/- {tolerance_seconds:.6f}s"
            )
        if spread > tolerance_seconds:
            raise RuntimeError(
                f"forced retry wave {attempt_index + 1} spread "
                f"{spread:.6f}s exceeds {tolerance_seconds:.6f}s"
            )
        waves.append(
            {
                "attempt": attempt_index + 1,
                "events": len(wave),
                "observed_offset_seconds": round(observed_offset, 6),
                "expected_offset_seconds": round(expected_offset, 6),
                "spread_seconds": round(spread, 6),
            }
        )
    return waves


def free_ports(count: int) -> list[int]:
    listeners: list[socket.socket] = []
    ports: list[int] = []
    try:
        for _ in range(count):
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.bind(("127.0.0.1", 0))
            listeners.append(listener)
            ports.append(int(listener.getsockname()[1]))
    finally:
        for listener in listeners:
            listener.close()
    if len(set(ports)) != count:
        return free_ports(count)
    return ports


def request_target(url: str) -> str:
    parsed = urlsplit(url)
    path = quote(parsed.path or "/", safe="/%:@-._~!$&'()*+,;=")
    if parsed.query:
        path += "?" + quote(parsed.query, safe="=&?/:@-._~!$'()*+,;%")
    return path


def dump_target(target: str) -> str:
    path, marker, query = target.partition("?")
    path = path.rstrip("/") + "/dump"
    return path + (marker + query if marker else "")


def read_jsonl_row(path: Path, source_line: int) -> dict:
    with path.open(encoding="utf-8") as stream:
        for text in stream:
            row = json.loads(text)
            if int(row["line"]) == source_line:
                return row
    raise RuntimeError(f"source line {source_line} not found in {path}")


def load_oracle(results_path: Path, source_line: int) -> tuple[dict, bytes]:
    row = read_jsonl_row(results_path, source_line)
    if row.get("outcome") != "parsed" or int(row.get("http_status", 0)) != 200:
        raise RuntimeError(
            f"source line {source_line} is not a successful parsed oracle row"
        )
    relative = row.get("output_path")
    if not relative:
        raise RuntimeError("oracle row has no output_path")
    output = (results_path.parent / relative).resolve()
    output.relative_to(results_path.parent.resolve())
    body = output.read_bytes()
    observed = sha256_bytes(body)
    expected = str(row.get("output_sha256", ""))
    if observed != expected:
        raise RuntimeError(
            f"oracle output integrity mismatch: observed={observed} expected={expected}"
        )
    return row, body


@dataclass
class CapturedResponse:
    client_id: int
    source_ip: str
    target: str
    user_agent: str
    started_monotonic_ns: int
    elapsed_seconds: float
    local_address: str | None
    status: int | None
    headers: dict[str, str]
    body: bytes
    error_type: str | None
    error: str | None

    def artifact(self, scenario: str, wave: str) -> dict:
        return {
            "scenario": scenario,
            "wave": wave,
            "client_id": self.client_id,
            "source_ip": self.source_ip,
            "local_address": self.local_address,
            "target": self.target,
            "user_agent_class": (
                "crawler" if self.user_agent == CRAWLER_USER_AGENT else "browser"
            ),
            "started_monotonic_ns": self.started_monotonic_ns,
            "elapsed_seconds": round(self.elapsed_seconds, 6),
            "status": self.status,
            "headers": self.headers,
            "body_bytes": len(self.body),
            "body_sha256": sha256_bytes(self.body),
            "error_type": self.error_type,
            "error": self.error,
        }


def capture_request(port: int, source_ip: str, target: str, user_agent: str,
                    client_id: int, timeout: float) -> CapturedResponse:
    started_ns = time.monotonic_ns()
    started = time.monotonic()
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        port,
        timeout=timeout,
        source_address=(source_ip, 0),
    )
    local_address: str | None = None
    try:
        connection.request(
            "GET",
            target,
            headers={
                "Host": "fastbed.invalid",
                "User-Agent": user_agent,
                "Connection": "close",
            },
        )
        if connection.sock is not None:
            local_address = str(connection.sock.getsockname()[0])
        response = connection.getresponse()
        body = response.read()
        headers = {
            key.lower(): value
            for key, value in response.getheaders()
            if key.lower() in RELEVANT_HEADERS
        }
        return CapturedResponse(
            client_id=client_id,
            source_ip=source_ip,
            target=target,
            user_agent=user_agent,
            started_monotonic_ns=started_ns,
            elapsed_seconds=time.monotonic() - started,
            local_address=local_address,
            status=response.status,
            headers=headers,
            body=body,
            error_type=None,
            error=None,
        )
    except Exception as exc:
        return CapturedResponse(
            client_id=client_id,
            source_ip=source_ip,
            target=target,
            user_agent=user_agent,
            started_monotonic_ns=started_ns,
            elapsed_seconds=time.monotonic() - started,
            local_address=local_address,
            status=None,
            headers={},
            body=b"",
            error_type=type(exc).__name__,
            error=str(exc),
        )
    finally:
        connection.close()


class RaceWave:
    """Release a seeded request plan through one process-level start barrier."""

    def __init__(self, port: int, target: str, user_agent: str,
                 source_ips: list[str], delays: list[float], timeout: float) -> None:
        if len(source_ips) != len(delays):
            raise ValueError("source/delay plan length mismatch")
        self.port = port
        self.target = target
        self.user_agent = user_agent
        self.source_ips = source_ips
        self.delays = delays
        self.timeout = timeout
        self.barrier = threading.Barrier(len(source_ips) + 1)
        self.executor = ThreadPoolExecutor(
            max_workers=len(source_ips), thread_name_prefix="fastbed-e2e-client"
        )
        self.futures: list[Future[CapturedResponse]] = []
        for client_id, (source_ip, delay) in enumerate(
            zip(source_ips, delays, strict=True), start=1
        ):
            self.futures.append(
                self.executor.submit(self._one, client_id, source_ip, delay)
            )
        self.barrier.wait(timeout=10.0)

    def _one(self, client_id: int, source_ip: str,
             delay: float) -> CapturedResponse:
        self.barrier.wait(timeout=10.0)
        if delay > 0.0:
            time.sleep(delay)
        return capture_request(
            self.port,
            source_ip,
            self.target,
            self.user_agent,
            client_id,
            self.timeout,
        )

    def completed(self) -> list[CapturedResponse]:
        return [future.result() for future in self.futures if future.done()]

    def collect(self, timeout: float) -> list[CapturedResponse]:
        deadline = time.monotonic() + timeout
        records: list[CapturedResponse] = []
        try:
            for future in self.futures:
                remaining = deadline - time.monotonic()
                if remaining <= 0.0:
                    raise TimeoutError("client race did not finish before deadline")
                records.append(future.result(timeout=remaining))
        finally:
            self.executor.shutdown(wait=False, cancel_futures=True)
        return records


class BrokerControl:
    def __init__(self, port: int) -> None:
        self.port = port

    def _get(self, path: str, timeout: float = 20.0) -> dict:
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=timeout
        )
        try:
            connection.request("GET", path, headers={"Connection": "close"})
            response = connection.getresponse()
            body = response.read()
            payload = json.loads(body)
            if response.status != 200:
                raise RuntimeError(
                    f"broker control {path} returned {response.status}: {payload}"
                )
            return payload
        finally:
            connection.close()

    def wait_ready(self, timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                self.report()
                return
            except Exception as exc:
                error = exc
                time.sleep(0.05)
        raise RuntimeError(f"concurrency broker was not ready: {error}")

    def reset(self, source_line: int, opened: bool = False,
              *, logical_flights: int = 1,
              occurrences_per_flight: int = 1) -> dict:
        query = urlencode(
            {
                "line": source_line,
                "gate": "open" if opened else "closed",
                "logical_flights": logical_flights,
                "occurrences_per_flight": occurrences_per_flight,
            }
        )
        return self._get(f"/__concurrency_reset?{query}")

    def gate(self, opened: bool) -> dict:
        state = "open" if opened else "closed"
        return self._get(f"/__concurrency_gate?state={state}")

    def report(self) -> dict:
        return self._get("/__concurrency_report")

    def wait(self, *, arrivals: int | None = None,
             waiting: int | None = None, active: int | None = None,
             timeout: float = 20.0) -> dict:
        values: dict[str, str | int | float] = {"timeout": timeout}
        if arrivals is not None:
            values["arrivals"] = arrivals
        if waiting is not None:
            values["waiting"] = waiting
        if active is not None:
            values["active"] = active
        return self._get(
            "/__concurrency_wait?" + urlencode(values), timeout=timeout + 2.0
        )


class ProcessSampler:
    def __init__(self, process: subprocess.Popen[bytes], scenario: str,
                 interval: float = 0.05) -> None:
        self.process = process
        self.scenario = scenario
        self.interval = interval
        self.phase = "startup"
        self.phase_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.samples: list[dict] = []
        self.thread = threading.Thread(
            target=self._run, name=f"sample-{scenario}", daemon=True
        )
        self.thread.start()

    def set_phase(self, phase: str) -> None:
        with self.phase_lock:
            self.phase = phase

    @staticmethod
    def _status(pid: int) -> dict:
        wanted = {
            "VmPeak",
            "VmSize",
            "VmHWM",
            "VmRSS",
            "RssAnon",
            "RssFile",
            "Threads",
            "voluntary_ctxt_switches",
            "nonvoluntary_ctxt_switches",
        }
        result: dict[str, int] = {}
        status = Path(f"/proc/{pid}/status")
        for text in status.read_text(encoding="utf-8").splitlines():
            key, marker, value = text.partition(":")
            if marker and key in wanted:
                fields = value.split()
                if fields and fields[0].isdigit():
                    normalized = key + "_kib" if fields[1:] == ["kB"] else key
                    result[normalized] = int(fields[0])
        result["fd_count"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
        result["task_count"] = len(list(Path(f"/proc/{pid}/task").iterdir()))
        return result

    def _run(self) -> None:
        while not self.stop_event.is_set():
            if self.process.poll() is not None:
                break
            try:
                with self.phase_lock:
                    phase = self.phase
                self.samples.append(
                    {
                        "scenario": self.scenario,
                        "phase": phase,
                        "monotonic_ns": time.monotonic_ns(),
                        "wall_time": datetime.now(timezone.utc).isoformat(),
                        **self._status(self.process.pid),
                    }
                )
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                break
            self.stop_event.wait(self.interval)

    def stop(self) -> list[dict]:
        self.stop_event.set()
        self.thread.join(timeout=2.0)
        return self.samples


class FastbedProcess:
    def __init__(self, *, binary: Path, root: Path, output: Path,
                 scenario: str, broker_http_port: int, broker_https_port: int,
                 workers: int, assets: Path, crawler_db: Path,
                 extra_args: list[str], source_ip: str) -> None:
        self.scenario = scenario
        self.directory = output / "processes" / scenario
        self.directory.mkdir(parents=True)
        self.port = free_ports(1)[0]
        self.config = self.directory / "config.yaml"
        self.config.write_text(
            "host: 127.0.0.1\n"
            f"port: {self.port}\n"
            "timezone: 7\n"
            "banned_users: []\n"
            "notifier_webhook: ''\n",
            encoding="utf-8",
        )
        self.command = [
            str(binary),
            "--config", str(self.config),
            "--assets", str(assets),
            "--crawler-db", str(crawler_db),
            "--workers", str(workers),
            "--allow-stock-curl",
            "--replay-http-port", str(broker_http_port),
            "--replay-https-port", str(broker_https_port),
            *extra_args,
        ]
        self.stdout_file = (self.directory / "stdout.log").open("wb")
        self.stderr_file = (self.directory / "stderr.log").open("wb")
        self.started_monotonic_ns = time.monotonic_ns()
        self.process = subprocess.Popen(
            self.command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=self.stdout_file,
            stderr=self.stderr_file,
            close_fds=True,
        )
        self.sampler = ProcessSampler(self.process, scenario)
        self.samples: list[dict] = []
        self.exit_record: dict | None = None
        self._wait_ready(source_ip)

    def _wait_ready(self, source_ip: str, timeout: float = 20.0) -> None:
        deadline = time.monotonic() + timeout
        error: str | None = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"Fastbed {self.scenario} exited during startup with "
                    f"status {self.process.returncode}"
                )
            result = capture_request(
                self.port, source_ip, "/healthz", CRAWLER_USER_AGENT, 0, 1.0
            )
            if result.status == 200:
                return
            error = result.error or f"HTTP {result.status}"
            time.sleep(0.05)
        raise RuntimeError(f"Fastbed {self.scenario} was not ready: {error}")

    def phase(self, name: str) -> None:
        self.sampler.set_phase(name)

    def signal_and_wait(self, sig: int, timeout: float) -> dict:
        if self.process.poll() is not None:
            raise RuntimeError(
                f"Fastbed {self.scenario} exited before signal: "
                f"{self.process.returncode}"
            )
        started_ns = time.monotonic_ns()
        self.process.send_signal(sig)
        status = self.process.wait(timeout=timeout)
        finished_ns = time.monotonic_ns()
        self.exit_record = {
            "signal": signal.Signals(sig).name,
            "sent_monotonic_ns": started_ns,
            "exited_monotonic_ns": finished_ns,
            "elapsed_seconds": round((finished_ns - started_ns) / 1e9, 6),
            "exit_status": status,
        }
        return self.exit_record

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5.0)
        self.samples = self.sampler.stop()
        self.stdout_file.close()
        self.stderr_file.close()


def open_disconnect_socket(port: int, source_ip: str, target: str) -> socket.socket:
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.settimeout(10.0)
    connection.bind((source_ip, 0))
    connection.connect(("127.0.0.1", port))
    request = (
        f"GET {target} HTTP/1.1\r\n"
        "Host: fastbed.invalid\r\n"
        f"User-Agent: {CRAWLER_USER_AGENT}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    connection.sendall(request)
    return connection


def close_with_fin(connection: socket.socket) -> None:
    try:
        connection.shutdown(socket.SHUT_WR)
    finally:
        connection.close()


def close_with_rst(connection: socket.socket) -> None:
    connection.setsockopt(
        socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
    )
    connection.close()


class ArtifactWriter:
    def __init__(self, output: Path) -> None:
        self.output = output
        self.responses = (output / "responses.jsonl").open("w", encoding="utf-8")
        (output / "broker").mkdir()
        (output / "representative_bodies").mkdir()
        self.scenarios: list[dict] = []
        self.commands: list[dict] = []
        self.samples: list[dict] = []

    def record_responses(self, scenario: str, wave: str,
                         records: list[CapturedResponse]) -> None:
        for record in records:
            self.responses.write(
                json.dumps(record.artifact(scenario, wave), sort_keys=True) + "\n"
            )
        self.responses.flush()

    def broker_report(self, name: str, report: dict) -> None:
        (self.output / "broker" / f"{name}.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def representative(self, name: str, body: bytes) -> str:
        path = self.output / "representative_bodies" / name
        path.write_bytes(body)
        return str(path.relative_to(self.output))

    def add_process(self, instance: FastbedProcess) -> None:
        sample_summary = {
            "count": len(instance.samples),
            "peak_rss_kib": max(
                (int(row.get("VmRSS_kib", 0)) for row in instance.samples),
                default=0,
            ),
            "peak_threads": max(
                (int(row.get("Threads", 0)) for row in instance.samples),
                default=0,
            ),
            "peak_fds": max(
                (int(row.get("fd_count", 0)) for row in instance.samples),
                default=0,
            ),
        }
        self.commands.append(
            {
                "scenario": instance.scenario,
                "pid": instance.process.pid,
                "command": instance.command,
                "started_monotonic_ns": instance.started_monotonic_ns,
                "exit": instance.exit_record,
                "process_sample_summary": sample_summary,
            }
        )
        self.samples.extend(instance.samples)

    def close(self) -> None:
        self.responses.close()
        commands_path = self.output / "commands.jsonl"
        commands_path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in self.commands),
            encoding="utf-8",
        )
        samples_path = self.output / "process_samples.jsonl"
        samples_path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in self.samples),
            encoding="utf-8",
        )


class E2EContext:
    def __init__(self, args: argparse.Namespace, root: Path, output: Path,
                 broker: BrokerControl, writer: ArtifactWriter,
                 expected_body: bytes, expected_headers: dict[str, str],
                 target: str, rng: random.Random,
                 broker_ports: tuple[int, int]) -> None:
        self.args = args
        self.root = root
        self.output = output
        self.broker = broker
        self.writer = writer
        self.expected_body = expected_body
        self.expected_hash = sha256_bytes(expected_body)
        self.expected_headers = expected_headers
        self.target = target
        self.dump_target = dump_target(target)
        self.rng = rng
        self.broker_ports = broker_ports
        self.current: FastbedProcess | None = None

    def plan(self, count: int) -> tuple[list[str], list[float]]:
        sources = [
            self.args.source_ips[index % len(self.args.source_ips)]
            for index in range(count)
        ]
        self.rng.shuffle(sources)
        delays = [
            self.rng.randint(0, self.args.race_jitter_us) / 1_000_000.0
            for _ in range(count)
        ]
        return sources, delays

    def start(self, scenario: str, workers: int,
              *, internal_cache: bool = False) -> FastbedProcess:
        if self.current is not None:
            raise RuntimeError("a Fastbed scenario process is already active")
        self.current = FastbedProcess(
            binary=self.args.binary,
            root=self.root,
            output=self.output,
            scenario=scenario,
            broker_http_port=self.broker_ports[0],
            broker_https_port=self.broker_ports[1],
            workers=workers,
            assets=self.args.assets,
            crawler_db=self.args.crawler_db,
            extra_args=[
                *self.args.fastbed_arg,
                *(["--internal-cache"] if internal_cache else []),
            ],
            source_ip=self.args.source_ips[0],
        )
        return self.current

    def finish(self) -> None:
        if self.current is None:
            return
        instance = self.current
        self.current = None
        instance.close()
        self.writer.add_process(instance)

    def assert_exact(self, records: list[CapturedResponse], label: str,
                     *, dump: bool = False) -> None:
        expected_headers = dict(self.expected_headers)
        if dump:
            expected_headers["cache-control"] = "no-store"
        for record in records:
            if record.error_type is not None:
                raise RuntimeError(
                    f"{label} client {record.client_id} failed: "
                    f"{record.error_type}: {record.error}"
                )
            if record.status != 200:
                raise RuntimeError(
                    f"{label} client {record.client_id} returned HTTP {record.status}"
                )
            if record.body != self.expected_body:
                raise RuntimeError(
                    f"{label} client {record.client_id} body mismatch: "
                    f"{sha256_bytes(record.body)} != {self.expected_hash}"
                )
            for key, value in expected_headers.items():
                if record.headers.get(key) != value:
                    raise RuntimeError(
                        f"{label} client {record.client_id} header {key!r} "
                        f"was {record.headers.get(key)!r}, expected {value!r}"
                    )
            if record.local_address != record.source_ip:
                raise RuntimeError(
                    f"{label} client {record.client_id} did not bind requested "
                    f"source address {record.source_ip}: {record.local_address}"
                )

    @staticmethod
    def assert_broker_clean(report: dict, expected_arrivals: int,
                            expected_calls: int) -> None:
        gate = report["gate"]
        corpus = report["corpus"]
        provisioning = report["provisioning"]
        if int(gate["arrivals"]) != expected_arrivals:
            raise RuntimeError(
                f"broker arrivals {gate['arrivals']} != {expected_arrivals}"
            )
        if len(corpus.get("calls", [])) != expected_calls:
            raise RuntimeError(
                f"broker calls {len(corpus.get('calls', []))} != {expected_calls}"
            )
        if (
            corpus.get("misses")
            or corpus.get("overuses")
            or corpus.get("integrity_errors")
        ):
            raise RuntimeError(
                "broker observed fixture misses, overuses, or integrity failures"
            )
        if int(provisioning["total_provisioned_occurrences"]) != expected_calls:
            raise RuntimeError(
                "broker provisioning does not match intentional call count"
            )
        occurrences = int(provisioning["occurrences_per_flight"])
        flights = corpus.get("flights", [])
        if len(flights) != int(provisioning["logical_flights"]):
            raise RuntimeError("broker logical flight report is incomplete")
        if any(int(flight["calls"]) != occurrences for flight in flights):
            raise RuntimeError(
                "an intentional logical flight did not consume exactly its "
                "explicitly provisioned occurrences"
            )


def normal_exit(context: E2EContext, process: FastbedProcess) -> dict:
    process.phase("normal_shutdown")
    result = process.signal_and_wait(
        signal.SIGTERM, context.args.grace_seconds + context.args.force_slack
    )
    if result["exit_status"] != 0:
        raise RuntimeError(
            f"Fastbed {process.scenario} exited with {result['exit_status']}"
        )
    return result


def scenario_singleflight(context: E2EContext) -> dict:
    default_name = "default_cache_disabled"
    context.broker.reset(
        context.args.line,
        opened=True,
        logical_flights=2,
        occurrences_per_flight=1,
    )
    default_process = context.start(default_name, context.args.workers)
    try:
        default_process.phase("sequential_repeated_post")
        default_records = [
            capture_request(
                default_process.port,
                context.args.source_ips[index],
                context.target,
                CRAWLER_USER_AGENT,
                index + 1,
                context.args.request_timeout,
            )
            for index in range(2)
        ]
        context.assert_exact(default_records, "default uncached repeat")
        context.writer.record_responses(
            default_name, "sequential", default_records)
        context.broker.wait(active=0, timeout=20.0)
        default_report = context.broker.report()
        context.writer.broker_report("default-cache-disabled", default_report)
        context.assert_broker_clean(default_report, 2, 2)
        default_exit = normal_exit(context, default_process)
    finally:
        context.finish()

    name = "singleflight_cache"
    context.broker.reset(
        context.args.line,
        opened=False,
        logical_flights=1,
        occurrences_per_flight=1,
    )
    process = context.start(
        name, context.args.workers, internal_cache=True)
    try:
        process.phase("cold_singleflight")
        cold_count = max(context.args.singleflight_clients, context.args.workers + 3)
        cold_sources, delays = context.plan(cold_count)
        cold = RaceWave(
            process.port, context.target, CRAWLER_USER_AGENT,
            cold_sources, delays, context.args.request_timeout,
        )
        context.broker.wait(arrivals=1, waiting=1, timeout=20.0)
        time.sleep(0.2)
        held = context.broker.report()
        context.writer.broker_report("singleflight-held", held)
        if held["gate"]["arrivals"] != 1:
            raise RuntimeError(
                "cold identical requests produced more than one upstream flight"
            )
        context.broker.gate(True)
        cold_records = cold.collect(context.args.request_timeout)
        context.assert_exact(cold_records, "cold singleflight")
        context.writer.record_responses(name, "cold", cold_records)
        context.writer.representative("singleflight-cold.html", cold_records[0].body)
        context.broker.wait(active=0, timeout=20.0)
        cold_report = context.broker.report()
        context.writer.broker_report("singleflight-cold", cold_report)
        context.assert_broker_clean(cold_report, 1, 1)

        process.phase("warm_cache")
        warm_count = max(8, context.args.workers * 2)
        warm_sources, delays = context.plan(warm_count)
        warm = RaceWave(
            process.port, context.target, CRAWLER_USER_AGENT,
            warm_sources, delays, context.args.request_timeout,
        )
        warm_records = warm.collect(context.args.request_timeout)
        context.assert_exact(warm_records, "warm cache")
        context.writer.record_responses(name, "warm", warm_records)
        warm_report = context.broker.report()
        context.writer.broker_report("singleflight-warm", warm_report)
        context.assert_broker_clean(warm_report, 1, 1)
        exit_record = normal_exit(context, process)
        return {
            "name": name,
            "default_cache_disabled": {
                "upstream_flights": default_report["gate"]["arrivals"],
                "exact_body_sha256": context.expected_hash,
                "exit": default_exit,
            },
            "internal_cache_flag": "--internal-cache",
            "seeded_clients": cold_count + warm_count,
            "source_ips": sorted(set(cold_sources + warm_sources)),
            "cold_upstream_flights": cold_report["gate"]["arrivals"],
            "warm_upstream_flights": (
                warm_report["gate"]["arrivals"]
                - cold_report["gate"]["arrivals"]
            ),
            "exact_body_sha256": context.expected_hash,
            "cold_latency_p95_seconds": percentile(
                [item.elapsed_seconds for item in cold_records], 0.95
            ),
            "warm_latency_p95_seconds": percentile(
                [item.elapsed_seconds for item in warm_records], 0.95
            ),
            "exit": exit_record,
        }
    finally:
        context.finish()


def wait_for_busy(wave: RaceWave, required: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        completed = wave.completed()
        failures = [item for item in completed if item.error_type is not None]
        unexpected = [
            item for item in completed
            if item.error_type is None
            and (item.status != 503 or item.body != BUSY_BODY)
        ]
        if failures:
            first = failures[0]
            raise RuntimeError(
                f"saturation client failed before release: "
                f"{first.error_type}: {first.error}"
            )
        if unexpected:
            first = unexpected[0]
            raise RuntimeError(
                f"saturation client completed unexpectedly with {first.status} "
                f"and body {sha256_bytes(first.body)}"
            )
        if len(completed) >= required:
            return
        time.sleep(0.02)
    raise RuntimeError(
        f"queue saturation did not produce {required} prompt overload responses"
    )


def assert_fast_paths(context: E2EContext, process: FastbedProcess,
                      scenario: str) -> dict:
    health = capture_request(
        process.port,
        context.args.source_ips[-1],
        "/healthz",
        CRAWLER_USER_AGENT,
        9001,
        context.args.fast_path_timeout,
    )
    if health.status != 200 or health.error_type is not None:
        raise RuntimeError("health fast path failed while worker queue was saturated")
    if health.headers.get("content-type") != "application/json" or \
       health.headers.get("cache-control") != "no-store":
        raise RuntimeError("health fast path header contract mismatch")
    try:
        health_payload = json.loads(health.body)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"health fast path returned invalid JSON: {exc}") from exc
    if health_payload.get("status") != "ok":
        raise RuntimeError("health fast path did not report ok")

    browser_target = f"/browser-race/{context.args.seed}?mode=saturated"
    browser_records = [
        capture_request(
            process.port,
            context.args.source_ips[-2],
            browser_target,
            BROWSER_USER_AGENT,
            9002 + index,
            context.args.fast_path_timeout,
        )
        for index in range(2)
    ]
    for browser in browser_records:
        if browser.status != 302 or browser.error_type is not None:
            raise RuntimeError(
                "browser redirect fast path failed while worker queue was saturated"
            )
        if browser.headers.get("location") != (
            "https://www.facebook.com" + browser_target
        ):
            raise RuntimeError("browser redirect location mismatch")
        if (
            browser.headers.get("content-type")
            != "text/html; charset=UTF-8"
            or browser.headers.get("cache-control") != "no-store"
            or browser.headers.get("vary") != "User-Agent"
        ):
            raise RuntimeError("browser redirect header contract mismatch")
    if browser_records[0].body != browser_records[1].body:
        raise RuntimeError("browser fast path response was not deterministic")
    all_records = [health, *browser_records]
    for record in all_records:
        if record.elapsed_seconds > context.args.fast_path_timeout:
            raise RuntimeError("a synchronous fast path exceeded its deadline")
    context.writer.record_responses(scenario, "fast_paths", all_records)
    context.writer.representative("saturated-browser.html", browser_records[0].body)
    return {
        "health_body_sha256": sha256_bytes(health.body),
        "browser_body_sha256": sha256_bytes(browser_records[0].body),
        "max_elapsed_seconds": round(
            max(record.elapsed_seconds for record in all_records), 6
        ),
    }


def scenario_saturation(context: E2EContext) -> dict:
    name = "saturation_disconnect_fastpaths"
    workers = context.args.saturation_workers
    context.broker.reset(
        context.args.line,
        opened=False,
        logical_flights=2,
        occurrences_per_flight=1,
    )
    process = context.start(name, workers)
    try:
        process.phase("client_disconnects")
        fin_socket = open_disconnect_socket(
            process.port, context.args.source_ips[0], context.dump_target
        )
        fin_endpoint = fin_socket.getsockname()
        fin_sent_ns = time.monotonic_ns()
        context.broker.wait(arrivals=1, waiting=1, timeout=20.0)
        close_with_fin(fin_socket)
        fin_closed_ns = time.monotonic_ns()

        rst_socket = open_disconnect_socket(
            process.port, context.args.source_ips[1], context.dump_target
        )
        rst_endpoint = rst_socket.getsockname()
        rst_sent_ns = time.monotonic_ns()
        context.broker.wait(arrivals=2, waiting=2, timeout=20.0)
        close_with_rst(rst_socket)
        rst_closed_ns = time.monotonic_ns()
        disconnect_evidence = [
            {
                "mode": "FIN",
                "source_ip": str(fin_endpoint[0]),
                "source_port": int(fin_endpoint[1]),
                "target": context.dump_target,
                "sent_monotonic_ns": fin_sent_ns,
                "closed_monotonic_ns": fin_closed_ns,
            },
            {
                "mode": "RST",
                "source_ip": str(rst_endpoint[0]),
                "source_port": int(rst_endpoint[1]),
                "target": context.dump_target,
                "sent_monotonic_ns": rst_sent_ns,
                "closed_monotonic_ns": rst_closed_ns,
            },
        ]
        (context.output / "disconnects.json").write_text(
            json.dumps(disconnect_evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        time.sleep(context.args.disconnect_settle_seconds)
        context.broker.gate(True)
        context.broker.wait(active=0, timeout=20.0)
        disconnect_report = context.broker.report()
        context.writer.broker_report("saturation-disconnects", disconnect_report)
        context.assert_broker_clean(disconnect_report, 2, 2)

        context.broker.reset(
            context.args.line,
            opened=False,
            logical_flights=workers + context.args.queue_limit,
            occurrences_per_flight=1,
        )
        process.phase("queue_saturation")
        active_sources, active_delays = context.plan(workers)
        active_wave = RaceWave(
            process.port, context.dump_target, CRAWLER_USER_AGENT,
            active_sources, active_delays, context.args.request_timeout,
        )
        context.broker.wait(arrivals=workers, waiting=workers, timeout=20.0)

        saturation_count = context.args.queue_limit + context.args.overflow_clients
        queued_sources, queued_delays = context.plan(saturation_count)
        queued_wave = RaceWave(
            process.port, context.dump_target, CRAWLER_USER_AGENT,
            queued_sources, queued_delays, context.args.request_timeout,
        )
        wait_for_busy(
            queued_wave, context.args.overflow_clients,
            context.args.saturation_timeout,
        )
        held = context.broker.report()
        context.writer.broker_report("saturation-held", held)
        if held["gate"]["arrivals"] != workers:
            raise RuntimeError(
                "worker-blocking gate did not hold upstream concurrency at worker count"
            )
        fast_paths = assert_fast_paths(context, process, name)

        process.phase("queue_release")
        context.broker.gate(True)
        active_records = active_wave.collect(context.args.request_timeout)
        queued_records = queued_wave.collect(context.args.request_timeout)
        context.assert_exact(active_records, "saturation active", dump=True)
        admitted = [item for item in queued_records if item.status == 200]
        overloaded = [item for item in queued_records if item.status == 503]
        other = [
            item for item in queued_records
            if item.error_type is not None or item.status not in {200, 503}
        ]
        if other:
            first = other[0]
            raise RuntimeError(
                f"unexpected saturated client result: status={first.status} "
                f"error={first.error_type}: {first.error}"
            )
        context.assert_exact(admitted, "saturation admitted", dump=True)
        if len(admitted) != context.args.queue_limit:
            raise RuntimeError(
                f"admitted queue depth {len(admitted)} != "
                f"configured expectation {context.args.queue_limit}"
            )
        if len(overloaded) != context.args.overflow_clients:
            raise RuntimeError(
                f"overload count {len(overloaded)} != "
                f"expected {context.args.overflow_clients}"
            )
        for record in overloaded:
            if (
                record.body != BUSY_BODY
                or record.headers.get("retry-after") != "1"
                or record.headers.get("cache-control") != "no-store"
                or record.headers.get("content-type")
                != "text/plain; charset=utf-8"
            ):
                raise RuntimeError("queue overload response contract mismatch")
        context.writer.record_responses(name, "active", active_records)
        context.writer.record_responses(name, "queued", queued_records)
        context.writer.representative("saturation-admitted.html", admitted[0].body)
        context.writer.representative("saturation-overload.txt", overloaded[0].body)

        expected_upstream = workers + context.args.queue_limit
        context.broker.wait(active=0, timeout=context.args.request_timeout)
        released_report = context.broker.report()
        context.writer.broker_report("saturation-released", released_report)
        context.assert_broker_clean(
            released_report, expected_upstream, expected_upstream
        )
        exit_record = normal_exit(context, process)
        return {
            "name": name,
            "workers": workers,
            "queue_limit": context.args.queue_limit,
            "overflow_clients": context.args.overflow_clients,
            "admitted": len(admitted),
            "overloaded": len(overloaded),
            "upstream_calls": expected_upstream,
            "disconnects": {
                "events": disconnect_evidence,
                "settle_seconds": context.args.disconnect_settle_seconds,
                "broker_write_errors": disconnect_report["gate"]["write_errors"],
            },
            "fast_paths": fast_paths,
            "exact_body_sha256": context.expected_hash,
            "exit": exit_record,
        }
    finally:
        try:
            context.broker.gate(True)
        except Exception:
            pass
        context.finish()


def scenario_graceful(context: E2EContext) -> dict:
    name = "graceful_drain"
    workers = context.args.shutdown_workers
    context.broker.reset(
        context.args.line,
        opened=False,
        logical_flights=workers,
        occurrences_per_flight=1,
    )
    process = context.start(name, workers)
    try:
        process.phase("graceful_gate_hold")
        sources, delays = context.plan(workers)
        wave = RaceWave(
            process.port, context.dump_target, CRAWLER_USER_AGENT,
            sources, delays, context.args.request_timeout,
        )
        context.broker.wait(arrivals=workers, waiting=workers, timeout=20.0)
        process.phase("graceful_drain")
        signal_ns = time.monotonic_ns()
        process.process.send_signal(signal.SIGTERM)
        time.sleep(context.args.grace_release_delay)
        if process.process.poll() is not None:
            raise RuntimeError("Fastbed exited before an in-grace request could drain")
        context.broker.gate(True)
        records = wave.collect(context.args.request_timeout)
        context.assert_exact(records, "graceful drain", dump=True)
        context.writer.record_responses(name, "drained", records)
        context.writer.representative("graceful-drain.html", records[0].body)
        status = process.process.wait(
            timeout=context.args.grace_seconds + context.args.force_slack
        )
        exit_ns = time.monotonic_ns()
        process.exit_record = {
            "signal": "SIGTERM",
            "sent_monotonic_ns": signal_ns,
            "exited_monotonic_ns": exit_ns,
            "elapsed_seconds": round((exit_ns - signal_ns) / 1e9, 6),
            "exit_status": status,
        }
        if status != 0:
            raise RuntimeError(f"graceful drain process exited with {status}")
        report = context.broker.report()
        context.writer.broker_report("graceful-drain", report)
        context.assert_broker_clean(report, workers, workers)
        return {
            "name": name,
            "workers": workers,
            "release_delay_seconds": context.args.grace_release_delay,
            "drained_exact_responses": len(records),
            "exact_body_sha256": context.expected_hash,
            "exit": process.exit_record,
        }
    finally:
        try:
            context.broker.gate(True)
        except Exception:
            pass
        context.finish()


def scenario_forced(context: E2EContext) -> dict:
    name = "forced_cancellation"
    workers = context.args.shutdown_workers
    context.broker.reset(
        context.args.line,
        opened=False,
        logical_flights=workers,
        occurrences_per_flight=context.args.expected_forced_attempts,
    )
    process = context.start(name, workers)
    try:
        process.phase("forced_gate_hold")
        sources, delays = context.plan(workers)
        wave = RaceWave(
            process.port, context.dump_target, CRAWLER_USER_AGENT,
            sources, delays,
            context.args.grace_seconds + context.args.force_slack + 10.0,
        )
        context.broker.wait(arrivals=workers, waiting=workers, timeout=20.0)
        pre_signal_report = context.broker.report()
        context.writer.broker_report("forced-before-signal", pre_signal_report)
        if (
            pre_signal_report["gate"]["arrivals"] != workers
            or pre_signal_report["gate"]["waiting"] != workers
            or pre_signal_report["gate"]["open"]
        ):
            raise RuntimeError(
                "forced-shutdown upstream work was not fully held before SIGTERM"
            )
        process.phase("forced_shutdown_wait")
        signal_ns = time.monotonic_ns()
        process.process.send_signal(signal.SIGTERM)
        alive_probe = min(1.0, context.args.grace_seconds / 2.0)
        if alive_probe > 0.0:
            time.sleep(alive_probe)
            if process.process.poll() is not None:
                raise RuntimeError(
                    "Fastbed exited before the graceful shutdown window elapsed"
                )
        status = process.process.wait(
            timeout=context.args.grace_seconds + context.args.force_slack
        )
        exit_ns = time.monotonic_ns()
        elapsed = (exit_ns - signal_ns) / 1e9
        process.exit_record = {
            "signal": "SIGTERM",
            "sent_monotonic_ns": signal_ns,
            "exited_monotonic_ns": exit_ns,
            "elapsed_seconds": round(elapsed, 6),
            "exit_status": status,
        }
        if status != 0:
            raise RuntimeError(f"forced cancellation process exited with {status}")
        lower_bound = max(
            0.0, context.args.grace_seconds - context.args.force_early_tolerance
        )
        if elapsed < lower_bound:
            raise RuntimeError(
                f"forced cancellation exited at {elapsed:.6f}s before "
                f"the {context.args.grace_seconds:.6f}s grace deadline"
            )
        records = wave.collect(context.args.force_slack + 10.0)
        for record in records:
            if record.error_type is not None:
                raise RuntimeError(
                    f"forced client did not receive terminal HTTP response: "
                    f"{record.error_type}: {record.error}"
                )
            if record.status != 503 or record.body != SHUTDOWN_BODY:
                raise RuntimeError(
                    f"forced client response mismatch: HTTP {record.status}, "
                    f"sha256={sha256_bytes(record.body)}"
                )
            if record.headers.get("retry-after") != "1":
                raise RuntimeError("forced cancellation response lacks Retry-After: 1")
            if (
                record.headers.get("cache-control") != "no-store"
                or record.headers.get("content-type")
                != "text/plain; charset=utf-8"
            ):
                raise RuntimeError("forced cancellation header contract mismatch")
        context.writer.record_responses(name, "forced", records)
        context.writer.representative("forced-shutdown.txt", records[0].body)
        held_report = context.broker.report()
        context.writer.broker_report("forced-before-release", held_report)
        expected_upstream = workers * context.args.expected_forced_attempts
        if held_report["gate"]["arrivals"] != expected_upstream:
            raise RuntimeError(
                f"forced upstream arrivals {held_report['gate']['arrivals']} != "
                f"configured retry expectation {expected_upstream}"
            )
        retry_waves = assert_forced_retry_timeline(
            held_report,
            workers,
            context.args.expected_forced_attempts,
            context.args.transport_attempt_timeout_seconds,
            context.args.transport_retry_delay_seconds,
            context.args.retry_timing_tolerance_seconds,
        )
        context.broker.gate(True)
        context.broker.wait(active=0, timeout=20.0)
        released_report = context.broker.report()
        context.writer.broker_report("forced-after-release", released_report)
        context.assert_broker_clean(
            released_report, expected_upstream, expected_upstream
        )
        return {
            "name": name,
            "workers": workers,
            "grace_seconds": context.args.grace_seconds,
            "force_early_tolerance_seconds": context.args.force_early_tolerance,
            "terminal_503_responses": len(records),
            "shutdown_body_sha256": sha256_bytes(SHUTDOWN_BODY),
            "waiting_before_signal": pre_signal_report["gate"]["waiting"],
            "waiting_after_exit": held_report["gate"]["waiting"],
            "expected_attempts_per_request": (
                context.args.expected_forced_attempts
            ),
            "upstream_arrivals": expected_upstream,
            "retry_waves": retry_waves,
            "broker_write_errors": released_report["gate"]["write_errors"],
            "exit": process.exit_record,
        }
    finally:
        try:
            context.broker.gate(True)
        except Exception:
            pass
        context.finish()


def stop_broker(process: subprocess.Popen[bytes] | None,
                timeout: float = 5.0) -> None:
    if process is None or process.poll() is not None:
        return
    process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5.0)


def write_sums(output: Path) -> None:
    lines = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            lines.append(f"{sha256_file(path)}  {path.relative_to(output)}")
    (output / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Arguments beginning with '-' must use the joined passthrough form, "
            "for example --fastbed-arg=--graceful-shutdown-seconds=2. "
            "Keep --queue-limit and --grace-seconds aligned with any production "
            "server overrides."
        ),
    )
    parser.add_argument("binary", type=Path)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--python-results", type=Path, required=True)
    parser.add_argument("--line", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--parent-netns", required=True)
    parser.add_argument("--assets", type=Path)
    parser.add_argument("--crawler-db", type=Path)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--saturation-workers", type=int, default=2)
    parser.add_argument("--shutdown-workers", type=int, default=2)
    parser.add_argument("--singleflight-clients", type=int, default=11)
    parser.add_argument("--queue-limit", type=int, default=64)
    parser.add_argument("--overflow-clients", type=int, default=8)
    parser.add_argument("--grace-seconds", type=float, default=30.0)
    parser.add_argument("--grace-release-delay", type=float, default=0.25)
    parser.add_argument("--force-early-tolerance", type=float, default=0.35)
    parser.add_argument("--force-slack", type=float, default=8.0)
    parser.add_argument(
        "--transport-attempt-timeout-seconds", type=float, default=25.0
    )
    parser.add_argument(
        "--transport-retry-delay-seconds", type=float, default=0.25
    )
    parser.add_argument("--transport-max-attempts", type=int, default=2)
    parser.add_argument(
        "--retry-timing-tolerance-seconds", type=float, default=2.0
    )
    parser.add_argument("--request-timeout", type=float, default=90.0)
    parser.add_argument("--saturation-timeout", type=float, default=20.0)
    parser.add_argument("--fast-path-timeout", type=float, default=2.0)
    parser.add_argument("--disconnect-settle-seconds", type=float, default=0.1)
    parser.add_argument("--race-jitter-us", type=int, default=3000)
    parser.add_argument("--seed", type=int, default=0xFA57BED)
    parser.add_argument(
        "--scenario",
        action="append",
        choices=("singleflight", "saturation", "graceful", "forced"),
        default=[],
        help="run only the named scenario; repeat to select multiple",
    )
    parser.add_argument(
        "--source-ips",
        default="127.0.0.2,127.0.0.3,127.0.0.4,127.0.0.5,127.0.0.6,127.0.0.7",
        help="comma-separated loopback client source addresses",
    )
    parser.add_argument(
        "--fastbed-arg",
        action="append",
        default=[],
        help="opaque argument appended to every Fastbed invocation",
    )
    args = parser.parse_args()
    if len(set(args.scenario)) != len(args.scenario):
        parser.error("--scenario values must be unique")
    args.source_ips = [
        item.strip() for item in args.source_ips.split(",") if item.strip()
    ]
    if len(args.source_ips) < 4:
        parser.error("at least four source IPs are required")
    if args.line <= 0:
        parser.error("--line must be positive")
    for source in args.source_ips:
        try:
            address = ipaddress.ip_address(source)
        except ValueError as exc:
            parser.error(f"invalid source IP {source}: {exc}")
        if not address.is_loopback or address.version != 4:
            parser.error(f"source IP is not IPv4 loopback: {source}")
    positive_ints = {
        "workers": args.workers,
        "saturation-workers": args.saturation_workers,
        "shutdown-workers": args.shutdown_workers,
        "singleflight-clients": args.singleflight_clients,
        "queue-limit": args.queue_limit,
        "overflow-clients": args.overflow_clients,
        "transport-max-attempts": args.transport_max_attempts,
    }
    for name, value in positive_ints.items():
        if value <= 0:
            parser.error(f"--{name} must be positive")
    if args.saturation_workers > len(args.source_ips):
        parser.error("saturation workers must not exceed source IP count")
    if args.saturation_workers < 2:
        parser.error("saturation workers must be at least two for FIN/RST coverage")
    if args.grace_seconds <= 0.0:
        parser.error("--grace-seconds must be positive")
    if not 0.0 < args.grace_release_delay < args.grace_seconds:
        parser.error("grace release delay must be inside the grace window")
    if args.force_early_tolerance < 0.0:
        parser.error("force early tolerance must be non-negative")
    if args.race_jitter_us < 0:
        parser.error("race jitter must be non-negative")
    reserved_fastbed_args = {
        "--config",
        "-c",
        "--assets",
        "--crawler-db",
        "--workers",
        "-w",
        "--replay-http-port",
        "--replay-https-port",
        "--internal-cache",
    }
    for value in args.fastbed_arg:
        option = value.partition("=")[0]
        if option in reserved_fastbed_args:
            parser.error(
                f"--fastbed-arg may not override harness-owned option {option}"
            )
    positive_floats = {
        "force-slack": args.force_slack,
        "transport-attempt-timeout-seconds": (
            args.transport_attempt_timeout_seconds
        ),
        "transport-retry-delay-seconds": args.transport_retry_delay_seconds,
        "retry-timing-tolerance-seconds": args.retry_timing_tolerance_seconds,
        "request-timeout": args.request_timeout,
        "saturation-timeout": args.saturation_timeout,
        "fast-path-timeout": args.fast_path_timeout,
        "disconnect-settle-seconds": args.disconnect_settle_seconds,
    }
    for name, value in positive_floats.items():
        if value <= 0.0:
            parser.error(f"--{name} must be positive")
    retry_interval = (
        args.transport_attempt_timeout_seconds
        + args.transport_retry_delay_seconds
    )
    for attempt_index in range(1, args.transport_max_attempts):
        boundary = attempt_index * retry_interval
        if abs(args.grace_seconds - boundary) <= \
           args.retry_timing_tolerance_seconds:
            parser.error(
                "grace deadline is too close to a configured retry boundary; "
                "choose a stable deadline or tighten the retry timing tolerance"
            )
    args.expected_forced_attempts = expected_forced_attempts(
        args.grace_seconds,
        args.transport_attempt_timeout_seconds,
        args.transport_retry_delay_seconds,
        args.transport_max_attempts,
    )
    return args


def main() -> int:
    args = parse_args()
    started = datetime.now(timezone.utc)
    interfaces = [name for _index, name in socket.if_nameindex()]
    namespace = os.readlink("/proc/self/ns/net")
    if interfaces != ["lo"] or namespace == args.parent_netns:
        raise SystemExit(
            "run inside unshare --user --map-root-user --net with loopback up"
        )

    root = Path(__file__).resolve().parent.parent
    args.binary = args.binary.resolve()
    args.corpus = args.corpus.resolve()
    args.python_results = args.python_results.resolve()
    args.output = args.output.resolve()
    args.assets = (
        args.assets.resolve() if args.assets else (root / "assets").resolve()
    )
    args.crawler_db = (
        args.crawler_db.resolve()
        if args.crawler_db
        else (
            root / "third_party" / "crawler-user-agents"
            / "crawler-user-agents.json"
        ).resolve()
    )
    if args.output.exists():
        raise SystemExit(f"output already exists: {args.output}")
    manifest_row = read_jsonl_row(
        args.corpus / "corpus_manifest.jsonl", args.line
    )
    oracle_row, expected_body = load_oracle(args.python_results, args.line)
    if str(manifest_row["url"]) != str(oracle_row["url"]):
        raise RuntimeError("corpus and Python oracle URL mismatch")
    target = request_target(str(manifest_row["url"]))
    expected_headers = {
        key.lower(): str(value)
        for key, value in oracle_row.get("headers", {}).items()
        if key.lower() in RELEVANT_HEADERS
    }
    input_hashes = {
        "binary": sha256_file(args.binary),
        "corpus_manifest": sha256_file(args.corpus / "corpus_manifest.jsonl"),
        "python_results": sha256_file(args.python_results),
        "runner": sha256_file(Path(__file__)),
        "broker": sha256_file(Path(__file__).with_name("concurrency_broker.py")),
        "fixture_broker": sha256_file(Path(__file__).with_name("fixture_broker.py")),
    }

    args.output.mkdir(parents=True)
    (args.output / "processes").mkdir()
    harness_snapshot = args.output / "harness"
    harness_snapshot.mkdir()
    for name in (
        "run_concurrency_e2e.py",
        "concurrency_broker.py",
        "fixture_broker.py",
        "run_concurrency_e2e.sh",
        "CONCURRENCY_E2E.md",
    ):
        shutil.copy2(Path(__file__).with_name(name), harness_snapshot / name)
    network_evidence = {
        "network_namespace": namespace,
        "parent_network_namespace": args.parent_netns,
        "interfaces": [
            {"index": index, "name": name}
            for index, name in socket.if_nameindex()
        ],
        "ipv4_routes": Path("/proc/net/route").read_text(encoding="utf-8"),
        "ipv6_routes": Path("/proc/net/ipv6_route").read_text(encoding="utf-8"),
        "planned_source_ips": args.source_ips,
    }
    (args.output / "network.json").write_text(
        json.dumps(network_evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    http_port, https_port = free_ports(2)
    cert = args.output / "fixture-cert.pem"
    key = args.output / "fixture-key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", "/CN=localhost",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    broker_log = (args.output / "broker.log").open("wb")
    broker_command = [
        sys.executable,
        os.fspath(Path(__file__).with_name("concurrency_broker.py")),
        os.fspath(args.corpus),
        "--http-port", str(http_port),
        "--https-port", str(https_port),
        "--cert", os.fspath(cert),
        "--key", os.fspath(key),
    ]
    broker_process: subprocess.Popen[bytes] | None = None
    broker_process_record: dict = {"command": broker_command}
    writer = ArtifactWriter(args.output)
    failure: dict | None = None
    broker = BrokerControl(http_port)
    rng = random.Random(args.seed)
    context = E2EContext(
        args, root, args.output, broker, writer, expected_body,
        expected_headers, target, rng, (http_port, https_port),
    )
    scenarios = {
        "singleflight": scenario_singleflight,
        "saturation": scenario_saturation,
        "graceful": scenario_graceful,
        "forced": scenario_forced,
    }
    requested_scenarios = args.scenario or list(scenarios)
    try:
        broker_started_ns = time.monotonic_ns()
        broker_process = subprocess.Popen(
            broker_command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=broker_log,
            stderr=subprocess.STDOUT,
            close_fds=True,
        )
        broker_process_record.update(
            {
                "pid": broker_process.pid,
                "started_monotonic_ns": broker_started_ns,
            }
        )
        broker.wait_ready()
        for scenario_name in requested_scenarios:
            summary = scenarios[scenario_name](context)
            writer.scenarios.append(summary)
    except Exception as exc:
        failure = {
            "type": type(exc).__name__,
            "message": str(exc),
            "at": datetime.now(timezone.utc).isoformat(),
            "traceback": traceback.format_exc(),
        }
        try:
            writer.broker_report("failure-final", broker.report())
        except Exception as report_exc:
            failure["broker_report_error"] = (
                f"{type(report_exc).__name__}: {report_exc}"
            )
        (args.output / "failure.json").write_text(
            json.dumps(failure, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    finally:
        try:
            broker.gate(True)
        except Exception:
            pass
        context.finish()
        stop_broker(broker_process)
        broker_exited_ns = time.monotonic_ns()
        broker_process_record.update(
            {
                "exited_monotonic_ns": broker_exited_ns,
                "elapsed_seconds": (
                    round(
                        (broker_exited_ns
                         - int(broker_process_record["started_monotonic_ns"]))
                        / 1e9,
                        6,
                    )
                    if "started_monotonic_ns" in broker_process_record
                    else None
                ),
                "exit_status": (
                    broker_process.returncode
                    if broker_process is not None else None
                ),
            }
        )
        broker_log.close()
        writer.close()

    if broker_process_record.get("exit_status") not in {0, None} and failure is None:
        failure = {
            "type": "BrokerExitFailure",
            "message": (
                "concurrency broker exited with status "
                f"{broker_process_record['exit_status']}"
            ),
            "at": datetime.now(timezone.utc).isoformat(),
        }
        (args.output / "failure.json").write_text(
            json.dumps(failure, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    final_input_hashes = {
        "binary": sha256_file(args.binary),
        "corpus_manifest": sha256_file(args.corpus / "corpus_manifest.jsonl"),
        "python_results": sha256_file(args.python_results),
        "runner": sha256_file(Path(__file__)),
        "broker": sha256_file(Path(__file__).with_name("concurrency_broker.py")),
        "fixture_broker": sha256_file(Path(__file__).with_name("fixture_broker.py")),
    }
    changed_inputs = sorted(
        name for name, digest in input_hashes.items()
        if final_input_hashes[name] != digest
    )
    if changed_inputs and failure is None:
        failure = {
            "type": "InputChangedDuringRun",
            "message": "authoritative inputs changed during run: "
                       + ", ".join(changed_inputs),
            "at": datetime.now(timezone.utc).isoformat(),
        }
        (args.output / "failure.json").write_text(
            json.dumps(failure, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    finished = datetime.now(timezone.utc)
    manifest = {
        "schema": 1,
        "status": "failed" if failure else "passed",
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "elapsed_seconds": round((finished - started).total_seconds(), 6),
        "seed": args.seed,
        "race_jitter_us": args.race_jitter_us,
        "requested_scenarios": requested_scenarios,
        "network_namespace": namespace,
        "parent_network_namespace": args.parent_netns,
        "network_interfaces": interfaces,
        "source_ips": args.source_ips,
        "binary": str(args.binary),
        "binary_sha256": input_hashes["binary"],
        "corpus": str(args.corpus),
        "corpus_manifest_sha256": input_hashes["corpus_manifest"],
        "source_line": args.line,
        "source_url": manifest_row["url"],
        "python_results": str(args.python_results),
        "python_results_sha256": input_hashes["python_results"],
        "oracle_output_path": oracle_row["output_path"],
        "oracle_output_sha256": sha256_bytes(expected_body),
        "oracle_headers": expected_headers,
        "runner_sha256": input_hashes["runner"],
        "broker_sha256": input_hashes["broker"],
        "fixture_broker_sha256": input_hashes["fixture_broker"],
        "input_hashes_after_run": final_input_hashes,
        "changed_inputs": changed_inputs,
        "broker_command": broker_command,
        "broker_process": broker_process_record,
        "contract": {
            "workers": args.workers,
            "saturation_workers": args.saturation_workers,
            "shutdown_workers": args.shutdown_workers,
            "queue_limit": args.queue_limit,
            "grace_seconds": args.grace_seconds,
            "transport_attempt_timeout_seconds": (
                args.transport_attempt_timeout_seconds
            ),
            "transport_retry_delay_seconds": (
                args.transport_retry_delay_seconds
            ),
            "transport_max_attempts": args.transport_max_attempts,
            "expected_forced_attempts": args.expected_forced_attempts,
            "retry_timing_tolerance_seconds": (
                args.retry_timing_tolerance_seconds
            ),
            "fastbed_args": args.fastbed_arg,
        },
        "scenarios": writer.scenarios,
        "failure": failure,
    }
    (args.output / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    write_sums(args.output)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "status": manifest["status"],
                "scenarios": len(writer.scenarios),
                "oracle_output_sha256": manifest["oracle_output_sha256"],
                "failure": failure,
            },
            sort_keys=True,
        )
    )
    return int(failure is not None)


if __name__ == "__main__":
    raise SystemExit(main())

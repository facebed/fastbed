#!/usr/bin/env python3
"""Gate exact saved-corpus responses for process-level concurrency E2E runs.

This broker deliberately builds on :mod:`fixture_broker` instead of changing
it.  The ordinary corpus replay remains stable while this process adds a
control-plane gate and detailed request lifecycle evidence around the same
hash-verified response loader. Independent logical flights receive independent
strict occurrence counters; intentional retry waves consume only explicitly
provisioned duplicate occurrence sets.
"""

from __future__ import annotations

import argparse
import http.server
import json
from pathlib import Path
import socket
import ssl
import threading
import time
from urllib.parse import parse_qs, urlsplit

from fixture_broker import CorpusState


class GateState:
    """A generation-scoped response gate with auditable lifecycle counters."""

    def __init__(self) -> None:
        self.condition = threading.Condition(threading.RLock())
        self.generation = 0
        self.is_open = True
        self.next_request_id = 1
        self.arrivals = 0
        self.waiting = 0
        self.active = 0
        self.completed = 0
        self.write_errors = 0
        self.events: list[dict] = []

    def reset(self, opened: bool) -> None:
        with self.condition:
            if self.active != 0:
                raise RuntimeError(
                    f"cannot reset gate with {self.active} active requests"
                )
            self.generation += 1
            self.is_open = opened
            self.next_request_id = 1
            self.arrivals = 0
            self.waiting = 0
            self.active = 0
            self.completed = 0
            self.write_errors = 0
            self.events = []
            self.condition.notify_all()

    def assert_idle(self) -> None:
        with self.condition:
            if self.active != 0:
                raise RuntimeError(
                    f"cannot reset gate with {self.active} active requests"
                )

    def set_open(self, opened: bool) -> None:
        with self.condition:
            self.is_open = opened
            self.condition.notify_all()

    def arrive(self, metadata: dict) -> tuple[int, int, dict]:
        now = time.monotonic_ns()
        with self.condition:
            request_id = self.next_request_id
            self.next_request_id += 1
            event = {
                "generation": self.generation,
                "request_id": request_id,
                "arrival_monotonic_ns": now,
                "released_monotonic_ns": None,
                "finished_monotonic_ns": None,
                "outcome": None,
                "error": None,
                **metadata,
            }
            self.events.append(event)
            self.arrivals += 1
            self.active += 1
            self.waiting += 1
            self.condition.notify_all()
            return self.generation, request_id, event

    def await_release(self, generation: int, event: dict) -> bool:
        with self.condition:
            while generation == self.generation and not self.is_open:
                self.condition.wait()
            if self.waiting != 0:
                self.waiting -= 1
            if generation != self.generation:
                event["outcome"] = "gate_generation_changed"
                event["finished_monotonic_ns"] = time.monotonic_ns()
                if self.active != 0:
                    self.active -= 1
                self.completed += 1
                self.condition.notify_all()
                return False
            event["released_monotonic_ns"] = time.monotonic_ns()
            self.condition.notify_all()
            return True

    def finish(self, event: dict, outcome: str, error: str | None = None) -> None:
        with self.condition:
            event["outcome"] = outcome
            event["error"] = error
            event["finished_monotonic_ns"] = time.monotonic_ns()
            if self.active != 0:
                self.active -= 1
            self.completed += 1
            if error is not None:
                self.write_errors += 1
            self.condition.notify_all()

    def wait_for(self, arrivals: int | None, waiting: int | None,
                 active: int | None, timeout: float) -> bool:
        deadline = time.monotonic() + timeout

        def satisfied() -> bool:
            return (
                (arrivals is None or self.arrivals >= arrivals)
                and (waiting is None or self.waiting >= waiting)
                and (active is None or self.active <= active)
            )

        with self.condition:
            while not satisfied():
                remaining = deadline - time.monotonic()
                if remaining <= 0.0:
                    return False
                self.condition.wait(remaining)
            return True

    def report(self) -> dict:
        with self.condition:
            return {
                "generation": self.generation,
                "open": self.is_open,
                "arrivals": self.arrivals,
                "waiting": self.waiting,
                "active": self.active,
                "completed": self.completed,
                "write_errors": self.write_errors,
                "events": [dict(event) for event in self.events],
            }


class ConcurrencyState:
    def __init__(self, corpus: Path) -> None:
        self.corpus_template = CorpusState(corpus)
        self.corpus_flights: list[CorpusState] = []
        self.gate = GateState()
        self.control_lock = threading.RLock()
        self.source_line: int | None = None
        self.logical_flights = 0
        self.occurrences_per_flight = 0

    @staticmethod
    def _clone_selected(template: CorpusState,
                        entries: list[dict]) -> CorpusState:
        """Clone selected immutable corpus data with independent strict uses."""
        clone = CorpusState.__new__(CorpusState)
        clone.__dict__ = dict(template.__dict__)
        clone.lock = threading.RLock()
        clone.entries = entries
        clone.uses = {}
        clone.calls = []
        clone.misses = []
        clone.overuses = []
        clone.integrity_errors = []
        return clone

    def reset(self, source_line: int, opened: bool,
              logical_flights: int,
              occurrences_per_flight: int) -> dict:
        with self.control_lock:
            self.gate.assert_idle()
            if logical_flights <= 0 or occurrences_per_flight <= 0:
                raise ValueError(
                    "logical_flights and occurrences_per_flight must be positive"
                )
            selected = self.corpus_template.select(source_line)
            provisioned_entries = [
                dict(entry, _provisioned_occurrence=occurrence + 1)
                for occurrence in range(occurrences_per_flight)
                for entry in self.corpus_template.entries
            ]
            self.corpus_flights = [
                self._clone_selected(self.corpus_template, provisioned_entries)
                for _index in range(logical_flights)
            ]
            self.source_line = source_line
            self.logical_flights = logical_flights
            self.occurrences_per_flight = occurrences_per_flight
            self.gate.reset(opened)
            return {
                "selected": selected,
                "provisioning": self.provisioning(),
                "gate": self.gate.report(),
            }

    def provisioning(self) -> dict:
        return {
            "line": self.source_line,
            "logical_flights": self.logical_flights,
            "occurrences_per_flight": self.occurrences_per_flight,
            "total_provisioned_occurrences": (
                self.logical_flights * self.occurrences_per_flight
            ),
            "allocation_policy": "round_robin_attempt_waves",
        }

    def arrive(self, metadata: dict) -> tuple[int, int, dict, CorpusState]:
        with self.control_lock:
            if not self.corpus_flights:
                raise RuntimeError("no corpus flights are provisioned")
            with self.gate.condition:
                next_request_id = self.gate.next_request_id
                logical_flight_index = (
                    (next_request_id - 1) % self.logical_flights
                )
                occurrence = (
                    (next_request_id - 1) // self.logical_flights + 1
                )
                generation, request_id, event = self.gate.arrive(
                    {
                        **metadata,
                        "logical_flight": logical_flight_index + 1,
                        "planned_occurrence": occurrence,
                        "occurrence_provisioned": (
                            occurrence <= self.occurrences_per_flight
                        ),
                    }
                )
                flight = self.corpus_flights[logical_flight_index]
        return generation, request_id, event, flight

    def report(self) -> dict:
        with self.control_lock:
            flight_reports = [
                flight.report() for flight in self.corpus_flights
            ]
            provisioning = self.provisioning()
        calls: list[dict] = []
        misses: list[dict] = []
        overuses: list[dict] = []
        integrity_errors: list[dict] = []
        flights: list[dict] = []
        for index, report in enumerate(flight_reports, start=1):
            calls.extend(
                dict(item, logical_flight=index)
                for item in report.get("calls", [])
            )
            misses.extend(
                dict(item, logical_flight=index)
                for item in report.get("misses", [])
            )
            overuses.extend(
                dict(item, logical_flight=index)
                for item in report.get("overuses", [])
            )
            integrity_errors.extend(
                dict(item, logical_flight=index)
                for item in report.get("integrity_errors", [])
            )
            flights.append(
                {
                    "logical_flight": index,
                    "calls": len(report.get("calls", [])),
                    "misses": len(report.get("misses", [])),
                    "overuses": len(report.get("overuses", [])),
                    "integrity_errors": len(
                        report.get("integrity_errors", [])
                    ),
                }
            )
        return {
            "gate": self.gate.report(),
            "provisioning": provisioning,
            "corpus": {
                "line": self.source_line,
                "calls": calls,
                "misses": misses,
                "overuses": overuses,
                "integrity_errors": integrity_errors,
                "flights": flights,
            },
        }


class ConcurrencyHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    concurrency_state: ConcurrencyState
    upstream_scheme: str

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _json(self, status: int, payload: object) -> None:
        body = (json.dumps(payload, sort_keys=True) + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    @staticmethod
    def _one_int(values: dict[str, list[str]], name: str) -> int | None:
        entries = values.get(name)
        if not entries:
            return None
        return int(entries[0])

    def _control(self) -> bool:
        host = self.headers.get("Host", "").partition(":")[0]
        parsed = urlsplit(self.path)
        if host not in {"127.0.0.1", "localhost"}:
            return False
        if not parsed.path.startswith("/__concurrency_"):
            return False
        values = parse_qs(parsed.query)
        try:
            if parsed.path == "/__concurrency_reset":
                source_line = int(values["line"][0])
                opened = values.get("gate", ["closed"])[0] == "open"
                logical_flights = int(
                    values.get("logical_flights", ["1"])[0]
                )
                occurrences_per_flight = int(
                    values.get("occurrences_per_flight", ["1"])[0]
                )
                self._json(
                    200,
                    self.concurrency_state.reset(
                        source_line,
                        opened,
                        logical_flights,
                        occurrences_per_flight,
                    ),
                )
                return True
            if parsed.path == "/__concurrency_gate":
                state = values["state"][0]
                if state not in {"open", "closed"}:
                    raise ValueError("state must be open or closed")
                self.concurrency_state.gate.set_open(state == "open")
                self._json(200, self.concurrency_state.report())
                return True
            if parsed.path == "/__concurrency_wait":
                timeout = float(values.get("timeout", ["10"])[0])
                if timeout < 0.0 or timeout > 300.0:
                    raise ValueError("timeout must be between 0 and 300 seconds")
                matched = self.concurrency_state.gate.wait_for(
                    self._one_int(values, "arrivals"),
                    self._one_int(values, "waiting"),
                    self._one_int(values, "active"),
                    timeout,
                )
                payload = self.concurrency_state.report()
                payload["matched"] = matched
                self._json(200 if matched else 408, payload)
                return True
            if parsed.path == "/__concurrency_report":
                self._json(200, self.concurrency_state.report())
                return True
            self._json(404, {"error": "unknown control endpoint"})
        except Exception as exc:
            self._json(409, {"error": str(exc)})
        return True

    def _serve(self) -> None:
        if self._control():
            return
        host = self.headers.get("Host", "")
        requested_url = f"{self.upstream_scheme}://{host}{self.path}"
        logical_hex = self.headers.get("X-Fastbed-Fixture-Requested-Hex")
        if logical_hex:
            try:
                requested_url = bytes.fromhex(logical_hex).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                pass
        client_host = str(self.client_address[0]) if self.client_address else ""
        generation, _request_id, event, corpus_flight = (
            self.concurrency_state.arrive(
            {
                "method": self.command,
                "requested_url": requested_url,
                "scheme": self.upstream_scheme,
                "client_address": client_host,
            }
            )
        )
        if not self.concurrency_state.gate.await_release(generation, event):
            return
        outcome = "internal_error"
        error: str | None = None
        try:
            entry, body = corpus_flight.response(self.command, requested_url)
            if entry is not None and entry.get("error_type"):
                outcome = "fixture_transport_error"
                try:
                    self.connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.connection.close()
                return
            if entry is None or body is None:
                outcome = "fixture_miss"
                self.send_response(598)
                self.send_header("X-Fastbed-Fixture-Miss", "1")
                self.send_header("Content-Length", "0")
                self.send_header("Connection", "close")
                self.end_headers()
                return
            self.send_response(int(entry["status"]))
            content_type = entry.get("content_type") or (
                "text/html"
                if entry.get("body_storage_type") == "facebook_html_gzip"
                else "application/octet-stream"
            )
            self.send_header("Content-Type", content_type)
            if entry.get("location"):
                self.send_header("Location", str(entry["location"]))
            if entry.get("retry_after"):
                self.send_header("Retry-After", str(entry["retry_after"]))
            if entry.get("final_url"):
                self.send_header(
                    "X-Fastbed-Fixture-Final-Url", str(entry["final_url"])
                )
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
            outcome = "response_sent"
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError) as exc:
            outcome = "client_disconnected"
            error = f"{type(exc).__name__}: {exc}"
        except Exception as exc:
            outcome = "handler_error"
            error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            self.concurrency_state.gate.finish(event, outcome, error)

    do_GET = _serve
    do_HEAD = _serve


class ReusableThreadingHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def server(state: ConcurrencyState, address: str, port: int, scheme: str,
           cert: Path | None = None, key: Path | None = None):
    handler = type(
        f"{scheme.upper()}ConcurrencyHandler",
        (ConcurrencyHandler,),
        {"concurrency_state": state, "upstream_scheme": scheme},
    )
    instance = ReusableThreadingHTTPServer((address, port), handler)
    if scheme == "https":
        assert cert is not None and key is not None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        instance.socket = context.wrap_socket(instance.socket, server_side=True)
    return instance


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, required=True)
    parser.add_argument("--https-port", type=int, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    args = parser.parse_args()

    state = ConcurrencyState(args.corpus)
    servers = [
        server(state, args.address, args.http_port, "http"),
        server(
            state, args.address, args.https_port, "https", args.cert, args.key
        ),
    ]
    threads = [
        threading.Thread(target=item.serve_forever, daemon=True)
        for item in servers
    ]
    for thread in threads:
        thread.start()
    try:
        threads[0].join()
    except KeyboardInterrupt:
        pass
    finally:
        state.gate.set_open(True)
        for item in servers:
            item.shutdown()
            item.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

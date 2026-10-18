#!/usr/bin/env python3
"""Serve one saved Facebed corpus row as a loopback HTTP/HTTPS upstream.

The control API selects a source line before the real Fastbed process receives
that client request. Upstream matching then mirrors Facebed's offline replay
policy and returns exact, hash-verified response bytes. The broker never opens
an outbound connection.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import http.server
import json
from pathlib import Path
import socket
import ssl
import threading
from urllib.parse import parse_qs, unquote, urlsplit


def url_key(url: str) -> tuple[str, str, str, str]:
    parsed = urlsplit(str(url))
    host = (parsed.hostname or "").lower()
    if host in {"facebook.com", "www.facebook.com"}:
        host = "www.facebook.com"
    return (
        parsed.scheme.lower(),
        host,
        unquote(parsed.path).rstrip("/") or "/",
        parsed.query,
    )


class CorpusState:
    def __init__(self, corpus: Path) -> None:
        self.corpus = corpus.resolve()
        self.manifest = self.corpus / "corpus_manifest.jsonl"
        self.lock = threading.RLock()
        self.offsets: dict[int, int] = {}
        self.entries: list[dict] = []
        self.uses: dict[tuple[str, str, str], int] = {}
        self.calls: list[dict] = []
        self.misses: list[dict] = []
        self.overuses: list[dict] = []
        self.integrity_errors: list[dict] = []
        self.current_line: int | None = None
        self.additional: dict[tuple[str, tuple[str, str, str, str]], dict] = {}
        self._index_manifest()
        self._load_additional()

    def _index_manifest(self) -> None:
        with self.manifest.open("rb") as stream:
            while True:
                offset = stream.tell()
                line = stream.readline()
                if not line:
                    break
                record = json.loads(line)
                self.offsets[int(record["line"])] = offset

    def _load_additional(self) -> None:
        catalog = self.corpus / "additional_response_catalog.jsonl"
        if not catalog.exists():
            return
        for text in catalog.read_text(encoding="utf-8").splitlines():
            entry = json.loads(text)
            if entry.get("body_path") and not entry.get("error_type"):
                key = (str(entry["method"]).upper(), url_key(entry["requested_url"]))
                self.additional.setdefault(
                    key,
                    dict(entry, _source="additional_capture", _index=0,
                         _selected=False),
                )

    def _row(self, source_line: int) -> dict:
        offset = self.offsets.get(source_line)
        if offset is None:
            raise KeyError(f"unknown corpus line {source_line}")
        with self.manifest.open("rb") as stream:
            stream.seek(offset)
            return json.loads(stream.readline())

    def select(self, source_line: int) -> dict:
        row = self._row(source_line)
        trace = {}
        trace_path = row.get("request_trace_path")
        if trace_path:
            candidate = (self.corpus / trace_path).resolve()
            candidate.relative_to(self.corpus)
            if candidate.exists():
                trace = json.loads(candidate.read_text(encoding="utf-8"))
        selected_index = trace.get("selected_physical_index")
        entries: list[dict] = []
        for source, field in (
            ("physical", "physical_requests"),
            ("supplemental", "supplemental_requests"),
        ):
            entries.extend(
                dict(
                    entry,
                    _source=source,
                    _index=index,
                    _selected=source == "physical" and index == selected_index,
                )
                for index, entry in enumerate(row.get(field, []))
            )
        with self.lock:
            self.current_line = source_line
            self.entries = entries
            self.uses = {}
            self.calls = []
            self.misses = []
            self.overuses = []
            self.integrity_errors = []
        return {
            "line": source_line,
            "url": row["url"],
            "entries": len(entries),
        }

    def report(self) -> dict:
        with self.lock:
            return {
                "line": self.current_line,
                "calls": list(self.calls),
                "misses": list(self.misses),
                "overuses": list(self.overuses),
                "integrity_errors": list(self.integrity_errors),
            }

    def _candidates(self, method: str, requested_url: str) -> tuple[list[dict], str]:
        candidates: list[dict] = []
        mode = ""
        for source in ("physical", "supplemental"):
            for normalized in (False, True):
                candidates = [
                    entry for entry in self.entries
                    if entry["_source"] == source
                    and str(entry.get("method", "")).upper() == method
                    and (
                        url_key(entry.get("requested_url", "")) == url_key(requested_url)
                        if normalized
                        else entry.get("requested_url") == requested_url
                    )
                ]
                if candidates:
                    mode = source + ("_normalized_request" if normalized
                                     else "_exact_request")
                    break
            if candidates:
                break
        if not candidates:
            candidates = [
                entry for entry in self.entries
                if str(entry.get("method", "")).upper() == method
                and not entry.get("error_type")
                and entry.get("final_url") == requested_url
                and entry.get("_selected")
            ]
            mode = "recorded_final_url"
        if not candidates:
            extra = self.additional.get((method, url_key(requested_url)))
            if extra is not None:
                candidates = [extra]
                mode = "additional_capture_endpoint"
        return candidates, mode

    def response(self, method: str, requested_url: str) -> tuple[dict | None, bytes | None]:
        method = method.upper()
        with self.lock:
            candidates, mode = self._candidates(method, requested_url)
            if not candidates:
                miss = {"method": method, "url": requested_url,
                        "reason": "no_saved_response"}
                self.misses.append(miss)
                return None, None
            use_key = (method, requested_url, mode)
            occurrence = self.uses.get(use_key, 0)
            self.uses[use_key] = occurrence + 1
            if occurrence >= len(candidates):
                overuse = {
                    "method": method,
                    "url": requested_url,
                    "reason": "saved_response_occurrences_exhausted",
                    "match_mode": mode,
                    "requested_occurrence": occurrence + 1,
                    "saved_occurrences": len(candidates),
                }
                self.misses.append(overuse)
                self.overuses.append(overuse)
                return None, None
            entry = candidates[occurrence]
            call = {
                "method": method,
                "requested_url": requested_url,
                "match_mode": mode,
                "source": entry["_source"],
                "saved_request_index": entry["_index"],
                "saved_requested_url": entry.get("requested_url", ""),
                "final_url": entry.get("final_url", ""),
                "status": entry.get("status"),
                "body_path": entry.get("body_path"),
                "body_sha256": entry.get("body_sha256"),
                "bytes": entry.get("bytes", 0),
                "error_type": entry.get("error_type", ""),
                "recorded_redirect_count": entry.get("redirect_count", 0),
                "reused_last_response": False,
                "capture_provenance": entry.get("capture_provenance"),
            }

        if entry.get("error_type"):
            with self.lock:
                self.calls.append(call)
            return entry, None
        relative = entry.get("body_path")
        if not relative:
            with self.lock:
                self.misses.append({"method": method, "url": requested_url,
                                    "reason": "response_body_not_retained"})
            return None, None
        try:
            path = (self.corpus / relative).resolve()
            path.relative_to(self.corpus)
            body = gzip.decompress(path.read_bytes())
            expected_size = int(entry["bytes"])
            expected_hash = str(entry["body_sha256"])
            observed_hash = hashlib.sha256(body).hexdigest()
            if len(body) != expected_size or observed_hash != expected_hash:
                raise ValueError(
                    f"integrity mismatch size={len(body)}/{expected_size} "
                    f"sha256={observed_hash}/{expected_hash}"
                )
        except Exception as exc:
            with self.lock:
                self.integrity_errors.append({"path": relative, "error": str(exc)})
            return None, None
        with self.lock:
            self.calls.append(call)
        return entry, body


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state: CorpusState
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

    def _control(self) -> bool:
        host = self.headers.get("Host", "").partition(":")[0]
        parsed = urlsplit(self.path)
        if host not in {"127.0.0.1", "localhost"}:
            return False
        if parsed.path == "/__fastbed_select":
            try:
                values = parse_qs(parsed.query)
                source_line = int(values["line"][0])
                self._json(200, self.state.select(source_line))
            except Exception as exc:
                self._json(400, {"error": str(exc)})
            return True
        if parsed.path == "/__fastbed_report":
            self._json(200, self.state.report())
            return True
        return False

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
        entry, body = self.state.response(self.command, requested_url)
        if entry is not None and entry.get("error_type"):
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
            return
        if entry is None or body is None:
            self.send_response(598)
            self.send_header("X-Fastbed-Fixture-Miss", "1")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        self.send_response(int(entry["status"]))
        content_type = entry.get("content_type") or (
            "text/html" if entry.get("body_storage_type") == "facebook_html_gzip"
            else "application/octet-stream"
        )
        self.send_header("Content-Type", content_type)
        if entry.get("location"):
            self.send_header("Location", str(entry["location"]))
        if entry.get("retry_after"):
            self.send_header("Retry-After", str(entry["retry_after"]))
        if entry.get("final_url"):
            self.send_header("X-Fastbed-Fixture-Final-Url", str(entry["final_url"]))
        self.send_header("Content-Length", str(len(body)))
        # Make every replayed exchange a distinct transport attempt.  Otherwise
        # libcurl may transparently replay an idempotent request when the next
        # saved fixture intentionally closes a reused keep-alive connection.
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _serve
    do_HEAD = _serve


def server(state: CorpusState, address: str, port: int, scheme: str,
           cert: Path | None = None, key: Path | None = None):
    handler = type(
        f"{scheme.upper()}FixtureHandler",
        (FixtureHandler,),
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, required=True)
    parser.add_argument("--https-port", type=int, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    args = parser.parse_args()
    state = CorpusState(args.corpus)
    servers = [
        server(state, args.address, args.http_port, "http"),
        server(state, args.address, args.https_port, "https", args.cert, args.key),
    ]
    threads = [threading.Thread(target=item.serve_forever, daemon=True)
               for item in servers]
    for thread in threads:
        thread.start()
    try:
        threads[0].join()
    except KeyboardInterrupt:
        pass
    finally:
        for item in servers:
            item.shutdown()
            item.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


#!/usr/bin/env python3
"""Replay frozen oracle request traces from the canonical zstd body archive.

The retired corpus metadata is not reconstructed.  Instead, one Python-oracle
row is selected at a time, its already-observed upstream operations define the
row-local response plan, and body hashes resolve through the independently
verified content-addressed archive.  The process has no outbound client code.
"""

from __future__ import annotations

import argparse
from collections import OrderedDict
import hashlib
import http.server
import json
from pathlib import Path
import socket
import ssl
import threading
from urllib.parse import parse_qs, unquote, urlsplit

try:
    from compression import zstd

    def decompress_zstd(data: bytes) -> bytes:
        return zstd.decompress(data)
except ImportError:  # pragma: no cover - Python < 3.14 compatibility
    import zstandard

    def decompress_zstd(data: bytes) -> bytes:
        return zstandard.ZstdDecompressor().decompress(data)


EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


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


class BodyArchive:
    """Validated archive indexes plus a bounded decompressed-body cache."""

    def __init__(self, archive: Path, cache_bytes: int) -> None:
        self.root = archive.resolve()
        self.cache_limit = cache_bytes
        self.cache_size = 0
        self.cache: OrderedDict[str, bytes] = OrderedDict()
        self.lock = threading.Lock()

        archive_path = self.root / "archive.json"
        verification_path = self.root / "verification.json"
        bodies_path = self.root / "bodies.jsonl"
        archive_record = json.loads(archive_path.read_text(encoding="utf-8"))
        verification = json.loads(verification_path.read_text(encoding="utf-8"))
        if archive_record.get("status") != "complete":
            raise ValueError("archive.json is not marked complete")
        if verification.get("status") != "complete":
            raise ValueError("verification.json is not marked complete")
        if archive_record.get("verification_sha256") != sha256(verification_path):
            raise ValueError("archive verification receipt hash mismatch")
        expected_index_hash = verification.get("index_sha256", {}).get("bodies.jsonl")
        if expected_index_hash != sha256(bodies_path):
            raise ValueError("archive bodies.jsonl hash mismatch")

        self.records: dict[str, dict] = {}
        with bodies_path.open("r", encoding="utf-8") as stream:
            for ordinal, text in enumerate(stream, 1):
                record = json.loads(text)
                body_hash = str(record["body_sha256"])
                if (len(body_hash) != 64
                        or any(ch not in "0123456789abcdef" for ch in body_hash)):
                    raise ValueError(f"invalid body hash at bodies.jsonl row {ordinal}")
                if body_hash in self.records:
                    raise ValueError(f"duplicate archive body hash {body_hash}")
                relative = record.get("body_path")
                if not isinstance(relative, str):
                    raise ValueError(f"missing body path at bodies.jsonl row {ordinal}")
                candidate = (self.root / relative).resolve()
                candidate.relative_to(self.root)
                self.records[body_hash] = record
        expected_bodies = int(archive_record.get("unique_bodies", -1))
        if len(self.records) != expected_bodies:
            raise ValueError(
                f"archive body count mismatch {len(self.records)}/{expected_bodies}"
            )

    def describe(self, body_hash: str) -> dict:
        try:
            return self.records[body_hash]
        except KeyError as exc:
            raise ValueError(f"body hash absent from archive index: {body_hash}") from exc

    def content_type(self, body_hash: str) -> str:
        record = self.describe(body_hash)
        content_types = record.get("content_types")
        if isinstance(content_types, dict) and content_types:
            return str(max(content_types.items(), key=lambda item: (int(item[1]), item[0]))[0])
        return "text/html" if record.get("is_html") else "application/octet-stream"

    def read(self, body_hash: str, expected_bytes: int) -> tuple[bytes, str]:
        with self.lock:
            cached = self.cache.get(body_hash)
            if cached is not None:
                self.cache.move_to_end(body_hash)
                if len(cached) != expected_bytes:
                    raise ValueError(
                        f"oracle/archive size mismatch {expected_bytes}/{len(cached)}"
                    )
                return cached, str(self.records[body_hash]["body_path"])

            record = self.describe(body_hash)
            indexed_bytes = int(record["body_bytes"])
            if indexed_bytes != expected_bytes:
                raise ValueError(
                    f"oracle/archive size mismatch {expected_bytes}/{indexed_bytes}"
                )
            relative = str(record["body_path"])
            path = (self.root / relative).resolve()
            path.relative_to(self.root)
            compressed = path.read_bytes()
            expected_compressed_bytes = int(record["compressed_bytes"])
            if len(compressed) != expected_compressed_bytes:
                raise ValueError(
                    "compressed size mismatch "
                    f"{len(compressed)}/{expected_compressed_bytes}"
                )
            expected_compressed_hash = str(record["compressed_sha256"])
            observed_compressed_hash = hashlib.sha256(compressed).hexdigest()
            if observed_compressed_hash != expected_compressed_hash:
                raise ValueError(
                    "compressed hash mismatch "
                    f"{observed_compressed_hash}/{expected_compressed_hash}"
                )
            body = decompress_zstd(compressed)
            observed_hash = hashlib.sha256(body).hexdigest()
            if len(body) != indexed_bytes or observed_hash != body_hash:
                raise ValueError(
                    f"body integrity mismatch size={len(body)}/{indexed_bytes} "
                    f"sha256={observed_hash}/{body_hash}"
                )
            if len(body) <= self.cache_limit:
                while self.cache and self.cache_size + len(body) > self.cache_limit:
                    _old_hash, old_body = self.cache.popitem(last=False)
                    self.cache_size -= len(old_body)
                self.cache[body_hash] = body
                self.cache_size += len(body)
            return body, relative


class ArchiveCorpusState:
    def __init__(self, oracle: Path, archive: Path, cache_bytes: int) -> None:
        self.oracle = oracle.resolve()
        self.body_archive = BodyArchive(archive, cache_bytes)
        self.lock = threading.RLock()
        self.offsets: dict[int, int] = {}
        self.urls: dict[int, str] = {}
        self.entries: list[dict] = []
        self.expected_gaps: dict[tuple[str, str], list[dict]] = {}
        self.gap_uses: dict[tuple[str, str], int] = {}
        self.uses: dict[tuple[str, str, str], int] = {}
        self.calls: list[dict] = []
        self.misses: list[dict] = []
        self.overuses: list[dict] = []
        self.integrity_errors: list[dict] = []
        self.current_line: int | None = None
        self.active_exchanges = 0
        self._index_oracle()

    def _index_oracle(self) -> None:
        with self.oracle.open("rb") as stream:
            ordinal = 0
            while True:
                offset = stream.tell()
                raw = stream.readline()
                if not raw:
                    break
                ordinal += 1
                row = json.loads(raw)
                line = int(row["line"])
                if line != ordinal:
                    raise ValueError(
                        f"oracle source lines are not sequential at row {ordinal}: {line}"
                    )
                if not isinstance(row.get("url"), str):
                    raise ValueError(f"oracle row {ordinal} has no URL")
                if not isinstance(row.get("requests", []), list):
                    raise ValueError(f"oracle row {ordinal} has invalid requests")
                if not isinstance(row.get("fixture_misses", []), list):
                    raise ValueError(f"oracle row {ordinal} has invalid fixture misses")
                self.offsets[line] = offset
                self.urls[line] = row["url"]

    def _row(self, source_line: int) -> dict:
        offset = self.offsets.get(source_line)
        if offset is None:
            raise KeyError(f"unknown oracle line {source_line}")
        with self.oracle.open("rb") as stream:
            stream.seek(offset)
            row = json.loads(stream.readline())
        if int(row["line"]) != source_line or row["url"] != self.urls[source_line]:
            raise ValueError(f"oracle row identity drift for line {source_line}")
        return row

    def _prepare_entry(self, row: dict, request: dict, index: int,
                       requests: list[dict]) -> dict:
        entry = dict(request)
        method = str(entry.get("method", "")).upper()
        requested_url = entry.get("requested_url")
        if method not in {"GET", "HEAD"} or not isinstance(requested_url, str):
            raise ValueError(f"invalid request trace operation at index {index}")
        entry["method"] = method
        entry["_location"] = ""
        entry["_body_error"] = ""
        status = int(entry.get("status", 0))
        if status in REDIRECT_STATUSES and index + 1 < len(requests):
            following = requests[index + 1]
            following_method = str(following.get("method", "")).upper()
            following_url = following.get("requested_url")
            if (following_method == method and isinstance(following_url, str)
                    and following_url != requested_url):
                entry["_location"] = following_url
        if status in REDIRECT_STATUSES and not entry["_location"]:
            following_gaps = [
                miss for miss in row.get("fixture_misses", [])
                if str(miss.get("method", "")).upper() == method
                and isinstance(miss.get("url"), str)
            ]
            if index + 1 == len(requests) and len(following_gaps) == 1:
                entry["_location"] = str(following_gaps[0]["url"])

        if not entry.get("error_type"):
            body_hash = str(entry.get("body_sha256", ""))
            try:
                record = self.body_archive.describe(body_hash)
                if int(record["body_bytes"]) != int(entry.get("bytes", -1)):
                    raise ValueError(
                        f"oracle/archive size mismatch {entry.get('bytes')}/"
                        f"{record['body_bytes']}"
                    )
                if (body_hash != EMPTY_SHA256
                        and body_hash == row.get("body_sha256")
                        and row.get("upstream_response_content_type")):
                    entry["_content_type"] = str(
                        row["upstream_response_content_type"]
                    )
                else:
                    entry["_content_type"] = self.body_archive.content_type(body_hash)
            except (KeyError, TypeError, ValueError) as exc:
                entry["_content_type"] = "application/octet-stream"
                entry["_body_error"] = str(exc)
        return entry

    def select(self, source_line: int) -> dict:
        row = self._row(source_line)
        requests = row.get("requests", [])
        entries = [
            self._prepare_entry(row, request, index, requests)
            for index, request in enumerate(requests)
        ]
        gaps: dict[tuple[str, str], list[dict]] = {}
        for miss in row.get("fixture_misses", []):
            method = str(miss.get("method", "")).upper()
            url = miss.get("url")
            if method not in {"GET", "HEAD"} or not isinstance(url, str):
                raise ValueError(f"invalid fixture miss in oracle row {source_line}")
            gaps.setdefault((method, url), []).append(dict(miss))
        with self.lock:
            if self.active_exchanges:
                raise RuntimeError(
                    f"cannot select line {source_line} with "
                    f"{self.active_exchanges} active exchanges"
                )
            self.current_line = source_line
            self.entries = entries
            self.expected_gaps = gaps
            self.gap_uses = {}
            self.uses = {}
            self.calls = []
            self.misses = []
            self.overuses = []
            self.integrity_errors = []
        return {
            "line": source_line,
            "url": row["url"],
            "entries": len(entries),
            "expected_gaps": sum(len(items) for items in gaps.values()),
        }

    def begin_exchange(self) -> None:
        with self.lock:
            if self.current_line is None:
                raise RuntimeError("no oracle row selected")
            self.active_exchanges += 1

    def finish_exchange(self) -> None:
        with self.lock:
            self.active_exchanges -= 1

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
        for source in ("physical", "supplemental"):
            candidates = [
                entry for entry in self.entries
                if entry.get("source") == source
                and entry["method"] == method
                and entry.get("saved_requested_url") == requested_url
            ]
            if candidates:
                return candidates, source + "_exact_request"
            candidates = [
                entry for entry in self.entries
                if entry.get("source") == source
                and entry["method"] == method
                and url_key(entry.get("saved_requested_url", "")) == url_key(requested_url)
            ]
            if candidates:
                return candidates, source + "_normalized_request"

        candidates = [
            entry for entry in self.entries
            if entry["method"] == method
            and entry.get("match_mode") == "recorded_final_url"
            and entry.get("final_url") == requested_url
        ]
        if candidates:
            return candidates, "recorded_final_url"

        candidates = [
            entry for entry in self.entries
            if entry.get("source") == "additional_capture"
            and entry["method"] == method
            and url_key(entry.get("saved_requested_url", "")) == url_key(requested_url)
        ]
        if candidates:
            return candidates, "additional_capture_endpoint"
        return [], ""

    def _consume_expected_gap(self, method: str, requested_url: str) -> dict | None:
        key = (method, requested_url)
        gaps = self.expected_gaps.get(key, [])
        occurrence = self.gap_uses.get(key, 0)
        if occurrence >= len(gaps):
            return None
        self.gap_uses[key] = occurrence + 1
        miss = dict(gaps[occurrence])
        self.misses.append(miss)
        return miss

    def response(self, method: str, requested_url: str) -> tuple[dict | None, bytes | None]:
        method = method.upper()
        with self.lock:
            candidates, mode = self._candidates(method, requested_url)
            use_key = (method, requested_url, mode)
            occurrence = self.uses.get(use_key, 0)
            self.uses[use_key] = occurrence + 1
            if occurrence >= len(candidates):
                shared_gap = self._consume_expected_gap(method, requested_url)
                if shared_gap is not None:
                    return None, None
                has_bodyless_saved_gap = any(
                    gap.get("reason") == "response_body_not_retained"
                    for gap in self.expected_gaps.get((method, requested_url), [])
                )
                if candidates or has_bodyless_saved_gap:
                    overuse = {
                        "method": method,
                        "url": requested_url,
                        "reason": "saved_response_occurrences_exhausted",
                        "match_mode": mode,
                        "requested_occurrence": occurrence + 1,
                        "saved_occurrences": len(candidates) + int(has_bodyless_saved_gap),
                    }
                    self.misses.append(overuse)
                    self.overuses.append(overuse)
                else:
                    self.misses.append({
                        "method": method,
                        "url": requested_url,
                        "reason": "no_saved_response",
                    })
                return None, None
            entry = candidates[occurrence]
            call = {
                "method": method,
                "requested_url": requested_url,
                "match_mode": entry.get("match_mode", mode),
                "source": entry.get("source"),
                "saved_request_index": entry.get("saved_request_index"),
                "saved_requested_url": entry.get("saved_requested_url", ""),
                "final_url": entry.get("final_url", ""),
                "status": entry.get("status"),
                "body_path": entry.get("body_path"),
                "body_sha256": entry.get("body_sha256"),
                "bytes": entry.get("bytes", 0),
                "error_type": entry.get("error_type", ""),
                "recorded_redirect_count": entry.get("recorded_redirect_count", 0),
                "reused_last_response": entry.get("reused_last_response", False),
                "capture_provenance": entry.get("capture_provenance"),
            }
            if entry.get("error_type"):
                self.calls.append(call)
                return entry, None
            if entry.get("_body_error"):
                self.integrity_errors.append({
                    "body_sha256": entry.get("body_sha256"),
                    "path": entry.get("body_path"),
                    "error": entry["_body_error"],
                })
                return None, None

        try:
            body, archive_path = self.body_archive.read(
                str(entry["body_sha256"]), int(entry["bytes"])
            )
        except Exception as exc:
            with self.lock:
                self.integrity_errors.append({
                    "body_sha256": entry.get("body_sha256"),
                    "path": entry.get("body_path"),
                    "error": str(exc),
                })
            return None, None
        with self.lock:
            call["archive_body_path"] = archive_path
            self.calls.append(call)
        return entry, body


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state: ArchiveCorpusState
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
        try:
            self.state.begin_exchange()
        except RuntimeError:
            self.send_error(409)
            return
        try:
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
            self.send_header("Content-Type", str(entry["_content_type"]))
            if entry.get("_location"):
                self.send_header("Location", str(entry["_location"]))
            if entry.get("final_url"):
                self.send_header("X-Fastbed-Fixture-Final-Url", str(entry["final_url"]))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)
        finally:
            self.state.finish_exchange()

    do_GET = _serve
    do_HEAD = _serve


def server(state: ArchiveCorpusState, address: str, port: int, scheme: str,
           cert: Path | None = None, key: Path | None = None):
    handler = type(
        f"{scheme.upper()}ArchiveFixtureHandler",
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
    parser.add_argument("oracle", type=Path)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, required=True)
    parser.add_argument("--https-port", type=int, required=True)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    parser.add_argument("--cache-mib", type=int, default=64)
    args = parser.parse_args()
    if args.cache_mib < 0 or args.cache_mib > 1024:
        parser.error("--cache-mib must be between 0 and 1024")
    try:
        state = ArchiveCorpusState(
            args.oracle, args.archive, args.cache_mib * 1024 * 1024
        )
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    servers = [
        server(state, args.address, args.http_port, "http"),
        server(state, args.address, args.https_port, "https", args.cert, args.key),
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
        for item in servers:
            item.shutdown()
            item.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

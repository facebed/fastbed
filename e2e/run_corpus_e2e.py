#!/usr/bin/env python3
"""Drive Fastbed against a retired corpus tree or its canonical zstd archive."""

from __future__ import annotations

import argparse
from collections import Counter
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
from urllib.parse import quote, urlsplit
from urllib.request import urlopen


CRAWLER_USER_AGENT = "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)"
RELEVANT_HEADERS = {"cache-control", "content-type", "location", "vary"}
TRACE_BASE_FIELDS = (
    "method", "requested_url", "final_url", "status", "match_mode",
)
TRACE_ATTEMPT_FIELDS = (
    "source", "saved_request_index", "saved_requested_url",
    "body_path", "body_sha256", "bytes", "error_type",
    "recorded_redirect_count", "reused_last_response", "capture_provenance",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def durable_write_text(path: Path, text: str, *, exclusive: bool = False) -> None:
    with path.open("x" if exclusive else "w", encoding="utf-8") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def wait_http(port: int, path: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urlopen(f"http://127.0.0.1:{port}{path}", timeout=1) as response:
                if response.status == 200:
                    return
        except Exception as exc:
            error = exc
        time.sleep(0.05)
    raise RuntimeError(f"service on port {port} was not ready: {error}")


def get_json(port: int, path: str) -> dict:
    with urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as response:
        return json.loads(response.read())


def request_fastbed(port: int, url: str) -> tuple[int, dict[str, str], bytes]:
    parsed = urlsplit(url)
    encoded_path = quote(parsed.path or "/", safe="/%:@-._~!$&'()*+,;=")
    target = encoded_path
    if parsed.query:
        target += "?" + quote(parsed.query, safe="=&?/:@-._~!$'()*+,;%")
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
    connection.request("GET", target, headers={"User-Agent": CRAWLER_USER_AGENT})
    response = connection.getresponse()
    body = response.read()
    headers = {key.lower(): value for key, value in response.getheaders()}
    status = response.status
    connection.close()
    return status, headers, body


def load_expected(path: Path | None) -> tuple[dict[int, dict], Path | None]:
    if path is None:
        return {}, None
    path = path.resolve()
    root = path.parent
    rows = {}
    for ordinal, text in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        row = json.loads(text)
        line = int(row["line"])
        if line in rows:
            raise RuntimeError(
                f"duplicate Python oracle row for corpus line {line} "
                f"at JSONL row {ordinal}"
            )
        rows[line] = row
    return rows, root


def expected_body(row: dict, root: Path) -> bytes:
    path = (root / row["output_path"]).resolve()
    path.relative_to(root)
    body = path.read_bytes()
    if hashlib.sha256(body).hexdigest() != row["output_sha256"]:
        raise RuntimeError(f"Python oracle output hash mismatch: {path}")
    return body


def normalized_calls(observed: list[dict], expected: list[dict]) -> tuple[list[dict], list[dict], list[str]]:
    fields = list(TRACE_BASE_FIELDS)
    fields.extend(
        field for field in TRACE_ATTEMPT_FIELDS
        if all(field in call for call in observed)
        and all(field in call for call in expected)
    )
    return (
        [{field: call.get(field) for field in fields} for call in observed],
        [{field: call.get(field) for field in fields} for call in expected],
        fields,
    )


def selected_manifest_rows(
    corpus: Path, wanted: set[int] | None,
) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    selected_lines: list[int] = []
    fingerprint = hashlib.sha256()
    seen_lines: set[int] = set()
    with (corpus / "corpus_manifest.jsonl").open("rb") as stream:
        for raw_record in stream:
            row = json.loads(raw_record)
            line = int(row["line"])
            if line in seen_lines:
                raise RuntimeError(f"duplicate corpus manifest line {line}")
            seen_lines.add(line)
            if wanted is None or line in wanted:
                record_hash = hashlib.sha256(raw_record).hexdigest()
                fingerprint.update(f"{line}\t{record_hash}\n".encode("ascii"))
                selected_lines.append(line)
                rows.append(row)
    if wanted is not None:
        missing = sorted(wanted - set(selected_lines))
        if missing:
            raise RuntimeError(f"unknown selected corpus lines: {missing}")
    return rows, {
        "algorithm": "sha256(line-tab-raw-record-sha256-newline-v1)",
        "sha256": fingerprint.hexdigest(),
        "count": len(selected_lines),
        "lines": selected_lines,
    }


def selected_oracle_rows(
    oracle: Path, wanted: set[int] | None,
) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    selected_lines: list[int] = []
    fingerprint = hashlib.sha256()
    with oracle.open("rb") as stream:
        for ordinal, raw_record in enumerate(stream, 1):
            row = json.loads(raw_record)
            line = int(row["line"])
            if line != ordinal:
                raise RuntimeError(
                    f"Python oracle lines are not sequential at JSONL row "
                    f"{ordinal}: {line}"
                )
            if not isinstance(row.get("url"), str):
                raise RuntimeError(f"Python oracle row {ordinal} has no URL")
            if wanted is None or line in wanted:
                record_hash = hashlib.sha256(raw_record).hexdigest()
                fingerprint.update(f"{line}\t{record_hash}\n".encode("ascii"))
                selected_lines.append(line)
                rows.append(row)
    if wanted is not None:
        missing = sorted(wanted - set(selected_lines))
        if missing:
            raise RuntimeError(f"unknown selected oracle lines: {missing}")
    return rows, {
        "algorithm": "sha256(line-tab-raw-oracle-record-sha256-newline-v1)",
        "sha256": fingerprint.hexdigest(),
        "count": len(selected_lines),
        "lines": selected_lines,
    }


def run_identity(
    binary: Path,
    fixtures: Path,
    fixture_kind: str,
    python_results: Path | None,
    runner: Path,
    broker: Path,
    selection: dict,
) -> dict:
    identity = {
        "binary": str(binary),
        "binary_sha256": sha256(binary),
        "fixture_source": str(fixtures),
        "fixture_source_kind": fixture_kind,
        "python_results": str(python_results) if python_results else None,
        "python_results_sha256": sha256(python_results) if python_results else None,
        "runner": str(runner),
        "runner_sha256": sha256(runner),
        "broker": str(broker),
        "broker_sha256": sha256(broker),
        "selection": selection,
    }
    if fixture_kind == "retired-corpus-tree":
        identity.update({
            "corpus": str(fixtures),
            "corpus_manifest_sha256": sha256(fixtures / "corpus_manifest.jsonl"),
        })
    else:
        identity.update({
            "archive": str(fixtures),
            "archive_metadata_sha256": sha256(fixtures / "archive.json"),
            "archive_verification_sha256": sha256(fixtures / "verification.json"),
            "archive_bodies_index_sha256": sha256(fixtures / "bodies.jsonl"),
        })
    return identity


def identity_differences(saved: object, current: object, prefix: str = "identity") -> list[str]:
    if isinstance(saved, dict) and isinstance(current, dict):
        differences: list[str] = []
        for key in sorted(set(saved) | set(current)):
            child = f"{prefix}.{key}"
            if key not in saved or key not in current:
                differences.append(child)
            else:
                differences.extend(identity_differences(saved[key], current[key], child))
        return differences
    return [] if saved == current else [prefix]


def classify_misses(report: dict, expected_row: dict | None) -> tuple[int, int]:
    expected_misses = Counter()
    if expected_row is not None and expected_row.get("outcome") == "replay_unavailable":
        expected_misses.update(
            (str(miss.get("method", "")).upper(), str(miss.get("url", "")))
            for miss in expected_row.get("fixture_misses", [])
        )
    shared = 0
    new = 0
    for miss in report.get("misses", []):
        key = (str(miss.get("method", "")).upper(), str(miss.get("url", "")))
        if (miss.get("reason") != "saved_response_occurrences_exhausted"
                and expected_misses[key] > 0):
            expected_misses[key] -= 1
            shared += 1
        else:
            new += 1
    return shared, new


def terminate(process: subprocess.Popen, timeout: float = 35.0) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument(
        "fixtures", type=Path,
        help="retired corpus tree or canonical upstream_archive directory",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--python-results", type=Path)
    parser.add_argument("--lines", help="comma-separated corpus source lines")
    parser.add_argument("--parent-netns", required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    interfaces = [name for _index, name in socket.if_nameindex()]
    namespace = os.readlink("/proc/self/ns/net")
    if interfaces != ["lo"] or namespace == args.parent_netns:
        parser.error("run under unshare --user --map-root-user --net")

    root = Path(__file__).resolve().parent.parent
    binary = args.binary.resolve()
    fixtures = args.fixtures.resolve()
    output = args.output.resolve()
    runner_path = Path(__file__).resolve()
    python_results = args.python_results.resolve() if args.python_results else None
    if not binary.is_file():
        parser.error(f"binary is not a file: {binary}")
    if python_results is not None and not python_results.is_file():
        parser.error(f"Python oracle is not a file: {python_results}")
    if (fixtures / "corpus_manifest.jsonl").is_file():
        fixture_kind = "retired-corpus-tree"
        broker_path = runner_path.with_name("fixture_broker.py")
    elif all((fixtures / name).is_file() for name in (
            "archive.json", "verification.json", "bodies.jsonl")):
        fixture_kind = "canonical-zstd-archive"
        broker_path = runner_path.with_name("archive_fixture_broker.py")
        if python_results is None:
            parser.error("archive-backed replay requires --python-results")
    else:
        parser.error(
            "fixture source is neither a corpus tree nor a canonical archive: "
            f"{fixtures}"
        )
    if not broker_path.is_file():
        parser.error(f"fixture broker is not a file: {broker_path}")
    if output.exists() and not args.resume:
        parser.error(f"output already exists: {output}")
    if args.resume and not output.exists():
        parser.error(f"resume output does not exist: {output}")
    if output.exists() and not output.is_dir():
        parser.error(f"output is not a directory: {output}")
    requested_lines = None
    if args.lines:
        try:
            requested_values = [int(value) for value in args.lines.split(",")]
        except ValueError as exc:
            parser.error(f"invalid --lines value: {exc}")
        if not requested_values:
            parser.error("--lines must select at least one corpus line")
        if len(requested_values) != len(set(requested_values)):
            parser.error("--lines contains duplicate corpus lines")
        requested_lines = set(requested_values)
    try:
        expected, expected_root = load_expected(python_results)
        if fixture_kind == "retired-corpus-tree":
            selected_rows, selection = selected_manifest_rows(
                fixtures, requested_lines,
            )
        else:
            assert python_results is not None
            selected_rows, selection = selected_oracle_rows(
                python_results, requested_lines,
            )
    except (OSError, ValueError, KeyError, json.JSONDecodeError, RuntimeError) as exc:
        parser.error(str(exc))
    if not selected_rows:
        parser.error("selection contains no corpus rows")
    if python_results is not None:
        missing_oracle = [
            int(row["line"]) for row in selected_rows
            if int(row["line"]) not in expected
        ]
        if missing_oracle:
            preview = ",".join(str(line) for line in missing_oracle[:20])
            suffix = "..." if len(missing_oracle) > 20 else ""
            parser.error(
                f"Python oracle lacks {len(missing_oracle)} selected rows: "
                f"{preview}{suffix}"
            )
    identity = run_identity(
        binary, fixtures, fixture_kind, python_results, runner_path,
        broker_path, selection,
    )
    start_state_path = output / "start-state.json"
    if not output.exists():
        output.mkdir(parents=True)
        (output / "outputs").mkdir()
    elif not (output / "outputs").is_dir():
        parser.error("resume output has no outputs directory")
    if args.resume:
        if not start_state_path.is_file():
            parser.error("resume output has no immutable start-state.json")
        try:
            start_state = json.loads(start_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            parser.error(f"cannot read immutable start state: {exc}")
        if start_state.get("schema") != 1 or not isinstance(start_state.get("identity"), dict):
            parser.error("unsupported or malformed immutable start state")
        drift = identity_differences(start_state["identity"], identity)
        if drift:
            parser.error("resume identity drift: " + ", ".join(drift))
    else:
        start_state = {
            "schema": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "identity": identity,
        }
        try:
            durable_write_text(
                start_state_path,
                json.dumps(start_state, indent=2, sort_keys=True) + "\n",
                exclusive=True,
            )
        except OSError as exc:
            parser.error(f"cannot write immutable start state: {exc}")

    started = datetime.fromisoformat(start_state["created_at"])
    results_path = output / "results.jsonl"
    summary = {
        "requested": 0,
        "completed": 0,
        "exact_body_matches": 0,
        "body_mismatches": 0,
        "status_mismatches": 0,
        "header_mismatches": 0,
        "request_trace_mismatches": 0,
        "fixture_misses": 0,
        "fixture_overuses": 0,
        "shared_fixture_gaps": 0,
        "new_fixture_gaps": 0,
        "integrity_errors": 0,
    }
    completed_lines: set[int] = set()
    selected_by_line = {int(row["line"]): row for row in selected_rows}
    if args.resume and results_path.exists():
        try:
            previous_text = results_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            parser.error(f"cannot read resume results: {exc}")
        if previous_text and not previous_text.endswith("\n"):
            parser.error("resume results end in a partial JSONL row")
        for ordinal, text in enumerate(previous_text.splitlines(), 1):
            try:
                previous = json.loads(text)
                previous_line = int(previous["line"])
            except (ValueError, KeyError, json.JSONDecodeError) as exc:
                parser.error(f"invalid resume result row {ordinal}: {exc}")
            if previous_line not in selected_by_line:
                parser.error(
                    f"resume result row {ordinal} has unselected corpus line {previous_line}"
                )
            if previous_line in completed_lines:
                parser.error(f"duplicate resume result for corpus line {previous_line}")
            if previous.get("url") != selected_by_line[previous_line]["url"]:
                parser.error(f"resume result URL drift for corpus line {previous_line}")
            relative_output = previous.get("output_path")
            if not isinstance(relative_output, str):
                parser.error(f"resume result has no output path for corpus line {previous_line}")
            previous_output = (output / relative_output).resolve()
            try:
                previous_output.relative_to(output)
            except ValueError:
                parser.error(f"resume output escapes artifact root: {relative_output}")
            if (not previous_output.is_file()
                    or sha256(previous_output) != previous.get("body_sha256")):
                parser.error(f"resume output integrity failure for corpus line {previous_line}")
            completed_lines.add(previous_line)
            summary["requested"] += 1
            summary["completed"] += 1
            python_result = previous.get("python")
            if python_results is not None and python_result is None:
                parser.error(
                    f"resume result for line {previous_line} has no Python oracle comparison"
                )
            if python_result is not None:
                summary["exact_body_matches"] += int(python_result["body_match"])
                summary["body_mismatches"] += int(not python_result["body_match"])
                summary["status_mismatches"] += int(not python_result["status_match"])
                summary["header_mismatches"] += int(not python_result["header_match"])
                summary["request_trace_mismatches"] += int(
                    not python_result["request_trace_match"])
            misses = len(previous.get("broker", {}).get("misses", []))
            summary["fixture_misses"] += misses
            summary["fixture_overuses"] += len(
                previous.get("broker", {}).get("overuses", []))
            previous_expected = expected.get(previous_line)
            shared, new = classify_misses(previous.get("broker", {}), previous_expected)
            summary["shared_fixture_gaps"] += shared
            summary["new_fixture_gaps"] += new
            summary["integrity_errors"] += len(
                previous.get("broker", {}).get("integrity_errors", []))

    http_port, https_port, fastbed_port = free_port(), free_port(), free_port()
    cert = output / "fixture-cert.pem"
    key = output / "fixture-key.pem"
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
    config = output / "config.yaml"
    config.write_text(
        "host: 127.0.0.1\n"
        f"port: {fastbed_port}\n"
        "timezone: 7\n"
        "banned_users: []\n"
        "notifier_webhook: ''\n",
        encoding="utf-8",
    )
    broker_log = (output / "broker.log").open("ab" if args.resume else "wb")
    fastbed_log = (output / "fastbed.log").open("ab" if args.resume else "wb")
    broker_arguments = [sys.executable, str(broker_path)]
    if fixture_kind == "canonical-zstd-archive":
        assert python_results is not None
        broker_arguments.extend((str(python_results), str(fixtures)))
    else:
        broker_arguments.append(str(fixtures))
    broker_arguments.extend((
        "--http-port", str(http_port),
        "--https-port", str(https_port), "--cert", str(cert),
        "--key", str(key),
    ))
    broker = subprocess.Popen(
        broker_arguments,
        stdout=broker_log,
        stderr=subprocess.STDOUT,
    )
    fastbed = None
    try:
        wait_http(http_port, "/__fastbed_report")
        environment = dict(os.environ)
        environment["FASTBED_ASSET_DIR"] = str(root / "assets")
        environment["FASTBED_CRAWLER_DB"] = str(
            root / "third_party/crawler-user-agents/crawler-user-agents.json")
        environment["FASTBED_TRACE_PARSER"] = "1"
        fastbed = subprocess.Popen(
            [
                str(binary), "--config", str(config), "--workers", "1",
                "--replay-http-port", str(http_port),
                "--replay-https-port", str(https_port),
            ],
            env=environment,
            stdout=fastbed_log,
            stderr=subprocess.STDOUT,
        )
        wait_http(fastbed_port, "/healthz")
        with results_path.open("ab" if args.resume else "xb") as results:
            for row in selected_rows:
                line = int(row["line"])
                if line in completed_lines:
                    continue
                summary["requested"] += 1
                get_json(http_port, f"/__fastbed_select?line={line}")
                began = time.monotonic()
                status, headers, body = request_fastbed(fastbed_port, row["url"])
                elapsed = time.monotonic() - began
                report = get_json(http_port, "/__fastbed_report")
                relative = f"outputs/{line:06d}.html"
                (output / relative).write_bytes(body)
                result = {
                    "line": line,
                    "url": row["url"],
                    "status": status,
                    "headers": {key: headers[key] for key in sorted(headers)
                                if key in RELEVANT_HEADERS},
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "body_bytes": len(body),
                    "output_path": relative,
                    "elapsed_seconds": round(elapsed, 6),
                    "broker": report,
                }
                expected_row = expected.get(line)
                if expected_row is not None and expected_root is not None:
                    oracle_body = expected_body(expected_row, expected_root)
                    body_match = body == oracle_body
                    status_match = status == int(expected_row["http_status"])
                    expected_headers = {
                        key.lower(): value
                        for key, value in expected_row.get("headers", {}).items()
                        if key.lower() in RELEVANT_HEADERS
                    }
                    observed_headers = result["headers"]
                    header_match = observed_headers == expected_headers
                    observed_trace, expected_trace, trace_fields = normalized_calls(
                        report.get("calls", []), expected_row.get("requests", []),
                    )
                    trace_match = observed_trace == expected_trace
                    result["python"] = {
                        "body_match": body_match,
                        "status_match": status_match,
                        "header_match": header_match,
                        "request_trace_match": trace_match,
                        "request_trace_fields": trace_fields,
                        "outcome": expected_row.get("outcome"),
                        "reason": expected_row.get("reason"),
                    }
                    summary["exact_body_matches"] += int(body_match)
                    summary["body_mismatches"] += int(not body_match)
                    summary["status_mismatches"] += int(not status_match)
                    summary["header_mismatches"] += int(not header_match)
                    summary["request_trace_mismatches"] += int(not trace_match)
                row_misses = len(report.get("misses", []))
                summary["fixture_misses"] += row_misses
                summary["fixture_overuses"] += len(report.get("overuses", []))
                shared, new = classify_misses(report, expected_row)
                summary["shared_fixture_gaps"] += shared
                summary["new_fixture_gaps"] += new
                summary["integrity_errors"] += len(report.get("integrity_errors", []))
                summary["completed"] += 1
                results.write(
                    (json.dumps(result, ensure_ascii=False) + "\n").encode("utf-8")
                )
                results.flush()
                os.fsync(results.fileno())
    finally:
        if fastbed is not None:
            terminate(fastbed)
        terminate(broker, timeout=5)
        broker_log.close()
        fastbed_log.close()

    metadata = {
        "schema": 1,
        "started_at": started.isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "network_namespace": namespace,
        "network_interfaces": interfaces,
        "parent_network_namespace": args.parent_netns,
        **identity,
        "start_state_sha256": sha256(start_state_path),
        "summary": summary,
    }
    durable_write_text(
        output / "manifest.json",
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
    )
    sums = []
    for path in sorted(output.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            sums.append(f"{sha256(path)}  {path.relative_to(output)}")
    durable_write_text(output / "SHA256SUMS", "\n".join(sums) + "\n")
    print(json.dumps({"output": str(output), **summary}, sort_keys=True))
    return int(
        summary["completed"] != summary["requested"]
        or summary["body_mismatches"] != 0
        or summary["status_mismatches"] != 0
        or summary["header_mismatches"] != 0
        or summary["request_trace_mismatches"] != 0
        or summary["fixture_overuses"] != 0
        or summary["new_fixture_gaps"] != 0
        or summary["integrity_errors"] != 0
    )


if __name__ == "__main__":
    raise SystemExit(main())


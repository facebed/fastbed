#!/usr/bin/env python3
"""Create a hash-pinned load-generator workload from Python oracle results."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import quote, urlsplit


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def request_target(url: str) -> str:
    parsed = urlsplit(url)
    path = quote(parsed.path or "/", safe="/%:@-._~!$&'()*+,;=")
    if parsed.query:
        path += "?" + quote(parsed.query, safe="=&?/:@-._~!$'()*+,;%")
    if "\t" in path or "\r" in path or "\n" in path:
        raise ValueError(f"URL produced an unsafe request target: {url!r}")
    return path


def parse_lines(text: str | None) -> set[int] | None:
    if text is None:
        return None
    result: set[int] = set()
    for token in text.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            first_text, last_text = token.split("-", 1)
            first, last = int(first_text), int(last_text)
            if first < 1 or last < first:
                raise ValueError(f"invalid line range: {token}")
            result.update(range(first, last + 1))
        else:
            value = int(token)
            if value < 1:
                raise ValueError(f"invalid line: {token}")
            result.add(value)
    if not result:
        raise ValueError("--lines selected nothing")
    return result


def parse_alternative(value: str) -> tuple[int, Path]:
    status_text, marker, path_text = value.partition(":")
    if not marker:
        raise argparse.ArgumentTypeError("alternative must be STATUS:BODY_FILE")
    status = int(status_text)
    if not 100 <= status <= 599:
        raise argparse.ArgumentTypeError("alternative status must be 100..599")
    path = Path(path_text).expanduser().resolve()
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"alternative body does not exist: {path}")
    return status, path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("python_results", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--lines", help="comma-separated source lines and inclusive ranges"
    )
    parser.add_argument(
        "--limit", type=int,
        help="take at most this many successful rows after line filtering",
    )
    parser.add_argument(
        "--allow-response", action="append", default=[], type=parse_alternative,
        metavar="STATUS:BODY_FILE",
        help="add an exact alternate outcome to every target (for queue tests)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    results = args.python_results.resolve()
    output = args.output.resolve()
    metadata = output.with_name(output.name + ".manifest.json")
    if not results.is_file():
        raise SystemExit(f"results do not exist: {results}")
    if output.exists() or metadata.exists():
        raise SystemExit("output and metadata paths must be new")
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be positive")
    selected_lines = parse_lines(args.lines)
    rows: list[dict] = []
    with results.open(encoding="utf-8") as stream:
        for text in stream:
            row = json.loads(text)
            line = int(row["line"])
            if selected_lines is not None and line not in selected_lines:
                continue
            if (
                row.get("outcome") != "parsed"
                or int(row.get("http_status", 0)) != 200
                or not row.get("output_path")
                or not row.get("output_sha256")
            ):
                continue
            body = (results.parent / str(row["output_path"])).resolve()
            body.relative_to(results.parent.resolve())
            observed = sha256_file(body)
            if observed != row["output_sha256"]:
                raise RuntimeError(
                    f"oracle body integrity mismatch on line {line}: "
                    f"{observed} != {row['output_sha256']}"
                )
            rows.append({
                "line": line,
                "url": str(row["url"]),
                "target": request_target(str(row["url"])),
                "status": int(row["http_status"]),
                "digest": observed,
                "bytes": body.stat().st_size,
                "category": row.get("category"),
            })
            if args.limit is not None and len(rows) >= args.limit:
                break
    if not rows:
        raise RuntimeError("no successful parsed oracle rows matched")
    if selected_lines is not None:
        found = {row["line"] for row in rows}
        missing = sorted(selected_lines - found)
        if missing:
            raise RuntimeError(
                f"requested lines were not successful replayable rows: {missing}"
            )
    alternatives = [
        {
            "status": status,
            "path": str(path),
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }
        for status, path in args.allow_response
    ]
    lines = ["# fastbed-http-workload-v1\n"]
    for row in rows:
        expected = [f"{row['status']}:{row['digest']}"]
        expected.extend(
            f"{alternative['status']}:{alternative['sha256']}"
            for alternative in alternatives
        )
        lines.append(
            f"{row['target']}\t{','.join(expected)}\tline-{row['line']}\n"
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text("".join(lines), encoding="utf-8")
    temporary.replace(output)
    manifest = {
        "schema": "fastbed-http-workload-manifest-v1",
        "generator": str(Path(__file__).resolve()),
        "generator_sha256": sha256_file(Path(__file__).resolve()),
        "python_results": str(results),
        "python_results_sha256": sha256_file(results),
        "workload": str(output),
        "workload_sha256": sha256_file(output),
        "selected_lines": [row["line"] for row in rows],
        "rows": rows,
        "alternatives": alternatives,
    }
    metadata.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps({
        "status": "created",
        "workload": str(output),
        "rows": len(rows),
        "sha256": sha256_file(output),
        "manifest": str(metadata),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

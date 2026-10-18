#!/usr/bin/env python3
"""Run bounded live Facebook canaries through the scratch production image."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any


SCHEMA = "fastbed-scratch-live-canary-v1"
USER_AGENT = "Discordbot/2.0"
ROUTES = (
    (
        "photo",
        "/25813264588296275/photos/p.25813264688296265/25813264688296265/?type=3",
    ),
    ("reel", "/reel/2179630576280040"),
    (
        "permalink",
        "/permalink.php?id=100092161735603&story_fbid="
        "pfbid0rxYMYRPFGcLe5UZNamM6qqnWw3gGJ6P2Eb6ze98WrYcn2pfVDa9y3d1bH42faxSrl",
    ),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def run(
    argv: list[str], *, check: bool = True, timeout: float = 120.0
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", "replace")[-4000:]
        raise RuntimeError(
            f"command failed ({completed.returncode}): {argv!r}\n{stderr}"
        )
    return completed


def inspect(engine: str, target: str, *, image: bool = False) -> dict[str, Any]:
    kind = ["image", "inspect"] if image else ["inspect"]
    payload = json.loads(run([engine, *kind, target]).stdout)
    if not isinstance(payload, list) or len(payload) != 1:
        raise RuntimeError(f"unexpected inspect result for {target!r}")
    return payload[0]


def http_get(
    port: int, path: str, *, user_agent: str | None = None, timeout: float = 60.0
) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"Host": "127.0.0.1", "Connection": "close"}
    if user_agent is not None:
        headers["User-Agent"] = user_agent
    try:
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read()
        response_headers = {
            key.lower(): value for key, value in response.getheaders()
        }
        return response.status, response_headers, body
    finally:
        connection.close()


def wait_ready(engine: str, name: str, deadline: float) -> tuple[dict[str, Any], int]:
    last = "not inspected"
    while time.monotonic() < deadline:
        record = inspect(engine, name)
        state = record.get("State", {})
        bindings = record.get("NetworkSettings", {}).get("Ports", {}).get(
            "9812/tcp"
        )
        last = f"running={state.get('Running')} bindings={bindings!r}"
        if not state.get("Running"):
            raise RuntimeError(f"container exited before readiness: {last}")
        if isinstance(bindings, list) and len(bindings) == 1:
            try:
                port = int(bindings[0]["HostPort"])
                status, _, body = http_get(port, "/healthz", timeout=5.0)
                if status == 200 and json.loads(body).get("status") == "ok":
                    return record, port
            except (KeyError, ValueError, OSError, json.JSONDecodeError):
                pass
        time.sleep(0.1)
    raise RuntimeError(f"container readiness deadline expired: {last}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--engine", choices=("docker",), default="docker")
    args = parser.parse_args()

    output = args.output.expanduser().resolve()
    if output.exists():
        parser.error(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)

    repo = Path(__file__).resolve().parents[1]
    harness_files = [
        Path(__file__).resolve(),
        repo / "e2e" / "SCRATCH_LIVE_CANARY.md",
    ]
    input_hashes = {str(path): sha256_file(path) for path in harness_files}
    work = Path(tempfile.mkdtemp(prefix=".fastbed-live-canary.", dir=output.parent))
    container_name = f"fastbed-live-canary-{os.getpid()}-{uuid.uuid4().hex[:10]}"
    container_created = False
    commands: list[list[str]] = []
    checks: list[dict[str, Any]] = []
    errors: list[str] = []
    route_results: list[dict[str, Any]] = []
    image_before: dict[str, Any] | None = None
    started_at = utc_now()

    def require(label: str, condition: bool, expected: Any, actual: Any) -> None:
        checks.append(
            {
                "label": label,
                "pass": bool(condition),
                "expected": expected,
                "actual": actual,
            }
        )
        if not condition:
            errors.append(f"{label}: expected {expected!r}, got {actual!r}")

    def engine_run(
        argv: list[str], **kwargs: Any
    ) -> subprocess.CompletedProcess[bytes]:
        command = [args.engine, *argv]
        commands.append(command)
        return run(command, **kwargs)

    try:
        image_before = inspect(args.engine, args.image, image=True)
        write_json(work / "image-inspect-before.json", image_before)
        require(
            "image-architecture",
            image_before.get("Architecture") == "amd64",
            "amd64",
            image_before.get("Architecture"),
        )
        require(
            "image-user",
            image_before.get("Config", {}).get("User") == "65532:65532",
            "65532:65532",
            image_before.get("Config", {}).get("User"),
        )

        run_argv = [
            "run",
            "--detach",
            "--name",
            container_name,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "32",
            "--ulimit",
            "core=0:0",
            "--stop-timeout",
            "90",
            "--publish",
            "127.0.0.1::9812",
            args.image,
            "--workers",
            "2",
            "--request-timeout-seconds",
            "45",
        ]
        cid = engine_run(run_argv).stdout.decode("ascii", "strict").strip()
        container_created = True
        require(
            "container-id-shape",
            bool(re.fullmatch(r"[0-9a-f]{64}", cid)),
            "64 lowercase hex characters",
            cid,
        )

        running, port = wait_ready(
            args.engine, container_name, time.monotonic() + 30.0
        )
        write_json(work / "container-inspect-running.json", running)
        require(
            "image-id-bound",
            running.get("Image") == image_before.get("Id"),
            image_before.get("Id"),
            running.get("Image"),
        )

        before_status, before_headers, before_body = http_get(port, "/healthz")
        write_json(work / "health-before.headers.json", before_headers)
        (work / "health-before.body").write_bytes(before_body)
        health_before = json.loads(before_body)
        require("health-before-status", before_status == 200, 200, before_status)
        require(
            "health-before-errors",
            health_before.get("errors") == 0,
            0,
            health_before.get("errors"),
        )

        for stem, route in ROUTES:
            start = time.monotonic()
            status, headers, body = http_get(
                port, route, user_agent=USER_AGENT, timeout=55.0
            )
            elapsed = time.monotonic() - start
            (work / f"{stem}.body").write_bytes(body)
            write_json(work / f"{stem}.headers.json", headers)
            body_digest = hashlib.sha256(body).hexdigest()
            require(f"{stem}-status", status == 200, 200, status)
            require(
                f"{stem}-content-type",
                headers.get("content-type") == "text/html; charset=UTF-8",
                "text/html; charset=UTF-8",
                headers.get("content-type"),
            )
            require(
                f"{stem}-cacheable-embed",
                headers.get("cache-control") == "public, max-age=900",
                "public, max-age=900",
                headers.get("cache-control"),
            )
            require(
                f"{stem}-vary-user-agent",
                headers.get("vary") == "User-Agent",
                "User-Agent",
                headers.get("vary"),
            )
            require(
                f"{stem}-og-metadata",
                b'<meta property="og:' in body,
                "OG meta tag",
                "present" if b'<meta property="og:' in body else "absent",
            )
            route_results.append(
                {
                    "name": stem,
                    "path": route,
                    "status": status,
                    "headers": headers,
                    "body_bytes": len(body),
                    "body_sha256": body_digest,
                    "elapsed_seconds": elapsed,
                }
            )

        after_status, after_headers, after_body = http_get(port, "/healthz")
        write_json(work / "health-after.headers.json", after_headers)
        (work / "health-after.body").write_bytes(after_body)
        health_after = json.loads(after_body)
        require("health-after-status", after_status == 200, 200, after_status)
        require(
            "health-request-delta",
            health_after.get("requests") - health_before.get("requests") == len(ROUTES),
            len(ROUTES),
            health_after.get("requests") - health_before.get("requests"),
        )
        require(
            "health-after-errors",
            health_after.get("errors") == 0,
            0,
            health_after.get("errors"),
        )

        runtime_binary = work / "runtime-fastbed"
        engine_run(
            ["cp", f"{container_name}:/usr/local/bin/fastbed", str(runtime_binary)]
        )
        engine_run(["stop", "--time", "90", container_name], timeout=100.0)
        stopped = inspect(args.engine, container_name)
        write_json(work / "container-inspect-stopped.json", stopped)
        require(
            "graceful-exit",
            stopped.get("State", {}).get("ExitCode") == 0,
            0,
            stopped.get("State", {}).get("ExitCode"),
        )

        logs = engine_run(["logs", container_name], check=False)
        (work / "container.stdout").write_bytes(logs.stdout)
        (work / "container.stderr").write_bytes(logs.stderr)
        stderr_text = logs.stderr.decode("utf-8", "replace")
        require(
            "no-fallback-log",
            "embed fallback" not in stderr_text,
            "no fallback",
            "present" if "embed fallback" in stderr_text else "absent",
        )
        image_after = inspect(args.engine, args.image, image=True)
        write_json(work / "image-inspect-after.json", image_after)
        require(
            "image-tag-stable",
            image_after.get("Id") == image_before.get("Id"),
            image_before.get("Id"),
            image_after.get("Id"),
        )
    except Exception as exc:
        errors.append(f"exception: {type(exc).__name__}: {exc}")
    finally:
        if container_created:
            logs = engine_run(["logs", container_name], check=False)
            if not (work / "container.stdout").exists():
                (work / "container.stdout").write_bytes(logs.stdout)
                (work / "container.stderr").write_bytes(logs.stderr)
            engine_run(["rm", "--force", container_name], check=False)

    for path, old_hash in input_hashes.items():
        current = sha256_file(Path(path))
        require(f"input-stable:{path}", current == old_hash, old_hash, current)

    (work / "harness").mkdir()
    for source in harness_files:
        shutil.copy2(source, work / "harness" / source.name)
    write_json(work / "commands.json", commands)
    write_json(work / "routes.json", route_results)
    report = {
        "schema": SCHEMA,
        "result": "pass" if not errors else "fail",
        "started_at": started_at,
        "finished_at": utc_now(),
        "image_reference": args.image,
        "image_id": image_before.get("Id") if image_before else None,
        "image_repo_digests": image_before.get("RepoDigests", []) if image_before else [],
        "runtime_binary_sha256": (
            sha256_file(work / "runtime-fastbed")
            if (work / "runtime-fastbed").exists()
            else None
        ),
        "user_agent": USER_AGENT,
        "routes": route_results,
        "checks": checks,
        "errors": errors,
    }
    write_json(work / "report.json", report)

    sums: list[str] = []
    for path in sorted(value for value in work.rglob("*") if value.is_file()):
        relative = path.relative_to(work)
        if relative.as_posix() == "SHA256SUMS":
            continue
        sums.append(f"{sha256_file(path)}  {relative.as_posix()}\n")
    (work / "SHA256SUMS").write_text("".join(sums), encoding="utf-8")
    work.replace(output)
    print(output)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

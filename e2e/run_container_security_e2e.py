#!/usr/bin/env python3
"""Exercise the production container under the documented security policy."""

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


SCHEMA = "fastbed-container-security-e2e-v1"


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


def http_get(port: int, path: str) -> tuple[int, dict[str, str], bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5.0)
    try:
        connection.request(
            "GET",
            path,
            headers={"Host": "127.0.0.1", "Connection": "close"},
        )
        response = connection.getresponse()
        body = response.read()
        headers = {key.lower(): value for key, value in response.getheaders()}
        return response.status, headers, body
    finally:
        connection.close()


def wait_healthy(engine: str, name: str, deadline: float) -> dict[str, Any]:
    last = "not inspected"
    while time.monotonic() < deadline:
        record = inspect(engine, name)
        state = record.get("State", {})
        health = state.get("Health", {})
        last = f"running={state.get('Running')} health={health.get('Status')}"
        if not state.get("Running"):
            raise RuntimeError(f"container exited before readiness: {last}")
        if health.get("Status") == "healthy":
            return record
        time.sleep(0.1)
    raise RuntimeError(f"container health deadline expired: {last}")


def parse_status(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key] = value.strip()
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
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
        repo / "e2e" / "CONTAINER_SECURITY_E2E.md",
    ]
    asset_files = [
        repo / "assets" / "index.html",
        repo / "assets" / "favicon.ico",
        repo / "assets" / "banner.png",
    ]
    for path in [*harness_files, *asset_files]:
        if not path.is_file():
            parser.error(f"required input is missing: {path}")
    input_hashes = {str(path): sha256_file(path) for path in harness_files}

    work = Path(
        tempfile.mkdtemp(prefix=".fastbed-container-e2e.", dir=output.parent)
    )
    container_name = f"fastbed-security-e2e-{os.getpid()}-{uuid.uuid4().hex[:10]}"
    container_created = False
    checks: list[dict[str, Any]] = []
    commands: list[list[str]] = []
    errors: list[str] = []
    started_at = utc_now()
    image_before: dict[str, Any] | None = None
    stopped_inspect: dict[str, Any] | None = None
    shutdown_seconds: float | None = None

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

    def engine_run(argv: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        command = [args.engine, *argv]
        commands.append(command)
        return run(command, **kwargs)

    try:
        image_before = inspect(args.engine, args.image, image=True)
        write_json(work / "image-inspect-before.json", image_before)

        run_argv = [
            "run",
            "--detach",
            "--name",
            container_name,
            "--user",
            "fastbed:fastbed",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "64",
            "--ulimit",
            "core=0:0",
            "--stop-timeout",
            "90",
            "--env",
            "FASTBED_HEALTH_PORT=9812",
            "--publish",
            "127.0.0.1::9812",
            args.image,
            "--workers",
            "16",
        ]
        cid = engine_run(run_argv).stdout.decode("ascii", "strict").strip()
        container_created = True
        require("container-id-shape", bool(re.fullmatch(r"[0-9a-f]{64}", cid)), "64 lowercase hex characters", cid)

        running = wait_healthy(args.engine, container_name, time.monotonic() + 45.0)
        write_json(work / "container-inspect-running.json", running)
        state = running["State"]
        host = running["HostConfig"]
        config = running["Config"]

        require("image-id-bound", running.get("Image") == image_before.get("Id"), image_before.get("Id"), running.get("Image"))
        require("runtime-user", config.get("User") == "fastbed:fastbed", "fastbed:fastbed", config.get("User"))
        require("not-privileged", host.get("Privileged") is False, False, host.get("Privileged"))
        require("read-only-root", host.get("ReadonlyRootfs") is True, True, host.get("ReadonlyRootfs"))
        require("no-binds", not host.get("Binds"), [], host.get("Binds"))
        require("no-mounts", not running.get("Mounts"), [], running.get("Mounts"))
        cap_drop = {str(value).upper() for value in host.get("CapDrop") or []}
        require("all-capabilities-dropped", "ALL" in cap_drop, "ALL", sorted(cap_drop))
        require("no-capabilities-added", not host.get("CapAdd"), [], host.get("CapAdd"))
        security_opt = host.get("SecurityOpt") or []
        require("no-new-privileges-option", any(value.startswith("no-new-privileges") for value in security_opt), "no-new-privileges", security_opt)
        require("pid-limit", host.get("PidsLimit") == 64, 64, host.get("PidsLimit"))
        core_limits = [value for value in host.get("Ulimits") or [] if value.get("Name") == "core"]
        require("host-core-limit", core_limits == [{"Name": "core", "Hard": 0, "Soft": 0}], [{"Name": "core", "Hard": 0, "Soft": 0}], core_limits)
        require("docker-health", state.get("Health", {}).get("Status") == "healthy", "healthy", state.get("Health", {}).get("Status"))

        bindings = running.get("NetworkSettings", {}).get("Ports", {}).get("9812/tcp")
        require("single-port-binding", isinstance(bindings, list) and len(bindings) == 1, "one binding", bindings)
        if not isinstance(bindings, list) or len(bindings) != 1:
            raise RuntimeError("cannot determine the published health port")
        binding = bindings[0]
        require("loopback-only-binding", binding.get("HostIp") == "127.0.0.1", "127.0.0.1", binding.get("HostIp"))
        host_port = int(binding["HostPort"])

        status, headers, body = http_get(host_port, "/healthz")
        (work / "health.body").write_bytes(body)
        write_json(work / "health.headers.json", headers)
        require("health-status", status == 200, 200, status)
        require("health-content-type", headers.get("content-type") == "application/json", "application/json", headers.get("content-type"))
        require("health-no-store", headers.get("cache-control") == "no-store", "no-store", headers.get("cache-control"))
        try:
            health = json.loads(body)
        except Exception as exc:
            health = {"decode_error": str(exc)}
        require("health-json-status", health.get("status") == "ok", "ok", health.get("status"))
        for field in ("uptime_secs", "requests", "errors"):
            require(f"health-{field}-integer", isinstance(health.get(field), int) and health[field] >= 0, "nonnegative integer", health.get(field))

        for route, source, expected_type, stem in (
            ("/", asset_files[0], "text/html; charset=UTF-8", "root"),
            ("/favicon.ico", asset_files[1], "image/vnd.microsoft.icon", "favicon"),
            ("/banner.png", asset_files[2], "image/png", "banner"),
        ):
            route_status, route_headers, route_body = http_get(host_port, route)
            (work / f"{stem}.body").write_bytes(route_body)
            write_json(work / f"{stem}.headers.json", route_headers)
            require(f"{stem}-status", route_status == 200, 200, route_status)
            require(f"{stem}-content-type", route_headers.get("content-type") == expected_type, expected_type, route_headers.get("content-type"))
            expected_body = source.read_bytes()
            if route == "/":
                marker = b"{|CREDIT|}"
                require("root-credit-marker-count", expected_body.count(marker) == 1, 1, expected_body.count(marker))
                expected_body = expected_body.replace(marker, b"facebed by pi.kt")
            require(f"{stem}-body", route_body == expected_body, hashlib.sha256(expected_body).hexdigest(), hashlib.sha256(route_body).hexdigest())

        uid = engine_run(["exec", container_name, "id", "-u"]).stdout.decode().strip()
        require("effective-uid-nonzero", uid.isdigit() and int(uid) > 0, "integer > 0", uid)

        status_text = engine_run([
            "exec", container_name, "/bin/sh", "-c",
            "sed -n '/^CapEff:/p;/^NoNewPrivs:/p;/^Threads:/p' /proc/1/status",
        ]).stdout.decode("utf-8", "replace")
        proc_status = parse_status(status_text)
        require("proc-capabilities-zero", proc_status.get("CapEff") == "0000000000000000", "0000000000000000", proc_status.get("CapEff"))
        require("proc-no-new-privileges", proc_status.get("NoNewPrivs") == "1", "1", proc_status.get("NoNewPrivs"))

        limits_text = engine_run([
            "exec", container_name, "/bin/sh", "-c",
            "grep '^Max core file size' /proc/1/limits",
        ]).stdout.decode("utf-8", "replace").strip()
        core_match = re.fullmatch(r"Max core file size\s+(\S+)\s+(\S+)\s+(\S+)", limits_text)
        require("proc-core-limit", bool(core_match and core_match.group(1) == "0" and core_match.group(2) == "0"), "soft=0 hard=0", limits_text)

        process_count_text = engine_run([
            "exec", container_name, "/bin/sh", "-c",
            "ls -d /proc/[0-9]* 2>/dev/null | wc -l",
        ]).stdout.decode().strip()
        process_count = int(process_count_text)
        require("process-budget", 1 <= process_count <= 64, "1..64", process_count)

        write_probes: dict[str, int] = {}
        for location in ("/fastbed-write-probe", "/tmp/fastbed-write-probe", "/var/tmp/fastbed-write-probe"):
            completed = engine_run(
                ["exec", container_name, "/bin/sh", "-c", f": > {location}"],
                check=False,
            )
            write_probes[location] = completed.returncode
            require(f"write-denied-{location}", completed.returncode != 0, "nonzero exit", completed.returncode)

        mem_probe = engine_run([
            "exec", container_name, "/bin/sh", "-c",
            "dd if=/proc/1/mem of=/dev/null bs=1 count=1",
        ], check=False)
        require("same-uid-proc-mem-denied", mem_probe.returncode != 0, "nonzero exit", mem_probe.returncode)
        write_json(
            work / "runtime-probes.json",
            {
                "uid": uid,
                "proc_status": proc_status,
                "core_limit_line": limits_text,
                "process_count": process_count,
                "write_probe_exit_codes": write_probes,
                "proc_mem_exit_code": mem_probe.returncode,
                "proc_mem_stderr": mem_probe.stderr.decode("utf-8", "replace"),
            },
        )

        shutdown_start = time.monotonic()
        engine_run(["stop", "--time", "90", container_name], timeout=100.0)
        shutdown_seconds = time.monotonic() - shutdown_start
        stopped_inspect = inspect(args.engine, container_name)
        write_json(work / "container-inspect-stopped.json", stopped_inspect)
        stopped_state = stopped_inspect["State"]
        require("graceful-exit", stopped_state.get("ExitCode") == 0, 0, stopped_state.get("ExitCode"))
        require("not-oom-killed", stopped_state.get("OOMKilled") is False, False, stopped_state.get("OOMKilled"))
        require("stopped", stopped_state.get("Running") is False, False, stopped_state.get("Running"))
        require("bounded-shutdown", shutdown_seconds < 90.0, "< 90 seconds", shutdown_seconds)

        image_after = inspect(args.engine, args.image, image=True)
        write_json(work / "image-inspect-after.json", image_after)
        require("image-tag-stable", image_after.get("Id") == image_before.get("Id"), image_before.get("Id"), image_after.get("Id"))
    except Exception as exc:
        errors.append(f"exception: {type(exc).__name__}: {exc}")
    finally:
        if container_created:
            logs = engine_run(["logs", container_name], check=False)
            (work / "container.stdout").write_bytes(logs.stdout)
            (work / "container.stderr").write_bytes(logs.stderr)
            engine_run(["rm", "--force", container_name], check=False)

    for path, old_hash in input_hashes.items():
        current = sha256_file(Path(path))
        require(f"input-stable:{path}", current == old_hash, old_hash, current)

    (work / "harness").mkdir()
    for source in harness_files:
        shutil.copy2(source, work / "harness" / source.name)
    (work / "source-assets").mkdir()
    for source in asset_files:
        shutil.copy2(source, work / "source-assets" / source.name)
    write_json(work / "commands.json", commands)
    report = {
        "schema": SCHEMA,
        "result": "pass" if not errors else "fail",
        "started_at": started_at,
        "finished_at": utc_now(),
        "image_reference": args.image,
        "image_id": image_before.get("Id") if image_before else None,
        "image_repo_digests": image_before.get("RepoDigests", []) if image_before else [],
        "container_name": container_name,
        "shutdown_seconds": shutdown_seconds,
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

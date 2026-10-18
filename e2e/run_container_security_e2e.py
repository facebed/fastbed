#!/usr/bin/env python3
"""Exercise the production container under the documented security policy."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
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


def wait_ready(
    engine: str, name: str, deadline: float
) -> tuple[dict[str, Any], int]:
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
                status, _, body = http_get(port, "/healthz")
                if status == 200 and json.loads(body).get("status") == "ok":
                    return record, port
            except (KeyError, ValueError, OSError, json.JSONDecodeError):
                pass
        time.sleep(0.1)
    raise RuntimeError(f"container readiness deadline expired: {last}")


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
            "--publish",
            "127.0.0.1::9812",
            args.image,
            "--workers",
            "16",
        ]
        cid = engine_run(run_argv).stdout.decode("ascii", "strict").strip()
        container_created = True
        require("container-id-shape", bool(re.fullmatch(r"[0-9a-f]{64}", cid)), "64 lowercase hex characters", cid)

        running, host_port = wait_ready(
            args.engine, container_name, time.monotonic() + 45.0
        )
        write_json(work / "container-inspect-running.json", running)
        state = running["State"]
        host = running["HostConfig"]
        config = running["Config"]

        require("image-id-bound", running.get("Image") == image_before.get("Id"), image_before.get("Id"), running.get("Image"))
        require("runtime-user", config.get("User") == "65532:65532", "65532:65532", config.get("User"))
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
        require("no-image-health-command", not config.get("Healthcheck"), None, config.get("Healthcheck"))

        bindings = running.get("NetworkSettings", {}).get("Ports", {}).get("9812/tcp")
        require("single-port-binding", isinstance(bindings, list) and len(bindings) == 1, "one binding", bindings)
        if not isinstance(bindings, list) or len(bindings) != 1:
            raise RuntimeError("cannot determine the published health port")
        binding = bindings[0]
        require("loopback-only-binding", binding.get("HostIp") == "127.0.0.1", "127.0.0.1", binding.get("HostIp"))
        require("readiness-port-stable", int(binding["HostPort"]) == host_port, host_port, binding.get("HostPort"))

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

        runtime_binary = work / "runtime-fastbed"
        runtime_manifest_path = work / "runtime-manifest.txt"
        runtime_packages_path = work / "runtime-build-packages.txt"
        ca_bundle_path = work / "ca-certificates.crt"
        for runtime_path, local_path in (
            ("/usr/local/bin/fastbed", runtime_binary),
            ("/usr/local/share/fastbed-runtime/RUNTIME-MANIFEST.txt", runtime_manifest_path),
            ("/usr/local/share/fastbed-runtime/ALPINE-BUILD-PACKAGES", runtime_packages_path),
            ("/etc/ssl/certs/ca-certificates.crt", ca_bundle_path),
        ):
            engine_run(["cp", f"{container_name}:{runtime_path}", str(local_path)])

        elf_header = run(["readelf", "-hW", str(runtime_binary)]).stdout.decode()
        elf_programs = run(["readelf", "-lW", str(runtime_binary)]).stdout.decode()
        elf_dynamic = run(["readelf", "-dW", str(runtime_binary)]).stdout.decode()
        (work / "runtime-elf-header.txt").write_text(elf_header, encoding="utf-8")
        (work / "runtime-elf-program-headers.txt").write_text(elf_programs, encoding="utf-8")
        (work / "runtime-elf-dynamic.txt").write_text(elf_dynamic, encoding="utf-8")
        require("static-pie-elf-type", "Type:                              DYN" in elf_header, "ELF ET_DYN static PIE", next((line.strip() for line in elf_header.splitlines() if "Type:" in line), "missing"))
        require("no-elf-interpreter", "Requesting program interpreter" not in elf_programs, "no PT_INTERP", "present" if "Requesting program interpreter" in elf_programs else "absent")
        needed = re.findall(r"Shared library: \[([^]]+)\]", elf_dynamic)
        require("no-dt-needed", needed == [], [], needed)

        archive = engine_run(["export", container_name], timeout=60.0).stdout
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as rootfs:
            rootfs_paths = sorted(
                member.name.removeprefix("./").rstrip("/")
                for member in rootfs.getmembers()
                if member.name.removeprefix("./").rstrip("/")
            )
        write_json(work / "rootfs-paths.json", rootfs_paths)
        rootfs_set = set(rootfs_paths)
        for required_path in (
            "usr/local/bin/fastbed",
            "etc/ssl/certs/ca-certificates.crt",
            "usr/local/share/fastbed-runtime/RUNTIME-MANIFEST.txt",
            "usr/local/share/fastbed/BUILD-RECEIPT.json",
        ):
            require(f"scratch-required:{required_path}", required_path in rootfs_set, True, required_path in rootfs_set)
        forbidden_paths = sorted(
            path for path in rootfs_paths
            if path in {
                "bin/sh", "bin/busybox", "lib/apk/db/installed",
                "lib/ld-musl-x86_64.so.1", "lib64/ld-linux-x86-64.so.2",
            }
            or re.search(r"(^|/)[^/]+\.so(?:\.|$)", path)
        )
        require("scratch-no-shell-loader-or-shared-objects", forbidden_paths == [], [], forbidden_paths)

        manifest_values: dict[str, str] = {}
        for line in runtime_manifest_path.read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                manifest_values[key] = value
        require("scratch-runtime-profile", manifest_values.get("profile") == "fastbed-scratch-static-v1", "fastbed-scratch-static-v1", manifest_values.get("profile"))
        require("runtime-ca-bundle-bound", manifest_values.get("ca_bundle_sha256") == sha256_file(ca_bundle_path), sha256_file(ca_bundle_path), manifest_values.get("ca_bundle_sha256"))
        package_names = sorted(re.findall(r"^P:(.+)$", runtime_packages_path.read_text(encoding="utf-8"), re.MULTILINE))
        expected_packages = sorted(["ca-certificates", "ca-certificates-bundle", "libgcc", "libstdc++", "musl"])
        require("scratch-build-package-provenance", package_names == expected_packages, expected_packages, package_names)

        host_pid = state.get("Pid")
        require("host-pid", isinstance(host_pid, int) and host_pid > 0, "integer > 0", host_pid)
        if not isinstance(host_pid, int) or host_pid <= 0:
            raise RuntimeError("cannot inspect container process on the host")
        status_text = Path(f"/proc/{host_pid}/status").read_text(encoding="utf-8")
        proc_status = parse_status(status_text)
        uid_fields = proc_status.get("Uid", "").split()
        uid = uid_fields[0] if uid_fields else ""
        require("effective-uid", uid == "65532", "65532", uid)
        require("proc-capabilities-zero", proc_status.get("CapEff") == "0000000000000000", "0000000000000000", proc_status.get("CapEff"))
        require("proc-no-new-privileges", proc_status.get("NoNewPrivs") == "1", "1", proc_status.get("NoNewPrivs"))

        limits_text = next(
            line for line in Path(f"/proc/{host_pid}/limits").read_text(
                encoding="utf-8"
            ).splitlines() if line.startswith("Max core file size")
        ).strip()
        core_match = re.fullmatch(r"Max core file size\s+(\S+)\s+(\S+)\s+(\S+)", limits_text)
        require("proc-core-limit", bool(core_match and core_match.group(1) == "0" and core_match.group(2) == "0"), "soft=0 hard=0", limits_text)

        process_lines = engine_run(["top", container_name, "-eo", "pid"]).stdout.decode().splitlines()
        process_count = max(0, len([line for line in process_lines[1:] if line.strip()]))
        require("process-budget", 1 <= process_count <= 64, "1..64", process_count)

        mem_error = ""
        try:
            descriptor = os.open(f"/proc/{host_pid}/mem", os.O_RDONLY)
        except OSError as exc:
            mem_denied = True
            mem_error = f"{type(exc).__name__}: {exc}"
        else:
            os.close(descriptor)
            mem_denied = False
        require("same-uid-proc-mem-denied", mem_denied, True, mem_error or "opened")
        write_json(
            work / "runtime-probes.json",
            {
                "uid": uid,
                "proc_status": proc_status,
                "core_limit_line": limits_text,
                "process_count": process_count,
                "proc_mem_denied": mem_denied,
                "proc_mem_error": mem_error,
                "rootfs_path_count": len(rootfs_paths),
                "build_package_provenance": package_names,
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

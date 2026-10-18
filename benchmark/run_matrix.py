#!/usr/bin/env python3
"""Run a correctness-gated, randomized paired HTTP performance matrix."""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import random
import re
import shutil
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
import traceback
from typing import Any, Iterable


PLAN_SCHEMA = "fastbed-benchmark-plan-v1"
MANIFEST_SCHEMA = "fastbed-benchmark-artifact-v1"
REQUIRED_VARIANTS = {"control", "current", "native", "ir-pgo", "bolt", "allocator"}
REQUIRED_SCENARIOS = {"cold", "nocache", "warm", "singleflight", "slow", "queue"}
RELEASE_PROFILE = "release-matrix"
SERVICE_COMPARE_PROFILE = "service-compare"
KNOWN_PROFILES = {RELEASE_PROFILE, SERVICE_COMPARE_PROFILE}
SECRET_NAME = re.compile(r"(secret|token|password|passwd|webhook|api.?key)", re.I)
CGROUP_FILES = (
    "cpu.stat", "cpu.stat.local", "memory.current", "memory.peak",
    "memory.events", "memory.stat", "pids.current", "pids.peak", "io.stat",
)
SOURCE_EXCLUDED = {".git", "artifacts", "__pycache__", ".pytest_cache"}


def raw_ns() -> int:
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def optional_sha256(path: str | Path | None) -> str | None:
    if path is None:
        return None
    candidate = Path(path)
    return sha256_file(candidate) if candidate.is_file() else None


def atomic_json(path: Path, value: Any) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def ensure_list_of_strings(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(f"{label} must be a nonempty argv string array")
    return list(value)


def parse_cpu_list(value: Any, label: str) -> set[int]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a nonempty integer array")
    result: set[int] = set()
    for item in value:
        if not isinstance(item, int) or item < 0:
            raise ValueError(f"{label} has an invalid CPU: {item!r}")
        result.add(item)
    if len(result) != len(value):
        raise ValueError(f"{label} contains duplicate CPUs")
    return result


def parse_kernel_cpu_list(value: str) -> set[int]:
    result: set[int] = set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            first_text, last_text = token.split("-", 1)
            first, last = int(first_text), int(last_text)
            result.update(range(first, last + 1))
        else:
            result.add(int(token))
    return result


def active_workload_lines(path: Path) -> list[str]:
    return [
        line for line in path.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]


def validate_hooks(scenario: dict[str, Any], key: str) -> None:
    value = scenario.get(key, [])
    if not isinstance(value, list):
        raise ValueError(f"scenario {scenario['name']} {key} must be an array")
    for index, argv in enumerate(value):
        ensure_list_of_strings(argv, f"{scenario['name']}.{key}[{index}]")


def resolve_env(template: dict[str, Any], label: str) -> dict[str, str]:
    if not isinstance(template, dict):
        raise ValueError(f"{label} env must be an object")
    resolved: dict[str, str] = {}
    for key, value in template.items():
        if not isinstance(key, str) or not key or not isinstance(value, str):
            raise ValueError(f"{label} env keys and values must be strings")
        if value.startswith("$ENV:"):
            source = value[5:]
            if not source or source not in os.environ:
                raise ValueError(f"{label} requires unset environment variable {source}")
            resolved[key] = os.environ[source]
        else:
            if SECRET_NAME.search(key) and value:
                raise ValueError(
                    f"{label} must reference sensitive {key} with $ENV:NAME"
                )
            resolved[key] = value
    return resolved


def effective_server(plan: dict[str, Any], variant: dict[str, Any]) -> dict[str, Any]:
    """Return base server settings with a variant-specific overlay."""
    base = dict(plan["server"])
    overlay = variant.get("server", {})
    if not isinstance(overlay, dict):
        raise ValueError(f"variant {variant.get('name')} server must be an object")
    base_env = base.get("env", {})
    overlay_env = overlay.get("env", {})
    base.update(overlay)
    if "env" in overlay:
        if not isinstance(base_env, dict) or not isinstance(overlay_env, dict):
            raise ValueError(
                f"variant {variant.get('name')} server env must be an object"
            )
        base["env"] = {**base_env, **overlay_env}
    return base


def validate_plan(plan: Any, root: Path) -> dict[str, Any]:
    if not isinstance(plan, dict) or plan.get("schema") != PLAN_SCHEMA:
        raise ValueError(f"plan schema must be {PLAN_SCHEMA}")
    if not isinstance(plan.get("seed"), int) or plan["seed"] < 0:
        raise ValueError("seed must be a nonnegative integer")
    if not isinstance(plan.get("blocks"), int) or plan["blocks"] < 2:
        raise ValueError("blocks must be at least two for paired evidence")
    if not isinstance(plan.get("host"), str) or not plan["host"]:
        raise ValueError("host must be a string")
    if not isinstance(plan.get("port"), int) or not 1 <= plan["port"] <= 65535:
        raise ValueError("port must be between 1 and 65535")
    profile = plan.get("profile", RELEASE_PROFILE)
    if profile not in KNOWN_PROFILES:
        raise ValueError(f"profile must be one of {sorted(KNOWN_PROFILES)}")
    plan["profile"] = profile
    server = plan.get("server")
    if not isinstance(server, dict):
        raise ValueError("server must be an object")
    if profile == RELEASE_PROFILE:
        server_argv = ensure_list_of_strings(server.get("argv"), "server.argv")
        if not any("{binary}" in item for item in server_argv):
            raise ValueError("server.argv must contain {binary}")
    elif "argv" in server:
        ensure_list_of_strings(server.get("argv"), "server.argv")
    if server.get("ready_path", "/healthz") != "/healthz":
        raise ValueError("server.ready_path must be /healthz to avoid warming work")
    resolve_env(server.get("env", {}), "server")
    resolve_env(plan.get("client_env", {}), "client")
    resolve_env(plan.get("controller_env", {}), "controller")

    variants = plan.get("variants")
    if not isinstance(variants, list) or not variants:
        raise ValueError("variants must be a nonempty array")
    variant_names: set[str] = set()
    for variant in variants:
        if not isinstance(variant, dict):
            raise ValueError("each variant must be an object")
        name = variant.get("name")
        binary = Path(str(variant.get("binary", ""))).expanduser()
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", name):
            raise ValueError(f"invalid variant name: {name!r}")
        if name in variant_names:
            raise ValueError(f"duplicate variant: {name}")
        variant_names.add(name)
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise ValueError(f"variant binary is not executable: {binary}")
        variant["binary"] = str(binary.resolve())
        variant.setdefault("args", [])
        if not isinstance(variant["args"], list) or not all(
            isinstance(item, str) for item in variant["args"]
        ):
            raise ValueError(f"variant {name} args must be strings")
        input_files = variant.get("input_files", [])
        if not isinstance(input_files, list) or not all(
            isinstance(item, str) and item for item in input_files
        ):
            raise ValueError(f"variant {name} input_files must be path strings")
        resolved_inputs: list[str] = []
        for item in input_files:
            path = Path(item).expanduser()
            if not path.is_file():
                raise ValueError(f"variant {name} input file does not exist: {path}")
            resolved_inputs.append(str(path.resolve()))
        variant["input_files"] = resolved_inputs
        kind_args = variant.get("kind_args", {})
        if not isinstance(kind_args, dict):
            raise ValueError(f"variant {name} kind_args must be an object")
        for kind, values in kind_args.items():
            if not isinstance(kind, str) or not kind:
                raise ValueError(f"variant {name} has an invalid kind_args key")
            if not isinstance(values, list) or not all(
                isinstance(item, str) for item in values
            ):
                raise ValueError(
                    f"variant {name} kind_args.{kind} must be string arguments"
                )
        variant_server = effective_server(plan, variant)
        variant_argv = ensure_list_of_strings(
            variant_server.get("argv"), f"variant {name} effective server.argv"
        )
        if not any("{binary}" in item for item in variant_argv):
            raise ValueError(
                f"variant {name} effective server.argv must contain {{binary}}"
            )
        if variant_server.get("ready_path", "/healthz") != "/healthz":
            raise ValueError(
                f"variant {name} ready_path must be /healthz to avoid warming work"
            )
        resolve_env(variant_server.get("env", {}), f"variant {name} server")
        resolved_variant_env = resolve_env(
            variant.get("env", {}), f"variant {name}"
        )
        if name == "allocator":
            preload = resolved_variant_env.get("LD_PRELOAD", "")
            preload_paths = [
                Path(item).expanduser() for item in re.split(r"[:\s]+", preload)
                if item
            ]
            if not preload_paths or not all(path.is_file() for path in preload_paths):
                raise ValueError(
                    "allocator variant requires existing LD_PRELOAD file(s)"
                )
    if profile == RELEASE_PROFILE:
        missing_variants = REQUIRED_VARIANTS - variant_names
        if missing_variants:
            raise ValueError(f"missing required variants: {sorted(missing_variants)}")
        plan["baseline_variant"] = "control"
    else:
        baseline = plan.get("baseline_variant")
        if not isinstance(baseline, str) or baseline not in variant_names:
            raise ValueError("service-compare baseline_variant must name a variant")
        if len(variant_names) < 2:
            raise ValueError("service-compare requires at least two variants")

    scenarios = plan.get("scenarios")
    if not isinstance(scenarios, list) or not scenarios:
        raise ValueError("scenarios must be a nonempty array")
    scenario_kinds: set[str] = set()
    scenario_names: set[str] = set()
    for scenario in scenarios:
        if not isinstance(scenario, dict):
            raise ValueError("each scenario must be an object")
        name, kind = scenario.get("name"), scenario.get("kind")
        if not isinstance(name, str) or not re.fullmatch(
            r"[a-z0-9][a-z0-9_.-]*", name
        ):
            raise ValueError(f"invalid scenario name: {name!r}")
        if name in scenario_names:
            raise ValueError(f"duplicate scenario: {name}")
        scenario_names.add(name)
        if profile == RELEASE_PROFILE and kind not in REQUIRED_SCENARIOS:
            raise ValueError(f"scenario {name} has invalid kind {kind!r}")
        if profile == SERVICE_COMPARE_PROFILE and (
            not isinstance(kind, str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", kind)
        ):
            raise ValueError(f"scenario {name} has invalid kind {kind!r}")
        if kind in scenario_kinds:
            raise ValueError(f"duplicate scenario kind: {kind}")
        scenario_kinds.add(kind)
        workload = Path(str(scenario.get("requests_file", ""))).expanduser()
        if not workload.is_file():
            raise ValueError(f"scenario {name} workload does not exist: {workload}")
        scenario["requests_file"] = str(workload.resolve())
        lines = active_workload_lines(workload)
        if not lines:
            raise ValueError(f"scenario {name} workload is empty")
        if kind == "singleflight" and len(lines) != 1:
            raise ValueError("singleflight workload must have exactly one target")
        if kind == "queue" and not any("," in line.split("\t")[1] for line in lines):
            raise ValueError("queue workload must allow exact success and overload pairs")
        for key in ("requests", "concurrency"):
            if not isinstance(scenario.get(key), int) or scenario[key] < 1:
                raise ValueError(f"scenario {name} {key} must be positive")
        if scenario["concurrency"] > scenario["requests"]:
            raise ValueError(f"scenario {name} concurrency exceeds requests")
        mode = scenario.get("mode", "closed")
        if mode not in {"closed", "open"}:
            raise ValueError(f"scenario {name} has invalid mode")
        if mode == "open" and not isinstance(scenario.get("rate"), (int, float)):
            raise ValueError(f"open scenario {name} requires rate")
        if scenario.get("connection_mode", "keepalive") not in {
            "keepalive", "fin", "rst"
        }:
            raise ValueError(f"scenario {name} has invalid connection mode")
        if kind == "warm" and "warmup_requests" not in scenario:
            raise ValueError("warm scenario requires warmup_requests")
        if "warmup_requests" in scenario and (
            not isinstance(scenario["warmup_requests"], int)
            or scenario["warmup_requests"] < 1
        ):
            raise ValueError(f"scenario {name} warmup_requests must be positive")
        if scenario.get("warmup_mode", "closed") not in {"closed", "open"}:
            raise ValueError(f"scenario {name} has invalid warmup_mode")
        if "warmup_concurrency" in scenario and "warmup_requests" not in scenario:
            raise ValueError(
                f"scenario {name} warmup_concurrency requires warmup_requests"
            )
        if "warmup_concurrency" in scenario and (
            not isinstance(scenario["warmup_concurrency"], int)
            or scenario["warmup_concurrency"] < 1
            or scenario["warmup_concurrency"] > scenario["warmup_requests"]
        ):
            raise ValueError(
                f"scenario {name} warmup_concurrency must be positive and no "
                "larger than warmup_requests"
            )
        if kind in {"slow", "queue"} and not scenario.get("after_ready"):
            raise ValueError(f"{kind} scenario requires an after_ready controller hook")
        for hook in ("before_start", "after_ready", "after_measure"):
            validate_hooks(scenario, hook)
        if not isinstance(scenario.get("server_args", []), list) or not all(
            isinstance(item, str) for item in scenario.get("server_args", [])
        ):
            raise ValueError(f"scenario {name} server_args must be strings")
    if profile == RELEASE_PROFILE:
        missing_scenarios = REQUIRED_SCENARIOS - scenario_kinds
        if missing_scenarios:
            raise ValueError(f"missing required scenarios: {sorted(missing_scenarios)}")
    else:
        required_kinds = plan.get("required_scenario_kinds")
        if not isinstance(required_kinds, list) or not required_kinds or not all(
            isinstance(kind, str) and kind for kind in required_kinds
        ):
            raise ValueError(
                "service-compare required_scenario_kinds must be a nonempty string array"
            )
        if len(set(required_kinds)) != len(required_kinds):
            raise ValueError("required_scenario_kinds contains duplicates")
        missing_scenarios = set(required_kinds) - scenario_kinds
        if missing_scenarios:
            raise ValueError(
                f"missing required service scenarios: {sorted(missing_scenarios)}"
            )

    affinity = plan.get("affinity")
    if not isinstance(affinity, dict):
        raise ValueError("affinity must be an object")
    server_cpus = parse_cpu_list(affinity.get("server"), "affinity.server")
    client_cpus = parse_cpu_list(affinity.get("client"), "affinity.client")
    sidecar_cpus = parse_cpu_list(affinity.get("sidecars"), "affinity.sidecars")
    if (
        server_cpus & client_cpus
        or server_cpus & sidecar_cpus
        or client_cpus & sidecar_cpus
    ):
        raise ValueError("server, client, and sidecar CPU sets must be disjoint")
    allowed = os.sched_getaffinity(0)
    if (
        not server_cpus <= allowed
        or not client_cpus <= allowed
        or not sidecar_cpus <= allowed
    ):
        raise ValueError(
            f"affinity CPUs must be allowed by current mask {sorted(allowed)}"
        )
    for sidecar in plan.get("sidecars", []):
        if not isinstance(sidecar, dict):
            raise ValueError("each sidecar must be an object")
        ensure_list_of_strings(sidecar.get("argv"), "sidecar.argv")
        resolve_env(sidecar.get("env", {}), "sidecar")
    quiet = plan.get("quiet", {})
    if not isinstance(quiet, dict):
        raise ValueError("quiet must be an object")
    quiet_duration = float(quiet.get("sample_seconds", 3.0))
    quiet_busy = float(quiet.get("max_cpu_busy_fraction", 0.20))
    quiet_load = float(quiet.get("max_load1_per_cpu", 0.35))
    quiet_running = int(quiet.get("max_procs_running", len(allowed)))
    sample_interval = float(plan.get("sample_interval_seconds", 0.05))
    if not 2.0 <= quiet_duration <= 30.0:
        raise ValueError("quiet sample must be between 2 and 30 seconds")
    if not 0.01 <= quiet_busy <= 0.25:
        raise ValueError("quiet max_cpu_busy_fraction must be 0.01..0.25")
    if not 0.01 <= quiet_load <= 0.50:
        raise ValueError("quiet max_load1_per_cpu must be 0.01..0.50")
    if not 1 <= quiet_running <= len(allowed):
        raise ValueError("quiet max_procs_running must be 1..allowed CPU count")
    if not 0.01 <= sample_interval <= 1.0:
        raise ValueError("sample_interval_seconds must be 0.01..1.0")
    source_root = Path(str(plan.get("source_root", root))).expanduser().resolve()
    if not source_root.is_dir():
        raise ValueError(f"source_root does not exist: {source_root}")
    plan["source_root"] = str(source_root)
    return plan


def source_tree_digest(root: Path) -> dict[str, Any]:
    aggregate = hashlib.sha256()
    count = 0
    for directory, names, filenames in os.walk(root):
        names[:] = sorted(
            name for name in names
            if name not in SOURCE_EXCLUDED and not name.startswith("build")
        )
        base = Path(directory)
        for name in sorted(filenames):
            path = base / name
            if path.is_symlink():
                value = os.readlink(path).encode()
                file_hash = sha256_bytes(value)
                size = len(value)
            elif path.is_file():
                before = path.stat()
                file_hash = sha256_file(path)
                after = path.stat()
                if (before.st_size, before.st_mtime_ns, before.st_ino) != (
                    after.st_size, after.st_mtime_ns, after.st_ino
                ):
                    raise RuntimeError(f"source moved while hashing: {path}")
                size = after.st_size
            else:
                continue
            relative = path.relative_to(root).as_posix()
            aggregate.update(relative.encode() + b"\0")
            aggregate.update(file_hash.encode() + b"\0")
            aggregate.update(str(size).encode() + b"\0")
            count += 1
    return {"sha256": aggregate.hexdigest(), "files": count}


def read_proc_stat_cpu() -> tuple[list[int], int]:
    lines = Path("/proc/stat").read_text(encoding="ascii").splitlines()
    fields = [int(value) for value in lines[0].split()[1:]]
    running = int(next(
        line.split()[1] for line in lines if line.startswith("procs_running ")
    ))
    return fields, running


def quiet_host_evidence(quiet: dict[str, Any]) -> dict[str, Any]:
    duration = float(quiet.get("sample_seconds", 3.0))
    if duration < 0.25 or duration > 30.0:
        raise ValueError("quiet.sample_seconds must be between 0.25 and 30")
    before, running_before = read_proc_stat_cpu()
    start = raw_ns()
    time.sleep(duration)
    after, running_after = read_proc_stat_cpu()
    end = raw_ns()
    deltas = [right - left for left, right in zip(before, after, strict=False)]
    total = sum(deltas)
    idle = (deltas[3] if len(deltas) > 3 else 0) + (
        deltas[4] if len(deltas) > 4 else 0
    )
    busy = 1.0 if total <= 0 else (total - idle) / total
    load = os.getloadavg()
    cpus = len(os.sched_getaffinity(0))
    evidence = {
        "started_monotonic_raw_ns": start,
        "finished_monotonic_raw_ns": end,
        "duration_seconds": duration,
        "cpu_busy_fraction": busy,
        "load_average": list(load),
        "load1_per_allowed_cpu": load[0] / cpus,
        "allowed_cpu_count": cpus,
        "procs_running_before": running_before,
        "procs_running_after": running_after,
        "thresholds": {
            "max_cpu_busy_fraction": float(
                quiet.get("max_cpu_busy_fraction", 0.20)
            ),
            "max_load1_per_cpu": float(quiet.get("max_load1_per_cpu", 0.35)),
            "max_procs_running": int(quiet.get("max_procs_running", cpus)),
        },
    }
    failures: list[str] = []
    if busy > evidence["thresholds"]["max_cpu_busy_fraction"]:
        failures.append("cpu_busy_fraction")
    if evidence["load1_per_allowed_cpu"] > evidence["thresholds"]["max_load1_per_cpu"]:
        failures.append("load1_per_allowed_cpu")
    if max(running_before, running_after) > evidence["thresholds"]["max_procs_running"]:
        failures.append("procs_running")
    evidence["passed"] = not failures
    evidence["failures"] = failures
    return evidence


def read_optional(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (FileNotFoundError, PermissionError, OSError):
        return None


def host_inventory() -> dict[str, Any]:
    sys_cpu = Path("/sys/devices/system/cpu")
    governors: dict[str, str] = {}
    for path in sorted(sys_cpu.glob("cpu[0-9]*/cpufreq/scaling_governor")):
        value = read_optional(path)
        if value is not None:
            governors[path.parent.parent.name] = value.strip()
    turbo_paths = (
        Path("/sys/devices/system/cpu/intel_pstate/no_turbo"),
        Path("/sys/devices/system/cpu/cpufreq/boost"),
    )
    return {
        "uname": list(os.uname()),
        "python": sys.version,
        "allowed_cpus": sorted(os.sched_getaffinity(0)),
        "loadavg": list(os.getloadavg()),
        "proc_cpuinfo_sha256": sha256_file(Path("/proc/cpuinfo")),
        "proc_cmdline": read_optional(Path("/proc/cmdline")),
        "current_cgroup": read_optional(Path("/proc/self/cgroup")),
        "cgroup_mountinfo": [
            line for line in Path("/proc/self/mountinfo").read_text(
                encoding="utf-8", errors="replace"
            ).splitlines() if " - cgroup2 " in line
        ],
        "governors": governors,
        "turbo": {str(path): read_optional(path) for path in turbo_paths},
        "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
        "page_size": os.sysconf("SC_PAGE_SIZE"),
    }


def network_inventory() -> dict[str, Any]:
    return {
        "namespace": os.readlink("/proc/self/ns/net"),
        "interfaces": [
            {"index": index, "name": name}
            for index, name in socket.if_nameindex()
        ],
        "ipv4_routes": read_optional(Path("/proc/net/route")),
        "ipv6_routes": read_optional(Path("/proc/net/ipv6_route")),
    }


def assert_loopback_only(evidence: dict[str, Any]) -> None:
    names = [item["name"] for item in evidence["interfaces"]]
    if names != ["lo"]:
        raise RuntimeError(
            "release benchmark requires a loopback-only network namespace; "
            f"observed interfaces={names}"
        )
    ipv4_lines = (evidence["ipv4_routes"] or "").splitlines()[1:]
    if any(line.strip() for line in ipv4_lines):
        raise RuntimeError("loopback-only namespace unexpectedly has IPv4 routes")
    ipv6_lines = (evidence["ipv6_routes"] or "").splitlines()
    # The kernel can expose local loopback routes; reject entries on non-lo devices.
    if any(line.split()[-1] != "lo" for line in ipv6_lines if line.split()):
        raise RuntimeError("loopback-only namespace unexpectedly has non-lo IPv6 routes")


def process_snapshot(pid: int) -> dict[str, Any] | None:
    try:
        stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        closing = stat_text.rfind(")")
        fields = stat_text[closing + 2 :].split()
        status: dict[str, str] = {}
        for line in Path(f"/proc/{pid}/status").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            key, marker, value = line.partition(":")
            if marker and key in {
                "VmRSS", "VmHWM", "RssAnon", "RssFile", "Threads",
                "voluntary_ctxt_switches", "nonvoluntary_ctxt_switches",
                "Cpus_allowed_list", "Mems_allowed_list",
            }:
                status[key] = value.strip()
        io_values: dict[str, int] = {}
        for line in Path(f"/proc/{pid}/io").read_text(encoding="ascii").splitlines():
            key, marker, value = line.partition(":")
            if marker:
                io_values[key] = int(value.strip())
        return {
            "state": fields[0],
            "minor_faults": int(fields[7]),
            "major_faults": int(fields[9]),
            "user_ticks": int(fields[11]),
            "system_ticks": int(fields[12]),
            "threads": int(fields[17]),
            "start_ticks": int(fields[19]),
            "virtual_bytes": int(fields[20]),
            "rss_pages": int(fields[21]),
            "status": status,
            "io": io_values,
            "cgroup": read_optional(Path(f"/proc/{pid}/cgroup")),
        }
    except (FileNotFoundError, ProcessLookupError, PermissionError, OSError, ValueError):
        return None


def parse_kib(value: str | None) -> int | None:
    if value is None:
        return None
    match = re.fullmatch(r"(\d+)\s+kB", value)
    return int(match.group(1)) * 1024 if match else None


class ProcessSampler:
    def __init__(self, path: Path, interval_seconds: float) -> None:
        self.path = path
        self.interval = interval_seconds
        self.targets: dict[str, tuple[int, int | None]] = {}
        self.pending: list[dict[str, Any]] = []
        self.samples: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.error: BaseException | None = None

    def add(
        self, role: str, pid: int, snapshot: dict[str, Any] | None = None
    ) -> None:
        if snapshot is None:
            snapshot = process_snapshot(pid)
        with self.lock:
            self.targets[role] = (
                pid, None if snapshot is None else int(snapshot["start_ticks"])
            )
            if snapshot is not None:
                self.pending.append({
                    "monotonic_raw_ns": raw_ns(),
                    "role": role,
                    "pid": pid,
                    **snapshot,
                })

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        try:
            with self.path.open("w", encoding="utf-8") as stream:
                while True:
                    timestamp = raw_ns()
                    cpu_fields, procs_running = read_proc_stat_cpu()
                    host_row = {
                        "monotonic_raw_ns": timestamp,
                        "role": "host",
                        "cpu_fields": cpu_fields,
                        "procs_running": procs_running,
                        "load_average": list(os.getloadavg()),
                        "cpu_pressure": read_optional(Path("/proc/pressure/cpu")),
                    }
                    with self.lock:
                        targets = dict(self.targets)
                        pending = self.pending
                        self.pending = []
                    for row in pending:
                        stream.write(json.dumps(row, sort_keys=True) + "\n")
                        self.samples[row["role"]].append(row)
                    stream.write(json.dumps(host_row, sort_keys=True) + "\n")
                    self.samples["host"].append(host_row)
                    for role, (pid, start_ticks) in targets.items():
                        snapshot = process_snapshot(pid)
                        if snapshot is None:
                            continue
                        if (
                            start_ticks is not None
                            and snapshot["start_ticks"] != start_ticks
                        ):
                            continue
                        row = {
                            "monotonic_raw_ns": timestamp,
                            "role": role,
                            "pid": pid,
                            **snapshot,
                        }
                        stream.write(json.dumps(row, sort_keys=True) + "\n")
                        stream.flush()
                        self.samples[role].append(row)
                    if self.stop_event.is_set():
                        break
                    self.stop_event.wait(self.interval)
        except BaseException as error:
            self.error = error

    def stop(self) -> dict[str, Any]:
        self.stop_event.set()
        self.thread.join(timeout=max(5.0, self.interval * 3.0))
        if self.thread.is_alive():
            raise RuntimeError("process sampler did not stop")
        if self.error is not None:
            raise RuntimeError(
                f"process sampler failed: {type(self.error).__name__}: {self.error}"
            ) from self.error
        summary: dict[str, Any] = {}
        for role, rows in self.samples.items():
            if not rows:
                summary[role] = {"samples": 0}
                continue
            if role == "host":
                before = rows[0]["cpu_fields"]
                after = rows[-1]["cpu_fields"]
                deltas = [
                    right - left
                    for left, right in zip(before, after, strict=False)
                ]
                total = sum(deltas)
                idle = (deltas[3] if len(deltas) > 3 else 0) + (
                    deltas[4] if len(deltas) > 4 else 0
                )
                summary[role] = {
                    "samples": len(rows),
                    "cpu_busy_fraction": (
                        None if total <= 0 else (total - idle) / total
                    ),
                    "max_procs_running": max(
                        row["procs_running"] for row in rows
                    ),
                    "max_load1": max(
                        row["load_average"][0] for row in rows
                    ),
                }
                continue
            voluntary = [
                int(row["status"].get("voluntary_ctxt_switches", "0"))
                for row in rows
            ]
            involuntary = [
                int(row["status"].get("nonvoluntary_ctxt_switches", "0"))
                for row in rows
            ]
            rss = [
                value for value in (
                    parse_kib(row["status"].get("VmRSS")) for row in rows
                ) if value is not None
            ]
            hwm = [
                value for value in (
                    parse_kib(row["status"].get("VmHWM")) for row in rows
                ) if value is not None
            ]
            summary[role] = {
                "samples": len(rows),
                "max_rss_bytes": max(rss) if rss else None,
                "max_vm_hwm_bytes": max(hwm) if hwm else None,
                "voluntary_context_switch_delta": max(voluntary) - min(voluntary),
                "involuntary_context_switch_delta": max(involuntary) - min(involuntary),
                "user_ticks_delta": rows[-1]["user_ticks"] - rows[0]["user_ticks"],
                "system_ticks_delta": (
                    rows[-1]["system_ticks"] - rows[0]["system_ticks"]
                ),
                "minor_fault_delta": (
                    rows[-1]["minor_faults"] - rows[0]["minor_faults"]
                ),
                "major_fault_delta": (
                    rows[-1]["major_faults"] - rows[0]["major_faults"]
                ),
            }
        return summary


class RunCgroup:
    def __init__(self, config: dict[str, Any], run_id: str) -> None:
        self.config = config
        self.required = bool(config.get("required", False))
        self.parent = Path(str(config.get("parent", "/sys/fs/cgroup"))).resolve()
        self.base = self.parent / f"fastbed-bench-{os.getpid()}-{run_id}"
        self.paths = {"server": self.base / "server", "client": self.base / "client"}
        self.available = False
        self.error: str | None = None

    def create(self) -> None:
        try:
            if not (self.parent / "cgroup.controllers").is_file():
                raise RuntimeError(f"{self.parent} is not a cgroup v2 directory")
            self.base.mkdir()
            for role, path in self.paths.items():
                path.mkdir()
                settings = self.config.get(role, {})
                if not isinstance(settings, dict):
                    raise ValueError(f"cgroup {role} settings must be an object")
                for key, value in settings.items():
                    if key not in {"cpu.max", "memory.max", "pids.max"}:
                        raise ValueError(f"unsupported cgroup control {key}")
                    (path / key).write_text(str(value) + "\n", encoding="ascii")
            self.available = True
        except Exception as error:
            self.error = f"{type(error).__name__}: {error}"
            self.cleanup()
            if self.required:
                raise RuntimeError(f"required cgroup setup failed: {self.error}") from error

    def add(self, role: str, pid: int) -> None:
        if not self.available:
            return
        try:
            (self.paths[role] / "cgroup.procs").write_text(
                f"{pid}\n", encoding="ascii"
            )
        except Exception as error:
            self.error = f"{type(error).__name__}: {error}"
            if self.required:
                raise RuntimeError(f"required cgroup placement failed: {self.error}") from error

    def snapshot(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "available": self.available,
            "required": self.required,
            "parent": str(self.parent),
            "error": self.error,
            "roles": {},
        }
        if not self.available:
            return result
        for role, path in self.paths.items():
            result["roles"][role] = {
                name: read_optional(path / name) for name in CGROUP_FILES
            }
        return result

    def cleanup(self) -> None:
        for path in reversed(list(self.paths.values())):
            try:
                path.rmdir()
            except OSError:
                pass
        try:
            self.base.rmdir()
        except OSError:
            pass


def template_strings(values: Iterable[str], context: dict[str, Any]) -> list[str]:
    return [value.format_map(context) for value in values]


def command_environment(*templates: dict[str, Any]) -> dict[str, str]:
    environment = os.environ.copy()
    for index, template in enumerate(templates):
        environment.update(resolve_env(template, f"runtime env {index}"))
    return environment


def start_process(
    argv: list[str],
    cwd: Path,
    environment: dict[str, str],
    stdout_path: Path,
    stderr_path: Path,
    cpus: set[int],
) -> tuple[subprocess.Popen[bytes], Any, Any, list[str]]:
    taskset = shutil.which("taskset")
    if taskset is None:
        raise RuntimeError("taskset is required for pre-exec CPU affinity")
    actual = [taskset, "--cpu-list", ",".join(str(cpu) for cpu in sorted(cpus)), *argv]
    stdout = stdout_path.open("wb")
    stderr = stderr_path.open("wb")
    try:
        process = subprocess.Popen(
            actual,
            cwd=cwd,
            env=environment,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
    except Exception:
        stdout.close()
        stderr.close()
        raise
    return process, stdout, stderr, actual


def wait_process_affinity(
    process: subprocess.Popen[bytes],
    expected: set[int],
    label: str,
    timeout: float = 1.0,
) -> tuple[dict[str, Any], str]:
    deadline = time.monotonic() + timeout
    observed = ""
    start_ticks: int | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"{label} exited before affinity proof with "
                f"{process.returncode}"
            )
        snapshot = process_snapshot(process.pid)
        if snapshot is not None:
            current_start = int(snapshot["start_ticks"])
            if start_ticks is None:
                start_ticks = current_start
            elif current_start != start_ticks:
                raise RuntimeError(f"{label} PID identity changed during affinity proof")
            observed = snapshot["status"].get("Cpus_allowed_list", "")
            if parse_kernel_cpu_list(observed) == expected:
                return snapshot, observed
        time.sleep(0.001)
    raise RuntimeError(
        f"{label} affinity mismatch: observed={observed} "
        f"expected={sorted(expected)}"
    )


def stop_process(
    process: subprocess.Popen[bytes],
    stdout: Any,
    stderr: Any,
    timeout: float,
    *,
    expected_exit: int = 0,
) -> dict[str, Any]:
    signal_sent_ns: int | None = None
    forced = False
    if process.poll() is None:
        signal_sent_ns = raw_ns()
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            forced = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
    stdout.close()
    stderr.close()
    result = {
        "pid": process.pid,
        "returncode": process.returncode,
        "signal_sent_monotonic_raw_ns": signal_sent_ns,
        "finished_monotonic_raw_ns": raw_ns(),
        "forced_kill": forced,
        "expected_exit": expected_exit,
    }
    if forced or process.returncode != expected_exit:
        raise RuntimeError(f"process {process.pid} exit was {result}")
    return result


def wait_http_ready(
    process: subprocess.Popen[bytes],
    host: str,
    port: int,
    path: str,
    timeout: float,
    expected_status: int,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error: str | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"process exited before readiness with {process.returncode}"
            )
        connection = http.client.HTTPConnection(host, port, timeout=1.0)
        try:
            connection.request(
                "GET", path,
                headers={"User-Agent": "Mozilla/5.0", "Connection": "close"},
            )
            response = connection.getresponse()
            body = response.read()
            if response.status == expected_status:
                return {
                    "status": response.status,
                    "body_sha256": sha256_bytes(body),
                    "bytes": len(body),
                    "ready_monotonic_raw_ns": raw_ns(),
                }
            last_error = f"HTTP {response.status}"
        except (OSError, http.client.HTTPException) as error:
            last_error = f"{type(error).__name__}: {error}"
        finally:
            connection.close()
        time.sleep(0.05)
    raise RuntimeError(f"readiness timed out: {last_error}")


def wait_sidecar_ready(
    process: subprocess.Popen[bytes],
    ready: dict[str, Any],
    context: dict[str, Any],
) -> dict[str, Any]:
    host = str(ready.get("host", "127.0.0.1")).format_map(context)
    port = int(str(ready["port"]).format_map(context))
    timeout = float(ready.get("timeout_seconds", 30.0))
    if "path" in ready:
        return wait_http_ready(
            process, host, port, str(ready["path"]).format_map(context),
            timeout, int(ready.get("status", 200)),
        )
    deadline = time.monotonic() + timeout
    last_error: str | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("sidecar exited before readiness")
        try:
            with socket.create_connection((host, port), timeout=1):
                return {"host": host, "port": port, "ready_monotonic_raw_ns": raw_ns()}
        except OSError as error:
            last_error = f"{type(error).__name__}: {error}"
        time.sleep(0.05)
    raise RuntimeError(f"sidecar readiness timed out: {last_error}")


def run_hook(
    argv: list[str],
    context: dict[str, Any],
    cwd: Path,
    environment: dict[str, str],
    path_prefix: Path,
    timeout: float,
) -> dict[str, Any]:
    command = template_strings(argv, context)
    started = raw_ns()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        path_prefix.with_suffix(".stdout").write_bytes(error.stdout or b"")
        path_prefix.with_suffix(".stderr").write_bytes(error.stderr or b"")
        evidence = {
            "argv": command,
            "started_monotonic_raw_ns": started,
            "finished_monotonic_raw_ns": raw_ns(),
            "timeout_seconds": timeout,
            "timed_out": True,
        }
        atomic_json(path_prefix.with_suffix(".json"), evidence)
        raise RuntimeError(f"controller hook timed out: {evidence}") from error
    path_prefix.with_suffix(".stdout").write_bytes(result.stdout)
    path_prefix.with_suffix(".stderr").write_bytes(result.stderr)
    evidence = {
        "argv": command,
        "started_monotonic_raw_ns": started,
        "finished_monotonic_raw_ns": raw_ns(),
        "returncode": result.returncode,
    }
    atomic_json(path_prefix.with_suffix(".json"), evidence)
    if result.returncode != 0:
        raise RuntimeError(f"controller hook failed: {evidence}")
    return evidence


def build_id(path: Path) -> str | None:
    readelf = shutil.which("readelf")
    if readelf is None:
        return None
    result = subprocess.run(
        [readelf, "-nW", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if result.returncode != 0:
        return None
    match = re.search(r"Build ID:\s*([0-9a-fA-F]+)", result.stdout)
    return match.group(1).lower() if match else None


def compile_loadgen(root: Path, output: Path, compiler: str) -> tuple[Path, dict[str, Any]]:
    source = root / "http_loadgen.c"
    binary = output / "http_loadgen"
    command = [
        compiler, "-std=c17", "-D_GNU_SOURCE", "-DNDEBUG", "-O3",
        "-fno-plt", "-Wall", "-Wextra", "-Wpedantic", "-Wconversion",
        "-Wshadow", "-Wformat=2", "-Wundef", "-Wstrict-prototypes",
        "-Wmissing-prototypes", "-Werror=implicit-function-declaration",
        str(source), "-o", str(binary), "-lcrypto",
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output / "loadgen-compile.stdout").write_bytes(result.stdout)
    (output / "loadgen-compile.stderr").write_bytes(result.stderr)
    if result.returncode != 0:
        raise RuntimeError("load generator compilation failed")
    version = subprocess.run(
        [compiler, "--version"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    ).stdout.decode(errors="replace")
    return binary, {
        "command": command,
        "source_sha256": sha256_file(source),
        "binary_sha256": sha256_file(binary),
        "compiler_version": version,
    }


def loadgen_command(
    binary: Path,
    plan: dict[str, Any],
    scenario: dict[str, Any],
    records: Path,
    summary: Path,
    requests: int,
    seed: int,
) -> list[str]:
    command = [
        str(binary),
        "--host", str(plan["host"]),
        "--port", str(plan["port"]),
        "--requests-file", str(scenario["requests_file"]),
        "--requests", str(requests),
        "--concurrency", str(min(scenario["concurrency"], requests)),
        "--records", str(records),
        "--summary", str(summary),
        "--mode", str(scenario.get("mode", "closed")),
        "--connection-mode", str(scenario.get("connection_mode", "keepalive")),
        "--timeout-ms", str(scenario.get("timeout_ms", 30000)),
        "--max-body-bytes", str(scenario.get("max_body_bytes", 67108864)),
        "--seed", str(seed),
    ]
    if scenario.get("mode", "closed") == "open":
        command.extend(["--rate", str(scenario["rate"])])
    for address in scenario.get("source_addresses", []):
        command.extend(["--source-address", str(address)])
    return command


def parse_raw_records(path: Path) -> list[dict[str, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    data = [line for line in lines if line and not line.startswith("#")]
    if not data:
        raise RuntimeError(f"raw records are empty: {path}")
    header = data[0].split("\t")
    result: list[dict[str, str]] = []
    for line in data[1:]:
        fields = line.split("\t")
        if len(fields) != len(header):
            raise RuntimeError(f"malformed raw latency row: {line!r}")
        result.append(dict(zip(header, fields, strict=True)))
    return result


def percentile(values: list[int], fraction: float) -> int | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


def summarize_latencies(records: Path, summary: dict[str, Any]) -> dict[str, Any]:
    rows = parse_raw_records(records)
    successful = [row for row in rows if row["outcome"] == "ok"]
    service = [int(row["service_ns"]) for row in successful]
    queue = [int(row["queue_delay_ns"]) for row in successful]
    sojourn = [
        int(row["end_ns"]) - int(row["scheduled_ns"]) for row in successful
    ]
    elapsed = int(summary["elapsed_ns"])
    return {
        "records": len(rows),
        "successful_records": len(successful),
        "requests_per_second": (
            len(successful) * 1_000_000_000 / elapsed if elapsed > 0 else None
        ),
        "service_ns": {
            "p50": percentile(service, 0.50),
            "p90": percentile(service, 0.90),
            "p95": percentile(service, 0.95),
            "p99": percentile(service, 0.99),
            "p999": percentile(service, 0.999),
            "max": max(service) if service else None,
        },
        "queue_delay_ns": {
            "p50": percentile(queue, 0.50),
            "p95": percentile(queue, 0.95),
            "p99": percentile(queue, 0.99),
            "max": max(queue) if queue else None,
        },
        "sojourn_ns": {
            "p50": percentile(sojourn, 0.50),
            "p95": percentile(sojourn, 0.95),
            "p99": percentile(sojourn, 0.99),
            "max": max(sojourn) if sojourn else None,
        },
    }


def run_one(
    plan: dict[str, Any],
    variant: dict[str, Any],
    scenario: dict[str, Any],
    block: int,
    run_index: int,
    output: Path,
    loadgen: Path,
    source_digest: dict[str, Any],
    sidecar_processes: dict[str, int],
) -> tuple[dict[str, Any], dict[str, Any]]:
    run_id = f"{run_index:04d}-b{block:02d}-{scenario['name']}-{variant['name']}"
    run_dir = output / "runs" / run_id
    run_dir.mkdir(parents=True)
    context = {
        "binary": variant["binary"],
        "variant": variant["name"],
        "scenario": scenario["name"],
        "kind": scenario["kind"],
        "block": block,
        "run": run_index,
        "run_dir": str(run_dir),
        "output": str(output),
        "source_root": plan["source_root"],
        "host": plan["host"],
        "port": plan["port"],
    }
    server = effective_server(plan, variant)
    server_cpus = set(plan["affinity"]["server"])
    client_cpus = set(plan["affinity"]["client"])
    cwd = Path(str(server.get("cwd", plan["source_root"]))).expanduser().resolve()
    server_environment = command_environment(
        server.get("env", {}), variant.get("env", {})
    )
    client_environment = command_environment(plan.get("client_env", {}))
    hook_environment = command_environment(plan.get("controller_env", {}))
    hook_timeout = float(scenario.get("hook_timeout_seconds", 30.0))
    hooks: list[dict[str, Any]] = []
    for hook_index, argv in enumerate(scenario.get("before_start", [])):
        hooks.append({
            "phase": "before_start",
            **run_hook(
                argv, context, cwd, hook_environment,
                run_dir / f"hook-before-{hook_index:02d}", hook_timeout,
            ),
        })

    server_args = list(variant.get("args", [])) + list(
        scenario.get("server_args", [])
    )
    server_args.extend(variant.get("kind_args", {}).get(scenario["kind"], []))
    if (
        plan["profile"] == RELEASE_PROFILE
        and scenario["kind"] in {"cold", "warm", "singleflight"}
        and "--internal-cache" not in server_args
    ):
        server_args.append("--internal-cache")
    server_argv = template_strings(server["argv"], context) + template_strings(
        server_args, context
    )
    cgroup = RunCgroup(plan.get("cgroup", {}), run_id)
    cgroup.create()
    cgroup_before = cgroup.snapshot()
    server_process = None
    server_stdout = None
    server_stderr = None
    client_process = None
    client_stdout = None
    client_stderr = None
    sampler: ProcessSampler | None = None
    run_error: BaseException | None = None
    server_exit: dict[str, Any] | None = None
    try:
        (
            server_process, server_stdout, server_stderr, actual_server_command
        ) = start_process(
            server_argv, cwd, server_environment,
            run_dir / "server.stdout", run_dir / "server.stderr", server_cpus,
        )
        cgroup.add("server", server_process.pid)
        readiness = wait_http_ready(
            server_process, str(plan["host"]), int(plan["port"]),
            str(server.get("ready_path", "/healthz")),
            float(server.get("startup_timeout_seconds", 30.0)),
            int(server.get("ready_status", 200)),
        )
        _server_snapshot, allowed_text = wait_process_affinity(
            server_process, server_cpus, "server")
        for hook_index, argv in enumerate(scenario.get("after_ready", [])):
            hooks.append({
                "phase": "after_ready",
                **run_hook(
                    argv, context, cwd, hook_environment,
                    run_dir / f"hook-ready-{hook_index:02d}", hook_timeout,
                ),
            })

        seed_material = (
            f"{plan['seed']}\0{block}\0{scenario['name']}".encode("utf-8")
        )
        seed = int.from_bytes(
            hashlib.sha256(seed_material).digest()[:8], "big"
        )
        warmup: dict[str, Any] | None = None
        if "warmup_requests" in scenario:
            warm_records = run_dir / "warmup.records.tsv"
            warm_summary_path = run_dir / "warmup.summary.json"
            warm_scenario = dict(scenario)
            warm_scenario["mode"] = scenario.get("warmup_mode", "closed")
            warm_scenario["concurrency"] = scenario.get(
                "warmup_concurrency", scenario["concurrency"]
            )
            if warm_scenario["mode"] == "closed":
                warm_scenario.pop("rate", None)
            warm_command = loadgen_command(
                loadgen, plan, warm_scenario, warm_records, warm_summary_path,
                int(scenario["warmup_requests"]), seed,
            )
            warm_process, warm_stdout, warm_stderr, actual_warm_command = (
                start_process(
                    warm_command, cwd, client_environment,
                    run_dir / "warmup.stdout", run_dir / "warmup.stderr",
                    client_cpus,
                )
            )
            try:
                cgroup.add("client", warm_process.pid)
                _warm_snapshot, warm_allowed = wait_process_affinity(
                    warm_process, client_cpus, "warm-up client")
                try:
                    warm_returncode = warm_process.wait(
                        timeout=float(scenario.get("run_timeout_seconds", 600.0))
                    )
                except subprocess.TimeoutExpired as error:
                    os.killpg(warm_process.pid, signal.SIGKILL)
                    warm_process.wait(timeout=10)
                    raise RuntimeError("warm-up exceeded run timeout") from error
            finally:
                if warm_process.poll() is None:
                    os.killpg(warm_process.pid, signal.SIGKILL)
                    warm_process.wait(timeout=10)
                warm_stdout.close()
                warm_stderr.close()
            if warm_returncode != 0:
                raise RuntimeError("hash-verified warm-up failed")
            warm_summary = read_json(warm_summary_path)
            if warm_summary.get("errors") != 0:
                raise RuntimeError("warm-up summary contains errors")
            warmup = {
                "command": actual_warm_command,
                "affinity_observed": warm_allowed,
                "summary": warm_summary,
                "latency": summarize_latencies(warm_records, warm_summary),
            }

        records_path = run_dir / "latency.records.tsv"
        summary_path = run_dir / "loadgen.summary.json"
        client_command = loadgen_command(
            loadgen, plan, scenario, records_path, summary_path,
            int(scenario["requests"]), seed,
        )
        sampler = ProcessSampler(
            run_dir / "process_samples.jsonl",
            float(plan.get("sample_interval_seconds", 0.05)),
        )
        sampler.add("server", server_process.pid)
        for name, pid in sorted(sidecar_processes.items()):
            sampler.add(f"sidecar:{name}", pid)
        sampler.start()
        (
            client_process, client_stdout, client_stderr, actual_client_command
        ) = start_process(
            client_command, cwd, client_environment,
            run_dir / "loadgen.stdout", run_dir / "loadgen.stderr", client_cpus,
        )
        cgroup.add("client", client_process.pid)
        client_snapshot, client_allowed = wait_process_affinity(
            client_process, client_cpus, "client")
        sampler.add("client", client_process.pid, client_snapshot)
        client_timeout = float(scenario.get("run_timeout_seconds", 600.0))
        try:
            client_returncode = client_process.wait(timeout=client_timeout)
        except subprocess.TimeoutExpired as error:
            os.killpg(client_process.pid, signal.SIGKILL)
            client_process.wait(timeout=10)
            raise RuntimeError("load generator exceeded run timeout") from error
        client_stdout.close()
        client_stderr.close()
        client_stdout = client_stderr = None
        if client_returncode != 0:
            raise RuntimeError(f"load generator exited {client_returncode}")
        load_summary = read_json(summary_path)
        if (
            not load_summary.get("run_completed")
            or load_summary.get("errors") != 0
            or load_summary.get("ok") != scenario["requests"]
        ):
            raise RuntimeError(f"load verification failed: {load_summary}")
        latency = summarize_latencies(records_path, load_summary)

        for hook_index, argv in enumerate(scenario.get("after_measure", [])):
            hooks.append({
                "phase": "after_measure",
                **run_hook(
                    argv, context, cwd, hook_environment,
                    run_dir / f"hook-measure-{hook_index:02d}", hook_timeout,
                ),
            })
        process_samples = sampler.stop()
        sampler = None
        for role in ("server", "client", "host"):
            if process_samples.get(role, {}).get("samples", 0) < 1:
                raise RuntimeError(f"missing required {role} process samples")
        server_exit = stop_process(
            server_process, server_stdout, server_stderr,
            float(server.get("shutdown_timeout_seconds", 30.0)),
            expected_exit=int(server.get("expected_exit", 0)),
        )
        server_process = None
        server_stdout = server_stderr = None
        cgroup_after = cgroup.snapshot()
        result = {
            "run_id": run_id,
            "block": block,
            "run_index": run_index,
            "scenario": scenario["name"],
            "scenario_kind": scenario["kind"],
            "variant": variant["name"],
            "profile": plan["profile"],
            "status": "passed",
            "seed": seed,
            "source_tree": source_digest,
            "variant_inputs": {
                path: sha256_file(Path(path))
                for path in variant.get("input_files", [])
            },
            "server_command": actual_server_command,
            "client_command": actual_client_command,
            "server_affinity_observed": allowed_text,
            "client_affinity_observed": client_allowed,
            "readiness": readiness,
            "warmup": warmup,
            "load_summary": load_summary,
            "latency": latency,
            "process_samples": process_samples,
            "cgroup_before": cgroup_before,
            "cgroup_after": cgroup_after,
            "server_exit": server_exit,
            "hooks": hooks,
        }
        atomic_json(run_dir / "run.json", result)
        return result, source_tree_digest(Path(plan["source_root"]))
    except BaseException as error:
        run_error = error
        raise
    finally:
        if sampler is not None:
            try:
                sampler.stop()
            except Exception:
                pass
        if client_process is not None and client_process.poll() is None:
            try:
                os.killpg(client_process.pid, signal.SIGKILL)
                client_process.wait(timeout=10)
            except Exception:
                pass
        for handle in (client_stdout, client_stderr):
            if handle is not None:
                handle.close()
        if server_process is not None:
            try:
                if server_process.poll() is None:
                    os.killpg(server_process.pid, signal.SIGTERM)
                    try:
                        server_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(server_process.pid, signal.SIGKILL)
                        server_process.wait(timeout=10)
            except Exception:
                pass
        for handle in (server_stdout, server_stderr):
            if handle is not None:
                handle.close()
        if run_error is not None:
            atomic_json(run_dir / "failure.json", {
                "type": type(run_error).__name__,
                "message": str(run_error),
                "monotonic_raw_ns": raw_ns(),
            })
        cgroup.cleanup()


def start_sidecars(
    plan: dict[str, Any], output: Path
) -> list[dict[str, Any]]:
    instances: list[dict[str, Any]] = []
    affinity = set(plan["affinity"].get("sidecars", plan["affinity"]["server"]))
    context = {
        "output": str(output),
        "source_root": plan["source_root"],
        "host": plan["host"],
        "port": plan["port"],
    }
    try:
        for index, sidecar in enumerate(plan.get("sidecars", [])):
            name = str(sidecar.get("name", f"sidecar-{index}"))
            directory = output / "sidecars" / f"{index:02d}-{name}"
            directory.mkdir(parents=True)
            command = template_strings(sidecar["argv"], context)
            cwd = Path(str(sidecar.get("cwd", plan["source_root"]))).resolve()
            environment = command_environment(sidecar.get("env", {}))
            process, stdout, stderr, actual = start_process(
                command, cwd, environment,
                directory / "stdout", directory / "stderr", affinity,
            )
            evidence = {
                "name": name,
                "process": process,
                "stdout": stdout,
                "stderr": stderr,
                "actual_command": actual,
                "directory": directory,
                "shutdown_timeout": float(sidecar.get("shutdown_timeout_seconds", 10)),
                "expected_exit": int(sidecar.get("expected_exit", 0)),
            }
            instances.append(evidence)
            _snapshot, observed = wait_process_affinity(
                process, affinity, f"sidecar {name}")
            evidence["affinity_observed"] = observed
            if "ready" in sidecar:
                evidence["ready"] = wait_sidecar_ready(
                    process, sidecar["ready"], context
                )
        return instances
    except Exception:
        stop_sidecars(instances)
        raise


def stop_sidecars(instances: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for item in reversed(instances):
        try:
            stopped = stop_process(
                item["process"], item["stdout"], item["stderr"],
                item["shutdown_timeout"], expected_exit=item["expected_exit"],
            )
            evidence.append({
                "name": item["name"],
                "command": item["actual_command"],
                "ready": item.get("ready"),
                "exit": stopped,
            })
        except Exception as error:
            evidence.append({
                "name": item["name"],
                "command": item["actual_command"],
                "ready": item.get("ready"),
                "stop_error": f"{type(error).__name__}: {error}",
            })
    return evidence


def generate_schedule(plan: dict[str, Any]) -> list[dict[str, Any]]:
    rng = random.Random(plan["seed"])
    variants = [variant["name"] for variant in plan["variants"]]
    schedule: list[dict[str, Any]] = []
    run_index = 0
    for block in range(plan["blocks"]):
        scenario_order = list(plan["scenarios"])
        rng.shuffle(scenario_order)
        for scenario in scenario_order:
            variant_order = list(variants)
            rng.shuffle(variant_order)
            for ordinal, variant in enumerate(variant_order):
                schedule.append({
                    "run_index": run_index,
                    "block": block,
                    "scenario": scenario["name"],
                    "scenario_kind": scenario["kind"],
                    "variant": variant,
                    "randomized_variant_ordinal": ordinal,
                })
                run_index += 1
    return schedule


def aggregate_analysis(
    results: list[dict[str, Any]], baseline_variant: str
) -> dict[str, Any]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    by_pair: dict[tuple[int, str, str], dict[str, Any]] = {}
    for result in results:
        groups[(result["scenario"], result["variant"])].append(result)
        by_pair[(result["block"], result["scenario"], result["variant"])] = result
    summaries: list[dict[str, Any]] = []
    for (scenario, variant), rows in sorted(groups.items()):
        throughput = [
            float(row["latency"]["requests_per_second"]) for row in rows
        ]
        p99 = [int(row["latency"]["service_ns"]["p99"]) for row in rows]
        rss = [
            row["process_samples"].get("server", {}).get("max_rss_bytes")
            for row in rows
        ]
        summaries.append({
            "scenario": scenario,
            "variant": variant,
            "blocks": len(rows),
            "throughput_requests_per_second": {
                "median": statistics.median(throughput),
                "min": min(throughput),
                "max": max(throughput),
                "per_block": throughput,
            },
            "service_p99_ns": {
                "median": statistics.median(p99),
                "min": min(p99),
                "max": max(p99),
                "per_block": p99,
            },
            "server_max_rss_bytes_per_block": rss,
        })
    paired: list[dict[str, Any]] = []
    variants = sorted(
        {result["variant"] for result in results} - {baseline_variant}
    )
    scenarios = sorted({result["scenario"] for result in results})
    blocks = sorted({result["block"] for result in results})
    for block in blocks:
        for scenario in scenarios:
            baseline = by_pair.get((block, scenario, baseline_variant))
            if baseline is None:
                continue
            baseline_rate = float(baseline["latency"]["requests_per_second"])
            baseline_p99 = int(baseline["latency"]["service_ns"]["p99"])
            for variant in variants:
                candidate = by_pair.get((block, scenario, variant))
                if candidate is None:
                    continue
                row = {
                    "block": block,
                    "scenario": scenario,
                    "variant": variant,
                    "baseline_variant": baseline_variant,
                    "throughput_ratio_to_baseline": (
                        float(candidate["latency"]["requests_per_second"])
                        / baseline_rate
                    ),
                    "service_p99_ratio_to_baseline": (
                        int(candidate["latency"]["service_ns"]["p99"])
                        / baseline_p99
                    ),
                }
                if baseline_variant == "control":
                    row["throughput_ratio_to_control"] = row[
                        "throughput_ratio_to_baseline"
                    ]
                    row["service_p99_ratio_to_control"] = row[
                        "service_p99_ratio_to_baseline"
                    ]
                paired.append(row)
    return {
        "schema": "fastbed-benchmark-analysis-v1",
        "baseline_variant": baseline_variant,
        "warning": (
            "Ratios are paired descriptive evidence, not a claim of statistical "
            "significance. Inspect raw blocks and host samples."
        ),
        "groups": summaries,
        "paired_blocks": paired,
    }


def seal(output: Path) -> None:
    rows: list[str] = []
    for path in sorted(output.rglob("*")):
        if path.is_symlink():
            raise RuntimeError(f"artifact contains symlink: {path}")
        if path.is_file() and path.name != "SHA256SUMS":
            rows.append(
                f"{sha256_file(path)}  {path.relative_to(output).as_posix()}\n"
            )
    temporary = output / "SHA256SUMS.tmp"
    temporary.write_text("".join(rows), encoding="utf-8")
    temporary.replace(output / "SHA256SUMS")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument(
        "--check-plan", action="store_true",
        help="validate and hash inputs without compiling or running anything",
    )
    return parser.parse_args()


def snapshot_inputs(
    plan: dict[str, Any], plan_path: Path, benchmark_root: Path, output: Path
) -> None:
    shutil.copy2(plan_path, output / "plan.json")
    for scenario in plan["scenarios"]:
        original = Path(scenario["requests_file"])
        scenario["_original_requests_file"] = str(original)
        snapshot = output / "workloads" / f"{scenario['name']}.tsv"
        shutil.copy2(original, snapshot)
        companion = original.with_name(original.name + ".manifest.json")
        if companion.is_file():
            shutil.copy2(
                companion,
                output / "workloads" / f"{scenario['name']}.manifest.json",
            )
        scenario["requests_file"] = str(snapshot)
    for variant in plan["variants"]:
        snapshot = output / "binaries" / variant["name"]
        shutil.copy2(Path(variant["binary"]), snapshot)
        variant["_binary_snapshot"] = str(snapshot)
        variant_input_dir = output / "variant-inputs" / variant["name"]
        variant_input_dir.mkdir(parents=True)
        snapshots: list[str] = []
        for index, item in enumerate(variant.get("input_files", [])):
            source = Path(item)
            destination = variant_input_dir / f"{index:03d}-{source.name}"
            shutil.copy2(source, destination)
            snapshots.append(str(destination))
        variant["_input_snapshots"] = snapshots
    harness_snapshot = output / "harness"
    harness_snapshot.mkdir()
    for name in (
        "http_loadgen.c", "run_matrix.py", "run_selftest.py",
        "prepare_workload.py", "FAILURE_MODEL.md", "README.md",
        "plan.example.json", "service_compare.example.json",
        "archive_broker.py", "run_facebed_replay.py",
    ):
        source = benchmark_root / name
        if source.is_file():
            shutil.copy2(source, harness_snapshot / name)


def main() -> int:
    args = parse_args()
    benchmark_root = Path(__file__).resolve().parent
    plan_path = args.plan.resolve()
    raw_plan = read_json(plan_path)
    plan = validate_plan(raw_plan, benchmark_root.parent)
    if args.check_plan:
        evidence = {
            "status": "valid",
            "plan_sha256": sha256_file(plan_path),
            "profile": plan["profile"],
            "baseline_variant": plan["baseline_variant"],
            "source_tree": source_tree_digest(Path(plan["source_root"])),
            "variants": {
                variant["name"]: {
                    "sha256": sha256_file(Path(variant["binary"])),
                    "build_id": build_id(Path(variant["binary"])),
                    "input_files": {
                        path: sha256_file(Path(path))
                        for path in variant.get("input_files", [])
                    },
                }
                for variant in plan["variants"]
            },
            "workloads": {
                scenario["name"]: sha256_file(Path(scenario["requests_file"]))
                for scenario in plan["scenarios"]
            },
        }
        print(json.dumps(evidence, indent=2, sort_keys=True))
        return 0

    output = args.output.resolve()
    if output.exists():
        raise SystemExit(f"output already exists: {output}")
    output.mkdir(parents=True)
    (output / "runs").mkdir()
    (output / "sidecars").mkdir()
    (output / "workloads").mkdir()
    (output / "binaries").mkdir()
    (output / "variant-inputs").mkdir()

    started_utc = utc_now()
    started_ns = raw_ns()
    schedule: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    sidecars: list[dict[str, Any]] = []
    sidecar_evidence: list[dict[str, Any]] = []
    source_initial: dict[str, Any] | None = None
    source_final: dict[str, Any] | None = None
    host: dict[str, Any] = {}
    network: dict[str, Any] = {}
    quiet: dict[str, Any] | None = None
    loadgen_evidence: dict[str, Any] | None = None
    binary_initial: dict[str, str] = {}
    variant_inputs_initial: dict[str, dict[str, str]] = {}
    status = "failed"
    failure: dict[str, Any] | None = None
    try:
        snapshot_inputs(plan, plan_path, benchmark_root, output)
        host = host_inventory()
        network = network_inventory()
        if bool(plan.get("require_loopback_only", True)):
            assert_loopback_only(network)
        # Compile before the quiet-host gate so compiler load cannot contaminate it.
        loadgen, loadgen_evidence = compile_loadgen(
            benchmark_root, output, args.cc
        )
        source_initial = source_tree_digest(Path(plan["source_root"]))
        binary_initial = {
            variant["name"]: sha256_file(Path(variant["binary"]))
            for variant in plan["variants"]
        }
        variant_inputs_initial = {
            variant["name"]: {
                path: sha256_file(Path(path))
                for path in variant.get("input_files", [])
            }
            for variant in plan["variants"]
        }
        for variant in plan["variants"]:
            if sha256_file(Path(variant["_binary_snapshot"])) != binary_initial[
                variant["name"]
            ]:
                raise RuntimeError(
                    f"variant moved while snapshotting: {variant['name']}"
                )
            source_inputs = variant_inputs_initial[variant["name"]]
            snapshots = variant.get("_input_snapshots", [])
            if len(source_inputs) != len(snapshots):
                raise RuntimeError(
                    f"variant input snapshot count changed: {variant['name']}"
                )
            for source_path, snapshot_path in zip(
                source_inputs, snapshots, strict=True
            ):
                if sha256_file(Path(snapshot_path)) != source_inputs[source_path]:
                    raise RuntimeError(
                        f"variant input moved while snapshotting: "
                        f"{variant['name']}:{source_path}"
                    )
        for scenario in plan["scenarios"]:
            original_hash = sha256_file(
                Path(scenario["_original_requests_file"])
            )
            snapshot_hash = sha256_file(Path(scenario["requests_file"]))
            if original_hash != snapshot_hash:
                raise RuntimeError(
                    f"workload moved while snapshotting: {scenario['name']}"
                )
            scenario["_original_requests_sha256"] = original_hash
        quiet = quiet_host_evidence(plan.get("quiet", {}))
        source_after_quiet = source_tree_digest(Path(plan["source_root"]))
        if source_after_quiet != source_initial:
            raise RuntimeError("source tree moved during quiet-host preflight")
        if not quiet["passed"]:
            raise RuntimeError(
                f"host is not quiet enough for release measurement: {quiet['failures']}"
            )
        os.sched_setaffinity(0, set(plan["affinity"]["sidecars"]))
        host["runner_affinity_during_matrix"] = sorted(os.sched_getaffinity(0))
        schedule = generate_schedule(plan)
        atomic_json(output / "schedule.json", {
            "schema": "fastbed-randomized-paired-schedule-v1",
            "seed": plan["seed"],
            "blocks": plan["blocks"],
            "schedule": schedule,
        })
        sidecars = start_sidecars(plan, output)
        variant_by_name = {
            variant["name"]: variant for variant in plan["variants"]
        }
        scenario_by_name = {
            scenario["name"]: scenario for scenario in plan["scenarios"]
        }
        expected_source = source_initial
        for item in schedule:
            current_source = source_tree_digest(Path(plan["source_root"]))
            if current_source != expected_source:
                raise RuntimeError(
                    f"source tree moved before run {item['run_index']}"
                )
            variant_path = Path(variant_by_name[item["variant"]]["binary"])
            if sha256_file(variant_path) != binary_initial[item["variant"]]:
                raise RuntimeError(
                    f"variant binary moved before run {item['run_index']}: "
                    f"{item['variant']}"
                )
            for path, expected_hash in variant_inputs_initial[
                item["variant"]
            ].items():
                if sha256_file(Path(path)) != expected_hash:
                    raise RuntimeError(
                        f"variant input moved before run {item['run_index']}: "
                        f"{item['variant']}:{path}"
                    )
            result, current_source = run_one(
                plan,
                variant_by_name[item["variant"]],
                scenario_by_name[item["scenario"]],
                int(item["block"]),
                int(item["run_index"]),
                output,
                loadgen,
                expected_source,
                {
                    str(sidecar["name"]): int(sidecar["process"].pid)
                    for sidecar in sidecars
                },
            )
            if current_source != expected_source:
                raise RuntimeError(
                    f"source tree moved during run {item['run_index']}"
                )
            results.append(result)
        source_final = source_tree_digest(Path(plan["source_root"]))
        if source_final != source_initial:
            raise RuntimeError("source tree moved during the matrix")
        for variant in plan["variants"]:
            if sha256_file(Path(variant["binary"])) != binary_initial[variant["name"]]:
                raise RuntimeError(f"variant binary moved: {variant['name']}")
            for path, expected_hash in variant_inputs_initial[
                variant["name"]
            ].items():
                if sha256_file(Path(path)) != expected_hash:
                    raise RuntimeError(
                        f"variant input moved: {variant['name']}:{path}"
                    )
        analysis = aggregate_analysis(results, str(plan["baseline_variant"]))
        atomic_json(output / "analysis.json", analysis)
        status = "passed"
    except BaseException as error:
        failure = {
            "type": type(error).__name__,
            "message": str(error),
            "traceback": traceback.format_exc(),
            "utc": utc_now(),
            "monotonic_raw_ns": raw_ns(),
            "completed_runs": len(results),
        }
        atomic_json(output / "failure.json", failure)
    finally:
        if sidecars:
            sidecar_evidence = stop_sidecars(sidecars)
            atomic_json(output / "sidecars.json", sidecar_evidence)
            stop_failures = [
                row for row in sidecar_evidence if "stop_error" in row
            ]
            if stop_failures and status == "passed":
                status = "failed"
                failure = {
                    "type": "SidecarLifecycleError",
                    "message": f"{len(stop_failures)} sidecar(s) failed shutdown",
                    "traceback": "",
                    "utc": utc_now(),
                    "monotonic_raw_ns": raw_ns(),
                    "completed_runs": len(results),
                }
                atomic_json(output / "failure.json", failure)
        try:
            if source_final is None:
                source_final = source_tree_digest(Path(plan["source_root"]))
        except Exception as error:
            source_final = {
                "error": f"{type(error).__name__}: {error}"
            }
        variants = {
            variant["name"]: {
                "binary": variant["binary"],
                "sha256": optional_sha256(variant["binary"]),
                "initial_sha256": binary_initial.get(variant["name"]),
                "snapshot": variant.get("_binary_snapshot"),
                "snapshot_sha256": optional_sha256(
                    variant.get("_binary_snapshot")
                ),
                "build_id": build_id(Path(variant["binary"])),
                "args": variant.get("args", []),
                "env_template": variant.get("env", {}),
                "server": variant.get("server", {}),
                "kind_args": variant.get("kind_args", {}),
                "input_files": [
                    {
                        "path": path,
                        "initial_sha256": variant_inputs_initial.get(
                            variant["name"], {}
                        ).get(path),
                        "final_sha256": optional_sha256(path),
                        "snapshot": snapshot,
                        "snapshot_sha256": optional_sha256(snapshot),
                    }
                    for path, snapshot in zip(
                        variant.get("input_files", []),
                        variant.get("_input_snapshots", []),
                        strict=True,
                    )
                ],
            }
            for variant in plan["variants"]
        }
        workloads = {
            scenario["name"]: {
                "source_path": scenario.get(
                    "_original_requests_file", scenario["requests_file"]
                ),
                "snapshot_path": scenario["requests_file"],
                "sha256": optional_sha256(scenario["requests_file"]),
                "source_sha256": scenario.get("_original_requests_sha256"),
                "active_rows": len(
                    active_workload_lines(Path(scenario["requests_file"]))
                ) if Path(scenario["requests_file"]).is_file() else None,
            }
            for scenario in plan["scenarios"]
        }
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "status": status,
            "started_utc": started_utc,
            "finished_utc": utc_now(),
            "started_monotonic_raw_ns": started_ns,
            "finished_monotonic_raw_ns": raw_ns(),
            "plan": {
                "path": str(plan_path),
                "sha256": sha256_file(plan_path),
                "snapshot": "plan.json",
                "snapshot_sha256": optional_sha256(output / "plan.json"),
                "seed": plan["seed"],
                "blocks": plan["blocks"],
                "profile": plan["profile"],
                "baseline_variant": plan["baseline_variant"],
            },
            "clock": "CLOCK_MONOTONIC_RAW",
            "loadgen": loadgen_evidence,
            "host": host,
            "network": network,
            "quiet_host_gate": quiet,
            "source_tree_initial": source_initial,
            "source_tree_final": source_final,
            "variants": variants,
            "workloads": workloads,
            "schedule_entries": len(schedule),
            "completed_runs": len(results),
            "sidecars": sidecar_evidence,
            "failure": None if failure is None else {
                "type": failure["type"],
                "message": failure["message"],
            },
            "replay": (
                f"python3 {Path(__file__).name} {plan_path} --output NEW_DIRECTORY"
            ),
        }
        atomic_json(output / "manifest.json", manifest)
        seal(output)

    print(json.dumps({
        "status": status,
        "artifact": str(output),
        "manifest_sha256": sha256_file(output / "manifest.json"),
        "completed_runs": len(results),
    }, sort_keys=True))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())

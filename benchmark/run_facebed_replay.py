#!/usr/bin/env python3
"""Launch the real Facebed HTTP service against the isolated archive broker."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import sys
from typing import Any
from urllib.parse import urlsplit, urlunsplit


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--facebed", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--broker-http-port", type=int, required=True)
    parser.add_argument("--broker-https-port", type=int, required=True)
    parser.add_argument("--identity-output", type=Path, required=True)
    return parser.parse_args()


def load_facebed(path: Path):
    source = path.resolve()
    sys.path.insert(0, str(source.parent))
    spec = importlib.util.spec_from_file_location(
        "_facebed_service_benchmark_target", source
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import Facebed source: {source}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    args = parse_args()
    facebed_path = args.facebed.resolve()
    config_path = args.config.resolve()
    if not facebed_path.is_file() or not config_path.is_file():
        raise SystemExit("Facebed source and benchmark config must be files")
    facebed = load_facebed(facebed_path)
    original_session = facebed.CffiSession

    class ReplaySession(original_session):
        def __init__(self, *session_args: Any, **session_kwargs: Any) -> None:
            session_kwargs["trust_env"] = False
            super().__init__(*session_args, **session_kwargs)

        def request(self, method: str, url: str, *request_args: Any,
                    **request_kwargs: Any):
            parsed = urlsplit(str(url))
            scheme = parsed.scheme.lower()
            if (
                scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError(f"refusing unsupported replay URL: {url!r}")
            port = (
                args.broker_https_port if scheme == "https"
                else args.broker_http_port
            )
            replay_url = urlunsplit((
                scheme,
                f"127.0.0.1:{port}",
                parsed.path or "/",
                parsed.query,
                "",
            ))
            supplied_headers = request_kwargs.pop("headers", None)
            headers = dict(supplied_headers or {})
            for key in list(headers):
                if str(key).lower() in {
                    "host", "x-fastbed-fixture-requested-hex"
                }:
                    del headers[key]
            headers["Host"] = parsed.netloc
            headers["X-Fastbed-Fixture-Requested-Hex"] = str(url).encode(
                "utf-8"
            ).hex()
            request_kwargs["headers"] = headers
            request_kwargs["verify"] = False
            response = super().request(
                method, replay_url, *request_args, **request_kwargs
            )
            response.url = response.headers.get(
                "X-Fastbed-Fixture-Final-Url", str(url)
            )
            return response

    facebed.CffiSession = ReplaySession
    packages = {}
    for name in (
        "beautifulsoup4", "bottle", "crawler-user-agents", "curl_cffi",
        "discord-webhook", "PyYAML", "yattag",
    ):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = None
    atomic_json(args.identity_output.resolve(), {
        "schema": "facebed-service-benchmark-launch-v1",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "facebed": str(facebed_path),
        "facebed_sha256": sha256_file(facebed_path),
        "config": str(config_path),
        "config_sha256": sha256_file(config_path),
        "python_executable": sys.executable,
        "python_version": sys.version,
        "packages": packages,
        "replay": {
            "address": "127.0.0.1",
            "http_port": args.broker_http_port,
            "https_port": args.broker_https_port,
            "transport": "curl_cffi loopback HTTP/TLS with logical URL header",
            "trust_environment_proxy": False,
            "tls_verification": False,
        },
    })
    sys.argv = [str(facebed_path), "--config", str(config_path)]
    facebed.main()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

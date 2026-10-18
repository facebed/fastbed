#!/usr/bin/env python3
"""Generate deterministic C arrays for Fastbed's immutable runtime resources."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


RESOURCES = (
    ("index", "index_html"),
    ("favicon", "favicon_ico"),
    ("banner", "banner_png"),
    ("crawler", "crawler_json"),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def emit_array(name: str, data: bytes) -> str:
    lines = [f"_Alignas(64) const unsigned char fb_embedded_{name}[] = {{"]
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        lines.append("    " + ", ".join(f"0x{byte:02x}" for byte in chunk) + ",")
    lines.extend(
        [
            "};",
            f"const size_t fb_embedded_{name}_length = sizeof(fb_embedded_{name});",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    for option, _name in RESOURCES:
        parser.add_argument(f"--{option}", type=Path, required=True)
    parser.add_argument("--output-c", type=Path, required=True)
    parser.add_argument("--output-h", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    outputs = (args.output_c, args.output_h, args.manifest)
    if len({path.resolve() for path in outputs}) != len(outputs):
        parser.error("output paths must be distinct")
    for output in outputs:
        if output.exists():
            parser.error(f"output already exists: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)

    values: dict[str, bytes] = {}
    records: list[dict[str, object]] = []
    for option, name in RESOURCES:
        path = getattr(args, option).resolve(strict=True)
        if not path.is_file() or path.is_symlink():
            parser.error(f"resource is not a regular file: {path}")
        data = path.read_bytes()
        if not data:
            parser.error(f"resource is empty: {path}")
        values[name] = data
        records.append(
            {
                "name": name,
                "source_name": path.name,
                "bytes": len(data),
                "sha256": sha256(data),
            }
        )

    header = [
        "#ifndef FASTBED_EMBEDDED_RESOURCES_H",
        "#define FASTBED_EMBEDDED_RESOURCES_H",
        "",
        "#include <stddef.h>",
        "",
    ]
    for _option, name in RESOURCES:
        header.extend(
            [
                f"extern const unsigned char fb_embedded_{name}[];",
                f"extern const size_t fb_embedded_{name}_length;",
            ]
        )
    header.extend(["", "#endif", ""])
    args.output_h.write_text("\n".join(header), encoding="ascii", newline="\n")

    source = ['#include "fastbed/embedded_resources.h"', ""]
    for _option, name in RESOURCES:
        source.append(emit_array(name, values[name]))
    args.output_c.write_text("\n".join(source), encoding="ascii", newline="\n")

    manifest = {
        "schema": "fastbed-embedded-resources-v1",
        "generator_sha256": sha256(Path(__file__).read_bytes()),
        "resources": records,
    }
    args.manifest.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Check the index actually selected by GhostScope, including supplement loading."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


INDEX_KINDS = ("full_scan", "gnu_pubnames", "gdb_index", "debug_names", "rejected")


def validate(expected: dict | None, actual: dict | None) -> None:
    # Older manifests remain usable for base/head timing comparisons.
    if expected is None:
        return
    if actual is None:
        raise ValueError("dwarf-tool did not report its selected indexes")
    required = {kind: int(kind == expected["kind"]) for kind in INDEX_KINDS}
    required["supplementary"] = int(expected["supplementary"])
    if actual != required:
        raise ValueError(f"index selection mismatch: expected {required}, got {actual}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--actual", required=True, help="Selected index counts as JSON, or null")
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    artifact = next(item for item in manifest["artifacts"] if item["name"] == args.target)
    validate(artifact.get("expected_index"), json.loads(args.actual))


if __name__ == "__main__":
    main()

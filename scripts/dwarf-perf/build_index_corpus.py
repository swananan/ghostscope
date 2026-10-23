#!/usr/bin/env python3
"""Derive indexed and real dwz corpora from the unchanged C parse corpus."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path


VARIANTS = {
    "gdb-index-stress": ("gdb_index", False),
    "debug-names-stress": ("debug_names", False),
    "supplementary-stress": ("full_scan", True),
    "supplementary-gdb-index-stress": ("gdb_index", True),
    "supplementary-debug-names-stress": ("debug_names", True),
}


def sections(binary: Path) -> set[str]:
    output = subprocess.check_output(["readelf", "--wide", "--sections", str(binary)], text=True)
    return set(re.findall(r"\[\s*\d+\]\s+(\.\S+)", output))


def artifact_file(path: Path, root: Path) -> dict:
    return {
        "relative_path": str(path.relative_to(root)),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size_bytes": path.stat().st_size,
    }


def build(root: Path, dwz: str, gdb_add_index: str) -> dict:
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    artifacts = [item for item in manifest["artifacts"] if item["name"] not in VARIANTS]
    by_name = {item["name"]: item for item in artifacts}
    source = root / by_name["parse-stress"]["relative_path"]
    # Copying, rather than rebuilding, keeps old and new cases on identical code.
    original_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    original_sections = sections(source)
    if original_sections.intersection({".gdb_index", ".debug_names", ".debug_gnu_pubnames", ".gnu_debugaltlink", ".debug_sup"}):
        raise ValueError("parse-stress must contain ordinary, unindexed DWARF")

    by_name["parse-stress"]["expected_index"] = {"kind": "full_scan", "supplementary": False}
    if "gnu-pubnames-stress" in by_name:
        by_name["gnu-pubnames-stress"]["expected_index"] = {"kind": "gnu_pubnames", "supplementary": False}

    seed_dir = root / "_build" / "supplementary-seed"
    seed_dir.mkdir(parents=True, exist_ok=True)
    primary = seed_dir / "program"
    peer = seed_dir / "peer"
    shared = seed_dir / "shared.debug"
    shutil.copy2(source, primary)
    shutil.copy2(source, peer)
    # An earlier build's output is never an input to dwz.
    shared.unlink(missing_ok=True)
    subprocess.run([dwz, "-r", "-m", str(shared), str(primary), str(peer)], check=True)
    peer.unlink()
    if not shared.is_file() or ".gnu_debugaltlink" not in sections(primary):
        raise ValueError("dwz did not produce a supplementary DWARF object")

    for name, (kind, supplementary) in VARIANTS.items():
        destination = root / name
        destination.mkdir(exist_ok=True)
        binary = destination / name.replace("-", "_")
        shutil.copy2(primary if supplementary else source, binary)
        if supplementary:
            shutil.copy2(shared, destination / "shared.debug")
        if kind != "full_scan":
            arguments = [gdb_add_index]
            if kind == "debug_names":
                arguments.append("-dwarf-5")
            # gdb-add-index also indexes the relative .gnu_debugaltlink target.
            subprocess.run([*arguments, str(binary)], cwd=destination, check=True)
            expected_section = ".gdb_index" if kind == "gdb_index" else ".debug_names"
            if expected_section not in sections(binary):
                raise ValueError(f"{name}: GDB did not produce {expected_section}")
        artifact = {
            "name": name,
            "kind": "fast-parse",
            "language": "c",
            **artifact_file(binary, root),
            "expected_index": {"kind": kind, "supplementary": supplementary},
            "generator": {"source_artifact": "parse-stress", **by_name["parse-stress"]["generator"]},
        }
        if supplementary:
            artifact["supplementary"] = artifact_file(destination / "shared.debug", root)
        artifacts.append(artifact)

    if hashlib.sha256(source.read_bytes()).hexdigest() != original_sha:
        raise ValueError("index generation modified the original parse-stress corpus")
    manifest["artifacts"] = artifacts
    manifest["index_tools"] = {
        "dwz": subprocess.check_output([dwz, "--version"], text=True).splitlines()[0],
        "gdb": subprocess.check_output(["gdb", "--version"], text=True).splitlines()[0],
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--dwz", default="dwz")
    parser.add_argument("--gdb-add-index", default="gdb-add-index")
    args = parser.parse_args()
    manifest = build(args.output_dir.resolve(), args.dwz, args.gdb_add_index)
    print(f"Built {len(VARIANTS)} index variants; {len(manifest['artifacts'])} corpus artifacts total")


if __name__ == "__main__":
    main()

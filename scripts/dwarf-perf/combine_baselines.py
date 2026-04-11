#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Combine multiple run_baseline.sh result files into one baseline snapshot."
        )
    )
    parser.add_argument(
        "--primary",
        required=True,
        help="Primary baseline JSON. Its query benchmark and top-level metadata are preserved.",
    )
    parser.add_argument(
        "--additional",
        action="append",
        default=[],
        help="Additional baseline JSON files that contribute extra parse targets.",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to write the combined baseline JSON.",
    )
    return parser.parse_args()


def load_json(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def parse_target_name(baseline: dict[str, Any]) -> str:
    return baseline["parse_benchmark"].get("artifact_name", "parse-stress")


def ensure_compatible(primary: dict[str, Any], candidate: dict[str, Any], candidate_path: str) -> None:
    primary_source = primary["query_benchmark"]["source"]
    candidate_source = candidate["query_benchmark"]["source"]
    if candidate_source != primary_source:
        raise ValueError(
            f"query source mismatch while combining baseline: {candidate_path}"
        )

    if candidate["query_result"]["source"] != primary["query_result"]["source"]:
        raise ValueError(
            f"query result source mismatch while combining baseline: {candidate_path}"
        )

    primary_result_shape = {
        key: primary["query_result"][key]
        for key in ["address_count", "total_variables", "first_address"]
    }
    candidate_result_shape = {
        key: candidate["query_result"][key]
        for key in ["address_count", "total_variables", "first_address"]
    }
    if candidate_result_shape != primary_result_shape:
        raise ValueError(
            f"query_result mismatch while combining baseline: {candidate_path}"
        )
    if candidate.get("corpus_manifest") != primary.get("corpus_manifest"):
        raise ValueError(
            f"corpus_manifest mismatch while combining baseline: {candidate_path}"
        )


def main() -> int:
    args = parse_args()
    primary = load_json(args.primary)

    parse_targets: dict[str, Any] = {
        parse_target_name(primary): primary["parse_benchmark"],
    }

    for additional_path in args.additional:
        additional = load_json(additional_path)
        ensure_compatible(primary, additional, additional_path)
        parse_targets[parse_target_name(additional)] = additional["parse_benchmark"]

    combined = dict(primary)
    combined["primary_parse_target"] = parse_target_name(primary)
    combined["parse_targets"] = parse_targets

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(combined, indent=2) + "\n")

    print(f"Combined baseline written to {output_path}")
    print(f"  primary: {combined['primary_parse_target']}")
    print(f"  parse targets: {', '.join(sorted(parse_targets.keys()))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

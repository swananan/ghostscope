#!/usr/bin/env python3
"""Generate a deterministic C++ deep-namespace corpus for DWARF parse baselines."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


PRESET_CONFIGS = {
    "medium": {
        "units": 8,
        "namespace_depth": 6,
        "branches_per_unit": 12,
        "functions_per_branch": 16,
    },
    "large": {
        "units": 16,
        "namespace_depth": 8,
        "branches_per_unit": 16,
        "functions_per_branch": 24,
    },
    "xlarge": {
        "units": 20,
        "namespace_depth": 10,
        "branches_per_unit": 18,
        "functions_per_branch": 28,
    },
}


@dataclass(frozen=True)
class CppDeepNamespaceConfig:
    preset: str
    units: int
    namespace_depth: int
    branches_per_unit: int
    functions_per_branch: int


def build_config(args: argparse.Namespace) -> CppDeepNamespaceConfig:
    preset = PRESET_CONFIGS[args.preset]
    units = args.units or preset["units"]
    namespace_depth = args.namespace_depth or preset["namespace_depth"]
    branches_per_unit = args.branches_per_unit or preset["branches_per_unit"]
    functions_per_branch = args.functions_per_branch or preset["functions_per_branch"]

    for field_name, value in [
        ("units", units),
        ("namespace_depth", namespace_depth),
        ("branches_per_unit", branches_per_unit),
        ("functions_per_branch", functions_per_branch),
    ]:
        if value <= 0:
            raise SystemExit(f"{field_name} must be > 0")

    return CppDeepNamespaceConfig(
        preset=args.preset,
        units=units,
        namespace_depth=namespace_depth,
        branches_per_unit=branches_per_unit,
        functions_per_branch=functions_per_branch,
    )


def namespace_path(unit_idx: int, branch_idx: int, depth: int) -> list[str]:
    fragments = [
        f"region_{unit_idx:02d}",
        f"tenant_{branch_idx:02d}",
        f"service_{(unit_idx + branch_idx) % 23:02d}",
        f"component_{(unit_idx * 3 + branch_idx) % 29:02d}",
        f"pipeline_{(unit_idx * 5 + branch_idx * 2) % 31:02d}",
        f"stage_{(unit_idx + branch_idx * 7) % 37:02d}",
        f"fragment_{(unit_idx * 11 + branch_idx) % 41:02d}",
        f"segment_{(unit_idx * 13 + branch_idx * 3) % 43:02d}",
        f"lane_{(unit_idx * 17 + branch_idx * 5) % 47:02d}",
        f"leaf_{(unit_idx * 19 + branch_idx * 7) % 53:02d}",
    ]
    return fragments[:depth]


def render_main(config: CppDeepNamespaceConfig) -> str:
    declarations = [
        f'extern "C" std::uint64_t cpp_deep_namespace_unit_{unit_idx:02d}_accumulate();'
        for unit_idx in range(config.units)
    ]
    call_table = ", ".join(
        f"cpp_deep_namespace_unit_{unit_idx:02d}_accumulate"
        for unit_idx in range(config.units)
    )
    return "\n".join(
        [
            "#include <cstddef>",
            "#include <cstdint>",
            "#include <cstdio>",
            "",
            *declarations,
            "",
            "using cpp_namespace_runner_t = std::uint64_t (*)();",
            "",
            f"static cpp_namespace_runner_t kCppNamespaceRunners[{config.units}] = {{{call_table}}};",
            "",
            "int main() {",
            "    std::uint64_t total = 0u;",
            "    for (std::size_t idx = 0; idx < (sizeof(kCppNamespaceRunners) / sizeof(kCppNamespaceRunners[0])); ++idx) {",
            "        total ^= kCppNamespaceRunners[idx]();",
            "    }",
            '    std::printf("cpp-deep-namespace:%llu\\n", static_cast<unsigned long long>(total));',
            "    return total == 0u ? 1 : 0;",
            "}",
            "",
        ]
    )


def render_branch(config: CppDeepNamespaceConfig, unit_idx: int, branch_idx: int) -> tuple[list[str], str]:
    path = namespace_path(unit_idx, branch_idx, config.namespace_depth)
    namespace_name = "::".join(path)
    lines = [
        f"namespace {namespace_name} {{",
        "",
        f"struct branch_ledger_{unit_idx:02d}_{branch_idx:02d} {{",
        "    static __attribute__((noinline)) std::uint64_t fold(std::uint64_t seed) {",
        f"        return seed ^ {((unit_idx + 1) * 97) + (branch_idx * 13)}u;",
        "    }",
        "",
        "    static __attribute__((noinline)) std::uint64_t sweep(std::uint64_t seed) {",
        f"        return (seed << 1) ^ (seed >> 3) ^ {((unit_idx + 1) * 131) + (branch_idx * 17)}u;",
        "    }",
        "};",
        "",
    ]

    sample_call = (
        f"{namespace_name}::operation_{branch_idx:02d}_000"
        f"({(unit_idx + 1) * (branch_idx + 3)}u)"
    )
    for fn_idx in range(config.functions_per_branch):
        bias = ((unit_idx + 3) * 0x51) + (branch_idx * 0x17) + fn_idx
        lines.extend(
            [
                "__attribute__((noinline)) std::uint64_t "
                f"operation_{branch_idx:02d}_{fn_idx:03d}(std::uint64_t seed) {{",
                f"    std::uint64_t total = branch_ledger_{unit_idx:02d}_{branch_idx:02d}::fold(seed + {bias}u);",
                f"    total ^= branch_ledger_{unit_idx:02d}_{branch_idx:02d}::sweep(seed ^ {bias + 11}u);",
                f"    return total ^ {(branch_idx + 1) * (fn_idx + 5)}u;",
                "}",
                "",
            ]
        )

    lines.extend(
        [
            f"}}  // namespace {namespace_name}",
            "",
        ]
    )
    return lines, sample_call


def render_unit_source(config: CppDeepNamespaceConfig, unit_idx: int) -> str:
    lines = [
        "#include <cstdint>",
        "",
    ]
    sample_calls: list[str] = []
    for branch_idx in range(config.branches_per_unit):
        branch_lines, sample_call = render_branch(config, unit_idx, branch_idx)
        lines.extend(branch_lines)
        sample_calls.append(sample_call)

    lines.extend(
        [
            f'extern "C" std::uint64_t cpp_deep_namespace_unit_{unit_idx:02d}_accumulate() {{',
            f"    std::uint64_t total = {unit_idx + 1}u;",
        ]
    )
    for call in sample_calls:
        lines.append(f"    total ^= {call};")
    lines.extend(
        [
            "    return total;",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(output_dir: Path, config: CppDeepNamespaceConfig) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "main.cpp").write_text(render_main(config), encoding="utf-8")
    for unit_idx in range(config.units):
        (output_dir / f"unit_{unit_idx:02d}.cpp").write_text(
            render_unit_source(config, unit_idx),
            encoding="utf-8",
        )

    estimated_symbols = (
        config.units * config.branches_per_unit * config.functions_per_branch * 3
    )
    generation_config = {
        "preset": config.preset,
        "units": config.units,
        "namespace_depth": config.namespace_depth,
        "branches_per_unit": config.branches_per_unit,
        "functions_per_branch": config.functions_per_branch,
        "estimated_mangled_symbols": estimated_symbols,
        "generated_cpp_files": config.units + 1,
    }
    (output_dir / "generation_config.json").write_text(
        json.dumps(generation_config, indent=2) + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic C++ deep-namespace DWARF corpus."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write generated C++ files")
    parser.add_argument(
        "--preset",
        choices=sorted(PRESET_CONFIGS.keys()),
        default="large",
        help="Named scale preset",
    )
    parser.add_argument("--units", type=int, help="Override translation unit count")
    parser.add_argument(
        "--namespace-depth",
        type=int,
        help="Override namespace nesting depth",
    )
    parser.add_argument(
        "--branches-per-unit",
        type=int,
        help="Override namespace branches per translation unit",
    )
    parser.add_argument(
        "--functions-per-branch",
        type=int,
        help="Override functions per deep namespace branch",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = build_config(args)
    write_outputs(Path(args.output_dir), config)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Generate a deterministic C++ template-heavy corpus for DWARF parse baselines."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


PRESET_CONFIGS = {
    "medium": {
        "units": 8,
        "families_per_unit": 10,
        "instantiations_per_family": 24,
        "methods_per_family": 4,
    },
    "large": {
        "units": 16,
        "families_per_unit": 16,
        "instantiations_per_family": 48,
        "methods_per_family": 4,
    },
    "xlarge": {
        "units": 20,
        "families_per_unit": 18,
        "instantiations_per_family": 56,
        "methods_per_family": 4,
    },
}


@dataclass(frozen=True)
class CppTemplateStressConfig:
    preset: str
    units: int
    families_per_unit: int
    instantiations_per_family: int
    methods_per_family: int


def build_config(args: argparse.Namespace) -> CppTemplateStressConfig:
    preset = PRESET_CONFIGS[args.preset]
    units = args.units or preset["units"]
    families_per_unit = args.families_per_unit or preset["families_per_unit"]
    instantiations_per_family = (
        args.instantiations_per_family or preset["instantiations_per_family"]
    )
    methods_per_family = args.methods_per_family or preset["methods_per_family"]

    for field_name, value in [
        ("units", units),
        ("families_per_unit", families_per_unit),
        ("instantiations_per_family", instantiations_per_family),
        ("methods_per_family", methods_per_family),
    ]:
        if value <= 0:
            raise SystemExit(f"{field_name} must be > 0")

    return CppTemplateStressConfig(
        preset=args.preset,
        units=units,
        families_per_unit=families_per_unit,
        instantiations_per_family=instantiations_per_family,
        methods_per_family=methods_per_family,
    )


def uint64_literal(value: int) -> str:
    return f"0x{value:016x}ull"


def type_expr(unit_idx: int, family_idx: int, inst_idx: int, branch: int) -> str:
    root_tag = (unit_idx * 4096) + (family_idx * 97) + (inst_idx * 7) + branch
    left_leaf = (
        f"lane_pack<tag<{root_tag % 257}>, {(inst_idx % 4) + 2}, "
        f"{((family_idx + branch) % 5) + 2}>"
    )
    middle_leaf = (
        f"lane_pack<tag<{(root_tag + 19) % 257}>, {((family_idx + inst_idx) % 5) + 2}, "
        f"{((unit_idx + branch) % 6) + 2}>"
    )
    right_leaf = (
        f"lane_pack<tag<{(root_tag + 53) % 257}>, {((family_idx + 2 * branch) % 4) + 2}, "
        f"{((inst_idx + branch) % 6) + 2}>"
    )
    return (
        f"composite_node<{left_leaf}, "
        f"composite_node<{middle_leaf}, {right_leaf}, {((inst_idx + branch) % 9) + 2}>, "
        f"{((family_idx + inst_idx + branch) % 11) + 3}>"
    )


def render_main(config: CppTemplateStressConfig) -> str:
    declarations = [
        f'extern "C" std::uint64_t cpp_template_stress_unit_{unit_idx:02d}_accumulate();'
        for unit_idx in range(config.units)
    ]
    call_table = ", ".join(
        f"cpp_template_stress_unit_{unit_idx:02d}_accumulate"
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
            "using cpp_template_runner_t = std::uint64_t (*)();",
            "",
            f"static cpp_template_runner_t kCppTemplateRunners[{config.units}] = {{{call_table}}};",
            "",
            "int main() {",
            "    std::uint64_t total = 0u;",
            "    for (std::size_t idx = 0; idx < (sizeof(kCppTemplateRunners) / sizeof(kCppTemplateRunners[0])); ++idx) {",
            "        total ^= kCppTemplateRunners[idx]();",
            "    }",
            '    std::printf("cpp-template-stress:%llu\\n", static_cast<unsigned long long>(total));',
            "    return total == 0u ? 1 : 0;",
            "}",
            "",
        ]
    )


def render_unit_source(config: CppTemplateStressConfig, unit_idx: int) -> str:
    namespace_name = f"dwarf::perf::cpp_template_stress::unit_{unit_idx:02d}"
    lines = [
        "#include <array>",
        "#include <cstddef>",
        "#include <cstdint>",
        "#include <tuple>",
        "#include <type_traits>",
        "",
        f"namespace {namespace_name} {{",
        "",
        "template <std::size_t Id>",
        "struct tag {};",
        "",
        "template <typename Tag, std::size_t Width, std::size_t Depth>",
        "struct lane_pack {",
        "    std::array<std::uint64_t, Width> lanes{};",
        "    static constexpr std::size_t k_width = Width;",
        "    static constexpr std::size_t k_depth = Depth;",
        "};",
        "",
        "template <typename Left, typename Right, std::size_t Rank>",
        "struct composite_node {",
        "    using left = Left;",
        "    using right = Right;",
        "    static constexpr std::size_t k_rank = Rank;",
        "};",
        "",
        "template <typename Left, typename Right, std::size_t Depth, std::uint64_t Salt>",
        "struct lattice {",
    ]

    for method_idx in range(config.methods_per_family):
        lines.append(
            f"    static __attribute__((noinline)) std::uint64_t step_{method_idx}(std::uint64_t seed);"
        )

    lines.extend(
        [
            "};",
            "",
        ]
    )

    for method_idx in range(config.methods_per_family):
        rotate_bits = ((unit_idx + method_idx) % 23) + 5
        lines.extend(
            [
                "template <typename Left, typename Right, std::size_t Depth, std::uint64_t Salt>",
                f"std::uint64_t lattice<Left, Right, Depth, Salt>::step_{method_idx}(std::uint64_t seed) {{",
                "    using stitched = std::tuple<Left, Right, composite_node<Left, Right, Depth>>;",
                "    constexpr std::uint64_t layout =",
                "        static_cast<std::uint64_t>(sizeof(stitched) + alignof(Left) + alignof(Right));",
                "    std::uint64_t total = seed ^ Salt ^ layout;",
                f"    total ^= static_cast<std::uint64_t>(Depth + {method_idx + 1});",
                f"    total = (total << {rotate_bits}) | (total >> {64 - rotate_bits});",
                "    return (total << 1) ^ (total >> 3) ^ static_cast<std::uint64_t>(layout * 17u);",
                "}",
                "",
            ]
        )

    lines.extend(
        [
            "template <typename Left, typename Right, std::size_t Depth, std::uint64_t Salt>",
            "__attribute__((noinline)) std::uint64_t drive(std::uint64_t seed) {",
            "    std::uint64_t total = seed ^ Salt;",
        ]
    )
    for method_idx in range(config.methods_per_family):
        lines.append(
            f"    total ^= lattice<Left, Right, Depth, Salt>::step_{method_idx}(seed + {method_idx + 1}u);"
        )
    lines.extend(
        [
            "    return total;",
            "}",
            "",
        ]
    )

    sample_calls: list[str] = []
    for family_idx in range(config.families_per_unit):
        for inst_idx in range(config.instantiations_per_family):
            alias_name = f"family_{family_idx:02d}_{inst_idx:03d}"
            left_alias = f"{alias_name}_left"
            right_alias = f"{alias_name}_right"
            depth = ((inst_idx + family_idx) % 13) + 2
            salt = (
                ((unit_idx + 1) * 0x9E37_79B1)
                ^ ((family_idx + 3) * 0xC2B2_AE35)
                ^ ((inst_idx + 11) * 0x1656_6671)
            ) & 0xFFFF_FFFF_FFFF_FFFF
            lines.extend(
                [
                    f"using {left_alias} = {type_expr(unit_idx, family_idx, inst_idx, 0)};",
                    f"using {right_alias} = {type_expr(unit_idx, family_idx, inst_idx, 1)};",
                    (
                        f"template struct lattice<{left_alias}, {right_alias}, {depth}, "
                        f"{uint64_literal(salt)}>;"
                    ),
                    (
                        f"template std::uint64_t drive<{left_alias}, {right_alias}, {depth}, "
                        f"{uint64_literal(salt)}>(std::uint64_t seed);"
                    ),
                    "",
                ]
            )
            if inst_idx == 0:
                sample_calls.append(
                    f"    total ^= drive<{left_alias}, {right_alias}, {depth}, {uint64_literal(salt)}>({family_idx + 3}u);"
                )

    lines.extend(
        [
            f'}}  // namespace {namespace_name}',
            "",
            f'extern "C" std::uint64_t cpp_template_stress_unit_{unit_idx:02d}_accumulate() {{',
            f"    using namespace {namespace_name};",
            f"    std::uint64_t total = {unit_idx + 1}u;",
            *sample_calls,
            "    return total;",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def write_outputs(output_dir: Path, config: CppTemplateStressConfig) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "main.cpp").write_text(render_main(config), encoding="utf-8")

    for unit_idx in range(config.units):
        (output_dir / f"unit_{unit_idx:02d}.cpp").write_text(
            render_unit_source(config, unit_idx),
            encoding="utf-8",
        )

    estimated_symbols = (
        config.units
        * config.families_per_unit
        * config.instantiations_per_family
        * (config.methods_per_family + 1)
    )
    generation_config = {
        "preset": config.preset,
        "units": config.units,
        "families_per_unit": config.families_per_unit,
        "instantiations_per_family": config.instantiations_per_family,
        "methods_per_family": config.methods_per_family,
        "estimated_mangled_symbols": estimated_symbols,
        "generated_cpp_files": config.units + 1,
    }
    (output_dir / "generation_config.json").write_text(
        json.dumps(generation_config, indent=2) + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic C++ template-heavy DWARF corpus."
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
        "--families-per-unit",
        type=int,
        help="Override template family count per translation unit",
    )
    parser.add_argument(
        "--instantiations-per-family",
        type=int,
        help="Override explicit instantiations per template family",
    )
    parser.add_argument(
        "--methods-per-family",
        type=int,
        help="Override generated methods per template family",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = build_config(args)
    write_outputs(Path(args.output_dir), config)


if __name__ == "__main__":
    main()

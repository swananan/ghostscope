#!/usr/bin/env python3
"""Generate a deterministic Rust generic-heavy corpus for DWARF parse baselines."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


PRESET_CONFIGS = {
    "medium": {
        "modules": 8,
        "families_per_module": 10,
        "monomorphs_per_family": 18,
    },
    "large": {
        "modules": 16,
        "families_per_module": 16,
        "monomorphs_per_family": 28,
    },
    "xlarge": {
        "modules": 20,
        "families_per_module": 18,
        "monomorphs_per_family": 34,
    },
}


@dataclass(frozen=True)
class RustGenericStressConfig:
    preset: str
    modules: int
    families_per_module: int
    monomorphs_per_family: int


def build_config(args: argparse.Namespace) -> RustGenericStressConfig:
    preset = PRESET_CONFIGS[args.preset]
    modules = args.modules or preset["modules"]
    families_per_module = args.families_per_module or preset["families_per_module"]
    monomorphs_per_family = (
        args.monomorphs_per_family or preset["monomorphs_per_family"]
    )

    for field_name, value in [
        ("modules", modules),
        ("families_per_module", families_per_module),
        ("monomorphs_per_family", monomorphs_per_family),
    ]:
        if value <= 0:
            raise SystemExit(f"{field_name} must be > 0")

    return RustGenericStressConfig(
        preset=args.preset,
        modules=modules,
        families_per_module=families_per_module,
        monomorphs_per_family=monomorphs_per_family,
    )


def module_ident(module_idx: int) -> str:
    return f"module_{module_idx:03d}"


def family_ident(module_idx: int, family_idx: int) -> str:
    return f"Module{module_idx:03d}Family{family_idx:03d}"


def variant_ident(module_idx: int, variant_idx: int) -> str:
    return f"Module{module_idx:03d}Variant{variant_idx:03d}"


def family_runner_ident(module_idx: int, family_idx: int) -> str:
    return f"run_family_{module_idx:03d}_{family_idx:03d}"


def render_shared_module() -> str:
    return "\n".join(
        [
            "#![allow(dead_code)]",
            "",
            "use std::marker::PhantomData;",
            "",
            "pub trait FamilyTag {",
            "    const KEY: u64;",
            "    const SHIFT: u32;",
            "}",
            "",
            "pub trait VariantTag {",
            "    const FACTOR: u64;",
            "    const ROTATE: u32;",
            "}",
            "",
            "pub struct Pair<A, B>(PhantomData<(A, B)>);",
            "",
            "pub struct Envelope<Family, Variant, const DEPTH: usize> {",
            "    marker: PhantomData<(Family, Variant)>,",
            "}",
            "",
            "impl<Family: FamilyTag, Variant: VariantTag, const DEPTH: usize>",
            "    Envelope<Family, Variant, DEPTH>",
            "{",
            "    #[inline(never)]",
            "    pub fn fold(seed: u64) -> u64 {",
            "        let layout = std::mem::size_of::<Pair<Family, Variant>>() as u64;",
            "        seed.rotate_left(Family::SHIFT % 31)",
            "            ^ Variant::FACTOR.wrapping_mul((DEPTH as u64) + 17)",
            "            ^ layout.wrapping_mul(13)",
            "    }",
            "",
            "    #[inline(never)]",
            "    pub fn twist(seed: u64) -> u64 {",
            "        let layout = std::mem::align_of::<Pair<Family, Variant>>() as u64;",
            "        seed.wrapping_add(Family::KEY ^ Variant::FACTOR)",
            "            .rotate_left(Variant::ROTATE % 31)",
            "            ^ layout.wrapping_mul((DEPTH as u64) + 29)",
            "    }",
            "}",
            "",
            "#[inline(never)]",
            "pub fn dispatch<Family: FamilyTag, Variant: VariantTag, const DEPTH: usize>(seed: u64) -> u64 {",
            "    Envelope::<Family, Variant, DEPTH>::fold(seed)",
            "        ^ Envelope::<Family, Variant, DEPTH>::twist(seed ^ Variant::FACTOR)",
            "}",
            "",
            "#[inline(never)]",
            "pub fn relay<Family: FamilyTag, Variant: VariantTag, const DEPTH: usize>(seed: u64) -> u64 {",
            "    dispatch::<Family, Variant, DEPTH>(seed.rotate_left((DEPTH as u32) % 31))",
            "        ^ Envelope::<Family, Variant, DEPTH>::fold(Family::KEY ^ seed)",
            "}",
            "",
        ]
    )


def render_module(config: RustGenericStressConfig, module_idx: int) -> str:
    lines = [
        "#![allow(dead_code)]",
        "",
        "use crate::shared::{dispatch, relay, FamilyTag, VariantTag};",
        "",
    ]

    for family_idx in range(config.families_per_module):
        family_name = family_ident(module_idx, family_idx)
        key = ((module_idx + 1) * 0x9E37_79B9_7F4A_7C15) ^ ((family_idx + 3) * 0xBF58_476D_1CE4_E5B9)
        shift = ((module_idx + family_idx) % 23) + 5
        lines.extend(
            [
                f"pub struct {family_name};",
                "",
                f"impl FamilyTag for {family_name} {{",
                f"    const KEY: u64 = 0x{key & 0xffff_ffff_ffff_ffff:016x};",
                f"    const SHIFT: u32 = {shift};",
                "}",
                "",
            ]
        )

    for variant_idx in range(config.monomorphs_per_family):
        variant_name = variant_ident(module_idx, variant_idx)
        factor = ((module_idx + 5) * 0x94D0_49BB_1331_11EB) ^ ((variant_idx + 7) * 0xD6E8_FD50_6A1F_1C4D)
        rotate = ((module_idx * 3 + variant_idx) % 27) + 3
        lines.extend(
            [
                f"pub struct {variant_name};",
                "",
                f"impl VariantTag for {variant_name} {{",
                f"    const FACTOR: u64 = 0x{factor & 0xffff_ffff_ffff_ffff:016x};",
                f"    const ROTATE: u32 = {rotate};",
                "}",
                "",
            ]
        )

    family_runners: list[str] = []
    for family_idx in range(config.families_per_module):
        runner = family_runner_ident(module_idx, family_idx)
        family_runners.append(runner)
        family_name = family_ident(module_idx, family_idx)
        lines.extend(
            [
                "#[inline(never)]",
                f"pub fn {runner}(seed: u64) -> u64 {{",
                f"    let mut total = seed ^ {family_idx + 1}u64;",
            ]
        )
        for variant_idx in range(config.monomorphs_per_family):
            variant_name = variant_ident(module_idx, variant_idx)
            depth = ((family_idx + variant_idx) % 17) + 3
            salt = ((family_idx + 1) * 0x517c_c1b7) ^ ((variant_idx + 11) * 0x2722_0a95)
            lines.extend(
                [
                    (
                        f"    total ^= dispatch::<{family_name}, {variant_name}, {depth}>"
                        f"(seed.wrapping_add(0x{salt & 0xffff_ffff:08x}u64));"
                    ),
                    (
                        f"    total ^= relay::<{family_name}, {variant_name}, {depth}>"
                        f"(seed ^ 0x{(salt ^ 0x9e37_79b9) & 0xffff_ffff:08x}u64);"
                    ),
                ]
            )
        lines.extend(
            [
                "    total",
                "}",
                "",
            ]
        )

    runner_table = ", ".join(family_runners)
    lines.extend(
        [
            (
                f"static MODULE_RUNNERS: [fn(u64) -> u64; {config.families_per_module}] = "
                f"[{runner_table}];"
            ),
            "",
            "#[inline(never)]",
            "pub fn run_module(seed: u64) -> u64 {",
            f"    let mut total = seed ^ 0x{(((module_idx + 1) * 0x9E37_79B1) & 0xffff_ffff):08x}u64;",
            "    for (idx, runner) in MODULE_RUNNERS.iter().enumerate() {",
            "        let module_seed = seed ^ (((idx as u64) + 1).wrapping_mul(0x94d0_49bb_1331_11ebu64));",
            "        total ^= runner(module_seed);",
            "    }",
            "    total",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def render_main(config: RustGenericStressConfig) -> str:
    module_lines = [f"mod {module_ident(module_idx)};" for module_idx in range(config.modules)]
    runner_table = ", ".join(
        f"{module_ident(module_idx)}::run_module" for module_idx in range(config.modules)
    )
    return "\n".join(
        [
            "#![allow(dead_code)]",
            "",
            "mod shared;",
            *module_lines,
            "",
            f"static MODULE_RUNNERS: [fn(u64) -> u64; {config.modules}] = [{runner_table}];",
            "",
            "fn main() {",
            "    let mut total = 0u64;",
            "    for (idx, runner) in MODULE_RUNNERS.iter().enumerate() {",
            "        let seed = 0x9e37_79b9_7f4a_7c15u64",
            "            ^ (((idx as u64) + 1).wrapping_mul(0xbf58_476d_1ce4_e5b9u64));",
            "        total ^= runner(seed);",
            "    }",
            '    println!("rust-generic-stress:{}", total);',
            "}",
            "",
        ]
    )


def write_outputs(output_dir: Path, config: RustGenericStressConfig) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "shared.rs").write_text(render_shared_module(), encoding="utf-8")
    (output_dir / "main.rs").write_text(render_main(config), encoding="utf-8")

    for module_idx in range(config.modules):
        (output_dir / f"{module_ident(module_idx)}.rs").write_text(
            render_module(config, module_idx),
            encoding="utf-8",
        )

    estimated_symbols = (
        config.modules
        * config.families_per_module
        * config.monomorphs_per_family
        * 4
    )
    generation_config = {
        "preset": config.preset,
        "modules": config.modules,
        "families_per_module": config.families_per_module,
        "monomorphs_per_family": config.monomorphs_per_family,
        "estimated_mangled_symbols": estimated_symbols,
        "generated_module_files": config.modules,
        "generated_rust_files": config.modules + 2,
    }
    (output_dir / "generation_config.json").write_text(
        json.dumps(generation_config, indent=2) + "\n",
        encoding="utf-8",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic Rust generic-heavy DWARF corpus."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write generated Rust files")
    parser.add_argument(
        "--preset",
        choices=sorted(PRESET_CONFIGS.keys()),
        default="large",
        help="Named scale preset",
    )
    parser.add_argument("--modules", type=int, help="Override module count")
    parser.add_argument(
        "--families-per-module",
        type=int,
        help="Override generic family count per module",
    )
    parser.add_argument(
        "--monomorphs-per-family",
        type=int,
        help="Override monomorphized variants per family",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = build_config(args)
    write_outputs(Path(args.output_dir), config)


if __name__ == "__main__":
    main()

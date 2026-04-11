#!/usr/bin/env python3
"""Generate a deterministic Rust corpus for large DWARF parse baselines."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


PRESET_CONFIGS = {
    "medium": {
        "modules": 24,
        "types_per_module": 16,
        "functions_per_module": 48,
    },
    "large": {
        "modules": 64,
        "types_per_module": 24,
        "functions_per_module": 96,
    },
    "xlarge": {
        "modules": 96,
        "types_per_module": 32,
        "functions_per_module": 160,
    },
}


@dataclass(frozen=True)
class RustParseStressConfig:
    preset: str
    modules: int
    types_per_module: int
    functions_per_module: int


def module_ident(module_idx: int) -> str:
    return f"module_{module_idx:03d}"


def record_ident(module_idx: int, type_idx: int) -> str:
    return f"Module{module_idx:03d}Record{type_idx:03d}"


def opcode_ident(module_idx: int, type_idx: int) -> str:
    return f"Module{module_idx:03d}Opcode{type_idx:03d}"


def apply_ident(module_idx: int, type_idx: int) -> str:
    return f"apply_{module_idx:03d}_{type_idx:03d}"


def worker_ident(module_idx: int, fn_idx: int) -> str:
    return f"worker_{module_idx:03d}_{fn_idx:03d}"


def build_config(args: argparse.Namespace) -> RustParseStressConfig:
    preset = PRESET_CONFIGS[args.preset]
    modules = args.modules or preset["modules"]
    types_per_module = args.types_per_module or preset["types_per_module"]
    functions_per_module = args.functions_per_module or preset["functions_per_module"]

    for field_name, value in [
        ("modules", modules),
        ("types_per_module", types_per_module),
        ("functions_per_module", functions_per_module),
    ]:
        if value <= 0:
            raise SystemExit(f"{field_name} must be > 0")

    return RustParseStressConfig(
        preset=args.preset,
        modules=modules,
        types_per_module=types_per_module,
        functions_per_module=functions_per_module,
    )


def render_shared_module() -> str:
    return "\n".join(
        [
            "#![allow(dead_code)]",
            "",
            "use std::collections::{BTreeMap, BinaryHeap, HashMap, VecDeque};",
            "use std::path::PathBuf;",
            "use std::sync::{Arc, OnceLock};",
            "use std::time::Duration;",
            "",
            "#[derive(Clone, Debug)]",
            "pub struct ModuleReport {",
            "    label: &'static str,",
            "    worker_count: usize,",
            "    checksum: u64,",
            "}",
            "",
            "impl ModuleReport {",
            "    #[inline(never)]",
            "    pub fn new(label: &'static str, worker_count: usize, checksum: u64) -> Self {",
            "        Self {",
            "            label,",
            "            worker_count,",
            "            checksum,",
            "        }",
            "    }",
            "",
            "    #[inline(never)]",
            "    pub fn finish(self) -> u64 {",
            "        self.checksum",
            "            ^ (self.label.len() as u64).wrapping_mul(0x9E37_79B1_85EB_CA87)",
            "            ^ (self.worker_count as u64).rotate_left(9)",
            "    }",
            "}",
            "",
            "#[inline(never)]",
            "pub fn shared_mix<T, U>(seed: u64, salt: u64) -> u64 {",
            "    static CACHE: OnceLock<Arc<[u64; 4]>> = OnceLock::new();",
            "",
            "    let cached = CACHE.get_or_init(|| Arc::new([3, 5, 11, 17]));",
            "    let left = std::any::type_name::<T>().len() as u64;",
            "    let right = std::any::type_name::<U>().len() as u64;",
            "",
            "    let mut tree = BTreeMap::new();",
            "    tree.insert(seed ^ left, salt.wrapping_add(right).wrapping_add(cached[0]));",
            "",
            "    let mut hash = HashMap::new();",
            "    hash.insert((left as usize) ^ 17usize, seed.rotate_left((salt % 31) as u32));",
            "",
            "    let mut queue = VecDeque::from([seed, salt, left, right]);",
            "    let mut heap = BinaryHeap::from([seed ^ left, salt ^ right, cached[3]]);",
            "",
            "    let mut path = PathBuf::from(\"rust-parse-stress\");",
            "    path.push(std::any::type_name::<T>().rsplit(\"::\").next().unwrap_or(\"t\"));",
            "",
            "    let duration = Duration::from_micros((seed & 0xffff).wrapping_add(right));",
            "    let mut acc = path.to_string_lossy().len() as u64;",
            "    acc ^= duration.as_micros() as u64;",
            "    acc ^= cached[1].wrapping_add(cached[2]);",
            "",
            "    while let Some(value) = queue.pop_front() {",
            "        acc = acc.rotate_left(7) ^ value.wrapping_mul(33);",
            "    }",
            "",
            "    while let Some(value) = heap.pop() {",
            "        acc ^= value.rotate_left(11);",
            "    }",
            "",
            "    for (key, value) in tree {",
            "        acc ^= key.wrapping_add(value);",
            "    }",
            "",
            "    for (key, value) in hash {",
            "        acc ^= (key as u64).wrapping_mul(value | 1);",
            "    }",
            "",
            "    acc",
            "}",
            "",
        ]
    )


def render_record_block(module_idx: int, type_idx: int) -> list[str]:
    record = record_ident(module_idx, type_idx)
    opcode = opcode_ident(module_idx, type_idx)
    apply_fn = apply_ident(module_idx, type_idx)

    lane_a = (module_idx + 1) * 17 + (type_idx * 3) + 1
    lane_b = ((type_idx + 5) % 31) + 1
    lane_c = (module_idx + 1) * 29 + (type_idx * 5) + 7
    lane_d = (module_idx + 3) * 11 + (type_idx * 7) + 9
    bias = (module_idx + 1) * (type_idx + 3)
    marker = (module_idx * 1024) + type_idx
    rotate_seed = ((type_idx + 9) % 29) + 1
    clamp_floor = (module_idx + 1) * 13 + type_idx
    clamp_ceiling = (module_idx + 1) * 17 + (type_idx * 2) + 9

    return [
        "#[derive(Clone, Copy, Debug)]",
        f"pub struct {record} {{",
        "    lanes: [u64; 4],",
        "    bias: i64,",
        "    marker: u32,",
        "}",
        "",
        f"impl {record} {{",
        "    #[inline(never)]",
        "    pub fn new(seed: u64) -> Self {",
        "        Self {",
        f"            lanes: [seed.wrapping_add({lane_a}u64), seed.rotate_left({lane_b}), seed ^ 0x{lane_c:016x}u64, seed.wrapping_mul({lane_d}u64)],",
        f"            bias: {bias}i64,",
        f"            marker: {marker}u32,",
        "        }",
        "    }",
        "",
        "    #[inline(never)]",
        "    pub fn fold(&self, salt: u64) -> u64 {",
        "        let mut acc = salt ^ (self.marker as u64);",
        "        for lane in self.lanes {",
        "            acc = acc.rotate_left(7) ^ lane.wrapping_mul(3);",
        "        }",
        "        acc ^ self.bias.unsigned_abs()",
        "    }",
        "}",
        "",
        "#[derive(Clone, Copy, Debug)]",
        f"pub enum {opcode} {{",
        "    Rotate(u32),",
        "    Mix(u64),",
        "    Clamp { floor: i64, ceiling: i64 },",
        "}",
        "",
        f"impl {opcode} {{",
        "    #[inline(never)]",
        "    pub fn from_seed(seed: u64) -> Self {",
        "        match seed % 3 {",
        f"            0 => Self::Rotate(((seed % 23) as u32) + {rotate_seed}),",
        "            1 => Self::Mix(seed.rotate_left(13)),",
        f"            _ => Self::Clamp {{ floor: {clamp_floor}i64, ceiling: {clamp_ceiling}i64 }},",
        "        }",
        "    }",
        "}",
        "",
        "#[inline(never)]",
        f"pub fn {apply_fn}(record: &{record}, opcode: {opcode}) -> u64 {{",
        "    match opcode {",
        f"        {opcode}::Rotate(bits) => record.fold(bits as u64).rotate_left(bits % 31),",
        f"        {opcode}::Mix(value) => record.fold(value) ^ value.rotate_left(5),",
        f"        {opcode}::Clamp {{ floor, ceiling }} => record",
        "            .fold(record.marker as u64)",
        "            .wrapping_add(floor.unsigned_abs())",
        "            .wrapping_sub(ceiling.unsigned_abs()),",
        "    }",
        "}",
        "",
    ]


def render_module(config: RustParseStressConfig, module_idx: int) -> str:
    lines = [
        "#![allow(dead_code)]",
        "",
        "use crate::shared::{shared_mix, ModuleReport};",
        "",
    ]

    for type_idx in range(config.types_per_module):
        lines.extend(render_record_block(module_idx, type_idx))

    worker_names: list[str] = []
    for fn_idx in range(config.functions_per_module):
        worker = worker_ident(module_idx, fn_idx)
        worker_names.append(worker)
        type_idx = fn_idx % config.types_per_module
        alt_idx = (fn_idx * 7 + 3) % config.types_per_module
        record = record_ident(module_idx, type_idx)
        opcode = opcode_ident(module_idx, type_idx)
        alt_opcode = opcode_ident(module_idx, alt_idx)
        apply_fn = apply_ident(module_idx, type_idx)
        worker_seed = (module_idx + 1) * 97 + (fn_idx * 13) + 5
        mix_salt = (module_idx + 1) * 131 + fn_idx
        fold_seed = (fn_idx + 3) * 19

        lines.extend(
            [
                "#[inline(never)]",
                f"pub fn {worker}(seed: u64) -> u64 {{",
                f"    let record = {record}::new(seed.wrapping_add({worker_seed}u64));",
                f"    let opcode = {opcode}::from_seed(seed.wrapping_add({fn_idx}u64));",
                f"    let folded = record.fold(seed.wrapping_mul({fold_seed}u64));",
                f"    let applied = {apply_fn}(&record, opcode);",
                f"    folded ^ applied ^ shared_mix::<{record}, {alt_opcode}>(seed, {mix_salt}u64)",
                "}",
                "",
            ]
        )

    worker_table = ", ".join(worker_names)
    module_name = module_ident(module_idx)
    module_seed = f"0x{((module_idx + 1) * 0x9E37_79B1) & 0xffff_ffff:08x}u64"
    lines.extend(
        [
            f"pub static {module_name.upper()}_WORKERS: [fn(u64) -> u64; {config.functions_per_module}] = [{worker_table}];",
            "",
            "#[inline(never)]",
            "pub fn run_module(seed: u64) -> u64 {",
            f"    let mut acc = seed ^ {module_seed};",
            f"    for (idx, worker) in {module_name.upper()}_WORKERS.iter().enumerate() {{",
            "        let worker_seed = seed.wrapping_add(((idx as u64) + 1).wrapping_mul(0x517c_c1b7_2722_0a95));",
            "        acc ^= worker(worker_seed);",
            "    }",
            f"    ModuleReport::new(\"{module_name}\", {module_name.upper()}_WORKERS.len(), acc).finish()",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def render_main(config: RustParseStressConfig) -> str:
    module_lines = [f"mod {module_ident(module_idx)};" for module_idx in range(config.modules)]
    runner_table = ", ".join(
        f"{module_ident(module_idx)}::run_module" for module_idx in range(config.modules)
    )

    lines = [
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
        "            ^ (((idx as u64) + 1).wrapping_mul(0x94d0_49bb_1331_11ebu64));",
        "        total ^= runner(seed);",
        "    }",
        "    println!(\"rust-parse-stress:{}\", total);",
        "}",
        "",
    ]
    return "\n".join(lines)


def write_outputs(output_dir: Path, config: RustParseStressConfig) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "shared.rs").write_text(render_shared_module())
    (output_dir / "main.rs").write_text(render_main(config))

    for module_idx in range(config.modules):
        module_path = output_dir / f"{module_ident(module_idx)}.rs"
        module_path.write_text(render_module(config, module_idx))

    config_payload = {
        "preset": config.preset,
        "modules": config.modules,
        "types_per_module": config.types_per_module,
        "functions_per_module": config.functions_per_module,
        "generated_module_files": config.modules,
        "generated_rust_files": config.modules + 2,
    }
    (output_dir / "generation_config.json").write_text(
        json.dumps(config_payload, indent=2) + "\n"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic Rust corpus for DWARF parse baselines."
    )
    parser.add_argument("--output-dir", required=True, help="Directory to write generated Rust files")
    parser.add_argument(
        "--preset",
        choices=sorted(PRESET_CONFIGS.keys()),
        default="large",
        help="Named scale preset",
    )
    parser.add_argument("--modules", type=int, help="Override module count")
    parser.add_argument("--types-per-module", type=int, help="Override type count per module")
    parser.add_argument(
        "--functions-per-module",
        type=int,
        help="Override function count per module",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config = build_config(args)
    write_outputs(Path(args.output_dir), config)


if __name__ == "__main__":
    main()

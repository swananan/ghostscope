#!/usr/bin/env python3
"""Generate a deterministic multi-TU C corpus for DWARF parse baselines."""

from __future__ import annotations

import argparse
from pathlib import Path


def render_shared_header(units: int, history_len: int) -> str:
    lines = [
        "#ifndef DWARF_PERF_PARSE_STRESS_SHARED_H",
        "#define DWARF_PERF_PARSE_STRESS_SHARED_H",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "typedef struct parse_perf_coord {",
        "    int32_t x;",
        "    int32_t y;",
        "    int32_t z;",
        "} parse_perf_coord_t;",
        "",
        "typedef union parse_perf_sample {",
        "    parse_perf_coord_t coord;",
        "    uint64_t words[2];",
        "} parse_perf_sample_t;",
        "",
        "typedef struct parse_perf_payload {",
        "    parse_perf_sample_t sample;",
        "    uint64_t revision;",
        f"    int32_t history[{history_len}];",
        "    char label[32];",
        "} parse_perf_payload_t;",
        "",
        "typedef struct parse_perf_metrics {",
        "    uint64_t ticks;",
        "    int32_t counters[16];",
        "    double ratios[4];",
        "} parse_perf_metrics_t;",
        "",
    ]

    for unit_idx in range(units):
        lines.append(f"int parse_unit_{unit_idx:02d}_dispatch(int seed);")

    lines.extend(
        [
            "",
            "int parse_stress_entry_point(int seed);",
            "",
            "#endif",
            "",
        ]
    )
    return "\n".join(lines)


def render_main_source(units: int) -> str:
    lines = [
        '#include "parse_stress_shared.h"',
        "",
        "#include <stdio.h>",
        "",
        "int parse_stress_entry_point(int seed) {",
        "    int total = seed;",
    ]

    for unit_idx in range(units):
        lines.append(f"    total += parse_unit_{unit_idx:02d}_dispatch(seed + {unit_idx});")

    lines.extend(
        [
            "    return total;",
            "}",
            "",
            "int main(void) {",
            "    int total = parse_stress_entry_point(11);",
            '    printf("%d\\n", total);',
            "    return total == 0 ? 1 : 0;",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def render_unit_source(
    unit_idx: int,
    types_per_unit: int,
    functions_per_unit: int,
    history_len: int,
) -> str:
    unit = f"{unit_idx:02d}"
    lines = [
        '#include "parse_stress_shared.h"',
        "",
        "#include <stddef.h>",
        "",
    ]

    for type_idx in range(types_per_unit):
        lines.extend(
            [
                f"typedef enum parse_unit_{unit}_state_{type_idx:02d} {{",
                f"    PARSE_UNIT_{unit}_STATE_{type_idx:02d}_IDLE = {type_idx},",
                f"    PARSE_UNIT_{unit}_STATE_{type_idx:02d}_HOT = {type_idx + 1},",
                f"    PARSE_UNIT_{unit}_STATE_{type_idx:02d}_COLD = {type_idx + 2},",
                f"}} parse_unit_{unit}_state_{type_idx:02d}_t;",
                "",
                f"typedef struct parse_unit_{unit}_node_{type_idx:02d} {{",
                "    parse_perf_payload_t payload;",
                f"    parse_unit_{unit}_state_{type_idx:02d}_t state;",
                f"    int32_t samples[{history_len}];",
                "    uint16_t windows[4];",
                "    char tag[24];",
                f"}} parse_unit_{unit}_node_{type_idx:02d}_t;",
                "",
                f"typedef union parse_unit_{unit}_view_{type_idx:02d} {{",
                f"    parse_unit_{unit}_node_{type_idx:02d}_t node;",
                f"    uint8_t raw[sizeof(parse_unit_{unit}_node_{type_idx:02d}_t)];",
                f"}} parse_unit_{unit}_view_{type_idx:02d}_t;",
                "",
            ]
        )

    for func_idx in range(functions_per_unit):
        type_idx = func_idx % types_per_unit
        next_type_idx = (func_idx + 1) % types_per_unit
        lines.extend(
            [
                f"static int parse_unit_{unit}_helper_{func_idx:02d}(int seed, uint64_t bias) {{",
                f"    parse_unit_{unit}_node_{type_idx:02d}_t primary = {{",
                "        .payload = {",
                f"            .sample = {{.coord = {{.x = {unit_idx + func_idx + 1}, .y = {unit_idx + func_idx + 3}, .z = {unit_idx + func_idx + 5}}}}},",
                f"            .revision = {1000 + (unit_idx * 100) + func_idx}u,",
                f"            .history = {{{', '.join(str((unit_idx + 1) * (hist_idx + 2) + func_idx) for hist_idx in range(history_len))}}},",
                f'            .label = "unit-{unit}-primary-{func_idx:02d}",',
                "        },",
                f"        .state = PARSE_UNIT_{unit}_STATE_{type_idx:02d}_HOT,",
                f"        .samples = {{{', '.join(str((type_idx + 1) * (sample_idx + 3) + func_idx) for sample_idx in range(history_len))}}},",
                f"        .windows = {{{', '.join(str((func_idx + window_idx + 1) * (unit_idx + 2)) for window_idx in range(4))}}},",
                f'        .tag = "tag-{unit}-{type_idx:02d}-a",',
                "    };",
                f"    parse_unit_{unit}_view_{next_type_idx:02d}_t secondary = {{",
                "        .node = {",
                "            .payload = {",
                f"                .sample = {{.coord = {{.x = {unit_idx + func_idx + 7}, .y = {unit_idx + func_idx + 9}, .z = {unit_idx + func_idx + 11}}}}},",
                f"                .revision = {2000 + (unit_idx * 100) + func_idx}u,",
                f"                .history = {{{', '.join(str((unit_idx + 2) * (hist_idx + 1) + func_idx) for hist_idx in range(history_len))}}},",
                f'                .label = "unit-{unit}-secondary-{func_idx:02d}",',
                "            },",
                f"            .state = PARSE_UNIT_{unit}_STATE_{next_type_idx:02d}_COLD,",
                f"            .samples = {{{', '.join(str((next_type_idx + 3) * (sample_idx + 2) + func_idx) for sample_idx in range(history_len))}}},",
                f"            .windows = {{{', '.join(str((func_idx + window_idx + 3) * (unit_idx + 1)) for window_idx in range(4))}}},",
                f'            .tag = "tag-{unit}-{next_type_idx:02d}-b",',
                "        },",
                "    };",
                "    parse_perf_metrics_t metrics = {",
                f"        .ticks = {5000 + (unit_idx * 100) + func_idx}u,",
                f"        .counters = {{{', '.join(str((func_idx + 1) * (counter_idx + 1) + unit_idx) for counter_idx in range(16))}}},",
                f"        .ratios = {{{', '.join(f'{(func_idx + ratio_idx + 1) / 3.0:.6f}' for ratio_idx in range(4))}}},",
                "    };",
                "    int total = seed + (int) bias;",
                f"    for (size_t idx = 0; idx < {history_len}; ++idx) {{",
                "        total += primary.samples[idx] - secondary.node.samples[idx];",
                "        total += primary.payload.history[idx] + secondary.node.payload.history[idx];",
                "    }",
                "    total += primary.payload.sample.coord.x + secondary.node.payload.sample.coord.z;",
                "    total += (int) primary.payload.revision + (int) secondary.node.payload.revision;",
                "    total += metrics.counters[(seed + (int) bias) & 0xf];",
                "    total += (int) metrics.ratios[((seed >> 1) + (int) bias) & 0x3];",
                "    return total;",
                "}",
                "",
            ]
        )

    lines.extend(
        [
            f"int parse_unit_{unit}_dispatch(int seed) {{",
            f"    int total = seed + {unit_idx};",
        ]
    )

    for func_idx in range(functions_per_unit):
        lines.append(
            f"    total += parse_unit_{unit}_helper_{func_idx:02d}(seed + {func_idx}, {func_idx + 1}u);"
        )

    lines.extend(
        [
            "    return total;",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--units", type=int, default=16)
    parser.add_argument("--types-per-unit", type=int, default=10)
    parser.add_argument("--functions-per-unit", type=int, default=24)
    parser.add_argument("--history-len", type=int, default=8)
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.units < 1 or args.types_per_unit < 1 or args.functions_per_unit < 1:
        raise SystemExit("all numeric generator parameters must be positive")

    (output_dir / "parse_stress_shared.h").write_text(
        render_shared_header(args.units, args.history_len),
        encoding="utf-8",
    )
    (output_dir / "main.c").write_text(
        render_main_source(args.units),
        encoding="utf-8",
    )

    for unit_idx in range(args.units):
        unit_path = output_dir / f"unit_{unit_idx:02d}.c"
        unit_path.write_text(
            render_unit_source(
                unit_idx,
                args.types_per_unit,
                args.functions_per_unit,
                args.history_len,
            ),
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()

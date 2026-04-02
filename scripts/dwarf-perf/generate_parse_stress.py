#!/usr/bin/env python3
"""Generate a deterministic multi-TU C corpus for DWARF parse baselines."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path


PRESET_CONFIGS = {
    "medium": {
        "units": 16,
        "types_per_unit": 12,
        "functions_per_unit": 32,
        "history_len": 8,
    },
    "large": {
        "units": 48,
        "types_per_unit": 24,
        "functions_per_unit": 72,
        "history_len": 16,
    },
    "xlarge": {
        "units": 96,
        "types_per_unit": 40,
        "functions_per_unit": 128,
        "history_len": 24,
    },
}


@dataclass(frozen=True)
class ParseStressConfig:
    preset: str
    units: int
    types_per_unit: int
    functions_per_unit: int
    history_len: int

    route_count: int = 4
    leaf_count: int = 3
    payload_bank_count: int = 4
    metric_bank_count: int = 2
    tensor_count: int = 2
    descriptor_weight_count: int = 4
    leaf_window_count: int = 6


def c_array(values: list[str]) -> str:
    return ", ".join(values)


def c_ints(values: list[int]) -> str:
    return ", ".join(str(value) for value in values)


def c_floats(values: list[float]) -> str:
    return ", ".join(f"{value:.6f}" for value in values)


def render_coord_init(base: int, salt: int) -> str:
    return (
        "{"
        f".x = {base + salt + 1}, "
        f".y = {base + (salt * 2) + 3}, "
        f".z = {base + (salt * 3) + 5}, "
        f".w = {base + (salt * 4) + 7}"
        "}"
    )


def render_extent_init(base: int, salt: int) -> str:
    return (
        "{"
        f".rows = {((base + salt) % 11) + 2}, "
        f".cols = {((base + (salt * 2)) % 13) + 3}, "
        f".depth = {((base + (salt * 3)) % 7) + 2}, "
        f".lanes = {((base + salt) % 5) + 1}"
        "}"
    )


def render_window_init(unit_idx: int, slot: int, salt: int) -> str:
    base = (unit_idx + 1) * 17 + (slot * 9)
    return (
        "{"
        f".start = {base + salt}, "
        f".stop = {base + salt + 19}, "
        f".stride = {((slot + salt) % 5) + 1}, "
        f".extent = {render_extent_init(base, salt)}"
        "}"
    )


def render_descriptor_init(unit_idx: int, type_idx: int, salt: int) -> str:
    return (
        "{"
        f".unit_id = {unit_idx}, "
        f".type_id = {type_idx}, "
        f".shard = {(unit_idx + salt) % 64}, "
        f".lane = {(type_idx + salt) % 64}, "
        f".state = {(unit_idx + type_idx + salt) % 32}, "
        f".flags = {(unit_idx + (type_idx * 3) + salt) % 32}"
        "}"
    )


def render_sample_init(unit_idx: int, slot: int, salt: int) -> str:
    base = (unit_idx + 3) * 11 + (slot * 5)
    return "{.coord = " + render_coord_init(base, salt) + "}"


def render_matrix_init(unit_idx: int, slot: int) -> str:
    rows = []
    for row_idx in range(3):
        row_values = [
            str((unit_idx + 1) * (slot + 2) * (row_idx + 1) + col_idx + row_idx)
            for col_idx in range(4)
        ]
        rows.append("{" + c_array(row_values) + "}")
    return "{" + c_array(rows) + "}"


def render_tensor_init(unit_idx: int, slot: int) -> str:
    windows = [render_window_init(unit_idx, slot, salt) for salt in range(4)]
    samples = [render_sample_init(unit_idx, slot, salt) for salt in range(3)]
    return (
        "{"
        f".windows = {{{c_array(windows)}}}, "
        f".samples = {{{c_array(samples)}}}, "
        f".matrix = {render_matrix_init(unit_idx, slot)}"
        "}"
    )


def render_payload_init(
    unit_idx: int,
    slot: int,
    history_len: int,
    label_prefix: str,
) -> str:
    history = [
        (unit_idx + 1) * (hist_idx + 2) + (slot * 3) + hist_idx
        for hist_idx in range(history_len)
    ]
    return (
        "{"
        f".tensor = {render_tensor_init(unit_idx, slot)}, "
        f".descriptor = {render_descriptor_init(unit_idx, slot % 256, slot + 5)}, "
        f".revision = {7000 + (unit_idx * 97) + (slot * 13)}u, "
        f".history = {{{c_ints(history)}}}, "
        f'.label = "{label_prefix}-{unit_idx:02d}-{slot:02d}"'
        "}"
    )


def render_metrics_init(unit_idx: int, slot: int) -> str:
    counters = [
        (unit_idx + 2) * (slot + counter_idx + 1) + counter_idx
        for counter_idx in range(24)
    ]
    ratios = [
        ((unit_idx + 1) * (slot + ratio_idx + 2)) / 7.0 for ratio_idx in range(6)
    ]
    return (
        "{"
        f".ticks = {13000 + (unit_idx * 101) + (slot * 29)}u, "
        f".counters = {{{c_ints(counters)}}}, "
        f".ratios = {{{c_floats(ratios)}}}"
        "}"
    )


def render_route_init(unit_idx: int, slot: int) -> str:
    base = (unit_idx + 1) * 19 + (slot * 7)
    weights = [((base + idx * 3) % 37) + 1 for idx in range(6)]
    return (
        "{"
        f".origin = {render_coord_init(base, slot + 1)}, "
        f".target = {render_coord_init(base + 9, slot + 3)}, "
        f".weights = {{{c_ints(weights)}}}, "
        f'.name = "route-{unit_idx:02d}-{slot:02d}"'
        "}"
    )


def render_leaf_init(unit_idx: int, slot: int, config: ParseStressConfig) -> str:
    payloads = [
        render_payload_init(unit_idx, slot * 2 + payload_idx, config.history_len, "leaf")
        for payload_idx in range(2)
    ]
    routes = [
        render_route_init(unit_idx, slot + route_idx) for route_idx in range(config.route_count)
    ]
    samples = [
        (unit_idx + slot + 1) * (sample_idx + 3) for sample_idx in range(config.history_len)
    ]
    windows = [((unit_idx + slot + idx) % 41) + 3 for idx in range(config.leaf_window_count)]
    return (
        "{"
        f".payloads = {{{c_array(payloads)}}}, "
        f".routes = {{{c_array(routes)}}}, "
        f".metrics = {render_metrics_init(unit_idx, slot)}, "
        f".samples = {{{c_ints(samples)}}}, "
        f".windows = {{{c_ints(windows)}}}"
        "}"
    )


def render_export_init(unit_idx: int, slot: int) -> str:
    counters = [(unit_idx + 1) * (slot + idx + 2) + idx for idx in range(4)]
    windows = [render_window_init(unit_idx, slot, salt) for salt in range(2)]
    return (
        "{"
        f".descriptor = {render_descriptor_init(unit_idx, slot, slot + 3)}, "
        f".windows = {{{c_array(windows)}}}, "
        f".stamp = {17000 + (unit_idx * 79) + (slot * 17)}u, "
        f".counters = {{{c_ints(counters)}}}"
        "}"
    )


def render_callback_init(unit_idx: int, units: int) -> str:
    prev_feed = (
        "NULL"
        if unit_idx == 0
        else f"parse_unit_{unit_idx - 1:02d}_cross_feed"
    )
    next_feed = (
        "NULL"
        if unit_idx + 1 >= units
        else f"parse_unit_{unit_idx + 1:02d}_cross_feed"
    )
    return (
        "{"
        f".self_feed = parse_unit_{unit_idx:02d}_cross_feed, "
        f".prev_feed = {prev_feed}, "
        f".next_feed = {next_feed}"
        "}"
    )


def render_public_init(unit_idx: int, config: ParseStressConfig) -> str:
    leaves = [render_leaf_init(unit_idx, slot, config) for slot in range(config.leaf_count)]
    tensors = [render_tensor_init(unit_idx, slot + 8) for slot in range(config.tensor_count)]
    prev_field = (
        f".prev_export = {render_export_init(unit_idx - 1, 0)}, "
        if unit_idx > 0
        else f".root_descriptor = {render_descriptor_init(unit_idx, 0, 11)}, "
    )
    return (
        "{"
        f"{prev_field}"
        f".export_block = {render_export_init(unit_idx, 1)}, "
        f".bank = {{.leaves = {{{c_array(leaves)}}}}}, "
        f".tensors = {{{c_array(tensors)}}}, "
        f".callbacks = {render_callback_init(unit_idx, config.units)}, "
        f'.label = "unit-{unit_idx:02d}-public"'
        "}"
    )


def render_shared_header(config: ParseStressConfig) -> str:
    lines = [
        "#ifndef DWARF_PERF_PARSE_STRESS_SHARED_H",
        "#define DWARF_PERF_PARSE_STRESS_SHARED_H",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "#define PARSE_PERF_WINDOW_COUNT 4",
        "#define PARSE_PERF_SAMPLE_COUNT 3",
        "#define PARSE_PERF_MATRIX_ROWS 3",
        "#define PARSE_PERF_MATRIX_COLS 4",
        "#define PARSE_PERF_ROUTE_COUNT 4",
        "#define PARSE_PERF_LEAF_COUNT 3",
        "#define PARSE_PERF_METRIC_COUNTERS 24",
        "#define PARSE_PERF_METRIC_RATIOS 6",
        "",
        "typedef struct parse_perf_coord {",
        "    int32_t x;",
        "    int32_t y;",
        "    int32_t z;",
        "    int32_t w;",
        "} parse_perf_coord_t;",
        "",
        "typedef struct parse_perf_extent {",
        "    uint16_t rows;",
        "    uint16_t cols;",
        "    uint16_t depth;",
        "    uint16_t lanes;",
        "} parse_perf_extent_t;",
        "",
        "typedef struct parse_perf_window {",
        "    int32_t start;",
        "    int32_t stop;",
        "    int32_t stride;",
        "    parse_perf_extent_t extent;",
        "} parse_perf_window_t;",
        "",
        "typedef struct parse_perf_descriptor {",
        "    uint16_t unit_id;",
        "    uint16_t type_id;",
        "    uint32_t shard : 8;",
        "    uint32_t lane : 8;",
        "    uint32_t state : 8;",
        "    uint32_t flags : 8;",
        "} parse_perf_descriptor_t;",
        "",
        "typedef union parse_perf_sample {",
        "    parse_perf_coord_t coord;",
        "    uint64_t words[2];",
        "    double scalars[2];",
        "} parse_perf_sample_t;",
        "",
        "typedef struct parse_perf_tensor {",
        "    parse_perf_window_t windows[PARSE_PERF_WINDOW_COUNT];",
        "    parse_perf_sample_t samples[PARSE_PERF_SAMPLE_COUNT];",
        "    int32_t matrix[PARSE_PERF_MATRIX_ROWS][PARSE_PERF_MATRIX_COLS];",
        "} parse_perf_tensor_t;",
        "",
        "typedef struct parse_perf_payload {",
        "    parse_perf_tensor_t tensor;",
        "    parse_perf_descriptor_t descriptor;",
        f"    int32_t history[{config.history_len}];",
        "    uint64_t revision;",
        "    char label[32];",
        "} parse_perf_payload_t;",
        "",
        "typedef struct parse_perf_metrics {",
        "    uint64_t ticks;",
        "    int32_t counters[PARSE_PERF_METRIC_COUNTERS];",
        "    double ratios[PARSE_PERF_METRIC_RATIOS];",
        "} parse_perf_metrics_t;",
        "",
        "typedef struct parse_perf_route {",
        "    parse_perf_coord_t origin;",
        "    parse_perf_coord_t target;",
        "    uint16_t weights[6];",
        "    char name[24];",
        "} parse_perf_route_t;",
        "",
        "typedef int (*parse_perf_feed_fn_t)(",
        "    const parse_perf_payload_t *payload,",
        "    int seed,",
        "    int bias",
        ");",
        "",
        "typedef struct parse_perf_callback_table {",
        "    parse_perf_feed_fn_t self_feed;",
        "    parse_perf_feed_fn_t prev_feed;",
        "    parse_perf_feed_fn_t next_feed;",
        "} parse_perf_callback_table_t;",
        "",
    ]

    for unit_idx in range(config.units):
        lines.append(f"int parse_unit_{unit_idx:02d}_dispatch(int seed);")
        lines.append(
            f"int parse_unit_{unit_idx:02d}_cross_feed("
            "const parse_perf_payload_t *payload, int seed, int bias);"
        )

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


def render_inline_header() -> str:
    return "\n".join(
        [
            "#ifndef DWARF_PERF_PARSE_STRESS_INLINE_H",
            "#define DWARF_PERF_PARSE_STRESS_INLINE_H",
            "",
            '#include "parse_stress_shared.h"',
            "",
            "static inline int parse_perf_fold_window(",
            "    const parse_perf_window_t *window,",
            "    int seed",
            ") {",
            "    int total = seed + window->start + window->stop + window->stride;",
            "    total += window->extent.rows + window->extent.cols;",
            "    total += window->extent.depth + window->extent.lanes;",
            "    return total;",
            "}",
            "",
            "static inline int parse_perf_fold_payload(",
            "    const parse_perf_payload_t *payload,",
            "    int bias",
            ") {",
            "    int total = bias;",
            "    for (size_t idx = 0; idx < PARSE_PERF_WINDOW_COUNT; ++idx) {",
            "        total += parse_perf_fold_window(&payload->tensor.windows[idx], bias + (int) idx);",
            "    }",
            "    for (size_t row = 0; row < PARSE_PERF_MATRIX_ROWS; ++row) {",
            "        for (size_t col = 0; col < PARSE_PERF_MATRIX_COLS; ++col) {",
            "            total += payload->tensor.matrix[row][col];",
            "        }",
            "    }",
            "    return total + (int) payload->revision + payload->descriptor.flags;",
            "}",
            "",
            "static inline int parse_perf_fold_route(",
            "    const parse_perf_route_t *route,",
            "    int salt",
            ") {",
            "    int total = salt + route->origin.x + route->target.z;",
            "    for (size_t idx = 0; idx < 6; ++idx) {",
            "        total += route->weights[idx];",
            "    }",
            "    return total + route->name[0];",
            "}",
            "",
            "#endif",
            "",
        ]
    )


def render_unit_header(unit_idx: int, config: ParseStressConfig) -> str:
    guard = f"DWARF_PERF_PARSE_STRESS_UNIT_{unit_idx:02d}_H"
    unit = f"{unit_idx:02d}"
    lines = [
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        '#include "parse_stress_shared.h"',
    ]
    if unit_idx > 0:
        lines.append(f'#include "unit_{unit_idx - 1:02d}.h"')
    lines.extend(
        [
            "",
            f"typedef enum parse_unit_{unit}_state {{",
            f"    PARSE_UNIT_{unit}_STATE_IDLE = 0,",
            f"    PARSE_UNIT_{unit}_STATE_WARM = 1,",
            f"    PARSE_UNIT_{unit}_STATE_HOT = 2,",
            f"}} parse_unit_{unit}_state_t;",
            "",
        ]
    )

    for type_idx in range(config.types_per_unit):
        type_name = f"parse_unit_{unit}_descriptor_{type_idx:02d}_t"
        slot_name = f"parse_unit_{unit}_slot_{type_idx:02d}_t"
        lines.extend(
            [
                f"typedef struct {type_name[:-2]} {{",
                "    parse_perf_descriptor_t descriptor;",
                "    parse_perf_window_t window;",
                "    uint16_t weights[4];",
                "    int32_t samples[4];",
                f"}} {type_name};",
                "",
                f"typedef union {slot_name[:-2]} {{",
                f"    {type_name} descriptor_view;",
                "    parse_perf_payload_t payload_view;",
                "    uint8_t raw[sizeof(parse_perf_payload_t)];",
                f"}} {slot_name};",
                "",
            ]
        )

    prev_field = (
        f"    parse_unit_{unit_idx - 1:02d}_export_t prev_export;"
        if unit_idx > 0
        else "    parse_perf_descriptor_t root_descriptor;"
    )
    lines.extend(
        [
            f"typedef struct parse_unit_{unit}_leaf {{",
            "    parse_perf_payload_t payloads[2];",
            "    parse_perf_route_t routes[PARSE_PERF_ROUTE_COUNT];",
            "    parse_perf_metrics_t metrics;",
            f"    int32_t samples[{config.history_len}];",
            f"    uint16_t windows[{config.leaf_window_count}];",
            f"}} parse_unit_{unit}_leaf_t;",
            "",
            f"typedef union parse_unit_{unit}_bank {{",
            f"    parse_unit_{unit}_leaf_t leaves[PARSE_PERF_LEAF_COUNT];",
            "    parse_perf_payload_t payloads[4];",
            "    uint8_t raw[sizeof(parse_perf_payload_t) * 4];",
            f"}} parse_unit_{unit}_bank_t;",
            "",
            f"typedef struct parse_unit_{unit}_export {{",
            "    parse_perf_descriptor_t descriptor;",
            "    parse_perf_window_t windows[2];",
            "    uint64_t stamp;",
            "    int32_t counters[4];",
            f"}} parse_unit_{unit}_export_t;",
            "",
            f"typedef struct parse_unit_{unit}_public {{",
            prev_field,
            f"    parse_unit_{unit}_export_t export_block;",
            f"    parse_unit_{unit}_bank_t bank;",
            "    parse_perf_tensor_t tensors[2];",
            "    parse_perf_callback_table_t callbacks;",
            "    const char *label;",
            f"}} parse_unit_{unit}_public_t;",
            "",
            f"int parse_unit_{unit}_dispatch(int seed);",
            f"int parse_unit_{unit}_cross_feed(",
            "    const parse_perf_payload_t *payload,",
            "    int seed,",
            "    int bias",
            ");",
            f"const parse_unit_{unit}_public_t *parse_unit_{unit}_public_state(void);",
            "",
            "#endif",
            "",
        ]
    )
    return "\n".join(lines)


def render_main_source(config: ParseStressConfig) -> str:
    dispatch_entries = ",\n    ".join(
        f"parse_unit_{unit_idx:02d}_dispatch" for unit_idx in range(config.units)
    )
    return "\n".join(
        [
            '#include "parse_stress_shared.h"',
            '#include "parse_stress_inline.h"',
            "",
            "#include <stdio.h>",
            "",
            "typedef int (*parse_dispatch_fn_t)(int seed);",
            "",
            "static const parse_dispatch_fn_t g_parse_dispatch_table[] = {",
            f"    {dispatch_entries}",
            "};",
            "",
            "int parse_stress_entry_point(int seed) {",
            "    int total = seed;",
            "    for (size_t idx = 0; idx < (sizeof(g_parse_dispatch_table) / sizeof(g_parse_dispatch_table[0])); ++idx) {",
            "        total += g_parse_dispatch_table[idx](seed + (int) (idx * 3));",
            "    }",
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


def render_unit_source(unit_idx: int, config: ParseStressConfig) -> str:
    unit = f"{unit_idx:02d}"
    lines = [
        f'#include "unit_{unit}.h"',
        '#include "parse_stress_inline.h"',
        "",
    ]

    lines.extend(
        [
            f"static parse_unit_{unit}_public_t g_parse_unit_{unit}_public = {render_public_init(unit_idx, config)};",
            "",
            f"static parse_perf_payload_t g_parse_unit_{unit}_payload_bank[{config.payload_bank_count}] = {{",
        ]
    )
    for slot in range(config.payload_bank_count):
        suffix = "," if slot + 1 < config.payload_bank_count else ""
        lines.append(
            f"    {render_payload_init(unit_idx, slot + 20, config.history_len, 'bank')}{suffix}"
        )
    lines.extend(
        [
            "};",
            "",
            f"static parse_perf_metrics_t g_parse_unit_{unit}_metric_bank[{config.metric_bank_count}] = {{",
        ]
    )
    for slot in range(config.metric_bank_count):
        suffix = "," if slot + 1 < config.metric_bank_count else ""
        lines.append(f"    {render_metrics_init(unit_idx, slot + 10)}{suffix}")
    lines.extend(
        [
            "};",
            "",
            f"static parse_perf_route_t g_parse_unit_{unit}_route_bank[{config.route_count}] = {{",
        ]
    )
    for slot in range(config.route_count):
        suffix = "," if slot + 1 < config.route_count else ""
        lines.append(f"    {render_route_init(unit_idx, slot + 20)}{suffix}")
    bias_values = [
        (unit_idx + 1) * (slot + 5) + (slot % 7)
        for slot in range(config.history_len * 2)
    ]
    lines.extend(
        [
            "};",
            "",
            f"static int32_t g_parse_unit_{unit}_bias_ring[{config.history_len * 2}] = "
            f"{{{c_ints(bias_values)}}};",
            "",
            f"static int parse_unit_{unit}_local_mix(",
            "    const parse_perf_payload_t *payload,",
            "    const parse_perf_metrics_t *metrics,",
            "    int seed,",
            "    int bias",
            ") {",
            "    int total = seed + bias;",
            "    total += parse_perf_fold_payload(payload, bias);",
            "    total += (int) metrics->ticks;",
            "    total += metrics->counters[(seed + bias) % PARSE_PERF_METRIC_COUNTERS];",
            "    total += (int) metrics->ratios[(seed + bias) % PARSE_PERF_METRIC_RATIOS];",
            "    return total;",
            "}",
            "",
        ]
    )

    for func_idx in range(config.functions_per_unit):
        type_idx = func_idx % config.types_per_unit
        leaf_idx = func_idx % config.leaf_count
        payload_idx = func_idx % config.payload_bank_count
        metric_idx = func_idx % config.metric_bank_count
        route_idx = func_idx % config.route_count
        typed_samples = [
            (unit_idx + func_idx + 1) * (sample_idx + 2) for sample_idx in range(4)
        ]
        typed_weights = [((func_idx + idx + 3) * (unit_idx + 2)) % 97 for idx in range(4)]
        prev_call = (
            ""
            if unit_idx == 0
            else f"    total += g_parse_unit_{unit}_public.callbacks.prev_feed("
            f"&leaf.payloads[{(func_idx + 1) % 2}], seed + {unit_idx}, bias + {func_idx + 1});\n"
        )
        next_call = (
            ""
            if unit_idx + 1 >= config.units
            else f"    total += g_parse_unit_{unit}_public.callbacks.next_feed("
            f"&payload, seed + {func_idx}, bias + {unit_idx + 1});\n"
        )
        lines.extend(
            [
                f"static int parse_unit_{unit}_helper_{func_idx:03d}(int seed, int bias) {{",
                f"    parse_unit_{unit}_leaf_t leaf = g_parse_unit_{unit}_public.bank.leaves[{leaf_idx}];",
                f"    parse_perf_payload_t payload = g_parse_unit_{unit}_payload_bank[{payload_idx}];",
                f"    parse_perf_metrics_t metrics = g_parse_unit_{unit}_metric_bank[{metric_idx}];",
                f"    parse_unit_{unit}_descriptor_{type_idx:02d}_t typed_descriptor = {{",
                f"        .descriptor = {render_descriptor_init(unit_idx, type_idx, func_idx + 1)},",
                f"        .window = {render_window_init(unit_idx, type_idx, func_idx + 2)},",
                f"        .weights = {{{c_ints(typed_weights)}}},",
                f"        .samples = {{{c_ints(typed_samples)}}},",
                "    };",
                f"    parse_unit_{unit}_slot_{type_idx:02d}_t typed_slot = {{",
                f"        .payload_view = g_parse_unit_{unit}_payload_bank[{(payload_idx + 1) % config.payload_bank_count}],",
                "    };",
                f"    int total = seed + bias + {unit_idx} + {func_idx};",
                "    total += parse_unit_{unit}_local_mix(&payload, &metrics, seed, bias);".replace(
                    "{unit}", unit
                ),
                f"    total += parse_perf_fold_route(&g_parse_unit_{unit}_route_bank[{route_idx}], seed + bias);",
                f"    total += parse_perf_fold_payload(&leaf.payloads[{func_idx % 2}], bias + {func_idx + 1});",
                f"    total += leaf.samples[(seed + {func_idx}) % {config.history_len}];",
                f"    total += (int) leaf.windows[(seed + bias + {func_idx}) % {config.leaf_window_count}];",
                f"    total += g_parse_unit_{unit}_bias_ring[(seed + {func_idx}) % {config.history_len * 2}];",
                "    total += typed_descriptor.samples[(seed + bias) & 0x3];",
                "    total += typed_descriptor.weights[(seed + bias) & 0x3];",
                f"    total += typed_slot.payload_view.history[(seed + {func_idx}) % {config.history_len}];",
                f"    total += g_parse_unit_{unit}_public.callbacks.self_feed(&payload, seed + {unit_idx}, bias + {func_idx});",
            ]
        )
        if prev_call:
            lines.extend(prev_call.rstrip("\n").split("\n"))
        if next_call:
            lines.extend(next_call.rstrip("\n").split("\n"))
        lines.extend(
            [
                "    return total;",
                "}",
                "",
            ]
        )

    lines.extend(
        [
            f"const parse_unit_{unit}_public_t *parse_unit_{unit}_public_state(void) {{",
            f"    return &g_parse_unit_{unit}_public;",
            "}",
            "",
            f"int parse_unit_{unit}_cross_feed(",
            "    const parse_perf_payload_t *payload,",
            "    int seed,",
            "    int bias",
            ") {",
            "    int total = seed + bias;",
            f"    total += g_parse_unit_{unit}_public.export_block.counters[(seed + bias) & 0x3];",
            f"    total += parse_perf_fold_route(&g_parse_unit_{unit}_route_bank[(seed + bias) % {config.route_count}], seed);",
            "    for (size_t idx = 0; idx < sizeof(payload->history) / sizeof(payload->history[0]); ++idx) {",
            f"        total += payload->history[idx] + g_parse_unit_{unit}_bias_ring[(idx + seed + bias) % {config.history_len * 2}];",
            "    }",
            "    total += parse_perf_fold_payload(payload, bias);",
            f"    return total + (int) g_parse_unit_{unit}_public.export_block.stamp;",
            "}",
            "",
            f"int parse_unit_{unit}_dispatch(int seed) {{",
            f"    int total = seed + {unit_idx};",
            f"    total += g_parse_unit_{unit}_public.export_block.counters[seed & 0x3];",
        ]
    )
    if unit_idx > 0:
        lines.append(
            f"    total += g_parse_unit_{unit}_public.prev_export.counters[(seed + {unit_idx}) & 0x3];"
        )
    for func_idx in range(config.functions_per_unit):
        lines.append(
            f"    total += parse_unit_{unit}_helper_{func_idx:03d}(seed + {func_idx}, {func_idx + 1});"
        )
    lines.extend(
        [
            "    return total;",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def resolve_config(args: argparse.Namespace) -> ParseStressConfig:
    preset_values = PRESET_CONFIGS[args.preset]
    units = args.units if args.units is not None else preset_values["units"]
    types_per_unit = (
        args.types_per_unit
        if args.types_per_unit is not None
        else preset_values["types_per_unit"]
    )
    functions_per_unit = (
        args.functions_per_unit
        if args.functions_per_unit is not None
        else preset_values["functions_per_unit"]
    )
    history_len = (
        args.history_len if args.history_len is not None else preset_values["history_len"]
    )

    if units < 1 or types_per_unit < 1 or functions_per_unit < 1 or history_len < 1:
        raise SystemExit("all numeric generator parameters must be positive")

    return ParseStressConfig(
        preset=args.preset,
        units=units,
        types_per_unit=types_per_unit,
        functions_per_unit=functions_per_unit,
        history_len=history_len,
    )


def write_generated_file(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument(
        "--preset",
        choices=sorted(PRESET_CONFIGS.keys()),
        default="large",
    )
    parser.add_argument("--units", type=int)
    parser.add_argument("--types-per-unit", type=int)
    parser.add_argument("--functions-per-unit", type=int)
    parser.add_argument("--history-len", type=int)
    args = parser.parse_args()

    config = resolve_config(args)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    write_generated_file(
        output_dir / "parse_stress_shared.h",
        render_shared_header(config),
    )
    write_generated_file(
        output_dir / "parse_stress_inline.h",
        render_inline_header(),
    )
    write_generated_file(
        output_dir / "main.c",
        render_main_source(config),
    )

    for unit_idx in range(config.units):
        write_generated_file(
            output_dir / f"unit_{unit_idx:02d}.h",
            render_unit_header(unit_idx, config),
        )
        write_generated_file(
            output_dir / f"unit_{unit_idx:02d}.c",
            render_unit_source(unit_idx, config),
        )

    generation_config = {
        "preset": config.preset,
        "units": config.units,
        "types_per_unit": config.types_per_unit,
        "functions_per_unit": config.functions_per_unit,
        "history_len": config.history_len,
        "generated_c_files": config.units + 1,
        "generated_header_files": config.units + 2,
    }
    (output_dir / "generation_config.json").write_text(
        json.dumps(generation_config, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class MetricRule:
    name: str
    json_path: str
    relative_regression_pct: float
    absolute_regression_ms: float
    severity: str
    description: str


@dataclass
class MetricComparison:
    name: str
    description: str
    base_ms: float
    head_ms: float
    delta_ms: float
    delta_pct: float
    relative_regression_pct: float
    absolute_regression_ms: float
    severity: str
    status: str
    enforced: bool


@dataclass(frozen=True)
class SupplementalMetricRule:
    name: str
    json_path: str
    description: str


@dataclass
class SupplementalMetricComparison:
    name: str
    description: str
    base_ms: float | None
    head_ms: float | None
    delta_ms: float | None
    delta_pct: float | None
    status: str


PARSE_RULES = [
    MetricRule(
        name="fast_parse_p50",
        json_path="parse_benchmark.metrics_ms.p50",
        relative_regression_pct=15.0,
        absolute_regression_ms=60.0,
        severity="fail",
        description="Fast parse p50",
    ),
    MetricRule(
        name="fast_parse_p95",
        json_path="parse_benchmark.metrics_ms.p95",
        relative_regression_pct=20.0,
        absolute_regression_ms=80.0,
        severity="fail",
        description="Fast parse p95",
    ),
]

QUERY_RULES = [
    MetricRule(
        name="source_line_query_p50",
        json_path="query_benchmark.metrics_ms.p50",
        relative_regression_pct=20.0,
        absolute_regression_ms=0.6,
        severity="fail",
        description="Source-line query p50",
    ),
    MetricRule(
        name="source_line_query_p95",
        json_path="query_benchmark.metrics_ms.p95",
        relative_regression_pct=25.0,
        absolute_regression_ms=0.8,
        severity="warn",
        description="Source-line query p95",
    ),
]

INDEX_PHASE_RULES = [
    SupplementalMetricRule(
        name="index_phase_average",
        json_path="parse_benchmark.internal_metrics_ms.index_phase.average",
        description="Index phase average",
    ),
    SupplementalMetricRule(
        name="index_phase_p50",
        json_path="parse_benchmark.internal_metrics_ms.index_phase.p50",
        description="Index phase p50",
    ),
    SupplementalMetricRule(
        name="index_phase_p95",
        json_path="parse_benchmark.internal_metrics_ms.index_phase.p95",
        description="Index phase p95",
    ),
    SupplementalMetricRule(
        name="index_phase_min",
        json_path="parse_benchmark.internal_metrics_ms.index_phase.min",
        description="Index phase min",
    ),
    SupplementalMetricRule(
        name="index_phase_max",
        json_path="parse_benchmark.internal_metrics_ms.index_phase.max",
        description="Index phase max",
    ),
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare two DWARF perf baseline result files and fail on guarded regressions."
        )
    )
    parser.add_argument("--base", required=True, help="Path to the base baseline JSON")
    parser.add_argument("--head", required=True, help="Path to the head baseline JSON")
    parser.add_argument(
        "--base-label",
        default="base",
        help="Short label to show for the base baseline",
    )
    parser.add_argument(
        "--head-label",
        default="head",
        help="Short label to show for the head baseline",
    )
    parser.add_argument(
        "--summary-file",
        required=True,
        help="Path to write a markdown summary",
    )
    parser.add_argument(
        "--result-file",
        required=True,
        help="Path to write machine-readable comparison JSON",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Report regressions without failing the command",
    )
    parser.add_argument(
        "--report-only-reason",
        default="",
        help="Optional note explaining why the comparison is report-only",
    )
    parser.add_argument(
        "--skip-query-metrics",
        action="store_true",
        help=(
            "Skip source-line query metrics for this comparison. The query "
            "benchmark is independent of the parse target and should only be "
            "enforced once per base/head comparison set."
        ),
    )
    parser.add_argument(
        "--skip-query-reason",
        default="",
        help="Optional note explaining why source-line query metrics were skipped.",
    )
    return parser.parse_args()


def load_json(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def get_nested(data: dict[str, Any], dotted_path: str) -> float:
    current: Any = data
    for segment in dotted_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            raise KeyError(f"Missing key '{segment}' while reading '{dotted_path}'")
        current = current[segment]
    return float(current)


def get_nested_optional(data: dict[str, Any], dotted_path: str) -> float | None:
    current: Any = data
    for segment in dotted_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]

    if current is None:
        return None
    return float(current)


def compare_metric(
    base_data: dict[str, Any],
    head_data: dict[str, Any],
    rule: MetricRule,
    report_only: bool,
) -> MetricComparison:
    base_ms = get_nested(base_data, rule.json_path)
    head_ms = get_nested(head_data, rule.json_path)
    delta_ms = head_ms - base_ms

    if base_ms <= 0.0:
        delta_pct = math.inf if head_ms > 0.0 else 0.0
    else:
        delta_pct = (delta_ms / base_ms) * 100.0

    regression = (
        delta_ms > rule.absolute_regression_ms
        and (delta_pct > rule.relative_regression_pct or math.isinf(delta_pct))
    )

    if delta_ms <= 0.0:
        status = "improved"
    elif regression and rule.severity == "fail":
        status = "would-fail" if report_only else "fail"
    elif regression and rule.severity == "warn":
        status = "would-warn" if report_only else "warn"
    else:
        status = "pass"

    return MetricComparison(
        name=rule.name,
        description=rule.description,
        base_ms=base_ms,
        head_ms=head_ms,
        delta_ms=delta_ms,
        delta_pct=delta_pct,
        relative_regression_pct=rule.relative_regression_pct,
        absolute_regression_ms=rule.absolute_regression_ms,
        severity=rule.severity,
        status=status,
        enforced=not report_only,
    )


def compare_supplemental_metric(
    base_data: dict[str, Any],
    head_data: dict[str, Any],
    rule: SupplementalMetricRule,
) -> SupplementalMetricComparison:
    base_ms = get_nested_optional(base_data, rule.json_path)
    head_ms = get_nested_optional(head_data, rule.json_path)

    if base_ms is None or head_ms is None:
        return SupplementalMetricComparison(
            name=rule.name,
            description=rule.description,
            base_ms=base_ms,
            head_ms=head_ms,
            delta_ms=None,
            delta_pct=None,
            status="missing",
        )

    delta_ms = head_ms - base_ms
    if base_ms <= 0.0:
        delta_pct = math.inf if head_ms > 0.0 else 0.0
    else:
        delta_pct = (delta_ms / base_ms) * 100.0

    return SupplementalMetricComparison(
        name=rule.name,
        description=rule.description,
        base_ms=base_ms,
        head_ms=head_ms,
        delta_ms=delta_ms,
        delta_pct=delta_pct,
        status="available",
    )


def format_delta_pct(delta_pct: float) -> str:
    if math.isinf(delta_pct):
        return "inf"
    return f"{delta_pct:+.2f}%"


def format_metric_row(metric: MetricComparison) -> str:
    threshold = (
        f">{metric.relative_regression_pct:.0f}% and >{metric.absolute_regression_ms:.3f}ms"
    )
    return (
        f"| {metric.description} | {metric.base_ms:.3f} | {metric.head_ms:.3f} | "
        f"{metric.delta_ms:+.3f} | {format_delta_pct(metric.delta_pct)} | "
        f"{threshold} | {metric.severity} | {metric.status} |"
    )


def format_optional_ms(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f}"


def format_optional_delta_pct(value: float | None) -> str:
    if value is None:
        return "n/a"
    return format_delta_pct(value)


def format_optional_ms_with_suffix(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f}ms"


def format_supplemental_metric_row(metric: SupplementalMetricComparison) -> str:
    return (
        f"| {metric.description} | {format_optional_ms(metric.base_ms)} | "
        f"{format_optional_ms(metric.head_ms)} | {format_optional_ms(metric.delta_ms)} | "
        f"{format_optional_delta_pct(metric.delta_pct)} | {metric.status} |"
    )


def resolve_parse_target_name(
    base_data: dict[str, Any], head_data: dict[str, Any]
) -> str:
    for candidate in [head_data, base_data]:
        parse_benchmark = candidate.get("parse_benchmark")
        if isinstance(parse_benchmark, dict):
            artifact_name = parse_benchmark.get("artifact_name")
            if isinstance(artifact_name, str) and artifact_name:
                return artifact_name
    return "unknown-target"


def format_console_metric_line(metric: MetricComparison) -> str:
    return (
        f"  [{metric.status:<10}] {metric.description:<22} "
        f"{metric.base_ms:9.3f}ms -> {metric.head_ms:9.3f}ms "
        f"({metric.delta_ms:+9.3f}ms, {format_delta_pct(metric.delta_pct):>8})"
    )


def format_console_supplemental_line(metric: SupplementalMetricComparison) -> str:
    return (
        f"  [{metric.status:<10}] {metric.description:<22} "
        f"{format_optional_ms_with_suffix(metric.base_ms):>12} -> "
        f"{format_optional_ms_with_suffix(metric.head_ms):>12} "
        f"({format_optional_ms_with_suffix(metric.delta_ms):>12}, "
        f"{format_optional_delta_pct(metric.delta_pct):>8})"
    )


def build_console_report(
    parse_target_name: str,
    metrics: list[MetricComparison],
    index_phase_metrics: list[SupplementalMetricComparison],
    base_label: str,
    head_label: str,
    report_only: bool,
    report_only_reason: str,
    query_skip_reason: str,
    overall_status: str,
) -> str:
    mode = "report-only" if report_only else "enforced"
    lines = [
        f"DWARF perf regression: {parse_target_name}",
        f"  mode: {mode}",
        f"  base: {base_label}",
        f"  head: {head_label}",
        f"  verdict: {overall_status}",
        "  guarded metrics:",
    ]
    lines.extend(format_console_metric_line(metric) for metric in metrics)
    lines.extend(
        [
            "  index phase:",
        ]
    )
    lines.extend(
        format_console_supplemental_line(metric) for metric in index_phase_metrics
    )
    if report_only_reason:
        lines.append(f"  note: {report_only_reason}")
    if query_skip_reason:
        lines.append(f"  query metrics: skipped ({query_skip_reason})")
    return "\n".join(lines)


def determine_overall_status(metrics: list[MetricComparison], report_only: bool) -> str:
    has_fail = any(metric.status in {"fail", "would-fail"} for metric in metrics)
    has_warn = any(metric.status in {"warn", "would-warn"} for metric in metrics)

    if report_only:
        if has_fail:
            return "report-only (would fail)"
        if has_warn:
            return "report-only (would warn)"
        return "report-only (no regression)"

    if has_fail:
        return "fail"
    if has_warn:
        return "warn"
    return "pass"


def build_summary(
    parse_target_name: str,
    metrics: list[MetricComparison],
    index_phase_metrics: list[SupplementalMetricComparison],
    base_label: str,
    head_label: str,
    report_only: bool,
    report_only_reason: str,
    query_skip_reason: str,
    overall_status: str,
) -> str:
    mode = "report-only" if report_only else "enforced"
    lines = [
        "## DWARF Perf Regression",
        "",
        f"- Parse target: `{parse_target_name}`",
        f"- Mode: `{mode}`",
        f"- Base: `{base_label}`",
        f"- Head: `{head_label}`",
        "- Gate rule: a regression only trips when both the relative and absolute thresholds are exceeded.",
    ]

    if report_only_reason:
        lines.append(f"- Note: {report_only_reason}")
    if query_skip_reason:
        lines.append(f"- Query metrics: skipped. {query_skip_reason}")

    lines.extend(
        [
            "",
            "| Metric | Base (ms) | Head (ms) | Delta (ms) | Delta % | Threshold | Policy | Result |",
            "| --- | ---: | ---: | ---: | ---: | --- | --- | --- |",
        ]
    )

    lines.extend(format_metric_row(metric) for metric in metrics)
    lines.extend(
        [
            "",
            "### Index Phase Breakdown",
            "",
            "| Metric | Base (ms) | Head (ms) | Delta (ms) | Delta % | Availability |",
            "| --- | ---: | ---: | ---: | ---: | --- |",
        ]
    )
    lines.extend(
        format_supplemental_metric_row(metric) for metric in index_phase_metrics
    )
    lines.extend(["", f"Overall verdict: `{overall_status}`"])
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    base_data = load_json(args.base)
    head_data = load_json(args.head)

    metric_rules = PARSE_RULES if args.skip_query_metrics else PARSE_RULES + QUERY_RULES
    metrics = [
        compare_metric(base_data, head_data, rule, args.report_only)
        for rule in metric_rules
    ]
    index_phase_metrics = [
        compare_supplemental_metric(base_data, head_data, rule)
        for rule in INDEX_PHASE_RULES
    ]
    overall_status = determine_overall_status(metrics, args.report_only)
    parse_target_name = resolve_parse_target_name(base_data, head_data)
    query_skip_reason = args.skip_query_reason if args.skip_query_metrics else ""

    summary = build_summary(
        parse_target_name,
        metrics,
        index_phase_metrics,
        args.base_label,
        args.head_label,
        args.report_only,
        args.report_only_reason,
        query_skip_reason,
        overall_status,
    )
    Path(args.summary_file).write_text(summary)

    result = {
        "schema_version": 2,
        "mode": "report-only" if args.report_only else "enforced",
        "report_only_reason": args.report_only_reason,
        "query_metrics_skipped": args.skip_query_metrics,
        "query_skip_reason": query_skip_reason,
        "parse_target": parse_target_name,
        "base": {"label": args.base_label, "path": args.base},
        "head": {"label": args.head_label, "path": args.head},
        "overall_status": overall_status,
        "metrics": [asdict(metric) for metric in metrics],
        "supplemental_metrics": {
            "index_phase": [asdict(metric) for metric in index_phase_metrics]
        },
    }
    Path(args.result_file).write_text(json.dumps(result, indent=2) + "\n")

    print(
        build_console_report(
            parse_target_name,
            metrics,
            index_phase_metrics,
            args.base_label,
            args.head_label,
            args.report_only,
            args.report_only_reason,
            query_skip_reason,
            overall_status,
        )
    )

    if args.report_only:
        return 0

    if any(metric.status == "fail" for metric in metrics):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

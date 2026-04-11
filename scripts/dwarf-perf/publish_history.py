#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import math
import shutil
from pathlib import Path
from typing import Any

MAX_HISTORY_ENTRIES = 500
PREFERRED_PARSE_TARGETS = [
    "parse-stress",
    "rust-parse-stress",
    "cpp-template-stress",
    "rust-generic-stress",
    "cpp-deep-namespace",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Publish a DWARF perf baseline snapshot into a persistent history site."
    )
    parser.add_argument("--baseline", required=True, help="Baseline JSON produced by run_baseline.sh")
    parser.add_argument("--site-dir", required=True, help="Output directory for the history site")
    parser.add_argument("--repo", required=True, help="GitHub repository in owner/name form")
    parser.add_argument("--sha", required=True, help="Commit SHA for this baseline")
    parser.add_argument("--ref", required=True, help="Git ref name for this baseline")
    parser.add_argument("--event", required=True, help="GitHub event name")
    parser.add_argument("--run-id", required=True, help="GitHub Actions run id")
    parser.add_argument("--run-number", required=True, help="GitHub Actions run number")
    parser.add_argument("--run-attempt", required=True, help="GitHub Actions run attempt")
    parser.add_argument("--run-url", required=True, help="URL for the current workflow run")
    parser.add_argument(
        "--site-url",
        default="",
        help="Optional GitHub Pages URL to show in the generated index",
    )
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def maybe_load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text())


def format_metric(value: float) -> str:
    return f"{value:.3f}"


def coerce_parse_target_detail(parse_info: Any) -> dict[str, Any]:
    if not isinstance(parse_info, dict):
        return {"metrics_ms": {}, "internal_metrics_ms": {}}

    metrics = parse_info.get("metrics_ms")
    internal = parse_info.get("internal_metrics_ms")
    if isinstance(metrics, dict) or isinstance(internal, dict):
        return {
            "metrics_ms": metrics if isinstance(metrics, dict) else {},
            "internal_metrics_ms": internal if isinstance(internal, dict) else {},
        }

    return {
        "metrics_ms": parse_info,
        "internal_metrics_ms": {},
    }


def extract_parse_target_details(
    baseline_or_entry: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    parse_targets = baseline_or_entry.get("parse_targets")
    if isinstance(parse_targets, dict):
        details = {
            target: coerce_parse_target_detail(parse_info)
            for target, parse_info in parse_targets.items()
        }
        if details:
            return details

    metrics = baseline_or_entry.get("metrics")
    if isinstance(metrics, dict):
        fast_parse_targets_detail = metrics.get("fast_parse_targets_detail")
        if isinstance(fast_parse_targets_detail, dict):
            details = {
                target: coerce_parse_target_detail(parse_info)
                for target, parse_info in fast_parse_targets_detail.items()
            }
            if details:
                return details

        fast_parse_targets = metrics.get("fast_parse_targets_ms")
        if isinstance(fast_parse_targets, dict):
            return {
                target: {"metrics_ms": parse_info, "internal_metrics_ms": {}}
                for target, parse_info in fast_parse_targets.items()
            }

        fast_parse = metrics.get("fast_parse_ms")
        if isinstance(fast_parse, dict):
            return {"parse-stress": {"metrics_ms": fast_parse, "internal_metrics_ms": {}}}

    parse_benchmark = baseline_or_entry["parse_benchmark"]
    return {
        parse_benchmark.get("artifact_name", "parse-stress"): coerce_parse_target_detail(
            parse_benchmark
        )
    }


def extract_parse_targets(
    baseline_or_entry: dict[str, Any],
) -> dict[str, dict[str, float]]:
    return {
        target: parse_info["metrics_ms"]
        for target, parse_info in extract_parse_target_details(baseline_or_entry).items()
    }


def metric_or_dash(
    parse_targets: dict[str, dict[str, float]],
    target: str,
    percentile: str,
) -> str:
    metrics = parse_targets.get(target)
    if metrics is None:
        return "-"
    return format_metric(float(metrics[percentile]))


def ordered_parse_targets(*parse_target_maps: dict[str, dict[str, float]]) -> list[str]:
    present_targets = {
        target for parse_targets in parse_target_maps for target in parse_targets.keys()
    }
    ordered = [target for target in PREFERRED_PARSE_TARGETS if target in present_targets]
    extras = sorted(present_targets - set(PREFERRED_PARSE_TARGETS))
    return ordered + extras


def nested_metric(data: dict[str, Any], dotted_path: str) -> float | None:
    current: Any = data
    for segment in dotted_path.split("."):
        if not isinstance(current, dict) or segment not in current:
            return None
        current = current[segment]
    if current is None:
        return None
    return float(current)


def format_metric_or_dash(value: float | None) -> str:
    if value is None:
        return "-"
    return format_metric(value)


def format_metric_with_unit_or_dash(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{format_metric(value)} ms"


def delta_metrics(current: float | None, previous: float | None) -> tuple[float | None, float | None]:
    if current is None or previous is None:
        return None, None
    delta_ms = current - previous
    if previous == 0.0:
        delta_pct = math.inf if current > 0.0 else 0.0
    else:
        delta_pct = (delta_ms / previous) * 100.0
    return delta_ms, delta_pct


def format_delta_pct(value: float | None) -> str:
    if value is None:
        return "n/a"
    if math.isinf(value):
        return "inf"
    return f"{value:+.2f}%"


def delta_css_class(delta_ms: float | None) -> str:
    if delta_ms is None or delta_ms == 0.0:
        return "delta-neutral"
    if delta_ms < 0.0:
        return "delta-better"
    return "delta-worse"


def render_delta_badge(
    label: str, current: float | None, previous: float | None
) -> str:
    delta_ms, delta_pct = delta_metrics(current, previous)
    css_class = delta_css_class(delta_ms)
    if delta_ms is None:
        content = f"{label}: n/a"
    else:
        content = f"{label}: {delta_ms:+.3f} ms ({format_delta_pct(delta_pct)})"
    return f'<span class="delta {css_class}">{html.escape(content)}</span>'


def render_metric_cell(label: str, value: float | None) -> str:
    return (
        '<div class="metric">'
        f"<span>{html.escape(label)}</span>"
        f"<strong>{html.escape(format_metric_with_unit_or_dash(value))}</strong>"
        "</div>"
    )


def find_previous_parse_target_detail(
    history: list[dict[str, Any]], target: str
) -> dict[str, Any] | None:
    for entry in history[1:]:
        details = extract_parse_target_details(entry)
        if target in details:
            return details[target]
    return None


def find_previous_query_metrics(history: list[dict[str, Any]]) -> dict[str, Any] | None:
    for entry in history[1:]:
        metrics = entry.get("metrics", {}).get("source_line_query_ms")
        if isinstance(metrics, dict):
            return metrics
    return None


def build_entry(args: argparse.Namespace, baseline: dict[str, Any], artifact_path: str) -> dict[str, Any]:
    parse_target_details = extract_parse_target_details(baseline)
    parse_targets = {
        target: parse_info["metrics_ms"]
        for target, parse_info in parse_target_details.items()
    }
    primary_parse_target = baseline.get("primary_parse_target")
    if primary_parse_target is None:
        primary_parse_target = baseline["parse_benchmark"].get(
            "artifact_name", "parse-stress"
        )
    parse_metrics = parse_targets[primary_parse_target]
    query_metrics = baseline["query_benchmark"]["metrics_ms"]
    query_result = baseline["query_result"]

    return {
        "generated_at": baseline["generated_at"],
        "sha": args.sha,
        "sha_short": args.sha[:12],
        "ref": args.ref,
        "event": args.event,
        "run_id": args.run_id,
        "run_number": args.run_number,
        "run_attempt": args.run_attempt,
        "run_url": args.run_url,
        "artifact_path": artifact_path,
        "primary_parse_target": primary_parse_target,
        "parse_targets": parse_target_details,
        "metrics": {
            "fast_parse_ms": parse_metrics,
            "fast_parse_targets_ms": parse_targets,
            "fast_parse_targets_detail": parse_target_details,
            "source_line_query_ms": query_metrics,
        },
        "query_result": {
            "source": query_result["source"],
            "address_count": query_result["address_count"],
            "total_variables": query_result["total_variables"],
            "first_address": query_result["first_address"],
        },
    }


def dedupe_and_sort(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for entry in sorted(history, key=lambda item: item["generated_at"], reverse=True):
        key = (entry["sha"], str(entry["run_id"]), str(entry["run_attempt"]))
        if key in seen:
            continue
        seen.add(key)
        unique.append(entry)
    return unique[:MAX_HISTORY_ENTRIES]


def prune_stale_run_snapshots(runs_dir: Path, history: list[dict[str, Any]]) -> None:
    referenced = {
        Path(entry["artifact_path"]).name
        for entry in history
        if entry.get("artifact_path", "").startswith("data/runs/")
    }
    for snapshot_path in runs_dir.glob("*.json"):
        if snapshot_path.name not in referenced:
            snapshot_path.unlink()

def render_summary_cards(latest: dict[str, Any], history: list[dict[str, Any]]) -> str:
    parse_target_details = extract_parse_target_details(latest)
    query_metrics = latest["metrics"]["source_line_query_ms"]
    previous_query_metrics = find_previous_query_metrics(history)
    cards: list[str] = []

    for target in ordered_parse_targets(extract_parse_targets(latest)):
        latest_detail = parse_target_details[target]
        previous_detail = find_previous_parse_target_detail(history, target)
        latest_avg = nested_metric(latest_detail, "metrics_ms.average")
        latest_p50 = nested_metric(latest_detail, "metrics_ms.p50")
        latest_p95 = nested_metric(latest_detail, "metrics_ms.p95")
        latest_index_avg = nested_metric(
            latest_detail, "internal_metrics_ms.index_phase.average"
        )
        previous_avg = (
            nested_metric(previous_detail, "metrics_ms.average")
            if previous_detail is not None
            else None
        )
        previous_index_avg = (
            nested_metric(previous_detail, "internal_metrics_ms.index_phase.average")
            if previous_detail is not None
            else None
        )

        cards.append(
            '<article class="card">'
            '<p class="eyebrow">Parse Target</p>'
            f"<h2>{html.escape(target)}</h2>"
            '<div class="metric-grid">'
            f"{render_metric_cell('AVG', latest_avg)}"
            f"{render_metric_cell('P50', latest_p50)}"
            f"{render_metric_cell('P95', latest_p95)}"
            f"{render_metric_cell('Index AVG', latest_index_avg)}"
            "</div>"
            '<div class="delta-list">'
            f"{render_delta_badge('vs prev avg', latest_avg, previous_avg)}"
            f"{render_delta_badge('vs prev index avg', latest_index_avg, previous_index_avg)}"
            "</div>"
            "</article>"
        )

    cards.append(
        '<article class="card card-query">'
        '<p class="eyebrow">Source-Line Query</p>'
        "<h2>query-hotspot</h2>"
        '<div class="metric-grid">'
        f"{render_metric_cell('AVG', query_metrics.get('average'))}"
        f"{render_metric_cell('P50', query_metrics.get('p50'))}"
        f"{render_metric_cell('P95', query_metrics.get('p95'))}"
        f"{render_metric_cell('First Run', query_metrics.get('first_run'))}"
        "</div>"
        '<div class="delta-list">'
        f"{render_delta_badge('vs prev avg', query_metrics.get('average'), None if previous_query_metrics is None else previous_query_metrics.get('average'))}"
        f"{render_delta_badge('vs prev p50', query_metrics.get('p50'), None if previous_query_metrics is None else previous_query_metrics.get('p50'))}"
        "</div>"
        "</article>"
    )

    return '<div class="cards">' + "".join(cards) + "</div>"


def render_parse_history_sections(history: list[dict[str, Any]]) -> str:
    parse_target_order = ordered_parse_targets(
        *(extract_parse_targets(entry) for entry in history)
    )
    sections: list[str] = []

    for idx, target in enumerate(parse_target_order):
        rows: list[str] = []
        run_count = 0
        latest_detail: dict[str, Any] | None = None

        for entry in history:
            parse_target_details = extract_parse_target_details(entry)
            parse_info = parse_target_details.get(target)
            if parse_info is None:
                continue

            run_count += 1
            if latest_detail is None:
                latest_detail = parse_info

            rows.append(
                "<tr>"
                f"<td>{html.escape(entry['generated_at'])}</td>"
                f"<td><a href=\"{html.escape(entry['run_url'])}\">{html.escape(entry['sha_short'])}</a></td>"
                f"<td>{html.escape(entry['event'])}</td>"
                f"<td>{format_metric_or_dash(nested_metric(parse_info, 'metrics_ms.average'))}</td>"
                f"<td>{format_metric_or_dash(nested_metric(parse_info, 'metrics_ms.p50'))}</td>"
                f"<td>{format_metric_or_dash(nested_metric(parse_info, 'metrics_ms.p95'))}</td>"
                f"<td>{format_metric_or_dash(nested_metric(parse_info, 'internal_metrics_ms.index_phase.average'))}</td>"
                f"<td>{format_metric_or_dash(nested_metric(parse_info, 'internal_metrics_ms.index_phase.p50'))}</td>"
                f"<td><a href=\"{html.escape(entry['artifact_path'])}\">json</a></td>"
                "</tr>"
            )

        if latest_detail is None:
            continue

        summary_bits = [
            f"avg {format_metric_or_dash(nested_metric(latest_detail, 'metrics_ms.average'))} ms",
            f"p50 {format_metric_or_dash(nested_metric(latest_detail, 'metrics_ms.p50'))} ms",
            f"p95 {format_metric_or_dash(nested_metric(latest_detail, 'metrics_ms.p95'))} ms",
            f"index avg {format_metric_or_dash(nested_metric(latest_detail, 'internal_metrics_ms.index_phase.average'))} ms",
        ]
        open_attr = " open" if idx == 0 else ""
        sections.append(
            f'<details class="history-group"{open_attr}>'
            "<summary>"
            f'<span class="summary-title">{html.escape(target)}</span>'
            f'<span class="summary-meta">{" · ".join(html.escape(bit) for bit in summary_bits)}</span>'
            f'<span class="summary-count">{run_count} runs</span>'
            "</summary>"
            '<div class="table-wrap">'
            "<table>"
            "<thead><tr>"
            "<th>Generated At</th><th>Commit</th><th>Event</th>"
            "<th>AVG</th><th>P50</th><th>P95</th><th>Index AVG</th><th>Index P50</th><th>Snapshot</th>"
            "</tr></thead>"
            f"<tbody>{''.join(rows)}</tbody>"
            "</table>"
            "</div>"
            "</details>"
        )

    return '<div class="history-groups">' + "".join(sections) + "</div>"


def render_query_history_table(history: list[dict[str, Any]]) -> str:
    rows = []
    for entry in history:
        query_metrics = entry["metrics"]["source_line_query_ms"]
        query_result = entry["query_result"]
        rows.append(
            "<tr>"
            f"<td>{html.escape(entry['generated_at'])}</td>"
            f"<td><a href=\"{html.escape(entry['run_url'])}\">{html.escape(entry['sha_short'])}</a></td>"
            f"<td>{html.escape(entry['event'])}</td>"
            f"<td>{format_metric(float(query_metrics['average']))}</td>"
            f"<td>{format_metric(float(query_metrics['p50']))}</td>"
            f"<td>{format_metric(float(query_metrics['p95']))}</td>"
            f"<td>{query_result['address_count']}</td>"
            f"<td>{query_result['total_variables']}</td>"
            f"<td><a href=\"{html.escape(entry['artifact_path'])}\">json</a></td>"
            "</tr>"
        )

    return (
        '<div class="table-wrap">'
        "<table>"
        "<thead><tr>"
        "<th>Generated At</th><th>Commit</th><th>Event</th>"
        "<th>AVG</th><th>P50</th><th>P95</th><th>Addresses</th><th>Variables</th><th>Snapshot</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
        "</div>"
    )


def render_index(repo: str, latest: dict[str, Any], history: list[dict[str, Any]], site_url: str) -> str:
    latest_query = latest["query_result"]
    latest_meta = (
        f"<p><strong>Latest run:</strong> {html.escape(latest['generated_at'])} "
        f"for <a href=\"{html.escape(latest['run_url'])}\">{html.escape(latest['sha_short'])}</a> "
        f"on <code>{html.escape(latest['ref'])}</code>.</p>"
    )
    query_meta = (
        "<ul>"
        f"<li>Source: <code>{html.escape(latest_query['source']['path'])}:{latest_query['source']['line']}</code></li>"
        f"<li>Address count: {latest_query['address_count']}</li>"
        f"<li>Total variables: {latest_query['total_variables']}</li>"
        f"<li>First address: <code>{html.escape(latest_query['first_address'])}</code></li>"
        "</ul>"
    )
    site_meta = ""
    if site_url:
        site_meta = f'<p><strong>Site URL:</strong> <a href="{html.escape(site_url)}">{html.escape(site_url)}</a></p>'

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DWARF Perf History</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5f1e8;
      --panel: #fffaf0;
      --ink: #1f2328;
      --accent: #b45309;
      --muted: #6b7280;
      --border: #dfd6c3;
    }}
    body {{
      margin: 0;
      font-family: "Iowan Old Style", "Palatino Linotype", Georgia, serif;
      background: linear-gradient(180deg, #efe7d8 0%, var(--bg) 100%);
      color: var(--ink);
    }}
    main {{
      max-width: 1100px;
      margin: 0 auto;
      padding: 40px 24px 56px;
    }}
    h1, h2 {{
      margin: 0 0 12px;
      letter-spacing: 0.01em;
    }}
    p, li, td, th {{
      line-height: 1.5;
      font-size: 15px;
    }}
    code {{
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 0.92em;
    }}
    .hero, .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: 0 10px 30px rgba(68, 54, 20, 0.08);
    }}
    .hero {{
      padding: 28px;
      margin-bottom: 24px;
    }}
    .hero p {{
      color: var(--muted);
      max-width: 68ch;
    }}
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin: 24px 0 10px;
    }}
    .card {{
      background: #fffdf8;
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 16px 18px;
    }}
    .eyebrow {{
      margin: 0 0 8px;
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--muted);
    }}
    .card h2 {{
      font-size: 18px;
      color: var(--ink);
      margin-bottom: 10px;
    }}
    .metric-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 10px;
      margin-top: 14px;
    }}
    .metric {{
      padding: 12px;
      border-radius: 12px;
      background: #fff8ec;
      border: 1px solid #eadfca;
    }}
    .metric span {{
      display: block;
      font-size: 12px;
      letter-spacing: 0.06em;
      text-transform: uppercase;
      color: var(--muted);
      margin-bottom: 6px;
    }}
    .metric strong {{
      display: block;
      font-size: 22px;
      color: var(--accent);
      line-height: 1.15;
    }}
    .delta-list {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 14px;
    }}
    .delta {{
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 6px 10px;
      font-size: 12px;
      line-height: 1.3;
      border: 1px solid var(--border);
      background: #f8f1e3;
      color: var(--muted);
    }}
    .delta-better {{
      background: #edf7ef;
      border-color: #bedcc4;
      color: #1f6b36;
    }}
    .delta-worse {{
      background: #fff1eb;
      border-color: #efc4b4;
      color: #9a3412;
    }}
    .delta-neutral {{
      background: #f8f1e3;
      border-color: #dfd6c3;
      color: var(--muted);
    }}
    .panel {{
      padding: 24px;
      margin-top: 24px;
    }}
    .panel > p {{
      color: var(--muted);
      margin-top: 0;
    }}
    .history-groups {{
      display: grid;
      gap: 14px;
      margin-top: 18px;
    }}
    .history-group {{
      border: 1px solid var(--border);
      border-radius: 16px;
      background: #fffdf8;
      overflow: hidden;
    }}
    .history-group summary {{
      display: grid;
      grid-template-columns: minmax(0, 220px) 1fr auto;
      gap: 12px;
      align-items: center;
      cursor: pointer;
      list-style: none;
      padding: 16px 18px;
    }}
    .history-group summary::-webkit-details-marker {{
      display: none;
    }}
    .summary-title {{
      font-weight: 700;
      color: var(--ink);
    }}
    .summary-meta {{
      color: var(--muted);
      font-size: 14px;
    }}
    .summary-count {{
      color: var(--accent);
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }}
    .table-wrap {{
      overflow-x: auto;
      border-top: 1px solid var(--border);
    }}
    table {{
      width: 100%;
      min-width: 760px;
      border-collapse: collapse;
    }}
    th, td {{
      text-align: left;
      padding: 10px 12px;
      border-bottom: 1px solid var(--border);
    }}
    th {{
      color: var(--muted);
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    a {{
      color: var(--accent);
    }}
    @media (max-width: 760px) {{
      main {{
        padding: 28px 16px 40px;
      }}
      .history-group summary {{
        grid-template-columns: 1fr;
      }}
      .metric strong {{
        font-size: 19px;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>DWARF Perf History</h1>
      <p>
        Main-branch and scheduled DWARF perf baselines for <strong>{html.escape(repo)}</strong>.
        This page records startup load, index-phase, and source-line query trends across the DWARF perf corpora from CI.
      </p>
      {site_meta}
      {latest_meta}
      {render_summary_cards(latest, history)}
    </section>
    <section class="panel">
      <h2>Latest Query Snapshot</h2>
      {query_meta}
    </section>
    <section class="panel">
      <h2>Parse History</h2>
      <p>Each parse corpus keeps its own recent run table, so AVG, P50, P95, and index-phase values stay readable.</p>
      {render_parse_history_sections(history)}
    </section>
    <section class="panel">
      <h2>Query History</h2>
      {render_query_history_table(history)}
    </section>
  </main>
</body>
</html>
"""


def main() -> int:
    args = parse_args()
    baseline_path = Path(args.baseline)
    site_dir = Path(args.site_dir)
    data_dir = site_dir / "data"
    runs_dir = data_dir / "runs"

    site_dir.mkdir(parents=True, exist_ok=True)
    data_dir.mkdir(parents=True, exist_ok=True)
    runs_dir.mkdir(parents=True, exist_ok=True)

    baseline = load_json(baseline_path)
    run_filename = f"{baseline['generated_at'].replace(':', '').replace('-', '')}-{args.sha[:12]}.json"
    run_relative_path = f"data/runs/{run_filename}"
    run_output_path = runs_dir / run_filename
    shutil.copyfile(baseline_path, run_output_path)

    history_path = data_dir / "history.json"
    history = maybe_load_json(history_path, [])
    history.append(build_entry(args, baseline, run_relative_path))
    history = dedupe_and_sort(history)
    prune_stale_run_snapshots(runs_dir, history)

    latest = history[0]

    (site_dir / ".nojekyll").write_text("\n")
    (data_dir / "latest.json").write_text(json.dumps(latest, indent=2) + "\n")
    history_path.write_text(json.dumps(history, indent=2) + "\n")
    (site_dir / "index.html").write_text(
        render_index(args.repo, latest, history, args.site_url)
    )

    print(f"Published DWARF perf history into {site_dir}")
    print(f"  latest: {site_dir / 'data/latest.json'}")
    print(f"  history: {history_path}")
    print(f"  page: {site_dir / 'index.html'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

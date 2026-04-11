#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import shutil
from pathlib import Path
from typing import Any

MAX_HISTORY_ENTRIES = 500


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


def extract_parse_targets(
    baseline_or_entry: dict[str, Any],
) -> dict[str, dict[str, float]]:
    metrics = baseline_or_entry.get("metrics")
    if isinstance(metrics, dict):
        fast_parse_targets = metrics.get("fast_parse_targets_ms")
        if isinstance(fast_parse_targets, dict):
            return fast_parse_targets
        fast_parse = metrics.get("fast_parse_ms")
        if isinstance(fast_parse, dict):
            return {"parse-stress": fast_parse}

    if "parse_targets" in baseline_or_entry:
        return {
            target: parse_info["metrics_ms"]
            for target, parse_info in baseline_or_entry["parse_targets"].items()
        }

    parse_benchmark = baseline_or_entry["parse_benchmark"]
    return {
        parse_benchmark.get("artifact_name", "parse-stress"): parse_benchmark["metrics_ms"]
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


def build_entry(args: argparse.Namespace, baseline: dict[str, Any], artifact_path: str) -> dict[str, Any]:
    parse_targets = extract_parse_targets(baseline)
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
        "metrics": {
            "fast_parse_ms": parse_metrics,
            "fast_parse_targets_ms": parse_targets,
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


def render_summary_cards(latest: dict[str, Any]) -> str:
    parse_targets = extract_parse_targets(latest)
    query_metrics = latest["metrics"]["source_line_query_ms"]
    cards = [
        ("parse-stress P50", metric_or_dash(parse_targets, "parse-stress", "p50")),
        ("parse-stress P95", metric_or_dash(parse_targets, "parse-stress", "p95")),
        (
            "rust-parse-stress P50",
            metric_or_dash(parse_targets, "rust-parse-stress", "p50"),
        ),
        (
            "rust-parse-stress P95",
            metric_or_dash(parse_targets, "rust-parse-stress", "p95"),
        ),
        ("Query P50", format_metric(query_metrics["p50"])),
        ("Query P95", format_metric(query_metrics["p95"])),
    ]
    return (
        '<div class="cards">'
        + "".join(
            f'<article class="card"><h2>{html.escape(title)}</h2><p>{html.escape(value)} ms</p></article>'
            for title, value in cards
        )
        + "</div>"
    )


def render_history_table(history: list[dict[str, Any]]) -> str:
    rows = []
    for entry in history:
        parse_targets = extract_parse_targets(entry)
        query_metrics = entry["metrics"]["source_line_query_ms"]
        rows.append(
            "<tr>"
            f"<td>{html.escape(entry['generated_at'])}</td>"
            f"<td><a href=\"{html.escape(entry['run_url'])}\">{html.escape(entry['sha_short'])}</a></td>"
            f"<td>{html.escape(entry['event'])}</td>"
            f"<td>{metric_or_dash(parse_targets, 'parse-stress', 'p50')}</td>"
            f"<td>{metric_or_dash(parse_targets, 'parse-stress', 'p95')}</td>"
            f"<td>{metric_or_dash(parse_targets, 'rust-parse-stress', 'p50')}</td>"
            f"<td>{metric_or_dash(parse_targets, 'rust-parse-stress', 'p95')}</td>"
            f"<td>{format_metric(query_metrics['p50'])}</td>"
            f"<td>{format_metric(query_metrics['p95'])}</td>"
            f"<td><a href=\"{html.escape(entry['artifact_path'])}\">json</a></td>"
            "</tr>"
        )

    return (
        "<table>"
        "<thead><tr>"
        "<th>Generated At</th><th>Commit</th><th>Event</th>"
        "<th>parse-stress P50</th><th>parse-stress P95</th>"
        "<th>rust-parse-stress P50</th><th>rust-parse-stress P95</th>"
        "<th>Query P50</th><th>Query P95</th><th>Snapshot</th>"
        "</tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
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
    .card h2 {{
      font-size: 14px;
      color: var(--muted);
      margin-bottom: 10px;
    }}
    .card p {{
      margin: 0;
      font-size: 28px;
      color: var(--accent);
    }}
    .panel {{
      padding: 24px;
      margin-top: 24px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 18px;
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
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>DWARF Perf History</h1>
      <p>
        Main-branch and scheduled DWARF perf baselines for <strong>{html.escape(repo)}</strong>.
        This page records the current C parse, Rust parse, and source-line query trends from CI.
      </p>
      {site_meta}
      {latest_meta}
      {render_summary_cards(latest)}
    </section>
    <section class="panel">
      <h2>Latest Query Snapshot</h2>
      {query_meta}
    </section>
    <section class="panel">
      <h2>Recent History</h2>
      {render_history_table(history)}
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

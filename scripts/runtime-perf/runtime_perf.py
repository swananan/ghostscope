#!/usr/bin/env python3
"""Measure real CLI output using the hot-function benchmark's start/ready barriers."""

from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "compare"))
import compare_hot_function_bench as hot


EVENT_PREFIX = "GHOSTSCOPE_RUNTIME_EVENT"
EVENT_RE = re.compile(rf"^{EVENT_PREFIX} (\d+)$")
READY_MARKER = "GHOSTSCOPE_RUNTIME_PERF_READY"
SCRIPTS = {
    "print": f'trace runtime_hot_fn {{ print "{EVENT_PREFIX} {{}}", payload.index; }}',
    "complex": f'trace runtime_hot_fn {{ print "{EVENT_PREFIX} {{}}", payload.index; print *payload; }}',
    "backtrace": f'trace runtime_hot_fn {{ print "{EVENT_PREFIX} {{}}", payload.index; bt full; }}',
}
COMPILER_FLAGS = [
    "-O2", "-g", "-fno-omit-frame-pointer", "-fno-optimize-sibling-calls",
    "-fno-pie", "-no-pie",
]
SAMPLE_INTERVAL = 0.01


class OutputCollector:
    """Drain both pipes concurrently; retain counters and a bounded diagnostic tail."""

    def __init__(self, process: subprocess.Popen, iterations: int):
        self.iterations = iterations
        self.ready = threading.Event()
        self.seen: set[int] = set()
        self.duplicates = 0
        self.invalid_events = 0
        self.complex_seen = False
        self.backtrace_seen = False
        self.value_error = False
        self.stdout_bytes = 0
        self.last_output = time.monotonic()
        self.tails = {"stdout": deque(maxlen=16), "stderr": deque(maxlen=16)}
        self.errors: list[str] = []
        self.threads = [
            threading.Thread(target=self._drain, args=(stream, name), daemon=True)
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr))
        ]
        for thread in self.threads:
            thread.start()

    def _drain(self, stream, name: str) -> None:
        try:
            for line in stream:
                self.tails[name].append(line[-2048:].rstrip())
                if name != "stdout":
                    continue
                self.stdout_bytes += len(line.encode("utf-8"))
                self.last_output = time.monotonic()
                text = line.strip()
                if text == READY_MARKER:
                    self.ready.set()
                if text.startswith(EVENT_PREFIX):
                    match = EVENT_RE.fullmatch(text)
                    if not match or not 0 <= int(match[1]) < self.iterations:
                        self.invalid_events += 1
                    elif int(match[1]) in self.seen:
                        self.duplicates += 1
                    else:
                        self.seen.add(int(match[1]))
                self.complex_seen |= "RuntimePayload" in text and "{" in text
                self.backtrace_seen |= "runtime_layer_3" in text
                self.value_error |= any(
                    marker in text
                    for marker in ("<error:", "<unreadable:", "<unavailable:", "OptimizedOut")
                )
        except Exception as exc:
            self.errors.append(f"{name} reader: {exc}")

    def join(self) -> None:
        for thread in self.threads:
            thread.join(timeout=2)
            if thread.is_alive():
                raise hot.BenchmarkError("observer output reader did not finish")
        if self.errors:
            raise hot.BenchmarkError("; ".join(self.errors))

    def diagnostics(self) -> str:
        return "\n".join(f"{name}:\n" + "\n".join(tail) for name, tail in self.tails.items())


def read_memory(pid: int) -> dict[str, int]:
    try:
        text = Path(f"/proc/{pid}/status").read_text()
    except (FileNotFoundError, ProcessLookupError):
        return {}
    return {
        name: int(value)
        for name, value in re.findall(r"^(VmRSS|VmHWM):\s+(\d+)\s+kB$", text, re.MULTILINE)
    }


class MemorySampler:
    def __init__(self, pid: int):
        self.pid = pid
        self.peak_kib = 0
        self.steady_peak_kib = 0
        self.steady = threading.Event()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def sample(self) -> None:
        memory = read_memory(self.pid)
        self.peak_kib = max(self.peak_kib, memory.get("VmHWM", 0))
        if self.steady.is_set():
            self.steady_peak_kib = max(self.steady_peak_kib, memory.get("VmRSS", 0))

    def _run(self) -> None:
        while not self.stop.wait(SAMPLE_INTERVAL):
            self.sample()

    def finish(self) -> None:
        self.sample()
        self.stop.set()
        self.thread.join(timeout=2)


def terminate(process: subprocess.Popen | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream is not None:
            stream.close()


def wait_until_ready(process: subprocess.Popen, output: OutputCollector, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while not output.ready.wait(timeout=0.02):
        if process.poll() is not None or time.monotonic() >= deadline:
            raise hot.BenchmarkError("observer failed to become ready\n" + output.diagnostics())


def run_once(target_bin: Path, ghostscope_bin: Path | None, workload: str,
             args: argparse.Namespace, workdir: Path) -> dict:
    target = observer = None
    sampler = output = None
    try:
        target, pid = hot.start_target(target_bin, args.iterations, args.inner_work)
        if args.target_cpu is not None:
            os.sched_setaffinity(pid, {args.target_cpu})
        attach_ns = None
        if ghostscope_bin is not None:
            script_path = workdir / "trace.gs"
            script_path.write_text(SCRIPTS[workload] + "\n")
            config_path = workdir / "config.toml"
            # An explicit empty config uses project defaults rather than local user settings.
            config_path.write_text("")
            command = [
                str(ghostscope_bin), "-t", str(target_bin), "-p", str(pid),
                "--config", str(config_path), "--no-log", "--no-status",
                "--no-save-llvm-ir", "--no-save-ast", "--no-save-ebpf",
                "--debuginfod", "off", "--script-file", str(script_path),
                "--script-output", "plain", "--script-output-events-per-sec", "0",
                "--backtrace-depth", "8", "--no-backtrace-runtime-modules",
                "--emit-ready-marker", READY_MARKER,
            ]
            if args.observer_cpu is not None:
                # Apply affinity before Rust creates its runtime threads.
                command = [str(hot.resolve_tool("taskset")), "-c", str(args.observer_cpu), *command]
            started = time.monotonic_ns()
            observer = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", bufsize=1, cwd=workdir,
            )
            output = OutputCollector(observer, args.iterations)
            sampler = MemorySampler(observer.pid)
            wait_until_ready(observer, output, args.ready_timeout)
            attach_ns = time.monotonic_ns() - started
            sampler.steady.set()
            sampler.sample()

        # Unlike the original comparison fixture, this target has a second barrier.
        target.stdin.write("s")
        target.stdin.flush()
        result_line = hot.read_line_with_timeout(
            target.stdout, args.target_timeout, "waiting for timed target result"
        )
        result = hot.parse_target_result(result_line, "")
        target_peak = read_memory(pid).get("VmHWM")
        if observer is not None:
            sampler.sample()
            sampler.steady.clear()
            deadline = time.monotonic() + args.drain_timeout
            while time.monotonic() < deadline:
                if observer.poll() is not None:
                    raise hot.BenchmarkError("observer exited before draining\n" + output.diagnostics())
                if len(output.seen) == args.iterations and time.monotonic() - output.last_output > 0.1:
                    break
                time.sleep(0.01)
            sampler.finish()
            observer.send_signal(signal.SIGINT)
            try:
                observer.wait(timeout=5)
            except subprocess.TimeoutExpired as exc:
                raise hot.BenchmarkError("observer shutdown timed out") from exc
            output.join()
            if observer.returncode != 0:
                raise hot.BenchmarkError("observer shutdown failed\n" + output.diagnostics())
            if output.invalid_events or output.duplicates or not output.seen or output.value_error:
                raise hot.BenchmarkError("invalid trace output\n" + output.diagnostics())
            if workload == "complex" and not output.complex_seen:
                raise hot.BenchmarkError("complex workload did not render RuntimePayload")
            if workload == "backtrace" and not output.backtrace_seen:
                raise hot.BenchmarkError("backtrace workload did not unwind runtime_layer_3")
            if not sampler.peak_kib or not sampler.steady_peak_kib:
                raise hot.BenchmarkError("unable to measure observer RSS")

        target.stdin.write("d")
        target.stdin.flush()
        target.stdin.close()
        target.stdin = None
        stdout, stderr = target.communicate(timeout=5)
        if target.returncode != 0:
            raise hot.BenchmarkError(f"target failed: {stdout}\n{stderr}")
        received = len(output.seen) if output else None
        return {
            "target_elapsed_ns": result["elapsed_ns"],
            "target_sink": result["sink"],
            "attach_latency_ns": attach_ns,
            "target_peak_rss_kib": target_peak,
            "observer_peak_rss_kib": sampler.peak_kib if sampler else None,
            "observer_steady_peak_rss_kib": sampler.steady_peak_kib if sampler else None,
            "expected_events": args.iterations if output else None,
            "received_events": received,
            "missing_events": args.iterations - received if output else None,
            "stdout_bytes": output.stdout_bytes if output else None,
            "diagnostic_tail": list(output.tails["stderr"]) if output else [],
        }
    finally:
        if sampler is not None:
            sampler.finish()
        # Kill a timed-out observer before closing its pipes, then join the readers.
        if observer is not None and observer.poll() is None:
            observer.kill()
            observer.wait(timeout=5)
        if output is not None:
            for thread in output.threads:
                thread.join(timeout=2)
        terminate(observer)
        terminate(target)


def summarize(runs: list[dict], baseline_runs: list[dict]) -> dict:
    for run, baseline in zip(runs, baseline_runs):
        if run["target_sink"] != baseline["target_sink"]:
            raise hot.BenchmarkError("tracing changed the target checksum")
    summary = {"runs": runs}
    for key in ("target_elapsed_ns", "attach_latency_ns", "observer_peak_rss_kib",
                "observer_steady_peak_rss_kib", "target_peak_rss_kib"):
        values = [run[key] for run in runs if run[key] is not None]
        summary[f"median_{key}"] = statistics.median(values) if values else None
    summary["median_slowdown"] = statistics.median(
        run["target_elapsed_ns"] / baseline["target_elapsed_ns"]
        for run, baseline in zip(runs, baseline_runs)
    )
    expected = sum(run["expected_events"] or 0 for run in runs)
    missing = sum(run["missing_events"] or 0 for run in runs)
    summary["expected_events"] = expected
    summary["missing_events"] = missing
    summary["loss_pct"] = 100 * missing / expected if expected else None
    return summary


def compare(results: dict, args: argparse.Namespace) -> list[dict]:
    comparisons = []
    if "base" not in results["variants"]:
        return comparisons
    for workload in args.workloads:
        base = results["variants"]["base"]["workloads"][workload]
        head = results["variants"]["head"]["workloads"][workload]
        for metric, threshold, percentage_points in (
            ("median_slowdown", args.max_slowdown_regression_pct, False),
            ("median_observer_peak_rss_kib", args.max_rss_regression_pct, False),
            ("loss_pct", args.max_loss_increase_pp, True),
        ):
            delta = head[metric] - base[metric]
            if not percentage_points:
                delta = 100 * delta / base[metric]
            comparisons.append({
                "workload": workload, "metric": metric, "base": base[metric],
                "head": head[metric], "increase": delta,
                "unit": "percentage points" if percentage_points else "%",
                "threshold": threshold, "regression": delta > threshold,
            })
    return comparisons


def markdown(results: dict) -> str:
    config = results["config"]
    cpus = results["environment"]["cpus"]
    lines = [
        "## Runtime performance baseline", "",
        f"- Calls per repetition: {config['iterations']}; inner work: {config['inner_work']}",
        f"- Recorded repetitions: {config['repetitions']}; untimed warmups: {config['warmups']}",
        f"- Build-profile label: {config['build_profile']}; target CPU: {cpus['target']}; observer CPU: {cpus['observer']}",
        f"- CPU: {results['environment']['cpu_model']}; kernel: {results['environment']['kernel']}", "",
        "Target time excludes attach, DWARF/LLVM preparation, output draining, and shutdown.",
        "Slowdown is the median of ratios to the untraced target in the same repetition.",
        "Loss counts unique event IDs missing after bounded draining and shutdown (all delivery stages).",
        "Observer peak RSS includes preparation; steady RSS is sampled every 10 ms during target work.", "",
        "| Variant | Workload | Target ms | Slowdown | Ready ms | Peak RSS MiB | Steady RSS MiB | Missing / expected | Loss % |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for variant, data in results["variants"].items():
        for workload, summary in data["workloads"].items():
            lines.append(
                f"| {variant} | {workload} | {summary['median_target_elapsed_ns'] / 1e6:.2f} | "
                f"{summary['median_slowdown']:.3f}x | {summary['median_attach_latency_ns'] / 1e6:.2f} | "
                f"{summary['median_observer_peak_rss_kib'] / 1024:.2f} | "
                f"{summary['median_observer_steady_peak_rss_kib'] / 1024:.2f} | "
                f"{summary['missing_events']} / {summary['expected_events']} | {summary['loss_pct']:.3f} |"
            )
    if results["comparisons"]:
        lines += ["", "### Base → head changes", "",
                  "| Workload | Metric | Increase | Threshold | Result |",
                  "|---|---|---:|---:|---|"]
        for row in results["comparisons"]:
            lines.append(
                f"| {row['workload']} | {row['metric']} | {row['increase']:+.2f} {row['unit']} | "
                f"{row['threshold']:.2f} {row['unit']} | "
                f"{'REGRESSION' if row['regression'] else 'ok'} |"
            )
    return "\n".join(lines) + "\n"


def positive_int(raw: str) -> int:
    value = int(raw)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def positive_float(raw: str) -> float:
    value = float(raw)
    if not 0 < value < float("inf"):
        raise argparse.ArgumentTypeError("must be finite and positive")
    return value


def nonnegative_float(raw: str) -> float:
    value = float(raw)
    if not 0 <= value < float("inf"):
        raise argparse.ArgumentTypeError("must be finite and nonnegative")
    return value


def nonnegative_int(raw: str) -> int:
    value = int(raw)
    if value < 0:
        raise argparse.ArgumentTypeError("must be nonnegative")
    return value


def core_key(cpu: int) -> tuple:
    topology = Path(f"/sys/devices/system/cpu/cpu{cpu}/topology")
    try:
        return tuple((topology / field).read_text().strip()
                     for field in ("physical_package_id", "core_id"))
    except OSError:
        return ("unknown", cpu)


def select_cpus(args: argparse.Namespace) -> dict:
    allowed = sorted(os.sched_getaffinity(0))
    if len(allowed) < 2:
        raise hot.BenchmarkError("runtime measurements require at least two allowed logical CPUs")
    target = args.target_cpu if args.target_cpu is not None else allowed[0]
    others = [cpu for cpu in allowed if cpu != target]
    other_cores = [cpu for cpu in others if core_key(cpu) != core_key(target)]
    observer = args.observer_cpu if args.observer_cpu is not None else (other_cores or others)[0]
    if target not in allowed or observer not in allowed or target == observer:
        raise hot.BenchmarkError("target and observer CPUs must be distinct and inside the allowed CPU set")
    # Keep the harness off the target core, including its SMT siblings when
    # topology is available. Prefer keeping it off the observer core as well.
    reserved = {core_key(target), core_key(observer)}
    harness = [cpu for cpu in allowed if core_key(cpu) not in reserved] or [observer]
    args.target_cpu, args.observer_cpu = target, observer
    return {"allowed": allowed, "target": target, "observer": observer, "harness": harness,
            "target_core": core_key(target), "observer_core": core_key(observer)}


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghostscope-bin", help="Candidate binary (default: local debug build).")
    parser.add_argument("--base-bin", help="Optional baseline binary, measured on the same host and fixture.")
    parser.add_argument("--build-profile", choices=["debug", "release", "unspecified"], default="unspecified")
    parser.add_argument("--workloads", nargs="+", choices=list(SCRIPTS), default=list(SCRIPTS))
    parser.add_argument("--iterations", type=positive_int, default=2000)
    parser.add_argument("--inner-work", type=positive_int, default=32768)
    parser.add_argument("--repetitions", type=positive_int, default=5)
    parser.add_argument("--warmups", type=int, choices=range(0, 11), default=1)
    parser.add_argument("--ready-timeout", type=positive_float, default=60)
    parser.add_argument("--target-timeout", type=positive_float, default=120)
    parser.add_argument("--drain-timeout", type=positive_float, default=5)
    parser.add_argument("--target-cpu", type=nonnegative_int, help="Target logical CPU (default: first allowed CPU).")
    parser.add_argument("--observer-cpu", type=nonnegative_int, help="Observer logical CPU (default: a different physical core when available).")
    parser.add_argument("--max-slowdown-regression-pct", type=nonnegative_float, default=15)
    parser.add_argument("--max-rss-regression-pct", type=nonnegative_float, default=20)
    parser.add_argument("--max-loss-increase-pp", type=nonnegative_float, default=1)
    parser.add_argument("--fail-on-regression", action="store_true", help="Fail if a paired base/head threshold is exceeded.")
    parser.add_argument("--output-json", type=Path, default=Path("/tmp/ghostscope_runtime_perf.json"))
    parser.add_argument("--output-markdown", type=Path, default=Path("/tmp/ghostscope_runtime_perf.md"))
    args = parser.parse_args(argv)
    if args.fail_on_regression and not args.base_bin:
        parser.error("--fail-on-regression requires --base-bin")
    if args.output_json.resolve() == args.output_markdown.resolve():
        parser.error("JSON and Markdown outputs must use different paths")
    args.workloads = list(dict.fromkeys(args.workloads))
    return args


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv=None) -> int:
    args = parse_args(argv)
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise hot.BenchmarkError("runtime measurements require Linux x86_64")
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR", hot.repo_root() / "target"))
    candidate = Path(args.ghostscope_bin) if args.ghostscope_bin else target_dir / "debug" / "ghostscope"
    candidate = candidate.expanduser().resolve()
    if not candidate.is_file():
        raise hot.BenchmarkError(f"candidate binary does not exist: {candidate}")
    binaries = {"head": candidate}
    if args.base_bin:
        base = Path(args.base_bin).resolve()
        if not base.is_file():
            raise hot.BenchmarkError(f"baseline binary does not exist: {base}")
        binaries = {"base": base, **binaries}
    compiler = hot.resolve_compiler()
    cpus = select_cpus(args)
    os.sched_setaffinity(0, cpus["harness"])
    source = Path(__file__).with_name("runtime_target.c")
    results = {
        "schema_version": 1,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "config": {key: getattr(args, key) for key in (
            "iterations", "inner_work", "repetitions", "warmups", "workloads",
            "build_profile", "drain_timeout",
        )},
        "environment": {
            "cpus": cpus,
            "kernel": platform.release(), "cpu_model": hot.cpu_model_name(),
            "cpu_count": os.cpu_count(), "python": platform.python_version(),
            "compiler": hot.capture_version_line([str(compiler), "--version"]),
            "compiler_flags": COMPILER_FLAGS, "target_source_sha256": sha256(source),
            "harness_sha256": sha256(Path(__file__)), "scripts": SCRIPTS,
            "shared_harness_sha256": sha256(Path(hot.__file__)),
            "cpu_affinity": sorted(os.sched_getaffinity(0)),
        },
        "baseline": {}, "variants": {}, "comparisons": [],
    }
    for variant, binary in binaries.items():
        results["variants"][variant] = {
            "binary": str(binary), "binary_sha256": sha256(binary),
            "version": hot.capture_version_line([str(binary), "--version"]), "workloads": {},
        }
    baseline_runs = []
    collected = {(variant, workload): [] for variant in binaries for workload in args.workloads}
    with tempfile.TemporaryDirectory(prefix="ghostscope-runtime-perf-") as temp:
        workdir = Path(temp)
        target = workdir / "runtime_target"
        hot.run_checked([str(compiler), *COMPILER_FLAGS, "-o", str(target), str(source)])
        for repetition in range(-args.warmups, args.repetitions):
            baseline = run_once(target, None, "baseline", args, workdir)
            if repetition >= 0:
                baseline_runs.append(baseline)
            # Alternate candidate ordering and rotate workloads to reduce order bias.
            variants = list(binaries)
            if repetition % 2:
                variants.reverse()
            offset = repetition % len(args.workloads)
            workloads = args.workloads[offset:] + args.workloads[:offset]
            for workload in workloads:
                for variant in variants:
                    print(f"runtime-perf: repetition={repetition} {variant}/{workload}", flush=True)
                    run = run_once(target, binaries[variant], workload, args, workdir)
                    if run["target_sink"] != baseline["target_sink"]:
                        raise hot.BenchmarkError("tracing changed the target checksum")
                    if repetition >= 0:
                        collected[(variant, workload)].append(run)
        results["baseline"] = summarize(baseline_runs, baseline_runs)
        for (variant, workload), runs in collected.items():
            results["variants"][variant]["workloads"][workload] = summarize(runs, baseline_runs)
    results["comparisons"] = compare(results, args)
    report = markdown(results)
    for path, content in (
        (args.output_json, json.dumps(results, indent=2) + "\n"),
        (args.output_markdown, report),
    ):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        path.chmod(0o644)
    print(report, end="")
    print(f"JSON_RESULT={args.output_json}")
    print(f"MARKDOWN_RESULT={args.output_markdown}")
    return int(args.fail_on_regression and any(row["regression"] for row in results["comparisons"]))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (hot.BenchmarkError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"runtime benchmark error: {exc}", file=sys.stderr)
        raise SystemExit(1)

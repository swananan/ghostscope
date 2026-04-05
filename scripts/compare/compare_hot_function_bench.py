#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import select
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


READY_RE = re.compile(r"READY pid=(\d+)")
RESULT_RE = re.compile(
    r"RESULT iterations=(\d+) inner_work=(\d+) elapsed_ns=(\d+) sink=(\d+)"
)

DEFAULT_ITERATIONS = 2000
DEFAULT_INNER_WORK = 4096
DEFAULT_REPETITIONS = 5
DEFAULT_READY_TIMEOUT_SECS = 15.0
DEFAULT_TARGET_TIMEOUT_SECS = 120.0
DEFAULT_OUTPUT_JSON = Path("/tmp/ghostscope_gdb_benchmark_result.json")
DEFAULT_OUTPUT_MARKDOWN = Path("/tmp/ghostscope_gdb_benchmark_result.md")
GHOSTSCOPE_READY_MARKER = "GHOSTSCOPE_BENCHMARK_READY"
PROBE_LINE_MARKER = "BENCH_LOCAL_PROBE_LINE"


class BenchmarkError(RuntimeError):
    pass


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def first_existing_path(paths: list[Path]) -> Path | None:
    for path in paths:
        expanded = path.expanduser()
        if expanded.exists():
            return expanded
    return None


def resolve_ghostscope_bin(explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    env_bin = os.environ.get("GHOSTSCOPE_BENCH_GHOSTSCOPE_BIN")
    if env_bin:
        candidates.append(Path(env_bin))
    candidates.extend(
        [
            repo_root() / "target" / "debug" / "ghostscope",
            Path.home() / ".ghostscope" / "bin" / "ghostscope",
        ]
    )

    match = first_existing_path(candidates)
    if match is not None:
        return match.resolve()

    which_match = shutil.which("ghostscope")
    if which_match:
        return Path(which_match).resolve()

    raise BenchmarkError("unable to locate ghostscope binary")


def resolve_tool(name: str) -> Path:
    match = shutil.which(name)
    if match is None:
        raise BenchmarkError(f"required tool not found in PATH: {name}")
    return Path(match).resolve()


def resolve_compiler() -> Path:
    cc_env = os.environ.get("CC")
    names = [cc_env] if cc_env else []
    names.extend(["cc", "clang", "gcc"])
    for name in names:
        if not name:
            continue
        match = shutil.which(name)
        if match:
            return Path(match).resolve()
    raise BenchmarkError("unable to locate a C compiler (checked CC, cc, clang, gcc)")


def run_checked(
    cmd: list[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        cmd,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise BenchmarkError(
            "command failed:\n"
            f"cmd={' '.join(shlex.quote(part) for part in cmd)}\n"
            f"exit_code={completed.returncode}\n"
            f"stdout={completed.stdout}\n"
            f"stderr={completed.stderr}"
        )
    return completed


def compile_target(source: Path, output: Path) -> dict[str, str]:
    compiler = resolve_compiler()
    cmd = [
        str(compiler),
        "-O2",
        "-g",
        "-fno-omit-frame-pointer",
        "-fno-pie",
        "-no-pie",
        "-o",
        str(output),
        str(source),
    ]
    run_checked(cmd, cwd=repo_root())
    return {"compiler": str(compiler), "command": " ".join(shlex.quote(part) for part in cmd)}


def resolve_probe_line(source: Path) -> int:
    for line_no, line in enumerate(source.read_text(encoding="utf-8").splitlines(), start=1):
        if PROBE_LINE_MARKER in line:
            return line_no
    raise BenchmarkError(f"unable to locate probe line marker {PROBE_LINE_MARKER} in {source}")


def read_line_with_timeout(stream, timeout_secs: float, description: str) -> str:
    deadline = time.monotonic() + timeout_secs
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BenchmarkError(f"timed out while {description}")
        ready, _, _ = select.select([stream], [], [], remaining)
        if not ready:
            continue
        line = stream.readline()
        if line:
            return line
        raise BenchmarkError(f"stream closed while {description}")


def wait_for_file(path: Path, timeout_secs: float, description: str) -> None:
    deadline = time.monotonic() + timeout_secs
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise BenchmarkError(f"timed out while {description}: {path}")


def parse_target_result(stdout: str, stderr: str) -> dict[str, int]:
    match = RESULT_RE.search(stdout)
    if match is None:
        raise BenchmarkError(f"unable to parse target result. stdout={stdout} stderr={stderr}")
    return {
        "iterations": int(match.group(1)),
        "inner_work": int(match.group(2)),
        "elapsed_ns": int(match.group(3)),
        "sink": int(match.group(4)),
    }


def start_target(target_bin: Path, iterations: int, inner_work: int) -> tuple[subprocess.Popen[str], int]:
    proc = subprocess.Popen(
        [str(target_bin), str(iterations), str(inner_work)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert proc.stderr is not None
    ready_line = read_line_with_timeout(proc.stderr, DEFAULT_READY_TIMEOUT_SECS, "waiting for target READY line")
    match = READY_RE.search(ready_line)
    if match is None:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise BenchmarkError(
            f"unexpected target readiness output: line={ready_line!r} stdout={stdout} stderr={stderr}"
        )
    return proc, int(match.group(1))


def release_target(proc: subprocess.Popen[str]) -> None:
    assert proc.stdin is not None
    proc.stdin.write("1\n")
    proc.stdin.flush()
    proc.stdin.close()
    proc.stdin = None


def finish_target(proc: subprocess.Popen[str], timeout_secs: float) -> tuple[dict[str, int], str, str]:
    try:
        stdout, stderr = proc.communicate(timeout=timeout_secs)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise BenchmarkError(
            f"target timed out after {timeout_secs}s. partial_stdout={stdout} partial_stderr={stderr}"
        ) from exc
    if proc.returncode != 0:
        raise BenchmarkError(
            f"target exited with {proc.returncode}. stdout={stdout} stderr={stderr}"
        )
    return parse_target_result(stdout, stderr), stdout, stderr


def cleanup_process(proc: subprocess.Popen[str], name: str) -> tuple[str, str]:
    try:
        stdout, stderr = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
    if proc.returncode not in (0, None):
        raise BenchmarkError(
            f"{name} exited with {proc.returncode}. stdout={stdout} stderr={stderr}"
        )
    return stdout, stderr


def run_baseline(target_bin: Path, iterations: int, inner_work: int) -> dict[str, object]:
    target, _pid = start_target(target_bin, iterations, inner_work)
    release_target(target)
    result, stdout, stderr = finish_target(target, DEFAULT_TARGET_TIMEOUT_SECS)
    return {
        "target_elapsed_ns": result["elapsed_ns"],
        "attach_latency_ns": None,
        "target_stdout": stdout,
        "target_stderr": stderr,
    }


def run_gdb(
    *,
    gdb_bin: Path,
    target_bin: Path,
    source: Path,
    probe_line: int,
    iterations: int,
    inner_work: int,
    workdir: Path,
) -> dict[str, object]:
    target, pid = start_target(target_bin, iterations, inner_work)
    ready_path = workdir / "gdb.ready"
    if ready_path.exists():
        ready_path.unlink()
    gdb_script = workdir / "gdb_attach.gdb"
    gdb_script.write_text(
        "\n".join(
            [
                "set confirm off",
                "set pagination off",
                "set print thread-events off",
                "set breakpoint pending on",
                f"attach {pid}",
                f"break {source.name}:{probe_line}",
                "commands",
                "  silent",
                "  if local_probe == 0",
                '    printf "never\\n"',
                "  end",
                "  continue",
                "end",
                f"shell printf ready > {shlex.quote(str(ready_path))}",
                "continue",
                "quit",
                "",
            ]
        ),
        encoding="utf-8",
    )
    observer_started_ns = time.monotonic_ns()
    gdb = subprocess.Popen(
        [str(gdb_bin), "-nx", "-q", "-batch", "-x", str(gdb_script)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    wait_for_file(ready_path, DEFAULT_READY_TIMEOUT_SECS, "waiting for gdb to arm breakpoint")
    # The target stays blocked on stdin until the observer is ready, so the
    # measured target runtime below excludes debugger setup and arming time.
    attach_latency_ns = time.monotonic_ns() - observer_started_ns
    release_target(target)
    result, target_stdout, target_stderr = finish_target(target, DEFAULT_TARGET_TIMEOUT_SECS)
    gdb_stdout, gdb_stderr = cleanup_process(gdb, "gdb")
    return {
        "target_elapsed_ns": result["elapsed_ns"],
        "attach_latency_ns": attach_latency_ns,
        "target_stdout": target_stdout,
        "target_stderr": target_stderr,
        "observer_stdout": gdb_stdout,
        "observer_stderr": gdb_stderr,
    }


def run_ghostscope(
    *,
    ghostscope_bin: Path,
    target_bin: Path,
    source: Path,
    probe_line: int,
    iterations: int,
    inner_work: int,
    workdir: Path,
) -> dict[str, object]:
    target, pid = start_target(target_bin, iterations, inner_work)
    script_path = workdir / "trace.gs"
    script_path.write_text(
        f"trace {source.name}:{probe_line} {{\n"
        "    if local_probe == 0 { print \"never\"; }\n"
        "}\n",
        encoding="utf-8",
    )
    observer_started_ns = time.monotonic_ns()
    ghostscope = subprocess.Popen(
        [
            str(ghostscope_bin),
            "-p",
            str(pid),
            "--script-file",
            str(script_path),
            "--script-output",
            "quiet",
            "--emit-ready-marker",
            GHOSTSCOPE_READY_MARKER,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    assert ghostscope.stdout is not None
    ready_line = read_line_with_timeout(
        ghostscope.stdout,
        DEFAULT_READY_TIMEOUT_SECS,
        "waiting for ghostscope ready marker",
    )
    if GHOSTSCOPE_READY_MARKER not in ready_line:
        stdout, stderr = cleanup_process(ghostscope, "ghostscope")
        raise BenchmarkError(
            f"unexpected ghostscope readiness output: line={ready_line!r} stdout={stdout} stderr={stderr}"
        )
    # GhostScope emits the ready marker only after compile_and_load_script_for_cli
    # completes, so DWARF indexing and script load time are reported separately
    # from the target steady-state runtime.
    attach_latency_ns = time.monotonic_ns() - observer_started_ns
    release_target(target)
    result, target_stdout, target_stderr = finish_target(target, DEFAULT_TARGET_TIMEOUT_SECS)
    ghostscope_stdout, ghostscope_stderr = cleanup_process(ghostscope, "ghostscope")
    return {
        "target_elapsed_ns": result["elapsed_ns"],
        "attach_latency_ns": attach_latency_ns,
        "target_stdout": target_stdout,
        "target_stderr": target_stderr,
        "observer_stdout": ready_line + ghostscope_stdout,
        "observer_stderr": ghostscope_stderr,
    }


def summarize_runs(runs: list[dict[str, object]]) -> dict[str, object]:
    elapsed_values = [int(run["target_elapsed_ns"]) for run in runs]
    attach_values = [
        int(run["attach_latency_ns"])
        for run in runs
        if run["attach_latency_ns"] is not None
    ]
    summary: dict[str, object] = {
        "runs": runs,
        "median_target_elapsed_ns": int(statistics.median(elapsed_values)),
        "min_target_elapsed_ns": min(elapsed_values),
        "max_target_elapsed_ns": max(elapsed_values),
    }
    if attach_values:
        summary["median_attach_latency_ns"] = int(statistics.median(attach_values))
        summary["min_attach_latency_ns"] = min(attach_values)
        summary["max_attach_latency_ns"] = max(attach_values)
    else:
        summary["median_attach_latency_ns"] = None
        summary["min_attach_latency_ns"] = None
        summary["max_attach_latency_ns"] = None
    return summary


def ns_to_ms(value: int | None) -> str:
    if value is None:
        return "n/a"
    return f"{value / 1_000_000:.2f}"


def slowdown_text(summary: dict[str, object], baseline_ns: int | None) -> str:
    if baseline_ns in (None, 0):
        return "n/a"
    median_ns = int(summary["median_target_elapsed_ns"])
    return f"{median_ns / baseline_ns:.2f}x"


def make_markdown(
    *,
    results: dict[str, object],
    iterations: int,
    inner_work: int,
    repetitions: int,
) -> str:
    lines = [
        "## Measured Single-Thread Hot-Function Benchmark",
        "",
        f"- Iterations per run: `{iterations}`",
        f"- Inner work per function hit: `{inner_work}`",
        f"- Repetitions per mode: `{repetitions}`",
        "- Shared observation intent: evaluate local variable `local_probe` on the marked hot-function source line without steady-state output",
        "- The target remains blocked until the observer reports ready, so steady-state target time excludes setup, DWARF indexing, and script load time",
        "",
        "| Mode | Median steady-state target time (ms) | Target min-max (ms) | Slowdown vs baseline | Median ready latency (ms, excluded) |",
        "|---|---:|---:|---:|---:|",
    ]
    baseline_summary = results["modes"].get("baseline")
    baseline_ns = None
    if baseline_summary is not None:
        baseline_ns = int(baseline_summary["median_target_elapsed_ns"])
    for mode in ["baseline", "ghostscope", "gdb"]:
        summary = results["modes"].get(mode)
        if summary is None:
            continue
        lines.append(
            "| "
            f"{mode} | "
            f"{ns_to_ms(int(summary['median_target_elapsed_ns']))} | "
            f"{ns_to_ms(int(summary['min_target_elapsed_ns']))}-{ns_to_ms(int(summary['max_target_elapsed_ns']))} | "
            f"{slowdown_text(summary, baseline_ns)} | "
            f"{ns_to_ms(summary['median_attach_latency_ns'])} |"
        )
    return "\n".join(lines) + "\n"


def capture_version_line(cmd: list[str]) -> str:
    try:
        completed = run_checked(cmd, cwd=repo_root(), timeout=10)
    except Exception as exc:
        return f"unavailable: {exc}"
    for line in completed.stdout.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    for line in completed.stderr.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return "unknown"


def cpu_model_name() -> str:
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("model name"):
                _, value = line.split(":", 1)
                return value.strip()
    return "unknown"


def chmod_world_readable(path: Path) -> None:
    os.chmod(path, 0o644)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Benchmark GhostScope and GDB against the same hot-function observation workload."
    )
    parser.add_argument(
        "--modes",
        nargs="+",
        choices=["baseline", "ghostscope", "gdb"],
        default=["baseline", "ghostscope", "gdb"],
        help="Benchmark modes to run.",
    )
    parser.add_argument("--iterations", type=int, default=DEFAULT_ITERATIONS)
    parser.add_argument("--inner-work", type=int, default=DEFAULT_INNER_WORK)
    parser.add_argument("--repetitions", type=int, default=DEFAULT_REPETITIONS)
    parser.add_argument("--ghostscope-bin", default=None)
    parser.add_argument("--output-json", default=str(DEFAULT_OUTPUT_JSON))
    parser.add_argument("--output-markdown", default=str(DEFAULT_OUTPUT_MARKDOWN))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_modes = list(dict.fromkeys(args.modes))
    output_json = Path(args.output_json)
    output_markdown = Path(args.output_markdown)
    if output_json.exists():
        output_json.unlink()
    if output_markdown.exists():
        output_markdown.unlink()
    work_root = Path(tempfile.mkdtemp(prefix="ghostscope-compare-"))
    source = repo_root() / "scripts" / "compare" / "compare_hot_function_target.c"
    target_bin = work_root / "bench_target"
    compile_info = compile_target(source, target_bin)
    probe_line = resolve_probe_line(source)
    gdb_bin = resolve_tool("gdb") if "gdb" in run_modes else None
    ghostscope_bin = (
        resolve_ghostscope_bin(args.ghostscope_bin) if "ghostscope" in run_modes else None
    )

    results: dict[str, object] = {
        "scenario": "single-thread hot-function local-variable observation with output suppressed",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repo_root": str(repo_root()),
        "config": {
            "iterations": args.iterations,
            "inner_work": args.inner_work,
            "repetitions": args.repetitions,
            "modes": run_modes,
            "probe_line": probe_line,
            "probe_variable": "local_probe",
        },
        "environment": {
            "platform": platform.platform(),
            "kernel": platform.release(),
            "cpu_model": cpu_model_name(),
            "python": platform.python_version(),
            "gdb": capture_version_line([str(gdb_bin), "--version"]) if gdb_bin else None,
            "ghostscope": capture_version_line([str(ghostscope_bin), "--version"])
            if ghostscope_bin
            else None,
        },
        "build": compile_info,
        "modes": {},
    }

    runners = {
        "baseline": lambda workdir: run_baseline(target_bin, args.iterations, args.inner_work),
        "gdb": lambda workdir: run_gdb(
            gdb_bin=gdb_bin,
            target_bin=target_bin,
            source=source,
            probe_line=probe_line,
            iterations=args.iterations,
            inner_work=args.inner_work,
            workdir=workdir,
        ),
        "ghostscope": lambda workdir: run_ghostscope(
            ghostscope_bin=ghostscope_bin,
            target_bin=target_bin,
            source=source,
            probe_line=probe_line,
            iterations=args.iterations,
            inner_work=args.inner_work,
            workdir=workdir,
        ),
    }

    for mode in run_modes:
        runs: list[dict[str, object]] = []
        for index in range(args.repetitions):
            run_workdir = work_root / f"{mode}-{index}"
            run_workdir.mkdir(parents=True, exist_ok=True)
            runs.append(runners[mode](run_workdir))
        results["modes"][mode] = summarize_runs(runs)

    baseline_summary = results["modes"].get("baseline")
    if baseline_summary is not None:
        baseline_ns = int(baseline_summary["median_target_elapsed_ns"])
        derived: dict[str, float | None] = {}
        for mode in ["ghostscope", "gdb"]:
            summary = results["modes"].get(mode)
            if summary is None:
                derived[f"{mode}_slowdown_vs_baseline"] = None
            else:
                derived[f"{mode}_slowdown_vs_baseline"] = round(
                    int(summary["median_target_elapsed_ns"]) / baseline_ns,
                    4,
                )
        results["derived"] = derived

    markdown = make_markdown(
        results=results,
        iterations=args.iterations,
        inner_work=args.inner_work,
        repetitions=args.repetitions,
    )

    output_json.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output_markdown.write_text(markdown, encoding="utf-8")
    chmod_world_readable(output_json)
    chmod_world_readable(output_markdown)

    print(markdown, end="")
    print(f"JSON_RESULT={output_json}")
    print(f"MARKDOWN_RESULT={output_markdown}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BenchmarkError as exc:
        print(f"benchmark error: {exc}", file=sys.stderr)
        raise SystemExit(1)

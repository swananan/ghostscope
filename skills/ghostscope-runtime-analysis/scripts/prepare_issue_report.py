#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import textwrap
from datetime import datetime
from pathlib import Path


DEFAULT_ISSUE_URL = "https://github.com/swananan/ghostscope/issues/new"


def parse_named_arg(raw: str) -> tuple[str, str]:
    if "=" not in raw:
        raise argparse.ArgumentTypeError("expected NAME=VALUE")
    name, value = raw.split("=", 1)
    name = name.strip()
    value = value.strip()
    if not name:
        raise argparse.ArgumentTypeError("name cannot be empty in NAME=VALUE")
    if not value:
        raise argparse.ArgumentTypeError("value cannot be empty in NAME=VALUE")
    return name, value


def read_text_file(path: Path, max_chars: int) -> tuple[str, bool]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars], True


def shell_capture(command: str, timeout: int, max_chars: int) -> tuple[int | None, str, str, bool, str | None]:
    try:
        result = subprocess.run(
            ["bash", "-lc", command],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        return None, "", "", False, "bash is not available"
    except subprocess.TimeoutExpired:
        return None, "", "", False, f"timed out after {timeout}s"
    stdout = result.stdout
    stderr = result.stderr
    combined_len = len(stdout) + len(stderr)
    truncated = False
    if combined_len > max_chars:
        keep_stdout = min(len(stdout), max_chars // 2)
        keep_stderr = min(len(stderr), max_chars - keep_stdout)
        stdout = stdout[:keep_stdout]
        stderr = stderr[:keep_stderr]
        truncated = True
    return result.returncode, stdout, stderr, truncated, None


def detect_os_release() -> str | None:
    os_release = Path("/etc/os-release")
    if not os_release.exists():
        return None
    for line in os_release.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def repo_root_from_script() -> Path | None:
    script_path = Path(__file__).resolve()
    repo_root = script_path.parents[3]
    if (repo_root / ".git").exists():
        return repo_root
    return None


def git_head(repo_root: Path | None) -> str | None:
    if repo_root is None:
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def ghostscope_version() -> str | None:
    binary = shutil.which("ghostscope")
    if not binary:
        return None
    try:
        result = subprocess.run(
            [binary, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return f"{binary} --version timed out"
    if result.returncode != 0:
        stderr = result.stderr.strip()
        return f"{binary} --version failed: {stderr or f'exit {result.returncode}'}"
    return result.stdout.strip() or f"{binary} --version returned no output"


def add_code_block(lines: list[str], title: str, body: str, language: str = "") -> None:
    lines.append(f"## {title}")
    lines.append("")
    lines.append(f"```{language}".rstrip())
    lines.append(body.rstrip() if body.strip() else "<empty>")
    lines.append("```")
    lines.append("")


def add_bullet(lines: list[str], label: str, value: str | None) -> None:
    if value:
        lines.append(f"- {label}: {value}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prepare a GhostScope GitHub issue draft in Markdown."
    )
    parser.add_argument("--output", help="Output markdown path. Defaults to /tmp/ghostscope-issue-<timestamp>.md")
    parser.add_argument("--title", default="", help="Short issue title")
    parser.add_argument(
        "--issue-type",
        default="bug",
        choices=["bug", "crash", "cannot-capture", "wrong-output", "performance", "other"],
        help="Issue category",
    )
    parser.add_argument("--ghostscope-command", default="", help="Exact GhostScope command used")
    parser.add_argument("--mode", default="", help="Tracing mode summary such as -p or -t")
    parser.add_argument("--target", default="", help="Target process, binary, or library")
    parser.add_argument("--expected", default="", help="Expected behavior")
    parser.add_argument("--actual", default="", help="Actual behavior")
    parser.add_argument("--notes", default="", help="Extra notes, context, or hypotheses")
    parser.add_argument("--issue-url", default=DEFAULT_ISSUE_URL, help="GitHub issue creation URL")
    parser.add_argument("--trace-script-file", action="append", default=[], help="Trace script file to embed")
    parser.add_argument("--config-file", action="append", default=[], help="Config file to embed")
    parser.add_argument("--log-file", action="append", default=[], help="Log or captured output file to embed")
    parser.add_argument("--repro-step", action="append", default=[], help="One reproduction step line")
    parser.add_argument(
        "--inline-text",
        action="append",
        default=[],
        type=parse_named_arg,
        metavar="NAME=TEXT",
        help="Inline text section to embed",
    )
    parser.add_argument(
        "--extra-file",
        action="append",
        default=[],
        type=parse_named_arg,
        metavar="NAME=PATH",
        help="Extra file to embed with a custom section name",
    )
    parser.add_argument(
        "--extra-command",
        action="append",
        default=[],
        type=parse_named_arg,
        metavar="NAME=COMMAND",
        help="Diagnostic shell command to run and embed",
    )
    parser.add_argument(
        "--max-section-chars",
        type=int,
        default=40000,
        help="Maximum embedded text per file or command section",
    )
    parser.add_argument(
        "--command-timeout-secs",
        type=int,
        default=20,
        help="Timeout for each extra shell command",
    )
    args = parser.parse_args()

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    output_path = Path(args.output) if args.output else Path(f"/tmp/ghostscope-issue-{timestamp}.md")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    repo_root = repo_root_from_script()
    repo_head = git_head(repo_root)
    os_release = detect_os_release()
    gs_version = ghostscope_version()

    lines: list[str] = []
    title = args.title or f"{args.issue_type}: GhostScope issue report"
    lines.append(f"# {title}")
    lines.append("")
    lines.append("Prepared by `ghostscope-runtime-analysis` for GitHub issue submission.")
    lines.append("")

    lines.append("## Submission")
    lines.append("")
    lines.append(f"- Issue URL: {args.issue_url}")
    lines.append(f"- Suggested title: {title}")
    lines.append(f"- Issue type: {args.issue_type}")
    lines.append(f"- Prepared at: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    add_bullet(lines, "Mode", args.mode)
    add_bullet(lines, "Target", args.target)
    add_bullet(lines, "Expected", args.expected)
    add_bullet(lines, "Actual", args.actual)
    if not any([args.mode, args.target, args.expected, args.actual]):
        lines.append("- Fill in the expected and actual behavior before filing.")
    lines.append("")

    if args.repro_step:
        lines.append("## Reproduction Steps")
        lines.append("")
        for index, step in enumerate(args.repro_step, start=1):
            lines.append(f"{index}. {step}")
        lines.append("")

    if args.ghostscope_command:
        add_code_block(lines, "GhostScope Command", args.ghostscope_command, "bash")

    if args.notes:
        lines.append("## Notes")
        lines.append("")
        lines.append(args.notes.strip())
        lines.append("")

    lines.append("## Environment")
    lines.append("")
    add_bullet(lines, "Hostname", platform.node() or None)
    add_bullet(lines, "User", os.environ.get("USER"))
    add_bullet(lines, "Working directory", os.getcwd())
    add_bullet(lines, "OS", os_release)
    add_bullet(lines, "Kernel", platform.release())
    add_bullet(lines, "Machine", platform.machine())
    add_bullet(lines, "Python", platform.python_version())
    add_bullet(lines, "GhostScope version", gs_version)
    if repo_root is not None:
        add_bullet(lines, "Repo root", str(repo_root))
    add_bullet(lines, "Repo HEAD", repo_head)
    lines.append("")

    file_sections: list[tuple[str, Path]] = []
    file_sections.extend(("Trace Script", Path(path)) for path in args.trace_script_file)
    file_sections.extend(("Config File", Path(path)) for path in args.config_file)
    file_sections.extend(("Log File", Path(path)) for path in args.log_file)
    file_sections.extend((name, Path(path)) for name, path in args.extra_file)

    for section_name, path in file_sections:
        lines.append(f"## {section_name}: {path}")
        lines.append("")
        if not path.exists():
            lines.append(f"`{path}` does not exist.")
            lines.append("")
            continue
        if path.is_dir():
            lines.append(f"`{path}` is a directory, not a file.")
            lines.append("")
            continue
        try:
            body, truncated = read_text_file(path, args.max_section_chars)
        except OSError as exc:
            lines.append(f"Failed to read `{path}`: {exc}")
            lines.append("")
            continue
        language = "toml" if path.suffix == ".toml" else ""
        if path.suffix in {".gs", ".ghostscope"}:
            language = "ghostscope"
        elif path.suffix in {".log", ".txt"}:
            language = "text"
        lines.append(f"```{language}".rstrip())
        lines.append(body.rstrip() if body.strip() else "<empty>")
        lines.append("```")
        if truncated:
            lines.append("")
            lines.append(f"_Truncated to the first {args.max_section_chars} characters._")
        lines.append("")

    for name, text in args.inline_text:
        add_code_block(lines, f"Inline Text: {name}", text, "text")

    for name, command in args.extra_command:
        lines.append(f"## Diagnostic Command: {name}")
        lines.append("")
        lines.append("```bash")
        lines.append(command)
        lines.append("```")
        lines.append("")
        exit_code, stdout, stderr, truncated, error = shell_capture(
            command,
            timeout=args.command_timeout_secs,
            max_chars=args.max_section_chars,
        )
        if error is not None:
            lines.append(f"Command could not be captured: {error}")
            lines.append("")
            continue
        lines.append(f"- Exit code: {exit_code}")
        lines.append("")
        add_code_block(lines, f"{name} stdout", stdout, "text")
        if stderr.strip():
            add_code_block(lines, f"{name} stderr", stderr, "text")
        if truncated:
            lines.append(f"_Command output truncated to {args.max_section_chars} characters total._")
            lines.append("")

    lines.append("## Recommended Next Step")
    lines.append("")
    lines.append(
        f"Open {args.issue_url} and file an issue with this report attached or pasted in. "
        "Keep the exact command, trace script, config, and logs unchanged so maintainers can reproduce the problem."
    )
    lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

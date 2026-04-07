---
name: ghostscope-runtime-analysis
description: Explain GhostScope and turn the project docs into concrete tracing commands, trace scripts, privilege setup, and issue-report workflows for source-aware runtime analysis. Use when the user asks how to install GhostScope, provide source tree and DWARF inputs, handle eBPF privileges, attach to a PID or binary, choose between `-p` and `-t`, inspect variables, write GhostScope trace scripts, use Input Mode commands, work through container or PID-namespace CLI scenarios, or triage GhostScope failures, crashes, and GitHub issue reports.
---

# GhostScope Runtime Analysis

## Overview

Translate GhostScope documentation into runnable commands and minimal trace scripts.
Prefer repository docs as the source of truth. When the user is writing in Chinese, prefer the `docs/zh/` counterparts first.

## Workflow

1. Classify the request before answering.
- Capabilities, positioning, tool comparisons, or "should I use GhostScope here?": read `references/doc-map.md`, then use `README.md`, `docs/comparison.md`, and `docs/faq.md` or `README-zh.md`, `docs/zh/comparison.md`, and `docs/zh/faq.md`.
- Installation, permissions, or debug symbols: read `references/cli-cookbook.md`, then `docs/install.md` or `docs/zh/install.md`.
- Exact CLI flags or launch syntax: run `ghostscope --help` first, and use subcommand help such as `ghostscope bpffs prune --help` when relevant. If `ghostscope` is unavailable but the shared workspace is the GhostScope repo, fall back to `references/cli-cookbook.md`, then `docs/configuration.md` or `docs/zh/configuration.md`.
- TUI commands such as `trace`, `info`, `source`, `save traces`, or `srcpath`: read `references/cli-cookbook.md`, then `docs/input-commands.md` or `docs/zh/input-commands.md`.
- Trace script authoring: run `ghostscope --script-help` first and treat its output as the source of truth for the current installed DSL. If `ghostscope` is unavailable but the shared workspace is the GhostScope repo, fall back to `docs/scripting.md` or `docs/zh/scripting.md`.
- Container or PID confusion: read `docs/container.md` or `docs/zh/container.md`.
- Limits or caveats: read `docs/limitations.md` or `docs/zh/limitations.md`.
- Crash, cannot-capture, or bug-report preparation: read `references/issue-reporting.md`, then `docs/install.md`, `docs/container.md`, and `docs/limitations.md` or their `docs/zh/` counterparts.

2. Check prerequisites before giving commands.
- If `ghostscope` is not installed or not found, recommend installing it first with `curl -fsSL https://raw.githubusercontent.com/swananan/ghostscope/main/scripts/install.sh | bash`.
- GhostScope currently targets Linux on x86_64.
- eBPF tracing usually needs `sudo` or equivalent capabilities.
- If the current privilege model is unclear, tell the user explicitly. Recommend either granting GhostScope eBPF-related capabilities with `setcap` or running a prepared wrapper script with `sudo`.
- If the source tree location is not already known, first try to discover it from the shared workspace, local filesystem, build paths, or command context before asking the user. GhostScope is most effective when it can be used together with the relevant source tree.
- DWARF debug information is required in the target binary or a separate debug file.
- If the relevant module's DWARF debug info or debug-file status is unknown, first inspect the target locally when possible. If it is still missing or unclear, tell the user and ask them to provide it. At minimum, the modules they care about must have debug info.
- For `ghostscope -p <PID>`, use the PID visible in the same environment where GhostScope runs.
- Do not suggest running GhostScope and GDB against the same target at the same time.

3. Choose the operating mode that matches the task.
- Use `-p <PID>` for one already-running process.
- Use `-t <PATH>` when the user wants startup coverage, wants to trace all processes using a binary or library, or is targeting a shared library explicitly.
- Use `--script-file` for repeatable command-line workflows.
- Use TUI `trace` and `info` commands for interactive exploration.

4. Answer with executable guidance.
- Start with a short capability or constraint summary only when it affects the recommendation.
- If prerequisites are missing, say exactly what is missing first: installation, source path, debug info, or privileges.
- Then give exact shell commands.
- If the user needs TUI interaction, include the minimum command-panel sequence.
- If the user needs a reusable trace file, emit a valid `trace <pattern> { ... }` block.
- If the user needs an inline script body after `trace <target>`, emit only the statements inside the block, not another top-level `trace`.
- When generating a GhostScope trace script and the relevant source path is known, also include the source-backed rationale:
  - quote or summarize the specific function signature, source lines, struct fields, branches, or variables the script depends on
  - explain why each probe target, printed variable, condition, or field access matches that source context
  - make it easy for the user to verify the script against their code instead of only pasting DSL
- If the source path is unknown or the relevant source cannot be inspected after local discovery attempts, say that explicitly before giving the script and ask the user for the checkout path.
- If DWARF or debug info is missing, say that source-backed variable tracing and explanation will be partial or unreliable.
- If the command needs privileges and the user is likely to rerun it, prefer offering either a `setcap` command or a ready-to-run `sudo` wrapper script.

5. Avoid common mistakes.
- Do not invent GhostScope DSL syntax. Validate it against `ghostscope --script-help`, or fall back to `docs/scripting.md` or `docs/zh/scripting.md` only when GhostScope is unavailable.
- Do not guess PID conversions across containers. Follow the current-namespace PID rule from `docs/container.md`.
- Do not overpromise unsupported behavior. Check `docs/limitations.md` for caveats first.
- Do not pretend source-line workflows are fully ready when the source tree path cannot be discovered. Ask the user for the source checkout path instead.
- Do not pretend DWARF-backed variable tracing is ready when the relevant module lacks debug info. Ask the user for the debug-enabled binary or debug file instead.
- For `-t` shared-library targets where new processes must expose globals, mention `--enable-sysmon-shared-lib`.
- When source paths do not resolve, prefer `srcpath map` over telling the user to move files manually.
- When docs and generated examples seem inconsistent, prefer the installed CLI help output from `ghostscope --help` and relevant subcommand help.

6. Prepare issue reports when the problem still looks like a GhostScope bug.
- First rule out missing privileges, missing debug symbols, wrong `-p` PID semantics, and known `-t` shared-library caveats.
- If the user still has an unexplained failure, crash, or incorrect capture result, gather the exact command, trace script, config, source-tree path, debug-file path or debug-symbol status, logs, expected behavior, actual behavior, and environment notes.
- Write the issue draft to `/tmp/ghostscope-issue-*.md` with `scripts/prepare_issue_report.py`.
- Recommend filing it at `https://github.com/swananan/ghostscope/issues`.
- Prefer preparing as much of the issue as possible for the user instead of only telling them to "open an issue".

## References

- Use [doc-map.md](references/doc-map.md) to choose the right docs quickly.
- Use [cli-cookbook.md](references/cli-cookbook.md) for concrete command patterns and common workflows.
- Use [issue-reporting.md](references/issue-reporting.md) for escalation and GitHub issue preparation.

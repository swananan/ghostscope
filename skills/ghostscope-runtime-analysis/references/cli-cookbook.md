# GhostScope CLI Cookbook

Use this file as a set of command templates and diagnostic prompts. Before
answering with exact flags, logging behavior, debug-info search behavior, or DSL
syntax, refresh the facts from the current `ghostscope --help`,
`ghostscope --script-help`, and repository docs. Do not treat this cookbook as a
frozen source of truth.

## Capability Snapshot

Use GhostScope when the user wants low-overhead userspace tracing with DWARF-aware access to locals, parameters, globals, source lines, and function entries without stopping the target process.

## Preconditions To Mention Early

- GhostScope works best when used together with the relevant source tree. If the source checkout path is unknown, first try to discover it from the shared workspace or local filesystem before asking the user.
- Linux and x86_64 only.
- Elevated privileges are usually required. If privileges are not available yet, either grant GhostScope capabilities or prepare a `sudo` wrapper script.
- Target binaries need DWARF debug info or a resolvable separate debug file. Re-check the current install/configuration docs before naming supported separate-debug sources or validation rules. If the user cannot provide debug info for the modules they care about, tell them variable and source-level tracing will not work reliably.
- Verify the current `[dwarf]` search-path behavior before relying on distro debuginfo packages. Current GhostScope docs/config normally include common system debug directories by default, but users can override that list.
- `-p <PID>` means the PID visible where GhostScope is being run.

## Common Workflows

### Install And Verify

```bash
curl -fsSL https://raw.githubusercontent.com/swananan/ghostscope/main/scripts/install.sh | bash
"$HOME/.ghostscope/bin/ghostscope" --version
"$HOME/.ghostscope/bin/ghostscope" --help
export PATH="$HOME/.ghostscope/bin:$PATH"
```

If `ghostscope` is missing, prefer this install flow before anything else.

### Get The Current CLI Flags

```bash
ghostscope --help
ghostscope bpffs prune --help
```

Use installed command help as the source of truth for currently supported flags and subcommands.
If `ghostscope` is unavailable but you are working inside the GhostScope repository, fall back to `docs/configuration.md`.

### Get The Current DSL Reference

```bash
ghostscope --script-help
```

Use this as the source of truth for the currently installed GhostScope script syntax.
If `ghostscope` is unavailable but you are working inside the GhostScope repository, fall back to `docs/scripting.md`.

### Ask For Source And Debug Inputs

Before giving file:line tracing or variable-inspection workflows, confirm:

- source tree path or checkout root
- target executable or shared-library path
- whether the relevant modules have DWARF debug info
- path to a separate debug file when the main binary is stripped
- whether separate debug info should be supplied explicitly with `--debug-file`, discovered from `.gnu_debuglink`, or fetched with debuginfod

Useful checks:

```bash
readelf -S /path/to/your_program | grep debug
readelf -x .gnu_debuglink /path/to/your_program
readelf -n /path/to/your_program | grep 'Build ID'
readelf -S /path/to/your_program.debug | grep .debug_info
```

If the source tree path is still unknown after local discovery, ask the user to provide it. If debug info is missing after local inspection, ask the user to provide a debug-enabled binary or separate debug file for the modules they actually want to trace.

If the current config overrides default search paths or omits a needed
directory, include the relevant directory explicitly:

```toml
[dwarf]
search_paths = ["/usr/lib/debug", "/usr/local/lib/debug"]
```

### Use An Explicit Debug File

```bash
# Bind the debug file to this binary or shared library
sudo ghostscope -t /path/to/your_program \
  --debug-file /path/to/your_program.debug

# Bind the debug file to /proc/<pid>/exe, the main executable
sudo ghostscope -p "$(pidof your_app)" \
  --debug-file /path/to/your_program.debug
```

Before giving these commands, verify the current `--debug-file` binding rules
from `ghostscope --help` and the configuration docs. Do not show
`--debug-file` without also showing which target it binds to.

### Grant GhostScope Privileges

Prefer one of these two approaches:

```bash
sudo setcap cap_sys_admin,cap_sys_ptrace,cap_bpf+eip "$HOME/.ghostscope/bin/ghostscope"
getcap "$HOME/.ghostscope/bin/ghostscope"
```

Or run GhostScope through `sudo` directly:

```bash
sudo "$HOME/.ghostscope/bin/ghostscope" -p "$(pidof your_app)"
```

If the user is going to rerun the same workflow several times, offer a small wrapper script:

```bash
cat >/tmp/run-ghostscope.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec sudo "$HOME/.ghostscope/bin/ghostscope" "$@"
EOF
chmod +x /tmp/run-ghostscope.sh
```

### Attach To One Running Process

```bash
sudo ghostscope -p $(pidof your_app)
```

Use this when the user wants one specific process instance and does not need startup events.

### Trace A Binary Or Shared Library

```bash
sudo ghostscope -t /path/to/binary
sudo ghostscope -t /usr/lib/libexample.so
```

Use this when the user wants startup coverage, multiple instances, or explicit shared-library tracing.

### Run A Reusable Trace File

Create `trace.gs`:

```ghostscope
trace main {
    print "argc={}", argc;
}

trace sample.c:42 {
    print "result={}", result;
}
```

Run it:

```bash
sudo ghostscope -p $(pidof your_app) --script-file trace.gs
```

Prefer `--script-file` over ad hoc inline snippets when the user wants a repeatable command-line workflow.

When you generate a trace file for the user, do not stop at the DSL alone. Also include:

- the relevant source function, line range, or struct fields that the trace depends on
- a short explanation of why the chosen probe target matches that source location
- a short explanation of why each printed variable or field is the right thing to capture

If the source tree path is not known yet, first try to discover it locally. Ask for it only when that discovery fails or the path is still ambiguous.

### Interactive TUI Workflow

Launch:

```bash
sudo ghostscope -p $(pidof your_app)
```

Inspect variables first:

```text
info function main
info line sample.c:42
info address 0x401234
```

Start tracing from the command panel:

```text
trace main
```

Then type only the script body in Script Mode:

```ghostscope
print "argc={}", argc;
```

Do not emit another top-level `trace main { ... }` block when the user is already inside Script Mode.

### Save And Reload Traces

```text
save traces session.gs
source session.gs
```

### Fix Missing Source Paths

If DWARF paths do not match the current machine, prefer:

```text
srcpath map /build/project /home/user/project
```

This is better than telling the user to move source files around.

If the local source path is not yet known, try to discover it first. Ask only when you cannot determine it reliably.

### Shared-Library `-t` With Globals For New Processes

```bash
sudo ghostscope -t /usr/lib/libexample.so --enable-sysmon-shared-lib
```

Mention this only when the user targets a shared library in `-t` mode and needs globals for processes that start after GhostScope.

### Container PID Rule

For `ghostscope -p <PID>`, tell the user to enter the PID visible in the same shell or namespace where GhostScope runs.

Examples:
- Run on host: use the host-visible PID.
- Run inside container: use the container-visible PID.

### Script Output For Automation

```bash
sudo ghostscope -p $(pidof your_app) --script-file trace.gs --script-output plain
```

Use `plain` when the user wants payload-only stdout and less formatting noise.

### Debug Logs For DWARF Or Startup Loading

Verify current logging behavior from `ghostscope --help` and
`docs/configuration.md` first. If script-mode logging is disabled by default,
use forms like:

```bash
sudo ghostscope -p "$(pidof your_app)" \
  --script-file trace.gs \
  --log --log-level debug

sudo env RUST_LOG=debug ghostscope -p "$(pidof your_app)" \
  --script-file trace.gs \
  --log
```

Use the current equivalent of these forms when the user needs full debuglink,
debuginfod, startup load, or module-resolution details.

## High-Value TUI Commands

- `trace <target> [index]`: open Script Mode for a function, line, or address.
- `info function <name>`: show function locations and visible variables.
- `info line <file:line>`: inspect a source line before tracing.
- `info address <addr>`: inspect a module-relative PC.
- `source <file>`: load trace blocks from a file.
- `save traces [file]`: persist current trace definitions.
- `srcpath map <from> <to>`: fix source tree path mismatches.

## Safety And Accuracy Notes

- Do not suggest GhostScope and GDB together on the same target.
- Do not promise write-side behavior; GhostScope is read-only.
- Optimized builds may show variables as optimized out.
- Source-oriented workflows depend on knowing the relevant source tree location, whether discovered locally or provided by the user.
- Variable and source-level tracing depend on debug info for the modules the user cares about.
- Re-check logging behavior before telling the user how to collect debug logs.
- Re-check debug-search behavior before telling the user where GhostScope looks
  for separate debug files.
- For exact script syntax on the installed version, run `ghostscope --script-help`.
- If the user needs exact supported flags, run `ghostscope --help` and relevant subcommand help such as `ghostscope bpffs prune --help`.

## When To Escalate Into A GitHub Issue

Prepare a GitHub issue draft when:
- GhostScope crashes
- GhostScope attaches but does not capture in a way that docs and prerequisites do not explain
- Output is clearly wrong and reproducible
- The user has already checked privileges, debug symbols, and the right PID semantics

When that happens, gather the reproduction artifacts and write them to `/tmp` with the installed skill helper:

```bash
SKILL_DIR="${CODEX_HOME:-$HOME/.codex}/skills/ghostscope-runtime-analysis"
if [[ ! -d "$SKILL_DIR" ]]; then
  SKILL_DIR="${CLAUDE_HOME:-$HOME/.claude}/skills/ghostscope-runtime-analysis"
fi

python3 "$SKILL_DIR/scripts/prepare_issue_report.py" \
  --title "ghostscope crash while tracing sample app" \
  --issue-type crash \
  --ghostscope-command 'sudo ghostscope -p 12345 --script-file /tmp/repro.gs' \
  --mode=-p \
  --target '/usr/bin/sample-app (pid 12345)' \
  --expected 'Attach successfully and print locals' \
  --actual 'Process exits after a segmentation fault' \
  --trace-script-file /tmp/repro.gs \
  --config-file ~/.ghostscope/config.toml \
  --log-file /tmp/ghostscope.log
```

Then recommend filing at `https://github.com/swananan/ghostscope/issues`.

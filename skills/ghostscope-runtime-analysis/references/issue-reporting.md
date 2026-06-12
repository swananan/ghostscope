# GhostScope Issue Reporting

Use this flow when GhostScope crashes, cannot capture as expected, shows obviously wrong output, or appears to hit an unexplained product bug after basic prerequisites have already been checked.

## Gather Before Escalating

- Exact GhostScope command
- Whether the user ran `-p`, `-t`, or `--script-file`
- Target process, executable, or shared library
- Trace script content, whether inline or file-based
- Config file used, especially when `--config` is involved
- Source checkout path or the fact that it is unknown
- Debug-enabled binary path or separate debug-file path for the affected modules
- Debug source status from startup output, including `embedded`, `explicit`,
  `debuglink`, `debuginfod`, `missing`, and any module failures
- DWARF configuration that affects separate debug files, especially
  `[dwarf].search_paths`, `--debug-file`, `--allow-loose-debug-match`, and
  debuginfod settings
- Relevant logs or captured output
- Expected behavior
- Actual behavior or crash text
- Container or WSL context when relevant
- Debug symbol checks when missing capture might be related to DWARF availability

## Prepare The Issue Draft

Use `scripts/prepare_issue_report.py` to write a Markdown draft under `/tmp`:

```bash
SKILL_DIR="${CODEX_HOME:-$HOME/.codex}/skills/ghostscope-runtime-analysis"
if [[ ! -d "$SKILL_DIR" ]]; then
  SKILL_DIR="${CLAUDE_HOME:-$HOME/.claude}/skills/ghostscope-runtime-analysis"
fi

python3 "$SKILL_DIR/scripts/prepare_issue_report.py" \
  --title "cannot capture target locals in -p mode" \
  --issue-type cannot-capture \
  --ghostscope-command 'sudo ghostscope -p 12345 --script-file /tmp/repro.gs' \
  --mode=-p \
  --target '/usr/bin/myapp (pid 12345)' \
  --expected 'Trace attaches and prints local variables' \
  --actual 'Trace compiles but nothing is emitted' \
  --trace-script-file /tmp/repro.gs \
  --config-file ~/.ghostscope/config.toml \
  --log-file /tmp/ghostscope.log \
  --inline-text 'source_root=/home/user/myapp' \
  --inline-text 'debug_file=/usr/lib/debug/usr/bin/myapp.debug' \
  --inline-text 'debug_sources=embedded:1 missing:3' \
  --extra-command 'debug_sections=readelf -S /usr/bin/myapp | grep debug' \
  --extra-command 'ghostscope_version=ghostscope --version'
```

The script prints the generated path, typically `/tmp/ghostscope-issue-YYYYMMDD-HHMMSS.md`.

## Skill Behavior

When issue prep is needed:

1. Rule out obvious non-bug causes first.
- Missing privileges
- Missing debug symbols
- Separate debug files that are present but not reachable because
  `[dwarf].search_paths` omits their directory
- Unknown source tree path for a source-oriented workflow
- Wrong PID namespace assumption for `-p`
- Shared-library `-t` case that actually needs `--enable-sysmon-shared-lib`

2. If the problem still looks like a GhostScope bug, crash, or unexplained failure:
- Generate the `/tmp` report
- Tell the user the report path
- Recommend filing at `https://github.com/swananan/ghostscope/issues`
- Keep the reproduction command and artifacts in the response so the user can paste them directly into the issue

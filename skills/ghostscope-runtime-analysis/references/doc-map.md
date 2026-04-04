# GhostScope Doc Map

## Language Choice

- Prefer English docs under `docs/` for English requests.
- Prefer Chinese docs under `docs/zh/` for Chinese requests.
- Use the Rust CLI definitions in `ghostscope/src/config/args.rs` when you need exact flag names or want to sanity-check docs wording.

## Route By User Intent

### What GhostScope is good at

Use these for capability overviews, tool comparisons, and "should I use GhostScope here?" questions:
- `README.md`
- `docs/comparison.md`
- `docs/faq.md`
- `docs/limitations.md`

Chinese:
- `README-zh.md` when needed
- `docs/zh/comparison.md`
- `docs/zh/faq.md`
- `docs/zh/limitations.md`

Useful search patterns:

```bash
rg -n "When To Use GhostScope|GhostScope vs|Tool Comparison|When Not To Use GhostScope" README.md docs/comparison.md docs/faq.md docs/limitations.md
```

### Install, permissions, and debug symbols

Use these when the user needs setup help before tracing:
- `docs/install.md`
- `docs/configuration.md`

Chinese:
- `docs/zh/install.md`
- `docs/zh/configuration.md`

Useful search patterns:

```bash
rg -n "Quick Install|Configure Permissions|Debug Symbols|script-file|enable-sysmon" docs/install.md docs/configuration.md ghostscope/src/config/args.rs
```

### Launch GhostScope and pick `-p` vs `-t`

Use these when the user needs the right startup command:
- `docs/tutorial.md`
- `docs/configuration.md`
- `docs/container.md` for namespace-sensitive `-p` questions

Chinese:
- `docs/zh/tutorial.md`
- `docs/zh/configuration.md`
- `docs/zh/container.md`

Useful search patterns:

```bash
rg -n "ghostscope -p|ghostscope -t|--script-file|--enable-sysmon-shared-lib|Most Important User Rule" docs/tutorial.md docs/configuration.md docs/container.md ghostscope/src/config/args.rs
```

### TUI commands and interactive workflows

Use these when the user asks about `trace`, `info`, `source`, `save traces`, or `srcpath`:
- `docs/tutorial.md`
- `docs/input-commands.md`
- `docs/tui-reference.md`

Chinese:
- `docs/zh/tutorial.md`
- `docs/zh/input-commands.md`
- `docs/zh/tui-reference.md`

Useful search patterns:

```bash
rg -n "^### trace|^### source|^### info|^### save traces|^### srcpath|^### help" docs/input-commands.md
```

### Writing GhostScope scripts

Use these before generating or validating trace scripts:
- `docs/scripting.md`

Chinese:
- `docs/zh/scripting.md`

Useful search patterns:

```bash
rg -n "^## Trace Statements|^## Variables|^## Special Variables|^## Examples|trace <pattern>" docs/scripting.md
```

### Caveats and troubleshooting

Use these when the user hits runtime issues or asks about unsupported cases:
- `docs/limitations.md`
- `docs/container.md`
- `docs/install.md`

Chinese:
- `docs/zh/limitations.md`
- `docs/zh/container.md`
- `docs/zh/install.md`

### Crash, cannot-capture, and issue preparation

Use these when the user wants a GitHub-ready bug report or the failure still looks unexplained after basic checks:
- `references/issue-reporting.md`
- `docs/install.md`
- `docs/container.md`
- `docs/limitations.md`

Useful search patterns:

```bash
rg -n "Permission Denied|Debug Symbols|Most Important User Rule|Global Variables in -t Mode|Limitations" docs/install.md docs/container.md docs/limitations.md
```

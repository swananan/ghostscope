# dwarf-tool

`dwarf-tool` is a standalone binary that ships with GhostScope for inspecting DWARF information and validating the `ghostscope-dwarf` parser stack. It is useful when debugging symbol resolution without running the full tracing pipeline.

Rust value-adapter diagnostics can be queried from a target binary without
starting the traced process:

```bash
dwarf-tool -t ./target/debug/my-program rust-adapter MY_GLOBAL
```

Add `--json` to inspect the target producer, rustc and DWARF versions, adapter
status, rejection stage and reason, and the selected capture plan.

Usage examples and context can be found in the main documentation: <https://github.com/swananan/ghostscope#readme>.

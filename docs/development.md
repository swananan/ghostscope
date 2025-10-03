# Development Guide

## Prerequisites

- Rust 1.88.0 (enforced via `rust-toolchain.toml`)
- LLVM 18 (including Polly library: `libpolly-18-dev`)
- Linux kernel 4.4+

## Build

```bash
cargo build
```

## Testing

### Integration Tests and Unit Tests

```bash
sudo cargo test
```

### Testing DWARF Parsing with dwarf-tool

GhostScope provides a standalone `dwarf-tool` for testing and debugging DWARF parsing:

```bash
cargo build -p dwarf-tool
```

### Debug Output Files

```bash
# Enable saving intermediate files
cargo run -- --save-llvm-ir --save-ebpf --save-ast

# Files saved as: gs_{pid}_{exec}_{func}_{index}.{ext}
ls gs_*.ll    # LLVM IR files
ls gs_*.ebpf  # eBPF bytecode
ls gs_*.ast   # AST dumps
```

## Code Style

### Rust Guidelines

- Follow standard Rust naming conventions
- Use `cargo fmt` before committing
- Run `cargo clippy` for linting

# Development Guide

## Prerequisites

- Rust 1.88.0 (enforced via `rust-toolchain.toml`)
- Linux kernel 4.4+
- LLVM 18 (including Polly library: `libpolly-18-dev`)

### Setting Up LLVM 18

#### Ubuntu/Debian

```bash
# Add LLVM official repository
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

# For Ubuntu 22.04 (Jammy)
sudo add-apt-repository "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main"

# For Ubuntu 20.04 (Focal)
sudo add-apt-repository "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-18 main"

# For Ubuntu 24.04 (Noble)
sudo add-apt-repository "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-18 main"

# Install LLVM 18 and dependencies
sudo apt-get update
sudo apt-get install -y \
  llvm-18 llvm-18-dev llvm-18-runtime \
  clang-18 libclang-18-dev \
  libpolly-18-dev \
  libzstd-dev zlib1g-dev libtinfo-dev libxml2-dev

# Set environment variable (add to ~/.bashrc for persistence)
export LLVM_SYS_181_PREFIX=/usr/lib/llvm-18

# Verify installation
llvm-config-18 --version
```

#### Troubleshooting

If you encounter `No suitable version of LLVM was found` error during build:

```bash
# Ensure LLVM_SYS_181_PREFIX is set
export LLVM_SYS_181_PREFIX=/usr/lib/llvm-18

# Verify LLVM installation
llvm-config-18 --prefix

# Clean and rebuild
cargo clean
cargo build
```

## Build

### Debug Build (Default)

```bash
# Set LLVM prefix if not in ~/.bashrc
export LLVM_SYS_181_PREFIX=/usr/lib/llvm-18

# Build debug version
cargo build
```

### Release Build

```bash
# Set LLVM prefix if not in ~/.bashrc
export LLVM_SYS_181_PREFIX=/usr/lib/llvm-18

# Build release version
cargo build --release
```

### Docker Build (Recommended for Release)

Build in Ubuntu 20.04 container for maximum compatibility (glibc 2.31):

```bash
# One-command build (automatically creates Docker image if needed)
./docker-build.sh

# Output: ./target/release/ghostscope
```

**Advantages:**
- Builds with glibc 2.31 (compatible with Ubuntu 20.04+, Debian 11+, RHEL 8+)
- Isolated environment, won't affect your system
- Reproducible builds across different development machines

**Other Docker commands:**

```bash
# Build debug version
docker run --rm -v $(pwd):/workspace -w /workspace \
    ghostscope-builder:ubuntu20.04 cargo build

# Interactive shell in container
docker run -it --rm -v $(pwd):/workspace -w /workspace \
    ghostscope-builder:ubuntu20.04 bash

# Rebuild Docker image (only needed if Dockerfile changes)
docker build -t ghostscope-builder:ubuntu20.04 .
```

**Note**: Debug builds are used by default during development for faster iteration and better debugging experience.

### Sysmon eBPF (prebuilt) and when to rebuild

GhostScope ships with prebuilt sysmon eBPF bytecode for both endiannesses. In normal development and usage, you do not need to build sysmon yourself — the build script copies the artifacts from `ghostscope-process/ebpf/obj` into the crate output directory and the runtime automatically selects the correct object by host endianness.

- Prebuilt artifacts (committed):
  - `ghostscope-process/ebpf/obj/sysmon-bpf.bpfel.o` (little‑endian)
  - `ghostscope-process/ebpf/obj/sysmon-bpf.bpfeb.o` (big‑endian)
- Build script behavior: `ghostscope-process/build.rs` copies these into `OUT_DIR`. If either file is missing or invalid, sysmon runs in a stub mode and logs a warning.

Only rebuild sysmon eBPF if you are actively modifying the sysmon program or need to regenerate objects for platform compatibility.

#### Rebuilding sysmon eBPF

Use the helper script:

```
./ghostscope-process/ebpf/build_sysmon_bpf.sh
```

Optional environment variables:

- `TOOLCHAIN` — Rust toolchain for BPF (default: `nightly-2024-07-01`)
- `TARGET` — `bpfel-unknown-none`, `bpfeb-unknown-none`, or `both` (default: `both`)
- `SKIP_RUST_SRC` — set to `1` to skip installing `rust-src`

Outputs are written to:

- `ghostscope-process/ebpf/obj/sysmon-bpf.bpfel.o`
- `ghostscope-process/ebpf/obj/sysmon-bpf.bpfeb.o`

After rebuilding, a regular workspace build will pick up the new objects automatically (the build script copies them to `OUT_DIR`).

## Testing

### Integration Tests and Unit Tests

```bash
sudo cargo test
```

### Agent E2E Runner (Codex)

This runner path is for running e2e from an AI agent environment, where the agent may not be able to execute `sudo cargo test` directly.

The service must be started by the developer manually with `sudo`:

```bash
cd /mnt/500g/code/ghostscope
sudo env HOST=127.0.0.1 PORT=8788 DEFAULT_SUDO=1 DEFAULT_REPO_DIR=/mnt/500g/code/ghostscope ./scripts/e2e/runner/start_e2e_runner_service.sh
```

Then run e2e through the agent wrapper:

```bash
./scripts/e2e/runner/run_e2e_runner.sh
```

Optional variables:

- `E2E_REPO_DIR=/path/to/repo`
- `E2E_TEST_CASE=<cargo_test_filter>`
- `E2E_SUDO=1|0` (default: `1`)

Test-framework environment variables:

- `E2E_GHOSTSCOPE_SANDBOX=host|docker-private|docker-host`
  Controls where GhostScope itself runs in Rust e2e tests. Default: `host`.
- `E2E_TARGET_SANDBOX=host|docker-private|docker-host`
  Controls where the traced target process runs in Rust e2e tests. Default: `host`.
- `E2E_SHARE_SANDBOX=1|0`
  When GhostScope and target use the same sandbox type, reuse a single sandbox for both.
  Default: `0`. This only makes sense when both sides use the same non-host sandbox.
- `E2E_GHOSTSCOPE_LOG_LEVEL=error|warn|info|debug|trace`
  Enables GhostScope logging for direct `cargo test` runs and sets the log level.
  The test helper automatically turns on GhostScope file+console logging when this is set.

To collect GhostScope logs during a direct `cargo test` run, set:

```bash
E2E_GHOSTSCOPE_LOG_LEVEL=debug cargo test --all-features --test script_execution test_correct_pid_filtering -- --nocapture
```

The test helper will enable GhostScope file+console logging automatically for that run.

To configure the runner service per job, submit JSON to `POST /runs` with optional `logging.level`:

```bash
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope",
    "test_case": "test_correct_pid_filtering",
    "logging": {
      "level": "debug"
    },
    "topology": {
      "ghostscope": "host",
      "target": "docker-private",
      "share": false
    }
  }'
```

Supported levels:

- `error`
- `warn`
- `info`
- `debug`
- `trace`

### Container E2E (Docker PID namespace smoke)

Run a focused PID-mode e2e subset in privileged Docker:

```bash
./scripts/e2e/container/run_container_e2e.sh --pid-mode private
./scripts/e2e/container/run_container_e2e.sh --pid-mode host
```

Notes:

- Tests run inside Docker, not on host.
- Default set is PID-focused smoke cases.
- Use `--all` for full `cargo test --all-features` in container.
- Override image with `--image` or `E2E_CONTAINER_IMAGE`.
- Local runs enable Docker volume cache by default (`E2E_USE_DOCKER_CACHE=1`).

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

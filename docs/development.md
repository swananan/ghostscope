# Development Guide

## Prerequisites

- Rust 1.98.0 (enforced via `rust-toolchain.toml`)
- Linux kernel 4.4+
- LLVM 22 (including Polly library: `libpolly-22-dev`)

### Setting Up LLVM 22

#### Ubuntu/Debian

```bash
# Add LLVM official repository
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

# For Ubuntu 22.04 (Jammy)
sudo add-apt-repository "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-22 main"

# For Ubuntu 20.04 (Focal)
sudo add-apt-repository "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-22 main"

# For Ubuntu 24.04 (Noble)
sudo add-apt-repository "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-22 main"

# Install LLVM 22 and dependencies
sudo apt-get update
sudo apt-get install -y \
  llvm-22 llvm-22-dev llvm-22-runtime \
  clang-22 libclang-22-dev \
  libpolly-22-dev \
  libzstd-dev zlib1g-dev libtinfo-dev libxml2-dev

# Set environment variable (add to ~/.bashrc for persistence)
export LLVM_SYS_221_PREFIX=/usr/lib/llvm-22

# Verify installation
llvm-config-22 --version
```

#### Troubleshooting

If you encounter `No suitable version of LLVM was found` error during build:

```bash
# Ensure LLVM_SYS_221_PREFIX is set
export LLVM_SYS_221_PREFIX=/usr/lib/llvm-22

# Verify LLVM installation
llvm-config-22 --prefix

# Clean and rebuild
cargo clean
cargo build
```

## Build

Runtime performance measurements and base/head comparisons are documented in
the [runtime baseline guide](../scripts/runtime-perf/README.md). It covers real
scalar output, complex values, and DWARF backtraces, including target slowdown,
event loss, and userspace RSS. Run measurements separately from ordinary tests
and compilation to avoid measuring host contention.

### Debug Build (Default)

```bash
# Set LLVM prefix if not in ~/.bashrc
export LLVM_SYS_221_PREFIX=/usr/lib/llvm-22

# Build debug version
cargo build
```

### Release Build

```bash
# Set LLVM prefix if not in ~/.bashrc
export LLVM_SYS_221_PREFIX=/usr/lib/llvm-22

# Build release version
cargo build --release
```

### Docker Build (Recommended for Release)

Build and package with the same pinned Ubuntu 20.04 / LLVM 22 image used by CI:

```bash
bash scripts/release/build.sh
python3 scripts/release/smoke_install.py target/dist/*.tar.gz
```

Docker, Python 3, binutils, and the usual shell/archive tools are required on the
host. Build outputs live under `target/release-build`; archives and SHA-256
checksums are written to `target/dist`. Existing debug builds are preserved.

Packaging checks the executable version, x86_64 ELF format, glibc 2.31 ceiling,
and absence of direct shared LLVM/libffi dependencies. CI also runs the packaged
installer, CLI, and a real DWARF parameter tracing smoke test in a privileged
Ubuntu 20.04 container. This checks the userspace baseline with the runner's
kernel; it does not establish compatibility with every supported kernel version.

Before tagging a release:

1. Update the workspace version, internal dependency versions, `Cargo.lock`,
   README badges, and installation examples.
2. Write `docs/releases/v<VERSION>.md` and wait for CI, supply-chain checks,
   and the relevant e2e jobs on the candidate revision.
3. Run **Release Build** manually on the candidate branch and review the archive,
   checksum, installer smoke results, and tracing behavior.
4. Push the matching tag when ready. The workflow rejects a version mismatch,
   builds the assets, and creates a **draft** GitHub Release using the release notes.
5. Review the draft and publish it manually. A manual workflow run builds artifacts
   without creating a release.

The archive contains the executable, English/Chinese config templates, README,
and all project license files. The install smoke test substitutes GitHub download
transport with a local archive; public asset download should be checked after
publication. The installer preserves existing user config files.

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

### Invariant-Oriented Validation

The [Design Guarantees and Trust Model](design-contract.md) defines the behavior
that validation must protect. Tests should prove an observable contract, not
only that a command exits successfully.

| Invariant | Minimum evidence when affected |
|---|---|
| `SCOPE-1` | Build/release target remains Linux x86_64, plus installer and unsupported-target ELF rejection coverage |
| `SAFE-1` | Generated helper/operation review and a verifier-backed load test for new eBPF behavior |
| `IDENT-1` | Positive target attribution and a wrong-PID/module/namespace negative case |
| `SEM-1` | A fixture with an exact source-level value oracle at a known PC, including relevant optimization/module variants |
| `FAIL-1` | A negative fixture that asserts the structured error, unavailable marker, or stop reason |
| `LOSS-1` | Counter propagation and CLI/TUI rendering, plus pressure coverage when transport behavior changes |
| `COST-1` | Boundary/rejection behavior and a verifier-backed load for changed event-size, read, or unwind budgets |

Relevant runtime evidence is organized in `e2e-tests/tests/`: PID filtering in
`script_execution.rs`, namespace behavior in `container_topology_execution.rs`,
PC-context semantics in `member_pointer_compilation.rs`, optimized values in
`optimized_inline_call_value_execution.rs`, structured expression failures in
`globals_execution.rs`, and unwind status/depth in `backtrace_execution.rs`.

For a behavior change, identify the affected invariant in the review or
handoff, run the corresponding positive oracle, and run at least one relevant
failure-path oracle. The test command is evidence only when the asserted output
matches the invariant.

### Workspace Tests

```bash
cargo test --all-features
```

### E2E Tests

```bash
cargo build -p ghostscope -p dwarf-tool --all-features
sudo cargo test -p ghostscope-e2e-tests --tests --all-features -- --nocapture
```

### DWARF Performance Baselines

DWARF parser performance baselines are documented separately under
[`scripts/dwarf-perf/corpus/README.md`](../scripts/dwarf-perf/corpus/README.md).

Use that document for:

- reproducible DWARF perf corpus builds
- `fast parse` benchmark semantics and commands
- `source-line query` benchmark semantics and commands
- output locations for generated corpus artifacts and `perf-results/`

The current published history dashboard is available at
<https://swananan.github.io/ghostscope/>.

### Agent E2E Runner (Codex)

This runner path is for running e2e from an AI agent environment, where the agent may not be able to execute `sudo cargo test -p ghostscope-e2e-tests ...` directly.

The service must be started by the developer manually with `sudo`:

```bash
cd /mnt/500g/code/ghostscope
sudo env HOST=127.0.0.1 PORT=8788 DEFAULT_SUDO=1 DEFAULT_REPO_DIR=/mnt/500g/code/ghostscope ./scripts/e2e/runner/start_e2e_runner_service.sh
```

Then submit e2e runs to the runner service:

```bash
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope"
  }'
```

Optional variables:

- Submit `repo` to override the repository root.
- Submit `test_case` to run a single cargo-test filter.
- Submit `sudo` to control whether the service executes the run with `sudo`.
- The runner service automatically sets `E2E_SANDBOX_SESSION=runner-<job-id>` for each submitted job and performs best-effort cleanup of session-scoped Docker sandboxes after the job finishes.

Test-framework environment variables:

- `E2E_GHOSTSCOPE_SANDBOX=host|docker-private|docker-host`
  Controls where GhostScope itself runs in Rust e2e tests. Default: `host`.
- `E2E_TARGET_SANDBOX=host|docker-private|docker-host`
  Controls where the traced target process runs in Rust e2e tests. Default: `host`.
- `E2E_TARGET_MODE=same|child-container`
  Refines how the target is launched inside the selected target sandbox. Default: `same`.
  `child-container` currently means "launch the target in a nested child container inside the outer `docker-private` sandbox".
- `E2E_RUN_CONTAINER_TOPOLOGY=1`
  Enables the explicit `container_topology_execution` tests. These tests are skipped in routine host-host e2e runs unless this flag is set or a docker-backed `E2E_GHOSTSCOPE_SANDBOX`/`E2E_TARGET_SANDBOX`/`E2E_TARGET_MODE` is requested.
- `E2E_CHILD_CONTAINER_IMAGE=<image-ref>`
  Overrides the image used for nested `child-container` targets. By default it inherits `E2E_CONTAINER_IMAGE`, so the outer sandbox and nested child container use the same runtime image unless you explicitly split them.
- `E2E_GHOSTSCOPE_LOG_LEVEL=error|warn|info|debug|trace`
  Enables GhostScope logging for direct e2e `cargo test` runs and sets the log level.
  The test helper automatically turns on GhostScope file+console logging when this is set.

To collect GhostScope logs during a direct e2e `cargo test` run, set:

```bash
cargo build -p ghostscope -p dwarf-tool --all-features
sudo env \
  E2E_GHOSTSCOPE_LOG_LEVEL=debug \
  cargo test -p ghostscope-e2e-tests --all-features --test script_execution test_correct_pid_filtering -- --nocapture
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
      "target": "docker-private"
    }
  }'
```

Supported levels:

- `error`
- `warn`
- `info`
- `debug`
- `trace`

### Container Topology E2E

Run full e2e for the primary supported container scenarios:

```bash
cargo build -p ghostscope -p dwarf-tool --all-features

sudo env \
  E2E_GHOSTSCOPE_SANDBOX=host \
  E2E_TARGET_SANDBOX=docker-private \
  cargo test -p ghostscope-e2e-tests --all-features -- --nocapture

sudo env \
  E2E_GHOSTSCOPE_SANDBOX=docker-private \
  E2E_TARGET_SANDBOX=docker-private \
  cargo test -p ghostscope-e2e-tests --all-features -- --nocapture

sudo env \
  E2E_GHOSTSCOPE_SANDBOX=docker-private \
  E2E_TARGET_SANDBOX=docker-private \
  E2E_TARGET_MODE=child-container \
  cargo test -p ghostscope-e2e-tests --all-features -- --nocapture
```

Run the PID-focused smoke subset for the host-PID same-sandbox topology:

```bash

for test_case in test_invalid_pid_handling test_correct_pid_filtering test_pid_specificity_with_multiple_processes; do
  sudo env \
    E2E_GHOSTSCOPE_SANDBOX=docker-host \
    E2E_TARGET_SANDBOX=docker-host \
    cargo test -p ghostscope-e2e-tests --all-features --test script_execution "$test_case" -- --nocapture
done
```

Notes:

- These commands keep the Rust test harness on the host and move GhostScope plus the traced target into the requested container sandbox topology.
- When GhostScope and target use the same sandbox kind, the topology-aware e2e helper automatically reuses the same sandbox instance.
- Routine host-host e2e, including the main `CI` workflow, skips the explicit `container_topology_execution` cases by default.
- `host -> docker-private`, `docker-private -> same docker-private`, and `docker-private -> child-container` are the explicit topology scenarios that currently run the full e2e suite in the dedicated `Container E2E` workflow.
- `docker-private -> child-container` uses `E2E_TARGET_MODE=child-container` and launches the target in a nested Docker child container inside the outer private sandbox. The full suite now runs in CI for that topology, but target-mode coverage is still split: nested backtrace `-t` cases run, while `globals_target` nested `-t` cases still follow their explicit skip path.
- `docker-host -> same docker-host` remains a smoke run because it is close to the default host PID view.
- Running the `docker-private` variant usually requires `sudo` because the host-side test harness must inspect the sandbox PID namespace.
- By default the topology-aware e2e framework uses a pinned digest of the dedicated Ubuntu 24.04 runtime image published for container e2e: `ghcr.io/swananan/ghostscope-e2e-runtime@sha256:832c5df935efcd6862e492ac4da2235ef411f494bf66879d737c04d0e96b9bdc`.
- Container e2e uses the dedicated runtime image above; release/containerized builds continue to use the separate `ghostscope-build` base image published from `docker/base-build/Dockerfile`.
- Override the Docker image with `E2E_CONTAINER_IMAGE`. Use this when you explicitly want to test a local image or a pinned digest of the runtime image.
- Nested `child-container` targets inherit `E2E_CONTAINER_IMAGE` by default. Override `E2E_CHILD_CONTAINER_IMAGE` only when you intentionally want a different child image.
- Set `E2E_SANDBOX_SESSION` when you want container-backed tests to reuse the same outer sandbox across separate Rust test binaries or repeated local commands. Remove leftovers with `docker ps -aq --filter "label=ghostscope.session=$E2E_SANDBOX_SESSION" | xargs -r docker rm -f`.
- The helper scripts under `scripts/e2e/container/` default to normal cargo test output capture. Pass `--nocapture` when you explicitly want them to append `-- --nocapture`.
- `E2E_CARGO_NOCAPTURE=1` remains supported as a compatibility fallback, but the script flag is the preferred local workflow.

### Testing DWARF Parsing with dwarf-tool

GhostScope provides a standalone `dwarf-tool` for testing and debugging DWARF parsing:

```bash
cargo build -p dwarf-tool
```

To inspect Rust value-adapter selection for a global or static variable, point
the tool at the target binary rather than GhostScope's own build toolchain:

```bash
cargo run -p dwarf-tool -- \
  -t ./target/debug/my-program \
  rust-adapter MY_GLOBAL
```

The report includes the reconstructed qualified type name, source language,
`DW_AT_producer`, parsed rustc version, DWARF version, selected adapter, and
capture plan. A `rejected` result identifies whether target-layout validation
or read-plan construction failed and describes the unmet DWARF constraints.
Use `--json` for machine-readable output. If a rejected adapter is followed by
a failed ordinary DWARF fallback, the normal CLI and TUI compilation failure
includes the same diagnostic. Successful conservative fallbacks remain quiet
and emit details only through the `ghostscope_dwarf::value_adapter` debug
target:

```bash
RUST_LOG=ghostscope_dwarf::value_adapter=debug \
  cargo run -p ghostscope -- --log ...
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


## ARM64 development VM

ARM64 runtime support is still under development. The VM helper prepares an
independent AArch64 Linux kernel for native eBPF/uprobe tests; preparing
this VM does not establish full ARM64 runtime support. An ARM64
container using user-mode emulation on an x86 kernel is not equivalent.

The host needs `qemu-system-aarch64`, `qemu-img`, AArch64 UEFI firmware, `curl`,
OpenSSH, and Python 3.11 or newer with venv support. Choose a state directory
outside the repository on a disk with enough free space. The 12 GiB guest disk
is a sparse overlay; installing LLVM/Rust and building tests requires additional
physical host disk space. TCG works on x86 without KVM or host sudo, but is slow.

```bash
ARM64_VM_DIR=/path/to/arm64-vm
python3 -m venv "$ARM64_VM_DIR/tools"
"$ARM64_VM_DIR/tools/bin/pip" install pycdlib==1.14.0
"$ARM64_VM_DIR/tools/bin/python" scripts/e2e/vm/arm64_vm.py --state-dir "$ARM64_VM_DIR" prepare
python3 scripts/e2e/vm/arm64_vm.py --state-dir "$ARM64_VM_DIR" start
# Allow several minutes for first boot under TCG; inspect console.log for progress.
python3 scripts/e2e/vm/arm64_vm.py --state-dir "$ARM64_VM_DIR" check
python3 scripts/e2e/vm/arm64_vm.py --state-dir "$ARM64_VM_DIR" ssh
```

The helper pins and verifies an Ubuntu 24.04 minimal ARM64 image, creates a local
SSH key, and forwards host loopback ports 22264 (SSH) and 8789 (guest runner
8788). `check` verifies the guest architecture, cloud-init completion, readable
kernel BTF, BPF/uprobe kernel configuration, and loading a minimal BPF socket
filter. It does not attach a uprobe or execute GhostScope e2e. The helper never starts the runner service.

Inside the VM, copy a source checkout, install the normal project development
dependencies, and build ARM64 fixtures locally. Do not reuse x86 fixture or Cargo
caches. Once the ARM64 runtime is ready, start the runner **manually** in the guest:

```bash
cd /path/to/ghostscope
sudo env HOST=0.0.0.0 ./scripts/e2e/runner/start_e2e_runner_service.sh
```

Then use the existing runner API at `http://127.0.0.1:8789` on the host, with the
repository path **inside the guest**. Standard project `cargo test` commands
remain unchanged. Shut down the VM with:

```bash
python3 scripts/e2e/vm/arm64_vm.py --state-dir "$ARM64_VM_DIR" stop
```

ARM64 source builds are experimental. The build now permits Linux AArch64 and
requires target ELF files to match that architecture. DWARF backtraces and
executable static TLS are supported. For cross compilation, set `AYA_BPF_TARGET_ARCH=aarch64`
in addition to the Cargo target and cross linker: Aya's bindings otherwise
follow the build host. LLVM headers/configuration and linked libraries must be
compatible, and linked LLVM libraries must be ARM64. Never link the host's x86
LLVM archives into an ARM64 executable. Native builds use the usual commands.

### ARM64 CI coverage

`.github/workflows/arm64-e2e.yml` runs on `ubuntu-24.04-arm`, checks the native
kernel and BPF syscall, and builds the fixture compiler and topology runtime
images from the checkout. It uses local image tags, so PR validation does not
require publishing images or replacing the existing x86 pinned digests. The
manual image publishing workflows also build `linux/amd64,linux/arm64` manifests.
Cargo caches include `runner.arch`; ARM fixtures are rebuilt inside the native
compiler image rather than restored from an x86 fixture archive.

Clang 18 does not support basic-block sections on ARM64. For its indexed-range
fixture, `arm64_rnglistx.py` preserves native instructions, line tables, variable
locations, and types, and substitutes indexed, reordered function ranges with
an explicit entry PC. GCC still provides a naturally partitioned ARM64 fixture.
Both cases retain their range-encoding and runtime assertions. The fixture
compiler and native test host need `python3-pyelftools` for this transformation.

The ARM workflow runs host and host-to-private-container e2e as two parallel
matrix jobs with independent runners and `fail-fast: false`. Each job compiles
the full fixture set and Rust compatibility matrix and builds the CLI and
`dwarf-tool`. The host job also runs lint, platform/process unit tests, and
compiler architecture tests; only the container job builds the topology runtime
image. Both jobs reuse the Cargo and fixture-image caches, with only the host
job exporting the shared fixture-image cache. Each job runs its corresponding
ordinary e2e command:

```bash
sudo -E "$(which cargo)" test -p ghostscope-e2e-tests --all-features \
  --tests -- --nocapture

sudo -E env \
  E2E_CONTAINER_IMAGE=ghostscope-e2e-runtime:arm64-ci \
  E2E_GHOSTSCOPE_SANDBOX=host E2E_TARGET_SANDBOX=docker-private \
  E2E_TARGET_MODE=same \
  "$(which cargo)" test -p ghostscope-e2e-tests --all-features \
  --tests -- --nocapture
```

The architecture suite requires real events and checks eight scalar arguments,
global data, PC/SP against the target's mappings, O0/O2, PIE/non-PIE, PID/path
attachment, and the perf-event-array transport. On ARM64 it also checks LR-based
backtraces and executable TLS values. PAC fixtures cover A-key and B-key signed
return addresses, entry parameters, and complete stacks through both inline and
tail-call unwinding. Signed CFI rows strip PAC bits using the native instruction
address mask; unsigned rows retain the usual invalid-address checks. The startup suite covers native
ELF validation and debug-source reporting. The same portable architecture suite
runs in the existing x86 standard and container jobs. In the nested
child-container topology, the path-only globals case follows the existing
unsupported-topology exclusion; all PID-scoped architecture cases still run.

The full e2e suite includes backtraces, multithreaded TLS, and compiler-version
compatibility coverage. Shared-library/dynamic TLS retains the same explicit
limitation as x86. No `continue-on-error` or missing-privilege skips are used
in the architecture suite. A local QEMU system VM can run the same native test
binaries, but user-mode emulation on an x86 kernel cannot validate this contract.

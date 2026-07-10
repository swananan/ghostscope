# 开发指南

## 前置要求

- Rust 1.88.0（通过 `rust-toolchain.toml` 强制指定）
- Linux 内核 4.4+
- LLVM 18（包括 Polly 库：`libpolly-18-dev`）

### 设置 LLVM 18

#### Ubuntu/Debian

```bash
# 添加 LLVM 官方仓库
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -

# Ubuntu 22.04 (Jammy)
sudo add-apt-repository "deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-18 main"

# Ubuntu 20.04 (Focal)
sudo add-apt-repository "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-18 main"

# Ubuntu 24.04 (Noble)
sudo add-apt-repository "deb http://apt.llvm.org/noble/ llvm-toolchain-noble-18 main"

# 安装 LLVM 18 及依赖
sudo apt-get update
sudo apt-get install -y \
  llvm-18 llvm-18-dev llvm-18-runtime \
  clang-18 libclang-18-dev \
  libpolly-18-dev \
  libzstd-dev zlib1g-dev libtinfo-dev libxml2-dev

# 设置环境变量（添加到 ~/.bashrc 以持久化）
export LLVM_SYS_181_PREFIX=/usr/lib/llvm-18

# 验证安装
llvm-config-18 --version
```

#### 故障排查

如果构建时遇到 `No suitable version of LLVM was found` 错误：

```bash
# 确保设置了 LLVM_SYS_181_PREFIX
export LLVM_SYS_181_PREFIX=/usr/lib/llvm-18

# 验证 LLVM 安装
llvm-config-18 --prefix

# 清理并重新构建
cargo clean
cargo build
```

## 构建

### Debug 构建（默认）

```bash
# 如果未在 ~/.bashrc 中设置，需要先设置 LLVM 前缀
export LLVM_SYS_181_PREFIX=/usr/lib/llvm-18

# 构建 debug 版本
cargo build
```

### Release 构建

```bash
# 如果未在 ~/.bashrc 中设置，需要先设置 LLVM 前缀
export LLVM_SYS_181_PREFIX=/usr/lib/llvm-18

# 构建 release 版本
cargo build --release
```

### Docker 构建（推荐用于 Release）

在 Ubuntu 20.04 容器中构建，获得最大兼容性（glibc 2.31）：

```bash
# 一键构建（如需要会自动创建 Docker 镜像）
./docker-build.sh

# 输出：./target/release/ghostscope
```

**优势：**
- 使用 glibc 2.31 构建（兼容 Ubuntu 20.04+、Debian 11+、RHEL 8+）
- 隔离环境，不影响系统
- 在不同开发机器上可复现构建

**其他 Docker 命令：**

```bash
# 构建 debug 版本
docker run --rm -v $(pwd):/workspace -w /workspace \
    ghostscope-builder:ubuntu20.04 cargo build

# 进入容器交互式环境
docker run -it --rm -v $(pwd):/workspace -w /workspace \
    ghostscope-builder:ubuntu20.04 bash

# 重新构建 Docker 镜像（仅在 `docker/base-build/Dockerfile` 修改后需要）
docker build -t ghostscope-builder:ubuntu20.04 -f docker/base-build/Dockerfile .
```

**注意**：开发过程中默认使用 debug 构建，以获得更快的迭代速度和更好的调试体验。


### Sysmon eBPF（已预编译）与脚本使用

仓库内已预编译并提交了 sysmon 的 eBPF 字节码（同时包含大小端）。正常开发与使用场景下，无需自行编译 sysmon。构建时，`ghostscope-process/build.rs` 会将预编译产物从 `ghostscope-process/ebpf/obj` 拷贝到 crate 的 `OUT_DIR`，运行时会根据宿主机端序自动选择对应的对象文件。

- 预编译产物（已提交）：
  - `ghostscope-process/ebpf/obj/sysmon-bpf.bpfel.o`（小端）
  - `ghostscope-process/ebpf/obj/sysmon-bpf.bpfeb.o`（大端）
- 构建脚本行为：若文件缺失或无效，sysmon 只会打印告警，不会导致构建失败。

仅当你需要修改 sysmon eBPF 程序本身，或为特定平台/兼容性需求重新生成字节码时，才需要手动重新编译。

#### 重新编译 sysmon eBPF

使用辅助脚本：

```
./ghostscope-process/ebpf/build_sysmon_bpf.sh
```

可选环境变量：

- `TOOLCHAIN` — BPF 构建所用的 Rust 工具链（默认：`nightly-2024-07-01`）
- `TARGET` — `bpfel-unknown-none`、`bpfeb-unknown-none` 或 `both`（默认：`both`）
- `SKIP_RUST_SRC` — 置为 `1` 时跳过安装 `rust-src`

输出文件位于：

- `ghostscope-process/ebpf/obj/sysmon-bpf.bpfel.o`
- `ghostscope-process/ebpf/obj/sysmon-bpf.bpfeb.o`

重新编译后，正常工作区构建会自动拾取这些新产物（由构建脚本复制到 `OUT_DIR`）。

## 测试

### 面向不变量的验证

[设计保证与可信性模型](design-contract.md)定义验证必须保护的行为。测试需要证明可观测契约，而不能只证明命令成功退出。

| 不变量 | 受影响时的最低证据要求 |
|---|---|
| `SCOPE-1` | 构建/发布目标仍是 Linux x86_64，并覆盖安装器和不支持目标 ELF 的拒绝路径 |
| `SAFE-1` | 审查新增的 helper/操作，并为新的 eBPF 行为提供经过 verifier 的加载测试 |
| `IDENT-1` | 正向目标归因，以及错误 PID/模块/namespace 的负向场景 |
| `SEM-1` | 在已知 PC 上使用具有精确源码级值 oracle 的 fixture，并覆盖相关优化或模块变体 |
| `FAIL-1` | 使用负向 fixture 断言结构化错误、不可用标记或停止原因 |
| `LOSS-1` | 验证计数传递和 CLI/TUI 展示；传输行为变化时补充压力覆盖 |
| `COST-1` | 验证边界/拒绝行为，并为事件大小、读取或 unwind 预算变化提供经过 verifier 的加载测试 |

主要运行时证据位于 `e2e-tests/tests/`：`script_execution.rs` 覆盖 PID 过滤，`container_topology_execution.rs` 覆盖 namespace 行为，`member_pointer_compilation.rs` 覆盖 PC 上下文语义，`optimized_inline_call_value_execution.rs` 覆盖优化代码中的值，`globals_execution.rs` 覆盖结构化表达式失败，`backtrace_execution.rs` 覆盖 unwind 状态与深度。

行为变化需要在 review 或交接说明中指出受影响的不变量，运行对应的正向 oracle，并至少运行一个相关失败路径 oracle。只有断言结果与不变量一致时，测试命令才构成有效证据。

### Workspace 测试

```bash
cargo test --all-features
```

### E2E 测试

```bash
cargo build -p ghostscope -p dwarf-tool --all-features
sudo cargo test -p ghostscope-e2e-tests --tests --all-features -- --nocapture
```

### DWARF 性能基线

DWARF 解析性能基线的完整说明单独放在
[`scripts/dwarf-perf/corpus/README.md`](../../scripts/dwarf-perf/corpus/README.md)。

这里建议把它作为入口索引，具体细节都以该文档为准，包括：

- 可复现的 DWARF perf corpus 构建方式
- `fast parse` 基线的语义和执行命令
- `source-line query` 基线的语义和执行命令
- 生成产物目录和 `perf-results/` 结果目录

当前已经发布的历史页面地址是：
<https://swananan.github.io/ghostscope/>。

### Agent E2E Runner（Codex）

该流程用于在 AI agent 环境中执行 e2e，目的是规避 agent 无法直接执行 `sudo cargo test -p ghostscope-e2e-tests ...` 的限制。

`runner service` 需要开发者自行使用 `sudo` 启动：

```bash
cd /mnt/500g/code/ghostscope
sudo env HOST=127.0.0.1 PORT=8788 DEFAULT_SUDO=1 DEFAULT_REPO_DIR=/mnt/500g/code/ghostscope ./scripts/e2e/runner/start_e2e_runner_service.sh
```

启动后，通过 runner service 直接提交 e2e：

```bash
curl -sS -X POST http://127.0.0.1:8788/runs \
  -H 'Content-Type: application/json' \
  -d '{
    "sudo": true,
    "repo": "/mnt/500g/code/ghostscope"
  }'
```

可选变量：

- `repo`：覆盖仓库根目录
- `test_case`：指定单个 cargo test filter
- `sudo`：控制 service 是否用 `sudo` 执行该次运行
- runner service 会为每个提交的 job 自动设置 `E2E_SANDBOX_SESSION=runner-<job-id>`，并在 job 结束后尽力清理该 session 对应的 Docker sandbox。

测试框架级环境变量：

- `E2E_GHOSTSCOPE_SANDBOX=host|docker-private|docker-host`
  控制 Rust e2e 里 GhostScope 自己运行在哪个环境。默认：`host`。
- `E2E_TARGET_SANDBOX=host|docker-private|docker-host`
  控制 Rust e2e 里被追踪目标进程运行在哪个环境。默认：`host`。
- `E2E_TARGET_MODE=same|child-container`
  进一步描述目标进程在所选 target sandbox 里的启动方式。默认：`same`。
  目前 `child-container` 专指“在外层 `docker-private` sandbox 里再起一个子容器来运行目标进程”。
- `E2E_RUN_CONTAINER_TOPOLOGY=1`
  启用显式的 `container_topology_execution` 测试。常规 host-host e2e 默认跳过这些用例；只有设置该变量，或显式请求 docker-backed `E2E_GHOSTSCOPE_SANDBOX`/`E2E_TARGET_SANDBOX`/`E2E_TARGET_MODE` 时才会运行。
- `E2E_CHILD_CONTAINER_IMAGE=<image-ref>`
  覆盖 nested `child-container` 目标使用的镜像。默认会继承 `E2E_CONTAINER_IMAGE`，也就是外层 sandbox 和子容器默认共用同一张 runtime 镜像，除非你显式指定不同镜像。
- `E2E_GHOSTSCOPE_LOG_LEVEL=error|warn|info|debug|trace`
  为直接执行的 e2e `cargo test` 打开 GhostScope 日志并设置日志级别。
  设置该变量后，测试 helper 会自动启用 GhostScope 的文件日志和控制台日志。

如果要在直接执行 e2e `cargo test` 时收集 GhostScope 日志，可设置：

```bash
cargo build -p ghostscope -p dwarf-tool --all-features
sudo env \
  E2E_GHOSTSCOPE_LOG_LEVEL=debug \
  cargo test -p ghostscope-e2e-tests --all-features --test script_execution test_correct_pid_filtering -- --nocapture
```

测试 helper 会在该次运行里自动打开 GhostScope 的文件日志和控制台日志。

如果要按单次 job 配置 runner service，可向 `POST /runs` 提交带 `logging.level` 的 JSON：

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

支持的日志级别：

- `error`
- `warn`
- `info`
- `debug`
- `trace`

### 容器拓扑 E2E

通过 topology-aware Rust e2e 框架，对当前主要支持的容器场景运行全量 e2e：

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

`docker-host` 同 sandbox 的场景继续保留聚焦 `-p` 的 smoke 用例：

```bash

for test_case in test_invalid_pid_handling test_correct_pid_filtering test_pid_specificity_with_multiple_processes; do
  sudo env \
    E2E_GHOSTSCOPE_SANDBOX=docker-host \
    E2E_TARGET_SANDBOX=docker-host \
    cargo test -p ghostscope-e2e-tests --all-features --test script_execution "$test_case" -- --nocapture
done
```

说明：

- Rust 测试 harness 仍运行在宿主机上，GhostScope 和目标进程会按指定拓扑进入对应容器 sandbox。
- 当 GhostScope 和目标使用同一种 sandbox 类型时，topology-aware e2e helper 会自动复用同一个 sandbox 实例。
- 常规 host-host e2e，包括主 `CI` workflow，默认跳过显式的 `container_topology_execution` 用例。
- `host -> docker-private`、`docker-private -> same docker-private` 和 `docker-private -> child-container` 是当前在独立 `Container E2E` workflow 中按显式 topology 跑全量 e2e 的容器场景。
- `docker-private -> child-container` 通过 `E2E_TARGET_MODE=child-container` 启用，表示目标进程运行在外层 private sandbox 里再启动的子容器中。这个拓扑现在已经进入 full-CI 矩阵，但 target-mode 覆盖仍是分开的：nested backtrace `-t` 用例会运行，而 `globals_target` nested `-t` 用例仍沿用显式跳过路径。
- `docker-host -> same docker-host` 仍保留为 smoke，因为它更接近默认的 host PID 视角。
- `docker-private` 这一组通常需要 `sudo`，因为宿主机上的测试 harness 需要检查该 sandbox 的 PID namespace。
- topology-aware e2e 默认使用专门给容器 e2e 发布的 Ubuntu 24.04 runtime 镜像的固定 digest：`ghcr.io/swananan/ghostscope-e2e-runtime@sha256:d5df1b977c38f7a51bbf28b878f2246705a05b83ac6df7cb6be8f8a4de4105f4`。
- 容器 e2e 使用上面的 runtime 镜像；release / 容器化构建则继续使用从 `docker/base-build/Dockerfile` 发布出来的独立 `ghostscope-build` 基础镜像。
- 可通过 `E2E_CONTAINER_IMAGE` 覆盖容器镜像；只有在你明确想测试本地镜像或某个固定 digest 时，才建议手动改这个变量。
- nested `child-container` 默认会继承 `E2E_CONTAINER_IMAGE`。只有在你明确想让子容器使用不同镜像时，才需要额外设置 `E2E_CHILD_CONTAINER_IMAGE`。
- 如果你想让容器类测试在不同 Rust test binary 或多次本地命令之间复用同一个外层 sandbox，可显式设置 `E2E_SANDBOX_SESSION`。跑完后可用 `docker ps -aq --filter "label=ghostscope.session=$E2E_SANDBOX_SESSION" | xargs -r docker rm -f` 清理残留容器。
- `scripts/e2e/container/` 下的辅助脚本默认沿用 cargo test 的正常输出捕获；只有在你明确传 `--nocapture` 时，才会额外追加 `-- --nocapture`。
- `E2E_CARGO_NOCAPTURE=1` 仍然保留为兼容性兜底，但本地调试时更推荐直接用脚本参数。

### 使用 dwarf-tool 测试 DWARF 解析

GhostScope 提供了一个独立的 `dwarf-tool` 用于测试和调试 DWARF 解析：

```bash
cargo build -p dwarf-tool
```

### Debug 输出文件

```bash
# 启用保存中间文件
cargo run -- --save-llvm-ir --save-ebpf --save-ast

# 文件保存为：gs_{pid}_{exec}_{func}_{index}.{ext}
ls gs_*.ll    # LLVM IR 文件
ls gs_*.ebpf  # eBPF 字节码
ls gs_*.ast   # AST 转储
```

## 代码风格

### Rust 指南

- 遵循标准 Rust 命名约定
- 提交前使用 `cargo fmt`
- 运行 `cargo clippy` 进行 lint 检查

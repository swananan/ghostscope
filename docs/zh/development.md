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

# 重新构建 Docker 镜像（仅在 Dockerfile 修改后需要）
docker build -t ghostscope-builder:ubuntu20.04 .
```

**注意**：开发过程中默认使用 debug 构建，以获得更快的迭代速度和更好的调试体验。

## 测试

### 集成测试和 UT
sudo cargo test

### 使用 dwarf-tool 测试 DWARF 解析

GhostScope 提供了一个独立的 `dwarf-tool` 用于测试和调试 DWARF 解析：

cargo build -p dwarf-tool

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

# 开发指南

## 前置要求

- Rust 1.88.0（通过 `rust-toolchain.toml` 强制指定）
- Linux 内核 4.4+

## 构建

cargo build

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

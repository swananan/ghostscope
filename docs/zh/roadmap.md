# GhostScope 路线图（里程碑）

GhostScope 仍处在快速演进阶段，以下里程碑按照“优先修补基础能力 → 打磨使用体验 → 拓展更多语言与部署形态”的顺序规划。

## 链式数组访问与动态下标
- 先解锁 `a.b[idx].c` 这类链式访问的常量下标能力。
- 在验证 eBPF 验证器限制后，逐步引入表达式/动态下标，确保性能与安全达标。

## 容器追踪增强
- 容器（Docker/WSL 等）环境下的 `-p <pid>` 模式仍存在软限制，详见[限制列表](limitations.md#9-容器-wsl-场景下--pid-pid-模式的软限制)。
- 待核心能力稳定后，会评估如何改进在这些隔离场景中的兼容性。

## 栈回溯（Stack Unwinding）
- 在每个追踪点捕获完整调用栈，基于 `.eh_frame`/`.eh_frame_hdr` 信息做好解析。
- 结合符号/源信息，TUI 中提供直观的栈帧浏览。  
  参考资料：[Unwinding the stack the hard way](https://lesenechal.fr/en/linux/unwinding-the-stack-the-hard-way#h5.1-parsing-eh_frame-and-eh_frame_hdr-with-gimli)

## 稳定性与准确性
- 作为调试工具，持续修复缺陷、改进错误处理，确保数据一致性。
- 加强自动化测试与回归验证，让关键路径“可依赖”。

## 利用 bpftime 优化性能
- 评估从内核 uprobe 迁移到用户态 eBPF（[bpftime](https://github.com/eunomia-bpf/bpftime)）的可行性。
- 目标是降低上下文切换与 probe 开销，为高频追踪提供更好的采样能力。

## 高级语言特性
- 编译型语言方向：优先支持 Rust 的 async/trait 对象等高级语义。
- 解释型语言方向：探索与 Lua 等运行时协同抓取变量/栈信息的方案。

## Client-Server 调用模式
- 典型场景：代码与调试信息在云端，目标二进制运行在测试机或本地。
- 规划让 GhostScope TUI 仅运行在控制端，eBPF Agent 独立驻留在目标主机，参考 `gdb/gdbserver` 模式。
- 待核心能力稳定后再启动该特性，以免分散目前的开发精力。

# GhostScope 路线图（里程碑）

GhostScope 仍处在快速演进阶段，以下里程碑按照“优先修补基础能力 → 打磨使用体验 → 拓展更多语言与部署形态”的顺序规划。

## 链式数组访问
- 一维链式数组访问已经支持常量下标与表达式下标，包括链尾 `a.b.c[i]`、链中间 `a.b[i].c`，以及 `&arr[i]` 这类取地址形式。
- 后续工作主要集中在多维数组访问。

## 容器追踪增强
- `-p` 模式下，大部分容器 PID 追踪场景已经到位。
- 当前已验证覆盖的场景包括：
  - 宿主机 -> private PID namespace 容器
  - private PID namespace 容器 -> 同一个 private PID namespace
  - private PID namespace 容器 -> 嵌套子容器
  - `--pid=host` 容器 -> 同一 host PID 视角（smoke）
- 剩余里程碑已经收窄为：
  - 补强跨 PID namespace 的 `-t` 生命周期维护，尤其是 host -> private container 这类场景
  - 继续收敛 helper 可用性与 PID 映射仍属软限制的边界情况
  - WSL 目前仍不在支持范围内
- 详见[容器支持与限制](container.md)和[限制列表](limitations.md#10-容器-wsl-场景下--pid-pid-模式的软限制)。

## Uprobe 增强
- 支持 sleepable uprobe（`uprobe.s` / `uretprobe.s`），在合适场景下使用可睡眠 helper，尤其提升用户态内存读取的可靠性。
- 支持 multi-attach uprobe（`uprobe.multi` / `uretprobe.multi`），让脚本展开出大量探针点时仍能保持更好的扩展性。
- 对暂时只能走普通 `uprobe` 的内核或 libbpf/Aya 路径保留兼容性回退。

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

# GhostScope 的限制

## 硬性限制

### 1. 权限需求
eBPF 底层机制要求提升的权限以访问内核追踪基础设施，需要 root 权限或 CAP_BPF/CAP_SYS_ADMIN 能力。

### 2. 不要与 GDB 同时使用
uprobe 和 GDB 都会修改目标进程的指令（插入断点），同时使用可能导致冲突和不可预测的行为。

### 3. 只读访问，不可修改程序行为
虽然 eBPF 在技术上支持一定程度上修改进程行为，但是 GhostScope 设计为只读工具，无法修改程序状态、变量值或控制流。这确保了在生产环境中的安全性。

### 4. 平台支持
目前仅支持 **Linux** 操作系统，因为核心技术依赖 **eBPF** 和 **uprobe**。

## 软性限制

### 1. 语言支持
目前主要支持 **C 语言**，对 C 的端到端支持最完善。**C++** 和 **Rust** 目前属于更偏“按 DWARF 布局访问”的有限支持：GhostScope 支持对函数名以及全局/静态符号做自动 demangle，但大多数语言特性还没有建模。实际使用中，越接近 C 风格的数据布局越容易成功；Rust 和 C++ 的高级特性仍需要后续大量补强。

对于解释型语言（Lua、Python、Ruby 等），目前只能追踪解释器本身（因为解释器通常用编译型语言实现）。追踪脚本代码在技术上可行，但需要大量开发时间，JIT 语言支持计划就更远了。

### 2. 架构支持
目前仅支持 **x86_64 (AMD64)** 架构。其他平台（如 ARM64）技术上可行，但需要投入时间适配和测试。

### 3. 通过 `bpf_probe_read_user` 读取用户内存
在传统的非 sleepable probe 路径里，`bpf_probe_read_user` 这类 helper 仍然不能处理用户态缺页，因此当目标虚拟地址对应的页面尚未驻留，或访问时会触发 fault，读取就可能失败。

但这已经不是 eBPF 的绝对硬限制。Linux 已支持 sleepable uprobe（`uprobe.s` / `uretprobe.s`），而 sleepable 程序可以使用 `bpf_copy_from_user_task()` 之类的 helper 执行可睡眠的用户态内存读取。GhostScope 当前仍生成普通 `uprobe` 程序，所以现阶段它在实践中仍然是个限制；但更准确地说，这属于实现层面的软限制，而不是 eBPF 的根本设计上限。

**参考**：
- https://lists.iovisor.org/g/iovisor-dev/topic/accessing_user_memory_and/21386221
- https://docs.kernel.org/bpf/libbpf/program_types.html
- https://man7.org/linux/man-pages/man7/bpf-helpers.7.html

### 4. 性能影响
基于 uprobe 的实现，每次探针触发会产生一次上下文切换开销以及 eBPF 程序执行时间。如果探针设置在热点路径上，可能对被监测进程造成明显的性能影响，使用时需要谨慎。

### 5. 事件丢失（背压）
使用 ring buffer 在 eBPF 程序和用户态之间传递事件。如果事件产生速率过快，超过用户态消费能力，内核会丢弃事件，导致追踪数据缺失。目前 GhostScope 的错误提示还不够完善（后面会学习 bpftrace 是怎么处理这种的），建议避免在高频路径上设置过多探针。

### 6. DWARF 支持范围
主要测试和验证了 DWARF 5 格式。理论上支持 DWARF 2-5，但其他版本可能存在兼容性问题。部分 DWARF 表达式指令暂不支持转换为 eBPF（纯实现还没有支持的原因），遇到时会给出明确的错误提示。

### 7. 高度优化代码的支持
编译器优化（-O2、-O3）会导致变量被优化掉或生成复杂的 DWARF 表达式。GhostScope 会尽力解析，包括内联函数的支持，但部分变量可能无法访问（显示为 OptimizedOut），这是因为编译器优化掉了。

### 8. 动态加载库（dlopen）
GhostScope 启动时会扫描进程的 `/proc/PID/maps` 获取已加载的动态库信息。只要在 `dlopen` 之后启动 GhostScope，就可以正常追踪。后续计划支持动态监控进程的 `dlopen` 行为，提供更好的体验。

### 9. -t 模式下的全局变量支持

- **可执行目标**：当 `-t` 指向可执行文件（`-t /path/to/app`）时，会以该二进制作为主模块，默认支持全局变量。
- **共享库目标（已有进程）**：若 GhostScope 启动时，目标库已经被现有进程加载，例如追踪一个已运行但早先加载好 `libfoo.so` 的进程，能够直接解析全局变量。
- **共享库目标（新启动进程）**：如果目标进程在 GhostScope 启动之后才运行，为确保全局变量可用，需要开启 `--enable-sysmon-shared-lib`（或在配置文件中启用）。该功能会带来额外的系统负载，进程频繁启动/退出的环境下开销会更明显。
- **限定 PID 的目标模式（`-t ... -p ...`）**：不需要也不会启动 sysmon。`-t` 决定函数/源码行/地址目标解析使用哪个模块，`-p` 提供具体进程映射和 PID 过滤。

提示：`-p <pid>` 模式下仍会自动计算并下发模块偏移，全局变量始终可用。

> **说明**：目前 sysmon 假设共享库在 exec 事件处理时已经映射；若动态加载发生得更晚，目前不会自动重试。

### 10. 线程局部存储（TLS）变量

线程局部变量不是普通全局变量：每个线程都有一份独立实例。Static TLS 变量是当前支持的子集：当编译器/调试信息把它表示成当前线程内可固定寻址的 TLS 位置，并且 GhostScope 能针对目标架构降为 eBPF 读取计划时支持。

共享库中的 dynamic TLS 目前尚不支持，包括 ELF `general-dynamic` 或 `local-dynamic` TLS 模型下的变量，例如很多共享库里的 `__thread` 变量和 Rust `thread_local!` 值。

GhostScope 不能把这类变量解析成 `module_base + symbol_offset`，因为这样可能读到错误地址。正确的 dynamic TLS 解析需要从当前线程的 thread pointer 出发，沿运行时 DTV（dynamic thread vector）找到对应模块的 TLS block，再叠加变量偏移。GhostScope 当前不会在目标进程内调用 `__tls_get_addr()`，也不会复刻 libc / 动态链接器的这条查找路径。

如果检测到 TLS 变量但当前无法建模，应当将其视为不支持或不可用，而不是按普通全局变量处理。

### 11. 容器 / WSL 场景下 `-p <pid>` 模式的软限制

- 容器 / WSL 场景、PID namespace 术语、场景矩阵，以及当前实现限制的完整说明，见 [容器环境](container.md)。
- 参考 [PID namespaces 手册](https://www.man7.org/linux/man-pages/man7/pid_namespaces.7.html)、[WSL issue #12408](https://github.com/microsoft/WSL/issues/12408) 和 [WSL issue #12115](https://github.com/microsoft/WSL/issues/12115)。

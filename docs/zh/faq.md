# 常见问题

## 什么是 GhostScope？

GhostScope 是一个基于 eBPF 的运行时追踪器，允许你在不修改源代码、不重新编译、不重启进程的情况下，实时观察和分析运行中的应用程序。可以把它理解为生产系统的"printf 调试"工具。

## GhostScope 与 GDB 有什么区别？

请看 [工具对比 - GhostScope vs GDB](comparison.md#ghostscope-vs-gdb)。
如果你还想看同一类观测任务下的实测稳态开销，也可以继续看 [GhostScope vs GDB 实测性能快照](comparison.md#ghostscope-vs-gdb-实测性能快照)。

## perf probe 与 GhostScope 有什么区别？

请看 [工具对比 - GhostScope vs perf probe](comparison.md#ghostscope-vs-perf-probe)。

## bpftrace 与 GhostScope 有什么区别？

请看 [工具对比 - GhostScope vs bpftrace](comparison.md#ghostscope-vs-bpftrace)。

## SystemTap 与 GhostScope 有什么区别？
请看 [工具对比 - GhostScope vs SystemTap](comparison.md#ghostscope-vs-systemtap)。

## perf、GDB、SystemTap、bpftrace 以及 GhostScope 使用场景选择
请看 [工具对比 - 快速选择](comparison.md#快速选择) 和 [工具对比 - 到底该怎么选](comparison.md#到底该怎么选)。

## 什么是调试信息，Release 版本可以使用 GhostScope 吗

- 调试信息是什么
  - 指 DWARF `.debug_*` 段，包含“源码行表、类型信息、变量/参数/全局变量的 DWARF 位置表达式、内联/优化元数据”等。它与导出符号表不同，GhostScope 依赖它来做“源码行/指令级附着”和“变量位置求值+读值”。

- Release 能用吗
  - 可以。Release 版本只是可能使用了更高级别的编译器优化选项，并不代表不存在调试信息。换句话说，只要目标可执行文件/动态库“有可用的调试信息”。常见做法：
    - 保留 `-g` 的 Release：例如 `-O2/-O3 + -g`，体积更大，但 GhostScope 可直接使用嵌入在二进制内部的的调试信息段。
    - 使用独立调试文件：生产二进制做 `strip`，把调试信息写到 `your_program.debug` 并通过 `.gnu_debuglink` 关联；把调试文件部署到“同目录/.debug 子目录/`/usr/lib/debug` 路径”，GhostScope 会按约定自动搜索并加载。

- 系统库调试包
  - 可以安装发行版提供的 debuginfo 包（如 Ubuntu/Debian `libc6-dbg`，Fedora/RHEL `debuginfo-install glibc`），调试文件通常位于 `/usr/lib/debug/`，GhostScope 会自动查找。

- 优化的影响
  - 高优化构建中，部分变量可能“优化掉”或仅在某些指令点有位置（位置列表）。GhostScope 会按 DWARF 表达式实时求值；但若编译器未生成位置信息（无 `DW_AT_location`），则无法读取该变量。

- 快速检查与更多说明
  - 可用 `readelf -S` 检查是否存在 `.debug_*` 段，或用 `readelf -x .gnu_debuglink` 检查独立调试文件链接。命令示例、搜索路径与操作步骤请参考[安装指南 - 调试符号（必需）](install.md#3-调试符号必需)。


## GhostScope 的限制有哪些？

请参阅 [使用限制](limitations.md) 文档，了解硬性限制和软性限制的完整列表。

## 未来规划是什么样的？

请参阅 [未来规划](roadmap.md) 文档，了解计划中的功能和未来开发方向。

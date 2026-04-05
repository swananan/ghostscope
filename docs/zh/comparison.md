# 工具对比

GhostScope 的目标很明确：**针对带有 DWARF 调试信息的活跃进程，做面向源码语义的用户态追踪**。它并不是要在所有场景下替代 GDB、bpftrace 或 SystemTap。这份文档的目的，就是帮你快速判断该选谁。

## 快速选择

| 如果你需要…… | 优先选择…… | 原因 |
|---|---|---|
| 带断点、单步、改内存或调 coredump 的交互式调试体验 | GDB | 它是交互式调试器，具备完整执行控制能力 |
| 同时做内核 + 用户态事件聚合 | bpftrace 或 SystemTap | 它们更适合宽范围系统观测 |
| 在不停止进程的前提下，按源码行读取局部变量和真实类型值 | GhostScope | 它把运行时 DWARF 求值和低开销用户态追踪结合在一起 |
| 复用已有 tapset 或 SystemTap 工作流 | SystemTap | 生态复用本身就很重要 |

## GhostScope vs GDB

| 维度 | GhostScope | GDB |
|---|---|---|
| 执行模型 | 不停进程，直接做运行时追踪 | 停住进程，再检查和控制执行 |
| 最擅长 | 生产风格的在线观测 | 交互式调试和状态修改 |
| 变量读取方式 | 在设定的追踪点上，借助 DWARF + eBPF 读值 | 在暂停后的时刻读取调试状态 |
| 时序影响 | 低 | 高，断点会改变时序 |
| 适合的需求 | 你需要观测 | 你需要控制 |

如果时序不能被破坏，优先用 GhostScope。如果你需要一步一步推进执行过程，优先用 GDB。

## GhostScope vs GDB 实测性能快照

现在仓库里已经有一套可重复执行的单线程 benchmark，用来回答一个很窄但很实际的问题：**在热点函数每次命中时，读取同一个局部变量到底要付出多大代价？** harness 在 [`../scripts/compare/compare_hot_function_bench.py`](../scripts/compare/compare_hot_function_bench.py)，目标程序在 [`../scripts/compare/compare_hot_function_target.c`](../scripts/compare/compare_hot_function_target.c)，runner service 的入口在 [`../ghostscope/tests/manual_gdb_ghostscope_benchmark.rs`](../ghostscope/tests/manual_gdb_ghostscope_benchmark.rs)。

### 方法

- 测试时间：`2026-04-06`。机器是一台 x86_64 Ubuntu 开发机，CPU 为 Intel i7-8700K，内核 `6.14.0-37-generic`，GDB `15.0.50`，GhostScope `0.1.2`。
- 目标程序编译参数为 `-O2 -g -fno-omit-frame-pointer -fno-pie -no-pie`。
- 每轮执行 `2000` 次 `bench_hot_fn` 命中，每次命中额外做 `4096` 个 inner work 单元。目标程序只在 observer ready 之后开始记录内部耗时，所以 setup 成本和稳态运行成本是分开的。
- 共同观测意图：在 `bench_hot_fn` 内的源码第 `21` 行求值局部变量 `local_probe`，但不持续输出结果。
  GhostScope 使用 `trace compare_hot_function_target.c:21 { if local_probe == 0 { print "never"; } }`。
  GDB 使用 batch 行断点脚本，在同一源码行命中时执行 `if local_probe == 0`、`silent` 和 `continue`。
- 目标进程会一直阻塞到 observer 报告 ready。
  对 GhostScope 来说，ready marker 只有在 `compile_and_load_script_for_cli` 完成后才会发出，所以 DWARF 索引和 script load 时间被单独记到 ready latency 列，而不会算进 steady-state target time。
- 下表取 `5` 轮中位数。对 GDB 来说，暂停时间本来就是执行模型的一部分，所以有意计入目标运行时间。

### 结果

| 模式 | 稳态目标中位耗时 (ms) | 目标最小-最大 (ms) | 相对无观测减速 | 中位 ready 延迟 (ms，已排除) |
|---|---:|---:|---:|---:|
| 无观测 | 13.36 | 13.34-13.43 | 1.00x | n/a |
| GhostScope | 18.68 | 17.16-19.95 | 1.40x | 153.33 |
| GDB | 527.64 | 517.71-555.77 | 39.48x | 133.25 |

### 怎么读这组结果

- 在这个场景里，GhostScope 的 attach 延迟略高于 GDB，但一旦开始跑热点路径，稳态扰动明显更低。
- GhostScope 的 `153.33ms` ready latency 就是 DWARF 索引和脚本加载主要出现的位置。它被单独报告，但没有算进 `18.68ms` 的稳态目标耗时。
- 这不是一句泛化的“谁更快”。它只回答一个具体问题：在同一台机器上，对同一个热点路径局部变量做重复的源码语义观测，代价分别是多少。
- 这里 GhostScope 的减速看起来也不低，是因为这次压测故意盯住了一个高频热点路径，并且每次命中都做观测。这是压力测试，不是推荐的生产使用模式。
- 正常诊断里，GhostScope 更适合放在有针对性的 trace point 上，而不是持续盯住线上服务的核心热点路径。对在线产品服务，不建议直接跟踪延迟敏感的热点路径，除非你已经明确为这部分开销做过预算。
- 下一步最值得补的场景是：多线程热点路径、低频错误路径，以及短生命周期进程。

## GhostScope vs bpftrace

| 维度 | GhostScope | bpftrace |
|---|---|---|
| 重点 | 用户态、源码语义运行时追踪 | 通用 eBPF 追踪和事件聚合 |
| 用户态 DWARF 能力 | 运行时求值 DWARF location expr | 更适合参数、结构体和事件聚合，而不是基于 DWARF 的用户态进程源码级别语义还原 |
| 设点方式 | 面向函数、源码行、指令点 | 面向 probe 和事件 |
| 最擅长 | 从真实代码路径恢复用户态状态 | 快速关联多类事件源 |
| 代价 | 范围更聚焦 | 对源码级用户态诊断没那么聚焦 |

如果你关心的是“用户态源码语义”，GhostScope 更合适；如果你关心的是“广覆盖的事件流与聚合”，bpftrace 更合适。

## GhostScope vs SystemTap

| 维度 | GhostScope | SystemTap |
|---|---|---|
| 重点 | 带 TUI 的用户态追踪工具，配小型 DSL | 覆盖面更广的追踪框架，生态更成熟 |
| 工作流 | 轻量、源码导向、贴近生产 printf 调试 | 更成熟也更宽，但工作流更重一些 |
| 用户态变量追踪 | 围绕 DWARF-backed 用户态观测来设计 | 能做，但不是同样的低门槛主路径 |
| 最擅长 | 快速定位活跃用户态进程问题 | 复用 tapset、做更宽的混合追踪 |
| 代价 | 总体范围比 SystemTap 更窄 | 如果你只想做聚焦的用户态定位，会显得更重 |

如果你更看重和 AI 的适配，或者想要一个具备友好 TUI 界面的用户态追踪工具，GhostScope 更合适；如果你已经在使用 SystemTap 生态，或者要的是更宽的追踪框架，SystemTap 更合适。

## 到底该怎么选

- 选 GhostScope：你要在不干扰服务的前提下，看真实的用户态源码级变量值。
- 选 GDB：你要交互式控制执行流程，或者做事后调试。
- 选 bpftrace：你要快速聚合内核和用户态事件。
- 选 SystemTap：你要更宽的追踪框架，或者已经有现成的 SystemTap 资产。

更多细节和限制，可以继续看 [常见问题](faq.md) 和 [使用限制](limitations.md)。

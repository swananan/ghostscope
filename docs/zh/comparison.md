# 工具对比

GhostScope 的目标很明确：**针对带有 DWARF 调试信息的活跃进程，做面向源码语义的用户态追踪**。它并不是要在所有场景下替代 perf、GDB、bpftrace 或 SystemTap。这份文档的目的，就是帮你快速判断该选谁。

## 快速选择

| 工具 | 最擅长什么 | 不太适合什么 |
|---|---|---|
| GhostScope | 面向活跃进程的低开销、源码语义用户态追踪 | 需要交互式控制执行，或者要在同一套追踪工作流里做大范围内核 + 用户态聚合 |
| perf probe | 在 perf 生态里快速对函数、源码行、局部变量打一针式 probe | 需要可编程的内核侧过滤/聚合，或者更完整的实时 tracing 工作流 |
| GDB | 断点、单步、coredump、改状态 | 生产环境里目标进程不能被停住 |
| bpftrace | 混合内核 + 用户态观测，以及快速事件聚合 | 需要基于 DWARF 可靠地做用户态进程源码级别语义还原 |
| SystemTap | 更宽泛的追踪工作流、已有 tapset 生态、混合式探测 | 你更想要一个更聚焦、TUI 更友好、使用摩擦更低的用户态追踪工作流 |

## GhostScope vs GDB

| 特性 | GhostScope | GDB |
|---|---|---|
| 类型 | 追踪器，更接近生产环境下的 printf 调试 | 交互式调试器 |
| 执行模型 | 不停进程，直接做运行时追踪 | 停住进程，再检查和控制执行 |
| 运行时开销 | 选择性使用时通常较低 | 一旦依赖断点，开销通常较高 |
| 进程中断 | 从不 | 会 |
| 生产环境使用 | 面向生产友好的在线观测 | 更适合开发环境和事后调试 |
| 时序保持 | 是 | 否，断点和单步都会改变时序 |
| 并发调试 | 当你需要保留真实时序时更有优势 | stop-the-world 行为更容易扰动并发交错 |
| 交互控制 | 有 TUI 和脚本，但不控制执行流程 | 完整执行控制：断点、单步、继续、改状态 |
| 变量读取方式 | 在设定的追踪点上，借助 DWARF + eBPF 读值 | 在暂停后的时刻读取调试状态 |
| 最擅长 | 生产风格的在线观测 | 交互式调试和状态修改 |
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
| GhostScope | 18.68 | 17.16-19.95 | **1.40x** | 153.33 |
| GDB | 527.64 | 517.71-555.77 | **39.48x** | 133.25 |

### 怎么读这组结果

- 在这个场景里，GhostScope 和 GDB 的稳态运行时差距非常大：GhostScope 只把目标减速到 **1.40x**，而 GDB 把同一类工作负载推到了 **39.48x**。对于这种持续的在线观测任务，GhostScope 明显更适合线上追踪。
- GhostScope 的 attach 延迟虽然略高于 GDB，但这类一次性的准备成本，和 GDB 在运行过程中反复 stop-the-world 带来的扰动相比，要小得多。
- GhostScope 的 `153.33ms` ready latency 就是 DWARF 索引和脚本加载主要出现的位置。它被单独报告，但没有算进 `18.68ms` 的稳态目标耗时。
- 这不是一句泛化的“谁更快”。它只回答一个具体问题：在同一台机器上，对同一个热点路径局部变量做重复的源码语义观测，代价分别是多少。
- 这里 GhostScope 的减速看起来也不低，是因为这次压测故意盯住了一个高频热点路径，并且每次命中都做观测。这是压力测试，不是推荐的生产使用模式。
- 正常诊断里，GhostScope 更适合放在有针对性的 trace point 上，而不是持续盯住线上服务的核心热点路径。对在线产品服务，不建议直接跟踪延迟敏感的热点路径，除非你已经明确为这部分开销做过预算。
- 下一步最值得补的场景是：多线程热点路径、低频错误路径，以及短生命周期进程。

## GhostScope vs perf probe

| 维度 | GhostScope | perf probe / perf uprobes |
|---|---|---|
| 定位 | 面向用户态源码语义恢复的专用 tracer，带运行时 DWARF 求值、小型 DSL 和 TUI / session 工作流 | 偏声明式的 probe 定义前端，再接上更完整的 perf 记录和分析链路 |
| 可编程性与安全模型 | 基于 eBPF 的采集逻辑，可做可编程过滤和格式化；灵活性由 verifier 约束 | 能力面更窄、也更偏声明式：定义 probe 点和 fetchargs，但不是 eBPF 那种“每次命中都运行自定义逻辑”的编程模型 |
| 源码级前端 | 函数、源码行、指令级 tracing 都是核心路径 | `perf probe` 原生就很擅长函数、源码行、局部变量以及 inline 相关的 probe 发现 |
| 变量获取方式 | 运行时求值 DWARF，读取局部变量、参数和全局变量，并在 tracer UI 中按真实类型渲染 | 更偏声明式 fetchargs，可直接写局部变量、参数、寄存器、符号、数组和返回值 |
| inline 与发现体验 | 有不错的源码驱动附着体验，但工作流仍围绕 GhostScope 自己的 tracer 模型 | 在线、函数和 inline 相关搜索上更成熟，例如 `--line`、`--vars`、`--no-inlines` 这类入口 |
| 命中后的处理 | 可以先把结构化数据做过滤、采样、整形，再送到用户态 | 主要还是固定事件字段提取，然后交给 perf 的记录和分析工具链 |
| 输出与消费链路 | RingBuf 或 PerfEventArray，接自定义实时 reader / TUI | 常见链路是 `perf probe` -> `perf record` -> `perf.data` -> `perf report` 或 `perf script` |
| 最擅长 | 面向生产在线定位的用户态诊断，结构化输出和专用运行时工作流更完整 | 快速打一针式 probe，以及复用现有 perf 生态 |
| 代价 | 更偏有主见的专用工具，不是通用 perf 工具箱 | 可编程性弱于 eBPF tracer，也不那么适合自定义实时处理 |

如果你想要的是一个面向线上诊断的专用 tracer，强调运行时 DWARF 语义、可编程过滤以及更友好的实时定位工作流，GhostScope 更合适。如果你只是想快速在函数、源码行或局部变量上落一个 probe，并继续沿用 perf 生态，perf 会更顺手。

一句话概括：`perf probe` 更像“语义更固定、拿来就用”的前端，而不是“完全不可配置”；GhostScope 这类基于 eBPF 的 tracer 则用更高的命中后处理可编程性，换来更丰富的实时工作流。

## GhostScope vs bpftrace

| 维度 | GhostScope | bpftrace |
|---|---|---|
| 定位 | “DWARF 感知”的用户态观测，偏源码语义还原 | 通用 eBPF 动态追踪器，偏事件统计和观测 |
| DWARF 使用 | 运行时求值 DWARF 表达式，读参、局部变量和全局变量 | 擅长参数、结构体和事件流，但不以运行时求值 location expr 为核心 |
| 附着粒度与符号 | 行表驱动源码行、指令级附着，也支持函数级 tracing | 入口、返回、函数内偏移、绝对位置和事件探针；没有内建的源码行到地址工作流 |
| 可观测数据 | 支持局部变量、参数和全局变量，并能按真实类型渲染值 | 很适合参数、结构体和事件聚合，但不强调任意用户态实时状态还原 |
| ASLR 影响 | 运行时按 DWARF 计算，天然适配 ASLR 和 PIE | `uaddr()` 这一类全局变量读取方式在 ASLR 和 PIE 下会更别扭，甚至不可用 |
| 交互体验 | TUI 友好界面，可以不中断观测 | 更偏脚本输出和聚合，交互性较弱 |
| 最擅长 | 从真实代码路径恢复用户态状态 | 快速关联多类事件源 |
| 代价 | 范围更聚焦 | 对源码级用户态诊断没那么聚焦 |

如果你关心的是“用户态源码语义”，GhostScope 更合适；如果你关心的是“广覆盖的事件流与聚合”，bpftrace 更合适。

背景补充：GhostScope 的一个直接动机，就是新版 bpftrace 已经不再重点覆盖这个项目想要的那类重 DWARF 用户态工作流。

## GhostScope vs SystemTap

| 维度 | GhostScope | SystemTap |
|---|---|---|
| 定位与范围 | “DWARF 感知”的用户态观测，面向生产 printf 调试和交互式工作流 | 更宽的追踪框架，覆盖内核和用户态，也有 eBPF 后端 |
| 源码行/语句级设点 | 支持，行级附着是核心路径 | 支持，statement probe 可以解析后附着 |
| 变量访问（参/局/全） | 支持。运行时用 gimli 求值 DWARF，按真实类型渲染，天然适配 ASLR 和 PIE | 支持。DWARF 位置表达式会经过 SystemTap 的处理链路降为 eBPF 可执行逻辑，但要受验证器和栈限制 |
| DWARF 表达式处理 | 直接在用户态求值 DWARF，再通过 eBPF 程序取值 | 把 DWARF 操作翻译成内部表示，再继续降成 eBPF 指令序列 |
| 栈回溯（CFI） | 还不支持，计划通过 `.eh_frame` 支持 | eBPF 后端暂不支持 |
| 事件传输/格式化 | 新内核优先 RingBuf，也支持 PerfEventArray；页数和事件大小可配；内置 `{:x.N}`、`{:s.N}`、`{:p}` 等 dump helper | 更偏 PERF_EVENT_ARRAY + 用户态解释/格式化流程，格式和字符串能力更受约束 |
| BTF/CO-RE/链接 | Aya 生态，优先 RingBuf；不以 BTF/CO-RE 为核心 | 不以 BTF/CO-RE 为核心，更接近最小 libbpf 风格后端 |
| eBPF 生成链 | Rust + Aya 装载，重点是用户态 DWARF 变量读取和展示 | 自研 IR / assembler 流水线，产出 eBPF 字节码和 ELF 产物 |
| 交互与体验 | TUI 友好，支持实时日志、会话日志和小型 tracing DSL，贴近生产 printf 调试 | CLI + 用户态解释器输出，学习曲线更陡 |
| 最擅长 | 快速定位活跃用户态进程问题 | 复用 tapset、做更宽的混合追踪 |
| 代价 | 总体范围比 SystemTap 更窄 | 如果你只想做聚焦的用户态定位，会显得更重 |

如果你更看重和 AI 的适配，或者想要一个具备友好 TUI 界面的用户态追踪工具，GhostScope 更合适；如果你已经在使用 SystemTap 生态，或者要的是更宽的追踪框架，SystemTap 更合适。

背景补充：SystemTap 的 eBPF 后端和 GhostScope 的重叠比很多人直觉里更高，但 GhostScope 仍然刻意保持在“更窄、更低摩擦的用户态定位”这条路径上。

## 到底该怎么选

- 先看执行模型：如果你需要停进程、单步、改状态，或者调 coredump，就用 GDB。如果进程必须持续运行，那就继续在 GhostScope / perf / bpftrace / SystemTap 这几类工具里选。
- 再看你要的是“用户态源码语义定位”，还是“更宽的事件处理”。如果你想看真实用户态变量值、要类型化展示、又希望工作流更适合线上实时诊断，GhostScope 更合适。bpftrace 和 SystemTap 更适合做内核 + 用户态混合聚合；如果你已经有 tapset 或者本来就在用 SystemTap 工作流，SystemTap 会更顺手。
- perf 更像这两者之间的“一次性快工具”：你想快速在函数、源码行或局部变量上落一个 probe，并且继续沿用 perf 生态时，用 perf；如果你还需要 eBPF 那种命中后可编程处理能力，就不要指望 perf 这一层。

更多细节和限制，可以继续看 [常见问题](faq.md) 和 [使用限制](limitations.md)。

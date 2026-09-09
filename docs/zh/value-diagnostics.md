# 理解值诊断

GhostScope 区分“值不可用”“内存读取失败”“展示降级”和“只采集了部分内容”。
展示提示不代表 trace 创建失败；其他成功采集的字段仍可查看。

| 输出 | 含义 | 下一步 |
| --- | --- | --- |
| `<unavailable: optimized out>` | 当前追踪位置没有可恢复的值 | [换一个追踪位置](#optimized-out) |
| `<unreadable: memory read failed; errno=…; address=…>` | 本次读取失败；可能涉及无法处理的缺页或无效地址 | [检查读取条件，考虑 sleepable](#memory-read-failed) |
| `<internal fields: layout unsupported>` | 无法解释语义内容，保留内部字段 | [检查布局支持](#layout-unsupported) |
| `<internal fields: read plan unsupported>` | 调试信息不足以描述所需读取 | [检查调试信息](#read-plan-unsupported) |
| `<truncated: byte limit>` | 只采集了字节前缀 | [检查字节预算](#byte-limit) |
| `<truncated: element limit>` | 嵌套序列达到配置的元素上限 | [检查元素上限](#element-limit) |
| `<truncated: capture limit>` | 结果不完整，现有状态不能确定具体限制 | [检查采集限制](#capture-limit) |
| `<not expanded: capture budget>` | 嵌套采集放不下，保留根值展示 | [检查嵌套预算](#capture-budget) |
| `<nested display limits: depth limit; see trace details>` | 部分嵌套类型存在静态展示限制 | 查看 trace 的展示提示 |

## 去哪里看原因

可以直接从已安装的二进制离线查看本文档：

```bash
ghostscope --value-diagnostics-help
```

与 `--script-help` 一样，这会向 stdout 输出内嵌的英文参考文档并退出，
不加载配置、不检查目标，也不需要 eBPF 权限。内容随二进制发布，LLM 工具
也可以在没有源码仓库或网络的环境中读取。

CLI 在编译 trace 时向 stderr 输出展示提示，即使使用 `--no-log` 和
`--no-status` 也能看到；同一 trace 内相同表达式、类型和原因只提示一次。
TUI 在 trace 创建结果中展示提示，之后可通过 `info trace <id>` 再次查看。
从文件加载的 trace 也会保留这些提示。Dry run 能报告相同的静态限制，但实际
内存能否读出，要等探针运行才能确定。

每条提示包含表达式与受影响路径、类型、稳定原因名、技术详情和本文档入口。
`[]` 表示集合元素，`::Some.__0` 表示某个可能的枚举 payload（字段名沿用 DWARF）。
这些是**采集计划的限制**，不表示集合一定非空或该 variant 已经激活。
运行时读取错误则对应实际读取的值或子值。

普通 struct 本来就可以按字段展示，没有专用 adapter 并不代表出错。
调试日志和 `dwarf-tool rust-adapter` 仍可用于深入调查，但查看降级原因不再需要
先开启日志。

## optimized-out

`<unavailable: optimized out>` 表示当前 probe 位置没有可恢复的变量值。
直接打印可以显示这个占位符；将它用于运算或取地址，会在脚本编译时失败。

可以换到值仍然存活的源码位置。如果能够重建目标，保留调试信息，并考虑降低
优化级别。增大采集预算或开启 sleepable 不能恢复已经被编译器移除的值。

## memory-read-failed

`<unreadable: memory read failed>` 表示这次事件读取目标内存失败。
**仅凭 errno（包括 `-EFAULT`），无法区分无法处理的缺页和无效地址。**
其他可能原因还包括内存不可访问、观测期间发生修改、调试信息不匹配，或
GhostScope 计算地址有误。这是运行时读取失败，静态的深度限制提示不能解释
它的原因。其他成功采集的字段仍有参考价值；一次事件不是整个进程的原子快照。

先确认二进制与独立调试信息匹配，追踪位置和对象生命周期也正确。即使调试
信息匹配，目标指针本身仍可能为空、悬垂，或正在被并发修改。
**如果对象已确认有效且存活，调试信息也匹配，但 GhostScope 为它计算出了
无效地址，那就是 GhostScope 的 bug。** 报告时请保留表达式、源码/探针位置、
完整输出（含 errno 和地址）、二进制及调试文件标识、GhostScope 版本，并尽量
提供最小复现。单凭一次读取失败，还不能确定问题属于哪一方。

如果内存有效，但相关页面可能尚未驻留，建议在原命令上增加
**`--sleepable-uprobe`** 重试，或配置：

```toml
[ebpf]
sleepable_uprobe = true
```

sleepable uprobe 允许支持的内存读取处理缺页，要求 Linux 5.18+ 和 RingBuf
输出。固定长度读取会使用可处理缺页的 helper；需要 NUL 终止语义、仍使用
`bpf_probe_read_user_str()` 的读取不能因此处理缺页。它不能修复无效地址、
缺失的 DWARF 或不支持的类型布局。

开启后可能增加探针延迟，尤其是实际发生缺页或等待 I/O 时。特定负载下影响
可能较轻，但不能保证总是轻微；应结合命中频率观察目标延迟。
内核检查、输出兼容性和 backtrace 行为见
[Sleepable Uprobe](configuration.md#sleepable-uprobe)。

空指针、地址计算失败和进程偏移缺失有各自的提示，不能默认通过 sleepable 解决。

## layout-unsupported

类型匹配了已知 adapter，但目标 DWARF 中的布局没有通过验证。GhostScope
保留普通字段展示；这些字段是实现细节，不是字符串或集合的语义内容。
增大预算不能解决布局不支持。

检查 [Rust 值展示支持范围](scripting.md#rust-值展示)。报告问题时，提供类型名、
拒绝详情、目标 rustc 版本、匹配的调试信息和最小复现。如果普通 DWARF 采集也
无法编译，编译错误会附带 adapter 拒绝报告。

## read-plan-unsupported

目标调试信息无法解析所需的依赖类型、指针目标、字段投影、宽度或对齐。
提示会保留已知技术原因。检查目标对应的完整调试信息；对于可复现的不支持
场景，提交最小复现。增大内存预算或开启 sleepable 不能补全缺失的 DWARF。

## byte-limit

字符串或字节串只采集了前缀。检查 `[ebpf].mem_dump_cap`，默认每个间接参数
256 字节。嵌套值与根值、协议元数据、兄弟字段共享该预算，所以某个字段
实际能使用的字节可能更少。如果整个 payload 被省略，会使用更宽泛的
`capture limit`，因为这也可能由事件预算造成。

## element-limit

嵌套序列已经达到 `value_adapters.max_sequence_elements`。只采集了已显示的
元素；可以单独打印所需元素，或提高该设置。共享字节预算仍然有效。

## capture-limit

结果不完整。现有运行时状态并不总能区分字节、元素、稀疏 bucket、树节点
以及总事件大小限制；没有充分证据时，GhostScope 不会猜测具体原因。

检查 `[ebpf].mem_dump_cap`、`[ebpf].max_trace_event_size` 和
`[value_adapters].max_sequence_elements`（默认 4）。最后一项限制嵌套序列
元素或 Hash 表 bucket，稀疏 bucket 中实际条目可能更少。详见
[Value Adapter 限制](configuration.md#value-adapter-限制)。
只调整相关限制；更大的采集量可能增加 eBPF 程序大小、事件大小和探针开销。

## depth-limit

语义规划器在 `[value_adapters].max_nesting_depth`（默认 4）处停止继续展开。
提示路径指出受影响的更深层内容。穿过普通 struct 或进入枚举 payload 也会
消耗一层。这不是内存读取失败，也不表示根值丢失。
可以单独打印较浅的字段，或有针对性地提高深度上限。
原生 DWARF 格式化另有独立上限，达到时显示 `<MAX_DEPTH_EXCEEDED>`。

## recursive-type

规划器在当前展开路径遇到重复的 DWARF 类型，因此保留已有展示，不再无限
跟随。这是类型图的循环保护，不能据此断定运行时对象之间存在循环引用。
提高深度上限不会关闭该保护；可以单独检查字段，或显式解引用已知指针。

## capture-budget

编译后的嵌套采集无法放入共享字节预算。根值展示或其他已采集字段仍会保留，
可以确定时会指出受影响路径。建议单独打印该字段、降低嵌套深度或集合宽度，
或有针对性地增大 `ebpf.mem_dump_cap`。这项限制在探针运行前即可确定。

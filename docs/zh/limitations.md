# GhostScope 的限制

本文档描述支持范围之外的条件，以及会显式降级的场景。在支持范围内仍然必须成立的保证，统一定义在[设计保证与可信性模型](design-contract.md)中。

## 硬性限制

### 1. 权限需求
eBPF 底层机制要求提升的权限以访问内核追踪基础设施，需要 root 权限或 CAP_BPF/CAP_SYS_ADMIN 能力。

### 2. 不要与 GDB 同时使用
uprobe 和 GDB 都会在目标进程中安装基于断点的探测机制，同时使用可能导致冲突和不可预测的行为。

### 3. 只读访问，不可修改程序行为
GhostScope 的脚本和编译器能力面只用于观测，不提供主动修改应用可见状态、变量值或控制流的操作。但这不代表目标完全不受影响：uprobe 会安装 trap 点，每次命中都会让目标线程同步承担 uprobe 和 eBPF 执行。

### 4. 平台与架构支持
官方构建和正确性测试目前只支持 **Linux x86_64 (AMD64)**。GhostScope 依赖 Linux **eBPF** 和 **uprobe**，并且当前实现的是 x86_64 寄存器、ABI、TLS 和 unwind 行为。运行时构建会在其他构建目标上失败，安装器会拒绝非 Linux 系统和其他架构，trace setup 也会拒绝不是 64 位小端 x86_64 ELF 的目标文件。

## 软性限制

### 1. 语言支持
目前主要支持 **C 语言**，对 C 的端到端支持最完善。**C++** 和 **Rust** 目前属于更偏“按 DWARF 布局访问”的有限支持：GhostScope 支持对函数名以及全局/静态符号做自动 demangle，但大多数语言特性还没有建模。实际使用中，越接近 C 风格的数据布局越容易成功；Rust 和 C++ 的高级特性仍需要后续大量补强。

对于解释型语言（Lua、Python、Ruby 等），目前只能追踪解释器本身（因为解释器通常用编译型语言实现）。追踪脚本代码在技术上可行，但需要大量开发时间，JIT 语言支持计划就更远了。

### 2. 通过 `bpf_probe_read_user` 读取用户内存
在传统的非 sleepable probe 路径里，`bpf_probe_read_user` 这类 helper 仍然不能处理用户态缺页，因此当目标虚拟地址对应的页面尚未驻留，或访问时会触发 fault，读取就可能失败。

但这已经不是 eBPF 的绝对硬限制。Linux 已支持 sleepable uprobe（`uprobe.s` / `uretprobe.s`），而 sleepable 程序可以使用 `bpf_copy_from_user_task()` 之类的 helper 执行可睡眠的用户态内存读取。GhostScope 当前仍生成普通 `uprobe` 程序，所以现阶段它在实践中仍然是个限制；但更准确地说，这属于实现层面的软限制，而不是 eBPF 的根本设计上限。

**参考**：
- https://lists.iovisor.org/g/iovisor-dev/topic/accessing_user_memory_and/21386221
- https://docs.kernel.org/bpf/libbpf/program_types.html
- https://man7.org/linux/man-pages/man7/bpf-helpers.7.html

### 3. 性能影响
每次 uprobe 命中都会同步执行 trap 处理和生成的 eBPF 程序。即使单事件工作量有界，把探针放在热点路径上仍可能显著影响目标进程。GhostScope 不保证原始时序完全不变，也不承诺固定的总体开销；应当有针对性地设置探针，并把命中频率纳入性能预算。

### 4. 事件丢失（背压）
GhostScope 优先使用 RingBuf，并在需要时回退到 PerfEventArray。事件产生速度超过可用容量时，两种传输都可能拒绝输出。生成的程序会按 trace 增加输出失败计数，CLI 和 TUI 会定期报告区间增量和累计丢失量。

这保证的是丢失可见，而不是事件流无损。计数只覆盖 eBPF 输出 helper 的失败，不能说明具体丢失了哪些事件，也不能证明该计量点之外没有丢失。任何非零丢失报告都表示对应观测区间不完整；同时应避免在高频路径上放置数量过多或负载过大的探针。

### 5. DWARF 支持范围
主要测试和验证了 DWARF 5 格式。理论上支持 DWARF 2-5，但其他版本可能存在兼容性问题。部分 DWARF 表达式指令暂不支持转换为 eBPF（纯实现还没有支持的原因），遇到时会给出明确的错误提示。

GhostScope 能识别 `DW_OP_form_tls_address`，但运行时 TLS 地址解析目前只支持 x86_64 可执行文件里的 static TLS。GhostScope 会在探针触发时解析当前线程的 TLS 基址，因此在这个已支持的可执行文件场景下，同一个 trace 在不同 pthread 上会读取各自线程的 TLS 实例。同一个 DWARF 操作也会用于 dynamic/shared-library TLS；这类场景需要 DTV/module TLS lookup，目前尚未建模，所以 GhostScope 会拒绝共享对象里的 TLS，而不是猜测地址。

GhostScope 默认严格检查独立调试文件所有可用的 `.gnu_debuglink` CRC 和可比较 Build ID。启用 `--allow-loose-debug-match` 后，可以在 warning 提示下使用不匹配的调试文件，但这会削弱源码语义所依赖的证据保证。显式指定的调试文件如果既没有可用 CRC，也没有可比较的 Build ID，同样会在 warning 后继续使用，但此时文件身份属于用户提供的信任假设，而不是经过验证的匹配。

### 6. 栈回溯覆盖范围
`bt` 只使用 DWARF CFI。GhostScope 不会回退到内核 stack helper 或 frame pointer walking；当 CFI 不可用、无法转换为 compact eBPF fast path，或读取用户栈内存失败时，会输出明确的停止状态。只要进程模块映射可用，跨模块栈帧可以通过 raw IP 做正确符号化；运行时模块刷新也可以为新映射模块追加 compact DWARF rows，直到达到 `backtrace_unwind_rows_max_entries`。如果某个 trace 事件早于 map-change 刷新抵达用户态，它仍可能先停在新加载模块，后续事件才能看到已追加的 rows。深栈 DWARF unwind 已经通过 eBPF tail-call step program 分段执行，因此默认 `backtrace_depth = 128` 不会触发 LLVM 分支距离和 verifier 程序大小限制；`status=truncated` 表示达到配置深度或 tail-call unwind 预算后仍未自然停止。

运行模式也会影响 `bt` 的覆盖面。`-p <pid>` 是进程级视图，GhostScope 会从该 PID 的 `/proc/<pid>/maps` 加载已映射模块，因此跨模块 unwind 和符号化通常最完整。独立 `-t <path>` 是目标文件级、多进程 trace 视图，主要保证目标模块内的探针和变量；调用栈跨出目标模块后属于 best-effort，依赖运行时模块映射、`proc_module_offsets` 维护结果以及相关模块是否有可用 compact DWARF CFI。若既需要限定 trace 目标模块，又需要更完整的单进程 backtrace，优先使用 `-t <path> -p <pid>`。

### 7. 高度优化代码的支持
编译器优化（-O2、-O3）会导致变量被优化掉或生成复杂的 DWARF 表达式。GhostScope 会尽力解析，包括内联函数的支持，但部分变量可能无法访问（显示为 OptimizedOut），这是因为编译器优化掉了。

### 8. 动态加载库（dlopen）
GhostScope 启动时会扫描进程的 `/proc/PID/maps` 获取已加载的动态库信息；现在在 `-p <pid>` 和启用 sysmon 的独立 `-t <path>` 下，也会通过运行时 map-change 监控刷新模块映射。对 `bt`/`backtrace` 来说，这可以为后续通过 `dlopen` 加载的库追加 compact DWARF CFI rows 和模块偏移，但仍受 `backtrace_unwind_rows_max_entries` 以及上文提到的 map-change 竞态限制。

`-p <pid>` 有一个启动边界：trace setup 会先快照该 PID 当前的
`/proc/<pid>/maps`，再解析函数名目标。如果 GhostScope 紧贴进程启动，而
动态加载器还没有把某个共享库映射进来，脚本又要 trace 这个库里的函数，
setup 可能在运行时 map-change 监控有机会刷新之前失败。这主要影响“启动后
立刻 attach”的流程；attach 到已运行的进程、等目标库出现在
`/proc/<pid>/maps` 后再启动 GhostScope，或对已知库目标使用
`-t <path> -p <pid>`，都可以避开这个竞态。

这条运行时刷新链路不会自动新增 trace probe，也不会让脚本编译/附加时尚未知的库立即支持 print 或全局变量目标。这些目标仍依赖 trace setup 阶段能够看到对应目标模块和调试信息。

### 9. -t 模式下的全局变量支持

- **可执行目标**：当 `-t` 指向可执行文件（`-t /path/to/app`）时，会以该二进制作为主模块，默认支持全局变量。
- **共享库目标（已有进程）**：若 GhostScope 启动时，目标库已经被现有进程加载，例如追踪一个已运行但早先加载好 `libfoo.so` 的进程，能够直接解析全局变量。
- **共享库目标（新启动或后续映射的进程）**：独立 `-t` 默认启动 sysmon，因此能为后续启动的进程，以及后续通过 `dlopen` 映射目标库的进程解析全局变量。该功能会带来额外的系统负载，进程频繁启动/退出或内存映射变化频繁的环境下开销会更明显；可在配置文件中设置 `enable_sysmon_for_target = false` 关闭。
- **限定 PID 的目标模式（`-t ... -p ...`）**：`-t` 决定函数/源码行/地址目标解析使用哪个模块，`-p` 提供具体进程映射、PID 过滤和 watched-PID 模块刷新；不会使用 target-mode lifecycle sysmon。

提示：`-p <pid>` 模式下仍会自动计算并下发模块偏移，全局变量始终可用。

`-t` 下的全局变量依赖 `proc_module_offsets`，也就是按 `(pid, module)` 维护的运行时地址偏移。独立 `-t` 会面向多个 PID 维护目标模块偏移，因此适合观察目标模块里的全局变量；但它不是完整进程视图，`bt` 跨出目标模块后的 unwind/符号化能力不等同于 `-p`。需要单个进程的完整模块上下文时，使用 `-p <pid>`；需要把 trace 目标限定到某个模块并保留该进程上下文时，使用 `-t <path> -p <pid>`。

### 10. 容器 / WSL 场景下 `-p <pid>` 模式的软限制

- 容器 / WSL 场景、PID namespace 术语、场景矩阵，以及当前实现限制的完整说明，见 [容器环境](container.md)。
- 参考 [PID namespaces 手册](https://www.man7.org/linux/man-pages/man7/pid_namespaces.7.html)、[WSL issue #12408](https://github.com/microsoft/WSL/issues/12408) 和 [WSL issue #12115](https://github.com/microsoft/WSL/issues/12115)。

### 11. 观测一致性

一个 trace 事件不是整个进程的原子快照。寄存器值和当前线程栈帧对应 uprobe 命中时刻，但 GhostScope 依次读取多个字段期间，其他线程仍可能修改共享内存。因此，同一个事件中的多个值可能来自一个很短的观测区间，而不是经过全局同步的同一瞬间。

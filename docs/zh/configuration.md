# 配置参考

GhostScope 可以通过命令行参数、配置文件和环境变量进行配置。

## 配置优先级

配置遵循以下优先级顺序（从高到低）：
1. 命令行参数
2. 环境变量（RUST_LOG）
3. 配置文件（~/.ghostscope/config.toml 或 ./ghostscope.toml）
4. 默认值

> **注意**：GhostScope 通常需要以 sudo/root 身份运行以访问跟踪能力。当以 root 运行时，默认的 `$HOME` 指向 `/root`，因此用户目录下的 `~/.ghostscope/config.toml` 不会自动被读取。请使用 `ghostscope --config /home/<用户名>/.ghostscope/config.toml` 来显式指定个人配置文件。

## 命令行参数

### 目标选择

```bash
# 通过 PID 附加到运行中的进程
ghostscope -p <PID>
ghostscope --pid <PID>

# PID namespace 感知行为（Docker/WSL/容器）
# - 按你实际执行 `ghostscope -p` 命令的环境里看到的 PID 输入即可。
# - `-p` 的输入语义是“当前可见 PID”，不是“永远填写宿主机 PID”。
# - 更完整的容器场景解释见 docs/zh/container.md
# - 启动时的决策顺序：
#   1) 先检测 GhostScope 自身运行环境（container/host/unknown）
#   2) 解析 /proc/<pid>/status 的 NSpid 映射
#   3) 探测 helper 支持，若可用优先使用 bpf_get_ns_current_pid_tgid
#   4) helper 不可用时回退到 host PID 映射
# - 若该 PID 在当前命名空间不可见，GhostScope 会直接报错，
#   并要求你提供当前命名空间内真实存在的 PID。

# 指定目标可执行文件或库（支持路径解析）
ghostscope -t <PATH>
ghostscope --target <PATH>

# 相对路径的解析顺序：
# 1. 当前工作目录
# 2. ghostscope 可执行文件所在目录
# 3. 如果未找到则转换为绝对路径

# 两者可以一起使用：在一个运行中 PID 内追踪 -t 指定的模块。
# 这种形式下，函数/源码行/地址目标解析一律以 -t 为准，
# -p 只负责把运行时事件限制到该进程；sysmon 不会启动。
ghostscope -t /usr/bin/myapp -p 1234

# 启动新进程
ghostscope /path/to/program
ghostscope /path/to/program arg1 arg2

# 当目标程序参数可能被误认为 GhostScope 选项时，使用 --args 分隔
ghostscope --script-file trace.gs --args /path/to/program --target-flag value
# --args 后的所有内容都会传递给目标程序
```

### 脚本执行

```bash
# 运行内联脚本
ghostscope -s 'trace main { print "Started"; }'
ghostscope --script 'trace main { print "Started"; }'

# 从文件运行脚本
ghostscope --script-file trace.gs

# 输出内嵌的脚本语言参考并退出
ghostscope --script-help

# 选择脚本模式的事件 stdout 输出方式
ghostscope --script-output pretty   # 默认：格式化 stdout
ghostscope --script-output plain    # 仅保留 payload stdout

# 控制 stderr 上的交互式状态提示
ghostscope --status                 # 默认
ghostscope --no-status              # 隐藏 DWARF/脚本/attach 状态提示

# 控制 pretty 模式的时间戳格式
ghostscope --script-timestamp local # 默认
ghostscope --script-timestamp boot
ghostscope --script-timestamp none

# 脚本模式的输出流约定：
# - trace 事件始终走 stdout
# - DWARF 加载、脚本编译、attach 状态提示走 stderr
# - `--script-output` 只控制事件 stdout 的渲染
# - `--status` / `--no-status` 控制这些交互式 stderr 状态提示
# - 无论哪种模式，致命错误仍会输出到 stderr
# - pretty stdout 和交互式 stderr 状态的 ANSI 色彩可通过 config.toml 里的 [script].color 控制

# 以 TUI 模式启动（未提供脚本时的默认模式）
ghostscope --tui
```

### 调试信息

```bash
# 指定自定义调试文件（覆盖自动检测）
ghostscope -d /path/to/binary.debug
ghostscope --debug-file /path/to/binary.debug

# 自动检测按以下顺序搜索：
# 1. 二进制文件本身（.debug_info 节）
# 2. .gnu_debuglink 节（参见下方搜索路径）
# 3. .gnu_debugdata 节（Android/压缩格式）
# 4. 基于 Build-ID 的路径

# .gnu_debuglink 搜索路径（可在 config.toml 中配置）：
# 1. 绝对路径（如果 .gnu_debuglink 包含绝对路径 - 罕见）
# 2. 用户配置的 search_paths + basename（最高优先级）
# 3. 二进制文件同目录 + basename
# 4. 二进制文件同目录的 .debug 子目录 + basename
#
# 注意：如需使用系统范围的调试目录（如 /usr/lib/debug），
# 请在 config.toml 的 search_paths 中添加
```

### 日志配置

```bash
# 启用文件日志（默认：./ghostscope.log）
ghostscope --log

# 禁用所有日志
ghostscope --no-log

# 除文件外还启用控制台 stderr 日志
ghostscope --log-console

# 禁用控制台 stderr 日志
ghostscope --no-log-console

# 设置日志级别
ghostscope --log-level debug  # 选项：error, warn, info, debug, trace

# 自定义日志文件路径
ghostscope --log-file /var/log/ghostscope.log
```

### 调试输出文件

```bash
# 保存 LLVM IR 文件（默认：debug 构建启用）
ghostscope --save-llvm-ir
ghostscope --no-save-llvm-ir

# 保存 eBPF 字节码文件（默认：debug 构建启用）
ghostscope --save-ebpf
ghostscope --no-save-ebpf

# 保存 AST 文件（默认：debug 构建启用）
ghostscope --save-ast
ghostscope --no-save-ast
```

### UI 布局

```bash
# 设置 TUI 布局模式
ghostscope --layout horizontal  # 面板横向排列（默认）
ghostscope --layout vertical    # 面板纵向排列

# 显示/隐藏源码面板（当没有源码环境时非常有用）
ghostscope --no-source-panel    # 隐藏源码面板；仅保留 eBPF 输出 + 命令交互
ghostscope --source-panel       # 显示源码面板
```

### 高级 eBPF 选项

```bash
# 强制使用 PerfEventArray 模式（仅用于测试）
# 警告：仅用于测试目的。即使在内核 >= 5.8 上也强制使用 PerfEventArray
ghostscope --force-perf-event-array

# 当独立 -t 目标是共享库（.so）时启动 sysmon。
# -t 与 -p 同时使用时不需要。
# 警告：该选项会全局附加 sched 的 exec/fork/exit tracepoint，在进程频繁
# 启动/退出的主机上可能带来一定性能开销。默认关闭。
ghostscope --enable-sysmon-shared-lib
```

### BPFFS 维护

GhostScope 使用 bpffs，是因为有一部分运行时状态需要在用户态的 process 层、loader 以及 eBPF 程序之间共享。实际里像 `proc_module_offsets` 和 `allowed_pids` 这样的 map，会先 pin 到 bpffs，这样后续阶段就能按路径重新打开并复用同一个内核 map，而不是重复创建。GhostScope 又把这些 pin 放在按实例隔离的 `pid-starttime` 目录下，用来避免多个实例并发运行时互相冲突。

GhostScope 会把每个实例的 pinned map 放在 `/sys/fs/bpf/ghostscope/<pid-starttime>/` 下。

- 正常 tracing 启动时**不会**扫描并全局清理 `/sys/fs/bpf/ghostscope`。
- 正常退出时会自动清理当前实例目录。
- 如果看到残留目录，通常意味着进程发生了崩溃、`SIGKILL` 等异常退出。
- 全局清理通过显式的 `bpffs prune` 子命令执行。

```bash
# 只删除 stale 的 pid-starttime 目录
ghostscope bpffs prune

# 仅预览，不实际删除
ghostscope bpffs prune --dry-run

# 删除一个明确的实例目录
ghostscope bpffs prune --instance 1234-567890

# 删除所有 pid-starttime 目录，包括活实例
ghostscope bpffs prune --all --force

# 输出机器可读的结果
ghostscope bpffs prune --dry-run --json
```

行为说明：

- 默认 `prune` 只删除 stale 的 `pid-starttime` 目录。
- `--instance` 只处理一个明确的 `pid-starttime` 目录。
- `--all --force` 会删除所有 `pid-starttime` 目录，包括活实例。
- legacy 的纯数字目录会被忽略。

### 完整命令参考

| 选项 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--pid <PID>` | `-p` | 要附加的进程 ID | 无 |
| `--target <PATH>` | `-t` | 目标可执行文件或库。与 `-p` 同时使用时，`-t` 限定 trace 目标解析，`-p` 只提供 PID 过滤。 | 无 |
| `--script <SCRIPT>` | `-s` | 要执行的内联脚本 | 无 |
| `--script-file <PATH>` | | 要执行的脚本文件 | 无 |
| `--script-help` | | 输出内嵌的脚本语言参考并退出 | 关 |
| `--script-output <MODE>` | | 脚本事件 stdout 模式：pretty, plain | pretty |
| `--status` | | 启用交互式 DWARF/脚本/attach stderr 状态提示 | 开 |
| `--no-status` | | 禁用交互式 DWARF/脚本/attach stderr 状态提示 | 关闭覆盖 |
| `--script-timestamp <FORMAT>` | | pretty 输出时间戳：local, boot, none | local |
| `--debug-file <PATH>` | `-d` | 调试信息文件路径 | 自动检测 |
| `--debuginfod <MODE>` | | debuginfod 模式：off, on, ask | off |
| `--debuginfod-url <URL>` | | debuginfod 服务 URL，可重复传递 | 无 |
| `--debuginfod-cache-dir <DIR>` | | debuginfod 缓存目录 | debuginfod 兼容默认值 |
| `--debuginfod-timeout-secs <SECONDS>` | | debuginfod 请求超时；0 表示不设置超时 | 5 |
| `--debuginfod-max-size <BYTES>` | | debuginfod 最大响应大小；0 表示不设置上限 | 0 |
| `--tui` | | 以 TUI 模式启动 | 自动 |
| `--log` | | 启用文件日志 | Script: 关, TUI: 开 |
| `--no-log` | | 禁用所有日志 | - |
| `--log-console` | | 启用控制台 stderr 日志 | 关 |
| `--no-log-console` | | 禁用控制台 stderr 日志 | - |
| `--log-level <LEVEL>` | | 设置日志级别 | warn |
| `--log-file <PATH>` | | 日志文件路径 | ./ghostscope.log |
| `--save-llvm-ir` | | 保存 LLVM IR 文件 | Debug: 开, Release: 关 |
| `--no-save-llvm-ir` | | 不保存 LLVM IR | - |
| `--save-ebpf` | | 保存 eBPF 字节码 | Debug: 开, Release: 关 |
| `--no-save-ebpf` | | 不保存 eBPF | - |
| `--save-ast` | | 保存 AST 文件 | Debug: 开, Release: 关 |
| `--no-save-ast` | | 不保存 AST | - |
| `--layout <MODE>` | | TUI 布局模式 | horizontal |
| `--no-source-panel` | | 隐藏源码面板（两面板布局） | 关 |
| `--source-panel` | | 显示源码面板 | 开 |
| `--config <PATH>` | | 自定义配置文件 | 自动检测 |
| `--force-perf-event-array` | | 强制 PerfEventArray（测试） | 关 |
| `--enable-sysmon-shared-lib` | | 独立 `-t` 目标为共享库时启动 sysmon，以支持未来进程中的全局变量探测。`-t -p` 不需要。 | 关 |
| `[BINARY] [ARGS...]` | | 启动目标程序并传递位置参数 | 无 |
| `--args <PROGRAM> [ARGS...]` | | 分隔 GhostScope 选项和目标程序参数 | 无 |

子命令：

| 子命令 | 说明 |
|--------|------|
| `bpffs prune` | 显式检查或清理按实例分隔的 bpffs pin 目录 |


## 配置文件

GhostScope 按以下顺序查找配置文件：
1. 通过 `--config` 指定的路径
2. `~/.ghostscope/config.toml`（用户级）
3. `./ghostscope.toml`（项目级）

### 配置文件格式

```toml
# ~/.ghostscope/config.toml 或 ./ghostscope.toml

[general]
# 默认日志文件路径
log_file = "ghostscope.log"

# 未提供脚本时的默认 TUI 模式
default_tui_mode = true

# 启用/禁用文件日志
enable_logging = false

# 启用/禁用控制台 stderr 日志
enable_console_logging = false

# 日志级别：error, warn, info, debug, trace
log_level = "warn"

[script]
# 非 TUI 脚本模式的事件 stdout 渲染
# pretty: 时间戳 + TraceID/PID/TID 头信息 + 缩进 payload
# plain: 只输出 payload 行
output = "pretty"

# stderr 上的交互式 DWARF/脚本/attach 状态提示
status = true

# pretty 模式的时间戳格式：local, boot, none
timestamp = "local"

# pretty stdout 和交互式 stderr 状态的 ANSI 色彩模式：
# - auto: 仅在对应输出流是 TTY 时启用颜色
# - always: 即使被重定向也强制输出 ANSI 颜色
# - never: 完全禁用 ANSI 颜色
color = "auto"

[dwarf]
# DWARF 调试信息搜索路径（用于 .gnu_debuglink 文件）
# 当二进制文件使用 .gnu_debuglink 引用独立的调试文件时，
# GhostScope 会在这些路径中搜索调试文件。
#
# 搜索顺序（优先级从高到低）：
# 1. 绝对路径（如果 .gnu_debuglink 包含绝对路径 - 罕见）
# 2. 用户配置的 search_paths + basename（此处配置）
# 3. 二进制文件所在目录 + basename
# 4. 二进制文件所在目录的 .debug 子目录 + basename
#
# 对于每个用户配置的路径，会检查两种位置：
#   - <路径>/debug_文件名
#   - <路径>/.debug/debug_文件名
#
# 特性：
# - 主目录展开："~/" 会被替换为你的主目录
# - 自动去除重复路径以避免冗余检查
# - 按顺序尝试路径，直到找到匹配的调试文件
#
# 注意：.gnu_debuglink 通常使用 basename（相对路径），但也支持绝对路径。
# 如需使用系统范围的调试目录（如 /usr/lib/debug），请添加到 search_paths。
#
# 示例：
search_paths = [
    "/usr/lib/debug",           # 系统调试符号（用于已安装的软件包）
    "/usr/local/lib/debug",     # 本地调试符号
    "~/.local/lib/debug",       # 用户调试符号（~ 会展开为主目录）
    "/opt/debug-symbols"        # 自定义调试符号服务器
]

# 允许非严格的调试文件匹配（CRC/Build-ID）
# 默认：false（严格）。当设置为 true 时，即使 CRC 或 Build‑ID 不完全匹配，
# 也会继续使用该独立调试文件（会记录警告日志）。仅建议在排障或环境不规范时短期启用。
allow_loose_debug_match = false

[dwarf.debuginfod]
# 可选的 debuginfod 调试信息回退。
# 模式参考 GDB：
#   - "off"：完全不使用 debuginfod，也不读取 debuginfod 相关环境变量
#   - "on"：嵌入式 DWARF 和本地独立调试文件都失败后，允许使用 debuginfod
#   - "ask"：预留给未来 TUI 交互确认（当前不会使用）
#
# 默认："off"（除非显式开启，否则不会联网）
enabled = "off"

# 服务器 URL。开启后如果此列表为空，GhostScope 会回退读取 DEBUGINFOD_URLS。
# 环境变量中是空白分隔；配置文件中使用 TOML 数组。
urls = [
    # "https://debuginfod.ubuntu.com",
    # "https://debuginfod.archlinux.org",
]

# 下载的 debuginfo/source 本地缓存目录。
# 未设置时使用：
#   1. DEBUGINFOD_CACHE_PATH
#   2. $XDG_CACHE_HOME/debuginfod_client
#   3. ~/.cache/debuginfod_client
# cache_dir = "~/.cache/debuginfod_client"

# 请求超时时间（秒）。优先级：
# 命令行 > 配置文件 > DEBUGINFOD_TIMEOUT > 内置默认 5 秒。
# 设置为 0 表示不设置请求超时。
timeout_secs = 5

# 最大响应大小（字节）。优先级：
# 命令行 > 配置文件 > DEBUGINFOD_MAXSIZE。设置为 0 表示不设置客户端大小上限。
max_size_bytes = 0

[files]
# 保存 LLVM IR 文件
[files.save_llvm_ir]
debug = true
release = false

# 保存 eBPF 字节码文件
[files.save_ebpf]
debug = true
release = false

# 保存 AST 文件
[files.save_ast]
debug = true
release = false

[ui]
# TUI 布局模式：Horizontal 或 Vertical（首字母大写）
layout = "Horizontal"

# 默认焦点面板：Source, EbpfInfo, 或 InteractiveCommand
default_focus = "InteractiveCommand"

# 是否显示源码面板（也可通过命令行 --source-panel/--no-source-panel，或在 UI 命令面板中使用 'ui source on/off' 控制）
show_source_panel = true

# 面板大小比例 [Source, EbpfInfo, InteractiveCommand]
# 必须是 3 个正整数
panel_ratios = [4, 3, 3]

# 当源码面板被隐藏时的两面板比例 [EbpfInfo, InteractiveCommand]
# 若未设置，则回退为 panel_ratios 的后两项（例如 4:3:3 -> 3:3，即 1:1）
# two_panel_ratios = [3, 3]

# eBPF 输出面板保留的最大跟踪消息数量
# 超过限制时，旧消息会自动丢弃
# 最小值：100
# 推荐值：
#   - 低频跟踪：1000-2000
#   - 中频跟踪：2000-5000（默认：2000）
#   - 高频跟踪：5000-10000
# 注意：较大的值会消耗更多内存
ebpf_max_messages = 2000

[ui.history]
# 启用命令历史
enabled = true

# 最大历史条目数
max_entries = 5000

[ebpf]
# RingBuf map 大小（字节，必须是 2 的幂）
# 控制从内核向用户空间传输跟踪事件的环形缓冲区大小
# 有效范围：4096 (4KB) 到 16777216 (16MB)
ringbuf_size = 262144  # 256KB（默认）

# 推荐值：
#   - 低频跟踪：131072 (128KB)
#   - 中频跟踪：262144 (256KB)
#   - 高频跟踪：524288 (512KB) 或 1048576 (1MB)

# PerfEventArray 每 CPU 页面数（用于旧内核 < 5.8）
# 每个 CPU 为 PerfEventArray 缓冲区分配的内存页数
# 每页通常为 4KB，所以 64 页 = 每 CPU 256KB
# 必须是 2 的幂。有效范围：8 到 1024 页
perf_page_count = 64  # 默认（每 CPU 256KB）

# 推荐值：
#   - 低频跟踪：32 页（每 CPU ~128KB）
#   - 中频跟踪：64 页（每 CPU ~256KB）
#   - 高频跟踪：128-256 页（每 CPU 512KB-1MB）

# ASLR 地址转换的 (pid, module) 偏移条目最大数量
# 存储每个进程中每个加载模块的运行时地址偏移
# 有效范围：64 到 65536
proc_module_offsets_max_entries = 4096  # 默认

# 扩展格式占位符（{:x}/{:s}）单个参数的内存转储上限（字节）。
# 超过该上限的请求会被截断。
mem_dump_cap = 256

# 内置比较（strncmp/starts_with/memcmp）的最大比较字节数。
# 实际比较长度为 min(max(len, 0), compare_cap)。
# 默认：64 字节。
compare_cap = 64

# 单条 trace 事件的最大大小（字节）。适用于 PerfEventArray 累计缓冲区。
max_trace_event_size = 32768

# 推荐值：
#   - 简单打印：16384
#   - 通用场景：32768
#   - 大格式化输出：65536

# 强制使用 PerfEventArray 而非 RingBuf（仅用于测试）
# 警告：这仅用于测试目的。设为 true 会强制使用 PerfEventArray
# 即使在支持 RingBuf 的内核上（>= 5.8）。PerfEventArray 相比 RingBuf
# 有性能开销，仅应用于兼容性测试。
force_perf_event_array = false  # 默认（根据内核版本自动检测）

# 当独立 -t 目标为共享库（.so）时启动 sysmon eBPF，
# 用于维护后续启动进程里动态库的 ASLR 偏移。
# -t 与 -p 同时使用时不会使用 sysmon，因为 PID 已经提供具体进程映射。
# 启用后会注册系统范围的 sched tracepoint，进程频繁创建/退出的环境下可能带来性能开销。
enable_sysmon_for_shared_lib = false  # 默认关闭
```

### 配置示例

#### 开发配置

```toml
# 详细日志和调试输出的开发设置
[general]
log_level = "debug"
enable_logging = true
enable_console_logging = true

[files]
[files.save_llvm_ir]
debug = true
[files.save_ebpf]
debug = true
[files.save_ast]
debug = true
```

#### 生产配置

```toml
# 最小开销的生产设置
[general]
log_level = "error"
enable_logging = true
enable_console_logging = false
log_file = "/var/log/ghostscope.log"

[files]
[files.save_llvm_ir]
debug = false
release = false
[files.save_ebpf]
debug = false
release = false
```

#### UI 优化配置

```toml
# 为交互式调试优化
[ui]
layout = "Horizontal"
default_focus = "Source"
panel_ratios = [5, 2, 3]  # 更大的源代码面板

[ui.history]
enabled = true
max_entries = 10000
```

#### 高频跟踪配置

```toml
# 针对高频事件跟踪优化
[ebpf]
ringbuf_size = 1048576  # 1MB 缓冲区用于高事件率
mem_dump_cap = 4096     # 单参数转储上限更高
compare_cap = 64        # 内置比较最大比较字节数（strncmp/memcmp）
max_trace_event_size = 65536  # 大格式化输出需要更大的事件大小
proc_module_offsets_max_entries = 8192  # 支持更多模块

[general]
log_level = "info"  # 降低日志开销
enable_console_logging = false
```

#### 低开销配置

```toml
# 生产环境最小资源占用
[ebpf]
ringbuf_size = 131072  # 128KB 最小缓冲区
mem_dump_cap = 512
compare_cap = 32       # 降低内置比较上限以减小开销
max_trace_event_size = 16384
proc_module_offsets_max_entries = 1024  # 仅单进程

[general]
log_level = "error"
enable_logging = false

[files]
[files.save_llvm_ir]
debug = false
release = false
[files.save_ebpf]
debug = false
release = false
```

## 环境变量

### RUST_LOG

未指定 `--log-level` 时控制日志级别：

```bash
# 通过环境变量设置日志级别
export RUST_LOG=debug
ghostscope -p 1234

# 模块特定的日志
export RUST_LOG=ghostscope=debug,ghostscope_compiler=trace
```

优先级：命令行 > RUST_LOG > 配置文件

### LLVM_SYS_*_PREFIX

如果未自动找到，指定 LLVM 安装路径：

```bash
# 对于 LLVM 15
export LLVM_SYS_150_PREFIX=/usr/lib/llvm-15

# 对于 LLVM 17
export LLVM_SYS_170_PREFIX=/usr/lib/llvm-17
```

## 默认行为

### 日志默认值

- **TUI 模式**：启用文件日志，禁用控制台日志
- **脚本模式**：默认禁用所有日志
- **日志级别**：未指定时为 `warn`
- **日志文件**：当前目录中的 `./ghostscope.log`

### 调试输出默认值

- **Debug 构建**：保存 LLVM IR、eBPF 字节码和 AST 文件
- **Release 构建**：不保存任何调试文件

### UI 默认值

- **布局**：Horizontal（面板横向排列）
- **面板比例**：4:3:3（Source:EbpfInfo:Command）
- **默认焦点**：InteractiveCommand 面板
- **eBPF 最大消息数**：2000 条消息
- **历史记录**：启用，5000 条条目限制

## 文件输出命名

调试文件使用以下命名约定保存：
```
gs_{pid}_{exec}_{func}_{index}.{ext}
```

其中：
- `pid`：进程 ID
- `exec`：可执行文件名
- `func`：函数名
- `index`：多个追踪的唯一索引
- `ext`：文件扩展名（`.ll` 表示 LLVM IR，`.ebpf` 表示字节码，`.ast` 表示 AST）

示例：`gs_1234_myapp_main_0.ll`

## 验证

GhostScope 在启动时验证配置：

1. **PID 验证**：检查指定的 PID 是否存在（通过 Linux 上的 `/proc/<PID>`）
2. **文件验证**：验证目标、脚本和调试文件是否存在
3. **目标路径解析**：将相对路径转换为绝对路径
4. **面板比例**：确保所有 3 个值都是正（非零）整数
5. **日志级别**：验证是否为允许的值（error, warn, info, debug, trace）
6. **布局模式**：验证是否为允许的值（Horizontal, Vertical - 首字母大写）
7. **UI 配置**：
   - **ebpf_max_messages**：必须至少为 100
8. **eBPF 配置**：
   - **ringbuf_size**：必须是 2 的幂，范围 4096-16777216 字节
   - **perf_page_count**：必须是 2 的幂，范围 8-1024 页
   - **proc_module_offsets_max_entries**：必须在 64-65536 范围内
   - **mem_dump_cap**、**compare_cap** 和 **max_trace_event_size** 是运行时上限；`max_trace_event_size` 可能会根据实际事件传输方式被 clamp。

无效配置将产生清晰的错误消息和修复建议。

### 常见验证错误

- **"Process with PID X is not running"**：未找到目标进程。使用 `ps -p <PID>` 验证。
- **"Target file does not exist"**：未找到指定的目标路径。检查文件路径。
- **"Script file does not exist"**：未找到指定的脚本文件。
- **"Invalid log level"**：使用以下之一：error, warn, info, debug, trace。
- **"ringbuf_size must be a power of 2"**：使用 2 的幂值，如 131072、262144、524288 等。
- **"ringbuf_size X is out of reasonable range"**：必须在 4KB 到 16MB 之间。
- **"perf_page_count must be a power of 2"**：使用 32、64、128、256 等 2 的幂值。
- **"perf_page_count X is out of reasonable range"**：必须在 8 到 1024 页之间。
- **"proc_module_offsets_max_entries X is out of reasonable range"**：必须在 64 到 65536 之间。
- **"ebpf_max_messages X is too small"**：必须至少为 100。在配置文件中增加该值。

## 最佳实践

1. **使用配置文件**：将常用设置存储在 `~/.ghostscope/config.toml` 中
2. **环境特定配置**：为开发和生产保留单独的配置
3. **日志轮转**：为长时间运行的会话配置外部日志轮转
4. **调试输出**：在生产环境中禁用调试文件保存以提高性能
5. **面板布局**：宽屏使用水平布局，窄屏使用垂直布局
6. **eBPF 调优**：
   - 从默认 `ringbuf_size`（256KB）开始，如果事件丢失则增加
   - 使用大缓冲区时监控内核内存使用情况
   - 单进程调试时使用较小的 `proc_module_offsets_max_entries`
   - 高频跟踪场景下增加缓冲区大小

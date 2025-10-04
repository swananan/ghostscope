# 配置参考

GhostScope 可以通过命令行参数、配置文件和环境变量进行配置。

## 配置优先级

配置遵循以下优先级顺序（从高到低）：
1. 命令行参数
2. 环境变量（RUST_LOG）
3. 配置文件（~/.ghostscope/config.toml 或 ./ghostscope.toml）
4. 默认值

## 命令行参数

### 目标选择

```bash
# 通过 PID 附加到运行中的进程
ghostscope -p <PID>
ghostscope --pid <PID>

# 指定目标可执行文件或库（支持路径解析）
ghostscope -t <PATH>
ghostscope --target <PATH>

# 相对路径的解析顺序：
# 1. 当前工作目录
# 2. ghostscope 可执行文件所在目录
# 3. 如果未找到则转换为绝对路径

# 两者可以一起使用进行 PID 过滤
ghostscope -t /usr/bin/myapp -p 1234

# 启动新进程并传递参数
ghostscope --args /path/to/program arg1 arg2
# --args 后的所有内容都会传递给目标程序
```

### 脚本执行

```bash
# 运行内联脚本
ghostscope -s 'trace("main:entry") { print "Started"; }'
ghostscope --script 'trace("main:entry") { print "Started"; }'

# 从文件运行脚本
ghostscope --script-file trace.gs

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
# 2. .gnu_debuglink 节
# 3. .gnu_debugdata 节（Android/压缩格式）
# 4. /usr/lib/debug, /usr/local/lib/debug
# 5. 基于 Build-ID 的路径
# 6. binary.debug, binary.dbg
```

### 日志配置

```bash
# 启用文件日志（默认：./ghostscope.log）
ghostscope --log

# 禁用所有日志
ghostscope --no-log

# 除文件外还启用控制台输出
ghostscope --log-console

# 禁用控制台输出
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
```

### 高级 eBPF 选项

```bash
# 强制使用 PerfEventArray 模式（仅用于测试）
# 警告：仅用于测试目的。即使在内核 >= 5.8 上也强制使用 PerfEventArray
ghostscope --force-perf-event-array
```

### 完整命令参考

| 选项 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--pid <PID>` | `-p` | 要附加的进程 ID | 无 |
| `--target <PATH>` | `-t` | 目标可执行文件或库 | 无 |
| `--script <SCRIPT>` | `-s` | 要执行的内联脚本 | 无 |
| `--script-file <PATH>` | | 要执行的脚本文件 | 无 |
| `--debug-file <PATH>` | `-d` | 调试信息文件路径 | 自动检测 |
| `--tui` | | 以 TUI 模式启动 | 自动 |
| `--log` | | 启用文件日志 | Script: 关, TUI: 开 |
| `--no-log` | | 禁用所有日志 | - |
| `--log-console` | | 启用控制台日志 | 关 |
| `--no-log-console` | | 禁用控制台日志 | - |
| `--log-level <LEVEL>` | | 设置日志级别 | warn |
| `--log-file <PATH>` | | 日志文件路径 | ./ghostscope.log |
| `--save-llvm-ir` | | 保存 LLVM IR 文件 | Debug: 开, Release: 关 |
| `--no-save-llvm-ir` | | 不保存 LLVM IR | - |
| `--save-ebpf` | | 保存 eBPF 字节码 | Debug: 开, Release: 关 |
| `--no-save-ebpf` | | 不保存 eBPF | - |
| `--save-ast` | | 保存 AST 文件 | Debug: 开, Release: 关 |
| `--no-save-ast` | | 不保存 AST | - |
| `--layout <MODE>` | | TUI 布局模式 | horizontal |
| `--config <PATH>` | | 自定义配置文件 | 自动检测 |
| `--force-perf-event-array` | | 强制 PerfEventArray（测试） | 关 |
| `--args <PROGRAM> [ARGS...]` | | 启动程序并传递参数 | 无 |

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

# 启用/禁用控制台日志
enable_console_logging = false

# 日志级别：error, warn, info, debug, trace
log_level = "warn"

[dwarf]
# 调试信息搜索路径
search_paths = [
    "/usr/lib/debug",
    "/usr/local/lib/debug"
]

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

# 面板大小比例 [Source, EbpfInfo, InteractiveCommand]
# 必须是 3 个正整数
panel_ratios = [4, 3, 3]

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

# 推荐值：
#   - 单进程：1024
#   - 多进程：4096
#   - 系统级跟踪：8192 或 16384

# 强制使用 PerfEventArray 而非 RingBuf（仅用于测试）
# 警告：这仅用于测试目的。设为 true 会强制使用 PerfEventArray
# 即使在支持 RingBuf 的内核上（>= 5.8）。PerfEventArray 相比 RingBuf
# 有性能开销，仅应用于兼容性测试。
force_perf_event_array = false  # 默认（根据内核版本自动检测）
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
7. **eBPF 配置**：
   - **ringbuf_size**：必须是 2 的幂，范围 4096-16777216 字节
   - **proc_module_offsets_max_entries**：必须在 64-65536 范围内

无效配置将产生清晰的错误消息和修复建议。

### 常见验证错误

- **"Process with PID X is not running"**：未找到目标进程。使用 `ps -p <PID>` 验证。
- **"Target file does not exist"**：未找到指定的目标路径。检查文件路径。
- **"Script file does not exist"**：未找到指定的脚本文件。
- **"Invalid log level"**：使用以下之一：error, warn, info, debug, trace。
- **"ringbuf_size must be a power of 2"**：使用 2 的幂值，如 131072、262144、524288 等。
- **"ringbuf_size X is out of reasonable range"**：必须在 4KB 到 16MB 之间。
- **"proc_module_offsets_max_entries X is out of reasonable range"**：必须在 64 到 65536 之间。

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

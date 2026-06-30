# 安装指南

## 系统要求

- **操作系统**: Linux（内核 4.4 或更高版本）
  - **必需的内核特性**：
    - eBPF 支持 (CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y)
    - uprobe 支持 (CONFIG_UPROBE_EVENTS=y) - Linux 3.5 引入
    - BPF_MAP_TYPE_PERF_EVENT_ARRAY - Linux 4.3 引入
    - 稳定的 eBPF 追踪支持 - 建议 Linux 4.4+
- **架构**: 目前仅支持 x86_64 (AMD64)

## 安装

### 快速安装脚本（推荐）

GhostScope 提供了一个一键安装脚本，会自动下载最新的发布版二进制，复制默认配置到 `~/.ghostscope/config.toml`，并安装到 `~/.ghostscope/bin`（无需 sudo）。

```bash
curl -fsSL https://raw.githubusercontent.com/swananan/ghostscope/main/scripts/install.sh | bash
```

**环境要求**

- `curl`、`tar`、`install`
- `python3`（用于选择最新的 release 版本）

脚本执行完成后，请将以下 PATH 语句写入相应的 shell 配置文件：

- Bash：`echo 'export PATH="$HOME/.ghostscope/bin:$PATH"' >> ~/.bashrc`
- Zsh：`echo 'export PATH="$HOME/.ghostscope/bin:$PATH"' >> ~/.zshrc`
- Fish：`echo 'set -Ux PATH $HOME/.ghostscope/bin $PATH' >> ~/.config/fish/config.fish`

重新打开终端后运行 `ghostscope --version` 验证安装。

### 从 GitHub Releases 下载

1. 从 [GitHub Releases](https://github.com/swananan/ghostscope/releases) 下载最新版本

2. 解压二进制文件：
```bash
tar -xzf ghostscope-v0.1.6-x86_64-linux.tar.gz
```

3. 移动到系统路径（可选）：
```bash
sudo mv ghostscope /usr/local/bin/
```

4. 设置可执行权限：
```bash
chmod +x ghostscope
```

5. 验证安装：
```bash
ghostscope --version
```

## 安装后设置

### 1. 验证安装

```bash
# 检查 GhostScope 版本
ghostscope --version

# 查看帮助
ghostscope --help
```

### 2. 配置权限

GhostScope 需要 root 权限来附加 eBPF 程序。您有以下几种选择：

#### 选项 A：使用 sudo（推荐）
```bash
sudo ghostscope -p $(pidof target)
```

#### 选项 B：设置 Capabilities
```bash
sudo setcap cap_sys_admin,cap_sys_ptrace,cap_bpf+eip /path/to/ghostscope
```

#### 选项 C：添加用户到追踪组
```bash
# 如果不存在则创建追踪组
sudo groupadd tracing

# 将您的用户添加到组
sudo usermod -a -G tracing $USER

# 为组配置权限
echo 'kernel.perf_event_paranoid = -1' | sudo tee /etc/sysctl.d/10-ghostscope.conf
sudo sysctl -p /etc/sysctl.d/10-ghostscope.conf

# 重新登录以使组更改生效
```

### 3. 调试符号（必需）

GhostScope **需要** 目标二进制文件中的 DWARF 调试信息才能正常工作。调试符号通常嵌入在二进制文件中。

```bash
# 检查您的二进制文件是否有调试信息（必需）
readelf -S your_program | grep debug

# 带调试信息的示例输出：
# [28] .debug_aranges    PROGBITS         0000000000000000  0070a3c0
# [29] .debug_info       PROGBITS         0000000000000000  007158a0
# [30] .debug_abbrev     PROGBITS         0000000000000000  011b4eb1
# [31] .debug_line       PROGBITS         0000000000000000  012705a2
# [32] .debug_str        PROGBITS         0000000000000000  01542903
```

如果没有找到 `.debug_*` 段，则必须重新编译二进制文件并启用调试符号（通常使用 `-g` 标志或等效选项）。

**注意**：没有调试符号，GhostScope 无法解析函数名、变量或源代码行信息。

#### 独立调试文件（GNU debuglink）

GhostScope 支持使用 `.gnu_debuglink` 机制从独立的调试文件加载调试信息。这在生产环境中处理 stripped 二进制文件时非常有用。

**检查 debuglink 段：**
```bash
# 检查二进制文件是否有指向独立调试文件的 .gnu_debuglink
readelf -x .gnu_debuglink your_program

# 示例输出：
# Hex dump of section '.gnu_debuglink':
#   0x00000000 6d795f70 726f6772 616d2e64 65627567 my_program.debug
#   0x00000010 00000000 12345678                   ....4Vx
```

**为 stripped 二进制创建独立调试文件：**
```bash
# 1. 提取调试信息到独立文件
objcopy --only-keep-debug your_program your_program.debug

# 2. 从二进制文件中删除调试信息
objcopy --strip-debug your_program

# 3. 在二进制文件中添加指向调试文件的链接
objcopy --add-gnu-debuglink=your_program.debug your_program

# 验证 debuglink 已添加
readelf -x .gnu_debuglink your_program
```

**不依赖 debuglink，直接指定显式调试文件：**
```bash
# 目标模式：将调试文件绑定到该二进制或共享库
sudo ghostscope -t /path/to/your_program --debug-file /path/to/your_program.debug

# PID 模式：将调试文件绑定到 /proc/<pid>/exe（主可执行文件）
sudo ghostscope -p $(pidof your_program) --debug-file /path/to/your_program.debug
```

使用 `--debug-file`/`-d` 时，如果目标文件有 `.gnu_debuglink`，GhostScope
会校验 debuglink CRC；如果目标文件和调试文件都提供 Build-ID，也会比较
Build-ID 元数据。CRC 不匹配和 Build-ID 不匹配都会被拒绝，除非显式设置
`--allow-loose-debug-match`。如果任意一侧缺少 Build-ID，GhostScope 会记录
warning，但不会仅因此拒绝该文件。显式调试文件必须包含可用的 `.debug_info`。

默认情况下，自动 `.gnu_debuglink` 发现只有在独立文件通过 debuglink CRC 校验、
双方都提供 Build-ID 时通过 Build-ID 校验，并且包含可用 `.debug_info` 时才会
报告为 `debuglink`。设置 `--allow-loose-debug-match` 后，CRC/Build-ID 不匹配会
以 warning 形式接受；只要该文件包含可用 `.debug_info`，仍会报告为 `debuglink`。
如果文件不包含 DWARF，GhostScope 会忽略它，启用 debuginfod 时会继续 fallback，
否则该模块会报告为 `missing`。

**调试文件搜索路径：**

对于自动 `.gnu_debuglink` 发现，GhostScope 会搜索：
1. `.gnu_debuglink` 中的绝对路径（如果存在）
2. `[dwarf].search_paths` 中的目录（默认包含 `/usr/lib/debug`、
   `/usr/local/lib/debug`）
3. 二进制文件同目录：`/path/to/your_program.debug`
4. `.debug` 子目录：`/path/to/.debug/your_program.debug`

> **自定义搜索路径**：默认配置已经包含常见系统调试目录。如果你覆盖
> `[dwarf].search_paths`，需要把仍然希望 GhostScope 搜索的系统或自定义目录保留
> 在列表中。详细信息请参阅
> [配置参考 - DWARF 调试搜索路径](configuration.md#dwarf)。

**安装系统调试包：**
```bash
# Ubuntu/Debian - 安装 libc 的调试符号
sudo apt install libc6-dbg

# Fedora/RHEL - 安装调试符号
sudo dnf debuginfo-install glibc

# 调试文件通常安装在 /usr/lib/debug/ 目录下，
# 该目录已包含在默认 [dwarf].search_paths 中。
```

**验证：**

当独立调试文件位于搜索路径中时，GhostScope 会检测并使用它们。脚本模式中，
如果交互式终端启用 CLI status 输出，启动报告会展示 DWARF 来源汇总和模块加载明细：
```text
DWARF ready: 11 modules, 49425 functions, 3393 variables, 152543 types, debug: embedded:2 missing:9, 3.0s | pid=2762799
Startup load report:
  target: pid=2762799
  debug sources: embedded:2 missing:9
  modules loaded: 11 completed, 0 failed
  module details:
    embedded /usr/sbin/nginx      49000 funcs   3300 vars 150000 types  1200ms  /usr/sbin/nginx
  missing DWARF: 9 modules (libc.so.6, libssl.so.3, libcrypto.so.3 +6 more；使用 --log --log-level debug --log-file <path> 查看完整路径)
```

启动报告是 status 输出，不是 tracing 日志。stderr 不是终端，或者启用了
console stderr 日志时，它不会显示。需要查看更底层的 debuglink 解析过程时，
可以继续使用日志：
```bash
# 在脚本模式中启用调试日志以查看 debuglink 解析过程
sudo ghostscope -p $(pidof your_program) \
  --script-file /path/to/script.gs \
  --log --log-level debug

# RUST_LOG 也可以设置过滤器，但仍需启用 logging
sudo env RUST_LOG=debug ghostscope -p $(pidof your_program) \
  --script-file /path/to/script.gs \
  --log

# 查找类似以下的消息：
# "Looking for debug file 'your_program.debug' for binary '/path/to/your_program'"
# "Found matching debug file: /path/to/your_program.debug (CRC: 0x12345678)"
```

## 故障排除

### 权限被拒绝错误

如果运行 GhostScope 时遇到权限错误：

1. 确保您使用 sudo 或已设置适当的 capabilities
2. 检查内核配置：
   ```bash
   zcat /proc/config.gz | grep BPF
   ```
   确保设置了 `CONFIG_BPF=y` 和 `CONFIG_BPF_SYSCALL=y`

3. 检查 BPF 是否已启用：
   ```bash
   ls /sys/fs/bpf
   ```

4. 运行 GhostScope 前，检查 `bpffs` 是否已经挂载：
   ```bash
   mount | grep bpf
   ```
   你应该能看到 `/sys/fs/bpf` 以 `bpf` 文件系统类型挂载。
   如果 `/sys/fs/bpf` 目录存在，但那里没有实际挂载 `bpffs`，GhostScope 在 pin BPF map 时会失败。
   有些系统默认不会自动挂载 `bpffs`，WSL2、精简发行版或容器环境里更常见。
   这种情况下可以执行：
   ```bash
   sudo mount -t bpf bpf /sys/fs/bpf
   ```

## 下一步

- 阅读[快速教程](tutorial.md)学习基本用法
- 使用[配置指南](configuration.md)配置 GhostScope
- 探索[脚本示例](scripting.md)了解追踪功能

## 获取帮助

如果在安装过程中遇到问题：

1. 查看[常见问题](faq.md)了解常见问题
2. 搜索[现有问题](https://github.com/swananan/ghostscope/issues)
3. 提交新问题并附上安装日志

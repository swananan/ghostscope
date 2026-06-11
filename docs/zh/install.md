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
tar -xzf ghostscope-v0.1.5-x86_64-linux.tar.gz
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

使用 `--debug-file`/`-d` 时，GhostScope 会在加载前校验可用的 CRC 和
Build-ID 元数据。不匹配会被拒绝，除非显式设置 `--allow-loose-debug-match`。

**调试文件搜索路径（遵循 GDB 约定）：**

GhostScope 会自动在以下位置搜索调试文件：
1. 二进制文件同目录：`/path/to/your_program.debug`
2. `.debug` 子目录：`/path/to/.debug/your_program.debug`
3. 全局调试目录：`/usr/lib/debug/path/to/your_program.debug`

> **📝 自定义搜索路径**：你可以在配置文件中配置额外的搜索路径（包括用户特定目录如 `~/.local/lib/debug`）。详细信息请参阅 [配置参考 - DWARF 调试搜索路径](configuration.md#dwarf)。

**安装系统调试包：**
```bash
# Ubuntu/Debian - 安装 libc 的调试符号
sudo apt install libc6-dbg

# Fedora/RHEL - 安装调试符号
sudo dnf debuginfo-install glibc

# 调试文件通常安装在 /usr/lib/debug/ 目录下
```

**验证：**

GhostScope 会自动检测并使用独立调试文件。你可以通过日志验证：
```bash
# 启用调试日志以查看 debuglink 解析过程
RUST_LOG=debug sudo ghostscope -p $(pidof your_program)

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

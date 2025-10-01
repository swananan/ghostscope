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

### 从 GitHub Releases 下载

1. 从 [GitHub Releases](https://github.com/swananan/ghostscope/releases) 下载最新版本

2. 解压二进制文件：
```bash
tar -xzf ghostscope-v0.1.0-x86_64-linux.tar.gz
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

## 下一步

- 阅读[快速教程](tutorial.md)学习基本用法
- 使用[配置指南](configuration.md)配置 GhostScope
- 探索[脚本示例](scripting.md)了解追踪功能

## 获取帮助

如果在安装过程中遇到问题：

1. 查看[常见问题](faq.md)了解常见问题
2. 搜索[现有问题](https://github.com/swananan/ghostscope/issues)
3. 提交新问题并附上安装日志
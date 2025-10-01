# 命令参考

本文档详细介绍 GhostScope 命令交互面板输入模式下可以使用的所有命令。

## 快速参考

在命令面板中输入 `help` 查看所有可用命令及其快捷方式。

## 📊 追踪命令

用于设置和管理应用程序中的追踪点。

### trace - 开始追踪

**语法：**
```
trace <target>
t <target>          # 缩写形式
```

**参数：**
- `<target>`: 可以是：
  - 函数名：`function_name`
  - 文件和行号：`file:line`，其中文件可以是：
    - 完整路径：`/path/to/file.c:42`
    - 相对路径：`src/file.c:42`
    - 文件名（模糊匹配）：`file.c:42` 或者部分名称

**示例：**
```
trace main                    # 追踪 main 函数
trace calculate_something     # 追踪特定函数
trace /home/user/src/sample.c:42    # 完整路径
trace src/sample.c:42         # 相对路径
trace sample.c:42            # 仅文件名（模糊匹配）
trace sample:42              # 部分文件名（模糊匹配）
t process_data               # 使用缩写形式
```

**说明：**
执行 trace 命令后会进入脚本编辑模式，编写追踪脚本。按 `Ctrl+S` 保存并执行，`Ctrl+C` 取消。

### enable - 启用追踪

**语法：**
```
enable <id|all>
en <id|all>         # 缩写形式
```

**参数：**
- `<id>`: 追踪点ID号
- `all`: 启用所有追踪点

**示例：**
```
enable 1            # 启用ID为1的追踪
enable all          # 启用所有追踪
en 3               # 缩写形式启用ID 3
```

### disable - 禁用追踪

**语法：**
```
disable <id|all>
dis <id|all>        # 缩写形式
```

**参数：**
- `<id>`: 追踪点ID号
- `all`: 禁用所有追踪点

**示例：**
```
disable 2           # 禁用ID为2的追踪
disable all         # 禁用所有追踪
dis 1              # 缩写形式禁用ID 1
```

### delete - 删除追踪

**语法：**
```
delete <id|all>
del <id|all>        # 缩写形式
```

**参数：**
- `<id>`: 追踪点ID号
- `all`: 删除所有追踪点

**示例：**
```
delete 3            # 删除ID为3的追踪
delete all          # 删除所有追踪
del 2              # 缩写形式删除ID 2
```

### save traces - 保存追踪点

**语法：**
```
save traces [file]
save traces enabled [file]
save traces disabled [file]
s t [file]          # 缩写形式
```

**参数：**
- `[file]`: 可选文件名（未提供时使用默认文件名）
- `enabled`: 只保存启用的追踪
- `disabled`: 只保存禁用的追踪

**示例：**
```
save traces                     # 保存所有到默认文件
save traces my_traces.gs        # 保存到指定文件
save traces enabled active.gs   # 只保存启用的追踪
save traces disabled backup.gs  # 只保存禁用的追踪
s t session.gs                  # 缩写形式
```

### source - 加载追踪脚本

**语法：**
```
source <file>
s <file>            # 缩写形式（但不包括 "s t"）
```

**参数：**
- `<file>`: 要加载的脚本文件

**示例：**
```
source traces.gs            # 加载追踪脚本
source /path/to/script.gs   # 从路径加载
s my_script.gs             # 缩写形式
```

## 🔍 信息命令

用于查看调试信息和追踪状态。

### info - 显示信息命令

**语法：**
```
info                # 显示可用的info子命令
i                   # 缩写形式
```

**说明：**
显示所有可用的info子命令列表。

### info trace - 查看追踪状态

**语法：**
```
info trace [id]
i t [id]            # 缩写形式
```

**参数：**
- `[id]`: 可选的追踪ID（省略时显示全部）

**示例：**
```
info trace          # 显示所有追踪状态
info trace 1        # 显示ID为1的详情
i t                # 缩写形式显示全部
i t 2              # 缩写形式显示ID 2
```

### info source - 列出源文件

**语法：**
```
info source
i s                 # 缩写形式
```

**说明：**
显示所有已加载的带调试信息的源文件。

### info share - 列出共享库

**语法：**
```
info share
i sh                # 缩写形式
```

**说明：**
显示所有已加载的共享库（动态库）。

### info function - 函数调试信息

**语法：**
```
info function <name>
i f <name>          # 缩写形式
```

**参数：**
- `<name>`: 函数名

**示例：**
```
info function main       # 显示main的调试信息
i f calculate           # 缩写形式
```

### info line - 源码行调试信息

**语法：**
```
info line <file:line>
i l <file:line>     # 缩写形式
```

**参数：**
- `<file:line>`: 文件名和行号

**示例：**
```
info line main.c:42     # 第42行的调试信息
i l test.c:100         # 缩写形式
```

### info address - 地址调试信息 [待实现]

**语法：**
```
info address <addr>
i a <addr>          # 缩写形式
```

**参数：**
- `<addr>`: 内存地址

**状态：** 尚未实现

## ⚙️ 控制命令

通用控制和实用命令。

### help - 显示帮助

**语法：**
```
help
```

**说明：**
显示完整的帮助信息，包含所有可用命令和键盘快捷键。

### clear - 清除历史

**语法：**
```
clear
```

**说明：**
清除命令历史记录（删除所有历史命令）。

### quit/exit - 退出程序

**语法：**
```
quit
exit
```

**说明：**
退出 GhostScope。也可以按两次 `Ctrl+C` 退出。

## 🧭 导航与输入技巧

### 输入模式快捷键

| 快捷键 | 功能 |
|--------|------|
| `Tab` | 命令补全 |
| `→` 或 `Ctrl+E` | 接受自动建议（灰色文本）|
| `Ctrl+P` 或 `↑` | 上一条历史命令 |
| `Ctrl+N` 或 `↓` | 下一条历史命令 |
| `Ctrl+A` | 移到行首 |
| `Ctrl+E` | 移到行尾 |
| `Ctrl+B` 或 `←` | 光标左移 |
| `Ctrl+F` 或 `→` | 光标右移 |
| `Ctrl+W` | 删除前一个单词 |
| `Ctrl+U` | 删除到行首 |
| `Ctrl+K` | 删除到行尾 |
| `Ctrl+H` 或 `Backspace` | 删除前一个字符 |

### 命令模式（Vim风格）

| 快捷键 | 功能 |
|--------|------|
| `jk`（快速）或 `Esc` | 进入命令模式 |
| `h/j/k/l` | 左/下/上/右导航 |
| `i` | 返回输入模式 |
| `g` | 跳到顶部 |
| `G` | 跳到底部 |
| `Ctrl+U` | 向上翻半页 |
| `Ctrl+D` | 向下翻半页 |

## 命令缩写对照表

| 完整命令 | 缩写 | 说明 |
|---------|------|------|
| `trace` | `t` | 设置追踪点 |
| `enable` | `en` | 启用追踪 |
| `disable` | `dis` | 禁用追踪 |
| `delete` | `del` | 删除追踪 |
| `info` | `i` | 查看信息 |
| `info trace` | `i t` | 查看追踪状态 |
| `info source` | `i s` | 查看源文件 |
| `info share` | `i sh` | 查看共享库 |
| `info function` | `i f` | 查看函数信息 |
| `info line` | `i l` | 查看行信息 |
| `info address` | `i a` | 查看地址信息 |
| `save traces` | `s t` | 保存追踪点 |
| `source` | `s` | 加载脚本（除了"s t"）|

## 命令补全

GhostScope 提供智能命令补全：

1. **Tab 补全**：按 Tab 键自动补全命令和文件名
2. **自动建议**：输入时显示灰色建议文本，按 `→` 或 `Ctrl+E` 接受
3. **智能匹配**：补全支持完整命令和缩写

## 技巧与最佳实践

1. **使用缩写**：熟练掌握命令缩写（`t`、`en`、`dis`）提高效率
2. **Tab 是好帮手**：大量使用 Tab 进行补全和探索
3. **历史导航**：使用 `Ctrl+P/N` 或方向键快速重用命令
4. **批量操作**：使用 `all` 参数一次操作所有追踪
5. **保存会话**：定期使用 `save traces` 保存追踪配置
6. **脚本复用**：将常用追踪模式保存到文件，用 `source` 加载

## 错误消息

常见错误消息及其含义：

- `"Unknown command"`：命令未识别。检查拼写或使用 `help`
- `"Usage: <command> <args>"`：参数无效。检查命令语法
- `"Trace ID not found"`：指定的追踪ID不存在
- `"File not found"`：脚本文件在指定路径不存在

## 相关文档

- [TUI 参考指南](tui-reference.md) - 完整的键盘快捷键
- [脚本语言参考](../scripting.md) - 追踪脚本语法
- [快速教程](tutorial.md) - 入门指南
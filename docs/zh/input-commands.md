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
  - 地址：`0xADDR` 或 `模块后缀:0xADDR`
    - `0xADDR`：模块相对虚拟地址（DWARF PC）。默认模块取决于启动模式：
      - `-t <binary>`：默认模块为 `<binary>`（包含 `.so`）
      - `-p <pid>`：默认模块为进程的主可执行文件
    - `模块后缀:0xADDR`：指定模块 + 地址。模块部分支持“全路径”或“唯一后缀”匹配；若后缀不唯一，会报歧义并列出候选。

**示例：**
```
trace main                    # 追踪 main 函数
trace calculate_something     # 追踪特定函数
trace /home/user/src/sample.c:42    # 完整路径
trace src/sample.c:42         # 相对路径
trace sample.c:42            # 仅文件名（模糊匹配）
trace sample:42              # 部分文件名（模糊匹配）
t 0x401234                   # 在默认模块（取决于 -t/-p）按地址追踪
t libc.so.6:0x1234           # 指定共享库（后缀匹配）按地址追踪
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

### save output - 启动实时 eBPF 输出日志

**语法：**
```
save output [file]
s o [file]          # 缩写形式
```

**参数：**
- `[file]`: 可选文件名（未提供时使用带时间戳的默认文件名）

**行为：**
- 启动 eBPF 追踪事件的实时日志记录
- 后续所有追踪事件立即写入文件
- 文件不存在时创建，存在时追加
- 每个事件立即刷新，确保实时捕获
- 使用 `stop output` 停止日志记录

**示例：**
```
save output                     # 开始记录到 ebpf_output_时间戳.log
save output debug.log           # 开始记录到 debug.log
s o trace_events.log            # 缩写形式
```

### save session - 启动实时会话日志

**语法：**
```
save session [file]
s s [file]          # 缩写形式
```

**参数：**
- `[file]`: 可选文件名（未提供时使用带时间戳的默认文件名）

**行为：**
- 启动命令会话（命令 + 响应）的实时日志记录
- 后续所有命令及其响应立即写入文件
- 文件不存在时创建，存在时追加
- 命令以 `>>>` 标记，响应缩进显示
- 使用 `stop session` 停止日志记录

**示例：**
```
save session                    # 开始记录到 command_session_时间戳.log
save session debug_session.log  # 开始记录到 debug_session.log
s s my_session.log              # 缩写形式
```

### stop output - 停止实时 eBPF 输出日志

**语法：**
```
stop output
```

**行为：**
- 停止实时 eBPF 输出日志记录
- 刷新并关闭日志文件
- 如果没有活动的日志记录则返回错误

### stop session - 停止实时会话日志

**语法：**
```
stop session
```

**行为：**
- 停止实时会话日志记录
- 刷新并关闭日志文件
- 如果没有活动的日志记录则返回错误

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

### info file - 可执行文件信息

**语法：**
```
info file
i file              # 缩写形式
i f                 # 最短形式（无参数）
```

**说明：**
显示可执行文件的详细信息，包括：
- 文件路径和类型（ELF 64位/32位）
- 入口点地址
- 符号表状态
- 调试信息状态（包括 .gnu_debuglink 检测）
- 段地址（.text、.data）
- 启动模式（PID 模式或静态分析模式）

**输出说明：**
- **ELF 虚拟地址**：`-t` 模式（静态分析）
- **运行时加载地址**：`-p` 模式（附加到进程）
- **调试链接**：使用 .gnu_debuglink 时显示独立调试文件路径

**示例：**
```
info file           # 显示可执行文件信息
i file              # 缩写形式
i f                 # 最短形式
```

### info share - 列出共享库

**语法：**
```
info share
i sh                # 缩写形式
```

**说明：**
显示所有已加载的共享库（动态库），包括：
- 内存地址范围（起始/结束）
- 符号表状态
- 调试信息状态
- 库文件路径
- 独立调试文件（使用 .gnu_debuglink 时）

**输出格式：**
```
📚 Shared Libraries (N):

From               To                 Syms  Debug      Shared Object
──────────────────────────────────────────────────────────────────────
0x00007f...        0x00007f...        ✓     ✓          /lib/libc.so.6

Debug files (.gnu_debuglink):
  /lib/libc.so.6 → /usr/lib/debug/.build-id/ab/cdef.debug
```

### info function - 函数调试信息

**语法：**
```
info function <name> [verbose|v]
i f <name> [v]      # 缩写形式
```

**参数：**
- `<name>`: 函数名
- `[verbose|v]`: 可选。显示 DWARF 位置表达式（默认隐藏）

**示例：**
```
info function main       # 显示调试信息（不显示 DWARF 表达式）
info function main v     # 显示完整调试信息（包含 DWARF 表达式）
i f calculate verbose   # 缩写形式，显示详细信息
i f test v              # 最短形式，显示详细信息
```

### info line - 源码行调试信息

**语法：**
```
info line <file:line> [verbose|v]
i l <file:line> [v] # 缩写形式
```

**参数：**
- `<file:line>`: 文件名和行号
- `[verbose|v]`: 可选。显示 DWARF 位置表达式（默认隐藏）

**示例：**
```
info line main.c:42     # 显示第42行的调试信息（不显示 DWARF 表达式）
info line main.c:42 v   # 显示完整调试信息（包含 DWARF 表达式）
i l test.c:100 verbose # 缩写形式，显示详细信息
i l test.c:100 v       # 最短形式，显示详细信息
```

### info address - 地址调试信息

**语法：**
```
info address <0xADDR | 模块后缀:0xADDR> [verbose|v]
i a <0xADDR | 模块后缀:0xADDR> [v]    # 缩写形式
```

**参数：**
- `<0xADDR>`：模块相对虚拟地址（DWARF/符号表视角的 PC，十六进制）。未指定模块时，使用“默认模块”（见下）。
- `模块后缀:0xADDR`：指定模块 + 地址。模块部分支持“全路径”或“唯一后缀”匹配；若后缀匹配不唯一，会报歧义并列出候选。
- `[verbose|v]`：可选。显示 DWARF 位置表达式（默认隐藏）。

**默认与模式：**
- 使用 `-t <binary>`（目标文件模式）启动：默认模块为 `<binary>`。
- 使用 `-p <pid>`（PID 模式）启动：默认模块为进程的主可执行文件。若地址来自共享库，请通过模块后缀显式指定，或使用 `-t` 配合该 `.so`。

**说明：**
展示给定地址的跨模块调试信息：解析函数名（若存在）、源文件:行号（若可用），以及该 PC 处可见的参数/变量。同时进行模块后缀匹配，输出所对应的模块。

**示例：**
```
info address 0x401234          # 使用默认模块（取决于 -t/-p）
info address libc.so.6:0x1234  # 共享库后缀 + 地址（后缀匹配）
info address /usr/bin/nginx:0xdeadbeef v  # 全路径 + 详细信息
```

---

## 🗂️ 源码路径命令

用于管理源代码路径映射的命令，解决 DWARF 调试信息中的编译时路径与运行时路径不一致的问题。

### srcpath - 显示路径映射

**语法：**
```
srcpath
```

**说明：**
显示当前的路径替换规则和搜索目录，包括运行时添加的规则和配置文件规则。

### srcpath add - 添加搜索目录

**语法：**
```
srcpath add <directory>
```

**参数：**
- `<directory>`: 用于搜索源文件的目录路径

**示例：**
```
srcpath add /usr/local/src           # 添加搜索目录
srcpath add /home/user/sources       # 添加用户源码目录
```

**说明：**
当无法通过精确路径或替换规则找到源文件时，GhostScope 会在这些目录的**根目录**下按文件名（basename）搜索（不递归子目录）。例如，添加 `/usr/local/src` 后，可以找到 `/usr/local/src/foo.c`，但无法找到 `/usr/local/src/subdir/bar.c`。

### srcpath map - 映射编译路径到运行时路径

**语法：**
```
srcpath map <from> <to>
```

**参数：**
- `<from>`: 编译时路径前缀（来自 DWARF 调试信息）
- `<to>`: 运行时路径前缀（本机实际位置）

**示例：**
```
srcpath map /build/project /home/user/project          # CI 构建路径映射到本地
srcpath map /usr/src/linux-5.15 /home/user/kernel     # 内核源码已移动
srcpath map /buildroot/arm /local/embedded            # 交叉编译路径
```

**说明：**
将编译时的路径前缀替换为运行时路径。如果对同一个 `<from>` 路径运行两次映射并使用不同的 `<to>` 路径，第二次会更新现有映射。

### srcpath remove - 删除映射或目录

**语法：**
```
srcpath remove <path>
```

**参数：**
- `<path>`: 要删除的映射的路径前缀或搜索目录

**示例：**
```
srcpath remove /build/project        # 删除此 'from' 前缀的映射
srcpath remove /usr/local/src        # 删除搜索目录
```

**说明：**
删除运行时添加的规则（映射或搜索目录）。配置文件中的规则无法通过此命令删除。

### srcpath clear - 清除所有运行时规则

**语法：**
```
srcpath clear
```

**说明：**
清除所有运行时添加的规则（包括映射和搜索目录）。配置文件规则会保留。

### srcpath reset - 重置为配置文件规则

**语法：**
```
srcpath reset
```

**说明：**
删除所有运行时添加的规则，仅保留配置文件规则。与 `srcpath clear` 相同。

---

### 路径解析原理

GhostScope 使用**相对路径 + 目录前缀**的方式查找源文件：

1. **DWARF 信息包含**：
   - 编译目录（compilation directory/comp_dir）：如 `/home/build/nginx-1.27.1`
   - 源文件相对路径：如 `src/core/nginx.c`

2. **路径组合**：
   - 完整路径 = 编译目录 + 相对路径
   - 示例：`/home/build/nginx-1.27.1/src/core/nginx.c`

3. **解析顺序**：
   - **首先**：尝试原始完整路径
   - **然后**：应用 `map` 替换规则（推荐方式）
   - **最后**：在 `add` 搜索目录中按文件名查找

### 推荐使用方式

#### 🌟 推荐：使用 `srcpath map` 映射 DWARF 目录

将 DWARF 中的编译目录映射到本地源码目录，这样**所有相对路径文件都会自动解析**：

```bash
# 查看文件加载失败的错误信息，找到 DWARF 目录
# 错误会显示：
# DWARF Directory: /home/build/nginx-1.27.1
# Relative Path: src/core/nginx.c

# 映射 DWARF 目录到本地路径
srcpath map /home/build/nginx-1.27.1 /home/user/nginx-1.27.1

# 现在所有文件都能找到：
# /home/build/nginx-1.27.1/src/core/nginx.c → /home/user/nginx-1.27.1/src/core/nginx.c
# /home/build/nginx-1.27.1/src/http/ngx_http.c → /home/user/nginx-1.27.1/src/http/ngx_http.c
```

**优点**：
- ✅ 一次配置，所有文件生效
- ✅ 保持目录结构，便于理解
- ✅ 支持多级目录和复杂项目
- ✅ 文件搜索（`o` 键）自动更新路径

#### 辅助：使用 `srcpath add` 添加搜索目录

仅在无法用 `map` 解决时使用（如头文件分散在多个位置）：

```bash
# 添加额外的搜索目录
srcpath add /usr/local/include
srcpath add /opt/vendor/include
```

**注意**：`add` 只在目录根目录下按**文件名**（basename）搜索，不递归子目录，也不保证找到正确的同名文件。

### 配置文件支持

路径映射可以保存在 `config.toml` 中，避免每次手动配置：

```toml
[source]
# 推荐：DWARF 目录映射
substitutions = [
    { from = "/home/build/myproject", to = "/home/user/work/myproject" },
    { from = "/usr/src/linux-5.15", to = "/home/user/kernel/linux-5.15" },
]

# 辅助：额外搜索目录（按文件名查找）
search_dirs = [
    "/usr/local/include",
    "/opt/local/src",
]
```

运行时规则（通过命令添加）优先于配置文件规则。

### 常见使用场景

**场景 1：源码在 CI 服务器上编译** ⭐ 推荐
```bash
# 查看错误提示中的 DWARF Directory
# 然后映射到本地源码根目录
srcpath map /home/jenkins/workspace/myproject /home/user/myproject
```

**场景 2：容器内编译，本地调试** ⭐ 推荐
```bash
# Docker 容器中编译目录为 /build/app
# 本地源码在 /home/user/app
srcpath map /build/app /home/user/app
```

**场景 3：多个独立的头文件目录**
```bash
# 系统头文件和第三方库头文件
srcpath add /usr/local/include
srcpath add /opt/project/vendor
```

**场景 4：纠正错误的映射**
```bash
srcpath map /build /wrong/path        # 第一次尝试（错误）
srcpath map /build /correct/path      # 第二次尝试（更新现有映射）
```

### 最佳实践

1. **优先使用 `map`**：映射 DWARF 编译目录，而不是映射单个文件
2. **查看错误提示**：文件加载失败时会显示 DWARF Directory，直接映射它
3. **保持目录结构**：本地源码保持与编译时相同的相对路径结构
4. **保存到配置**：常用映射保存到 `config.toml`，避免重复配置
5. **谨慎使用 `add`**：只在无法用 `map` 解决时使用，因为只在根目录按文件名搜索，无法处理子目录，且可能找错同名文件

---

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
| `info file` | `i f`, `i file` | 查看可执行文件信息 |
| `info trace` | `i t` | 查看追踪状态 |
| `info source` | `i s` | 查看源文件 |
| `info share` | `i sh` | 查看共享库 |
| `info function` | `i f <name>` | 查看函数信息 |
| `info line` | `i l` | 查看行信息 |
| `info address` | `i a` | 查看地址信息 |
| `save traces` | `s t` | 保存追踪点 |
| `source` | `s` | 加载脚本（除了"s t"）|
| `srcpath` | - | 管理源码路径映射 |

## 命令补全与历史

### 命令补全

GhostScope 提供多层次的智能补全系统：

#### 1. Tab 命令补全

按 `Tab` 键触发命令和参数补全：

- **命令补全**：自动补全 GhostScope 命令（trace、enable、info 等）
- **文件路径补全**：支持 source 命令的文件路径自动补全
- **参数补全**：根据命令上下文提供智能参数建议

**示例**：
```
gs > t<Tab>          → trace
gs > info s<Tab>     → info source
gs > source /pa<Tab> → source /path/to/script.gs
```

#### 2. 自动建议（灰色提示）

在您输入时，GhostScope 会根据命令历史显示灰色建议文本：

- **触发条件**：输入 3 个或更多字符
- **建议来源**：从历史命令中匹配前缀
- **接受建议**：按 `→`（右方向键）或 `Ctrl+E`
- **忽略建议**：继续输入或移动光标

**示例**：
```
gs > trace main<输入中>
     trace main -s "print(a, b, c)"  ← 灰色建议文本

     按 → 接受整条建议
```

#### 3. 文件名补全

对于需要文件路径的命令，Tab 补全支持：

- **相对路径**：从当前目录开始
- **绝对路径**：从根目录开始
- **多级目录**：支持多级目录导航
- **智能过滤**：只显示相关文件类型（.gs 脚本文件）

### 命令历史

GhostScope 自动保存命令历史，支持快速重用和搜索：

#### 历史导航

| 快捷键 | 功能 |
|--------|------|
| `↑` 或 `Ctrl+P` | 上一条历史命令 |
| `↓` 或 `Ctrl+N` | 下一条历史命令 |

#### 历史持久化

- **自动保存**：命令自动保存到 `.ghostscope_history` 文件
- **跨会话**：历史在不同 GhostScope 会话间共享
- **去重机制**：连续重复的命令不会重复记录
- **容量限制**：默认保存最近 1000 条命令

#### 历史管理

使用 `clear` 命令清除历史：

```bash
gs > clear          # 清除命令历史
```

**注意**：清除历史会删除 `.ghostscope_history` 文件中的所有记录。

### 补全配置

可在配置文件中调整历史和补全行为（参见 [配置文档](configuration.md)）：

```toml
[history]
enabled = true          # 启用历史记录
max_entries = 1000     # 最大历史条数

[auto_suggestion]
enabled = true         # 启用自动建议
min_chars = 3         # 触发建议的最小字符数
```

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

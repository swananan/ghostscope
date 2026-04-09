<div align="center">
  <img src="https://raw.githubusercontent.com/swananan/ghostscope/main/assets/logo.png" alt="GhostScope Logo" width="200"/>
  <h1 style="margin-top: 0.2em;">GhostScope</h1>
  <h3>⚡ 下一代 eBPF 用户态运行时追踪器</h3>
  <p>
    <strong>Printf 调试的进化</strong> — 无需停止或修改应用即可实时追踪。
  </p>

  <p>
    <img src="https://img.shields.io/badge/版本-0.1.1-blue.svg" alt="版本"/>
    <img src="https://img.shields.io/badge/协议-GPL-green.svg" alt="协议"/>
    <img src="https://img.shields.io/badge/Linux-4.4+-orange.svg" alt="Linux 4.4+"/>
    <img src="https://img.shields.io/badge/Rust-1.88.0-red.svg" alt="Rust 1.88.0"/>
  </p>
</div>

<br />

## 概述

GhostScope 是一个 **面向源码语义的用户态追踪器**。有 DWARF 调试信息时，它可以在不停住目标进程的前提下，按函数、源码行或指令粒度设点，并打印真正重要的信息。

> *"The most effective debugging tool is still careful thought, coupled with judiciously placed print statements."* — Brian Kernighan

### 什么时候适合用 GhostScope

- 你在排查线上正在运行的服务，不能接受 GDB 式 stop-the-world 带来的巨大性能扰动，同时又更希望使用基于 eBPF 的工作流，获得比传统内核模块式探测更好的安全边界和更低开销。
- 你关心的是源码行和真实变量值，而不只是函数入口参数。
- 你想把“这里要是能加一条 printf 就好了”快速变成一个可运行的追踪脚本。
- 你希望让 AI agent 基于 GhostScope 文档、源码路径和 DWARF 二进制直接产出追踪命令。

### 什么时候不适合用 GhostScope

- 如果你需要带断点、单步、改内存或调 coredump 的交互式调试体验，用 GDB。
- 如果你想在 perf 生态里快速对某个函数、源码行或局部变量打一针式 probe，用 `perf probe`。
- 如果你要在同一套脚本里混合大量内核 + 用户态事件做聚合，优先考虑 bpftrace 或 SystemTap。
- 如果目标模块没有 DWARF 调试信息，就不要期待源码级变量追踪能很好地工作。

### GhostScope 和 perf、GDB、bpftrace、SystemTap 的区别

完整、统一维护的对比请看 [工具对比](docs/zh/comparison.md)。另外也可以参考 [常见问题](docs/zh/faq.md)。

### AI 运行时分析 Skill

GhostScope 支持两种模式：一种是交互式 TUI 模式，另一种是基于 `--script` 和 `--script-file` 的 CLI 模式。后者是更适合 AI 和自动化的工作流。

给 Codex 或 Claude Code 安装共享 skill：

```bash
curl -fsSL https://raw.githubusercontent.com/swananan/ghostscope/main/scripts/skills/install_ghostscope_runtime_analysis_skill.sh | bash -s -- --copy
```

如果你已经把仓库 clone 到本地，也可以继续使用 `./scripts/skills/install_ghostscope_runtime_analysis_skill.sh --copy`。

如果你想强制指定目标，可以追加 `--codex`、`--claude` 或 `--all`。安装后需要重启 Codex 或 Claude Code。

当 AI 和你共享同一个 workspace 时，它通常可以自己发现源码 checkout 路径以及 DWARF/调试符号状态。只有在这些信息无法可靠判断时，它才应该先追问，再生成带源码依据的结果。一个典型的会话可以拆成四步。

这个例子里，AI 可以在本地自行发现的上下文：

- 源码 checkout：`/mnt/500g/code/openresty/openresty-1.27.1.1/build/nginx-1.27.1`
- 目标二进制：`/usr/local/openresty/nginx/sbin/nginx`
- 调试信息状态：二进制内带有 DWARF 调试信息

提问：

```text
$ghostscope-runtime-analysis 跟踪正在运行的 nginx worker，并把请求 body 的原始字节打印出来
```

生成的命令：

```bash
WORKER_PID=$(pgrep -n -f 'nginx: worker process')
sudo ghostscope -p "$WORKER_PID" --script-file /tmp/ghostscope-nginx-body-discard.gs --script-output plain
```

生成的脚本：

```ghostscope
trace /mnt/500g/code/openresty/openresty-1.27.1.1/build/nginx-1.27.1/src/http/ngx_http_request_body.c:671 {
    if size > 0 {
        let req_line_len = r.request_line.len;
        let body_len = size;

        print "src=discard-preread pid={} req={:p} line={:s.req_line_len$} body_len={} body={:x.body_len$}",
            $pid, r, r.request_line.data, body_len, r.header_in.pos;
    }
}
```

演示效果：

![GhostScope CLI 演示](assets/demo-cli.gif)

为了得到最好效果，请确保相关源码树可用、你关心的模块带有 DWARF 调试信息，并且 GhostScope 具备加载 eBPF 程序所需的权限。如果这些信息无法在本地可靠发现，skill 应该先追问，再生成带源码依据的追踪结果。拉取仓库更新后，重新执行同一个安装脚本即可；安装的 skill 自带版本号，版本变化时会自动刷新。

### 理想中的 Printf

GhostScope 把编译后的二进制重新变成“可观测系统”。在 TUI 里，这个过程是递进展开的：先定位到感兴趣的函数或源码行，看清楚当前可见的变量，再从那个位置进入 Script Mode 设点，最后一边让目标进程继续运行，一边在输出面板里看实时结果。它不是一个泛泛的监控面板，而是一个沿着源码路径逐步展开的运行时 printf 调试界面。

下面这个演示就是按这条路径展开的：先在带 DWARF 的 nginx worker 里找到目标代码，再在对应行写一小段脚本，最后立刻看到条件判断、按源码语义访问变量，以及运行中进程的实时输出。

<br />

<div align="center">
  <img src="https://raw.githubusercontent.com/swananan/ghostscope/main/assets/demo.gif" alt="GhostScope Demo" width="100%"/>
  <p><sub><i>实时追踪运行中的 nginx worker 进程</i></sub></p>
</div>

### 工作原理

想象一下，你面对的是一片广袤的二进制数据荒野 —— 内存地址、寄存器值、栈帧数据 —— 没有上下文，它们只是毫无意义的数字。**DWARF 调试信息就是我们的地图**：它告诉我们栈地址 `RSP-0x18` 存储着局部变量 `count`，堆地址 `0x5621a8c0` 处的结构体是 `user` 对象，其偏移 `+0x20` 处是字符串指针 `user.name`；它追踪每个变量在程序执行过程中的位置变化 —— 参数 `x` 现在在寄存器 `RDI` 中，之后会被移到栈上 `RSP-0x10` 的位置。

有了这张地图，GhostScope 利用 **eBPF 和 uprobe** 技术从运行中的程序任意指令点安全地提取二进制数据。这种组合威力强大：DWARF 揭示进程虚拟地址空间中每个字节的含义，eBPF 安全地获取我们需要的数据。结果呢？你可以从程序的任何位置打印变量值（局部变量或全局变量）、函数参数、复杂数据结构，甚至回溯函数调用栈 —— 完全无需停止或修改程序。

## ✨ 核心特性

<div align="center">
  <table>
    <tr>
      <td align="center" width="25%">
        <img src="https://raw.githubusercontent.com/swananan/ghostscope/main/assets/icons/performance.svg" width="60" alt="Performance"/>
        <br />
        <strong>零开销</strong>
        <br />
        <sub>仅需一次上下文切换 + eBPF 执行</sub>
      </td>
      <td align="center" width="25%">
        <img src="https://raw.githubusercontent.com/swananan/ghostscope/main/assets/icons/realtime.svg" width="60" alt="Real-time"/>
        <br />
        <strong>实时追踪</strong>
        <br />
        <sub>实时跟踪流</sub>
      </td>
      <td align="center" width="25%">
        <img src="https://raw.githubusercontent.com/swananan/ghostscope/main/assets/icons/dwarf.svg" width="60" alt="DWARF"/>
        <br />
        <strong>DWARF 感知</strong>
        <br />
        <sub>完整调试信息支持</sub>
      </td>
      <td align="center" width="25%">
        <img src="https://raw.githubusercontent.com/swananan/ghostscope/main/assets/icons/rust.svg" width="60" alt="Rust"/>
        <br />
        <strong>Rust 构建</strong>
        <br />
        <sub>内存安全且极速</sub>
      </td>
    </tr>
  </table>
</div>

## ⚠️ 实验性工具声明

> **GhostScope 目前处于早期开发阶段**，仍在积极迭代中。虽然我们努力确保数据准确性，但在某些情况下可能出现错误或不完整的追踪信息，更多的应该是探测功能不支持。
>
> **建议**：将 GhostScope 采集的数据作为问题排查的**辅助参考**，而非唯一依据。在做出关键决策前，请结合其他调试工具交叉验证。
>
> 我们正在持续改进稳定性和准确性，期待未来版本能够移除此声明。

当前的硬性限制和软性限制，请参阅 [使用限制](docs/zh/limitations.md)。

## 📚 文档

<table>
<tr>
<td width="33%" valign="top">

### 🎯 入门指南

- [**安装指南**](docs/zh/install.md)
  系统要求和设置

- [**快速教程**](docs/zh/tutorial.md)
  10分钟学习基础知识

- [**工具对比**](docs/zh/comparison.md)
  在 GhostScope、perf、GDB、bpftrace 和 SystemTap 之间做选择

- [**常见问题**](docs/zh/faq.md)
  常见问题解答

- [**使用限制**](docs/zh/limitations.md)
  已知的限制和约束

</td>
<td width="33%" valign="top">

### ⚙️ 配置

- [**配置参考**](docs/zh/configuration.md)
  所有配置选项

- [**TUI 参考手册**](docs/zh/tui-reference.md)
  完整的快捷键和面板导航
  

- [**命令参考**](docs/zh/input-commands.md)
  输入模式所有可用命令

- [**脚本语言**](docs/zh/scripting.md)
  编写强大的追踪脚本

</td>
<td width="33%" valign="top">

### 👨‍💻 开发

- [**架构概览**](docs/zh/architecture.md)
  系统设计和内部原理

- [**开发指南**](docs/zh/development.md)
  构建和扩展 GhostScope

- [**贡献指南**](docs/zh/contributing.md)
  加入社区

- [**未来规划**](docs/zh/roadmap.md)
  里程碑

</td>
</tr>
</table>

## 🤝 贡献

我们欢迎贡献！无论是错误报告、功能请求、文档改进还是代码贡献，我们都感谢您帮助改进 GhostScope。

请查看我们的[贡献指南](docs/zh/contributing.md)了解：
- 行为准则
- 开发工作流
- 编码标准
- 如何提交拉取请求

## 📜 许可证

GhostScope 采用 [GNU 通用公共许可证](LICENSE) 授权。

## 🙏 致谢

使用以下优秀的开源项目构建：

- [**Aya**](https://aya-rs.dev/) - Rust 的 eBPF 库（使用其 loader 功能）
- [**LLVM**](https://llvm.org/) - 编译器基础设施
- [**Inkwell**](https://github.com/TheDan64/inkwell) - Rust 的安全 LLVM 绑定
- [**Gimli**](https://github.com/gimli-rs/gimli) - DWARF 解析器
- [**Ratatui**](https://ratatui.rs/) - 终端 UI 框架
- [**Tokio**](https://tokio.rs/) - 异步运行时
- [**Pest**](https://github.com/pest-parser/pest) - PEG 解析器生成器

受到以下项目的启发和借鉴：

- [**GDB**](https://www.gnu.org/software/gdb/) - DWARF 解析优化
- [**bpftrace**](https://github.com/iovisor/bpftrace) - eBPF 追踪技术
- [**cgdb**](https://cgdb.github.io/) - TUI 设计和用户体验

特别感谢以下优秀资源，从中学到了很多：

**博客文章：**
- [**动态追踪漫谈**](https://blog.openresty.com.cn/cn/dynamic-tracing/)
- [**Unwinding the stack the hard way**](https://lesenechal.fr/en/linux/unwinding-the-stack-the-hard-way)

**技术书籍：**
- [**Crafting Interpreters**](https://craftinginterpreters.com/)

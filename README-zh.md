<div align="center">
  <br />
  <img src="assets/logo.png" alt="GhostScope Logo" width="200"/>
  <br />
  <br />
  <h1>GhostScope</h1>
  <h3>⚡ 下一代 eBPF 用户态运行时追踪器</h3>
  <p>
    <strong>Printf 调试的进化</strong> — 无需停止和修改应用即可实时追踪
  </p>

  <!-- 徽章 -->
  <p>
    <img src="https://img.shields.io/badge/版本-0.1.0-blue.svg" alt="Version"/>
    <img src="https://img.shields.io/badge/协议-GPL-green.svg" alt="License: GPL"/>
    <img src="https://img.shields.io/badge/Linux-4.4+-orange.svg" alt="Linux 4.4+"/>
    <img src="https://img.shields.io/badge/Rust-1.75+-red.svg" alt="Rust 1.75+"/>
  </p>

</div>

<br />

## 概述

GhostScope 是一个**运行时追踪工具**，将 printf 调试的简单性带入生产系统。

> *"最有效的调试工具仍然是仔细的思考，加上恰当放置的打印语句。"* — Brian Kernighan

### 工作原理：DWARF + eBPF 的魔法

想象一下，你面对的是一片广袤的二进制数据荒野 —— 内存地址、寄存器值、栈帧数据 —— 没有上下文，它们只是毫无意义的数字。**DWARF 调试信息就是我们的地图**：它告诉我们栈地址 `RSP-0x18` 存储着局部变量 `count`，堆地址 `0x5621a8c0` 处的结构体是 `user` 对象，其偏移 `+0x20` 处是字符串指针 `user.name`；它追踪每个变量在程序执行过程中的位置变化 —— 参数 `x` 现在在寄存器 `RDI` 中，之后会被移到栈上 `RSP-0x10` 的位置。

有了这张地图，GhostScope 利用 **eBPF 和 uprobe** 技术从运行中的程序任意指令点安全地提取二进制数据。这种组合威力强大：DWARF 揭示进程虚拟地址空间中每个字节的含义，eBPF 安全地获取我们需要的数据。结果呢？你可以从程序的任何位置打印变量值（局部变量或全局变量）、函数参数、复杂数据结构，甚至回溯函数调用栈 —— 完全无需停止或修改程序。

### 理想中的 Printf

GhostScope 将编译后的二进制文件转变为可观测系统。在函数入口、特定源代码行或任何中间位置设置追踪点，打印局部变量、全局变量、函数参数、复杂嵌套结构，甚至函数调用栈。既拥有 printf 调试的简单性，又具备现代追踪技术的强大功能。

<br />

<!-- 演示视频占位符 -->
<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/demo-dark.gif">
    <source media="(prefers-color-scheme: light)" srcset="assets/demo-light.gif">
    <img src="assets/demo.gif" alt="GhostScope Demo" width="100%"/>
  </picture>
  <p><sub><i>使用 GhostScope 实时追踪运行中的应用程序</i></sub></p>
</div>

## ✨ 核心特性

<div align="center">
  <table>
    <tr>
      <td align="center" width="25%">
        <img src="assets/icons/performance.svg" width="60" alt="Performance"/>
        <br />
        <strong>零开销</strong>
        <br />
        <sub>仅需一次上下文切换 + eBPF 执行</sub>
      </td>
      <td align="center" width="25%">
        <img src="assets/icons/realtime.svg" width="60" alt="Real-time"/>
        <br />
        <strong>实时追踪</strong>
        <br />
        <sub>实时跟踪流</sub>
      </td>
      <td align="center" width="25%">
        <img src="assets/icons/dwarf.svg" width="60" alt="DWARF"/>
        <br />
        <strong>DWARF 感知</strong>
        <br />
        <sub>完整调试信息支持</sub>
      </td>
      <td align="center" width="25%">
        <img src="assets/icons/rust.svg" width="60" alt="Rust"/>
        <br />
        <strong>Rust 构建</strong>
        <br />
        <sub>内存安全且极速</sub>
      </td>
    </tr>
  </table>
</div>

## 📚 文档

<table>
<tr>
<td width="33%" valign="top">

### 🎯 入门指南

- [**安装指南**](docs/zh/install.md)
  系统要求和设置

- [**快速教程**](docs/zh/tutorial.md)
  10分钟学习基础知识

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

</td>
</tr>
</table>

## 🤝 贡献

我们欢迎贡献！无论是错误报告、功能请求、文档改进还是代码贡献，我们都感谢您帮助改进 GhostScope。

请查看我们的[贡献指南](docs/contributing.md)了解：
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

特别感谢以下优秀博客文章，学习了很多：

- [**动态追踪漫谈**](https://blog.openresty.com.cn/cn/dynamic-tracing/)
- [**硬核方式进行栈回溯**](https://lesenechal.fr/en/linux/unwinding-the-stack-the-hard-way)

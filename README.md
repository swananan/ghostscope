<div align="center">
  <img src="assets/logo.png" alt="GhostScope Logo" width="200"/>
  <h1 style="margin-top: 0.2em;">GhostScope</h1>
  <h3>⚡ Next-Generation eBPF Userspace Runtime Tracer</h3>
  <p>
    <strong>Printf debugging evolved</strong> — Real-time tracing without stopping your application.
  </p>

  <!-- Badges -->
  <p>
    <img src="https://img.shields.io/badge/version-0.1.0-blue.svg" alt="Version"/>
    <img src="https://img.shields.io/badge/license-GPL-green.svg" alt="License: GPL"/>
    <img src="https://img.shields.io/badge/Linux-4.4+-orange.svg" alt="Linux 4.4+"/>
    <img src="https://img.shields.io/badge/Rust-1.88.0-red.svg" alt="Rust 1.88.0"/>
  </p>

  <!-- Language Switch -->
  <p>
    <a href="README-zh.md"><strong>中文文档</strong></a>
  </p>

</div>

<br />

## Overview

GhostScope is a **runtime tracing tool** that brings the simplicity of printf debugging to production systems.

> *"The most effective debugging tool is still careful thought, coupled with judiciously placed print statements."* — Brian Kernighan

### How It Works: The Magic of DWARF + eBPF

Imagine navigating a vast, uncharted forest of binary data — memory addresses, register values, stack frames — all meaningless numbers without context. **DWARF debug information is our map**: it tells us that stack address `RSP-0x18` stores local variable `count`, heap address `0x5621a8c0` is a `user` object with string pointer `user.name` at offset `+0x20`; it tracks where each variable lives throughout program execution — parameter `x` is in register `RDI` now but will move to stack offset `RSP-0x10` later.

With this map in hand, GhostScope leverages **eBPF and uprobe** technology to safely extract binary data from any instruction point in your running program. The combination is powerful: DWARF reveals the meaning of every byte in the process's virtual address space, while eBPF safely retrieves exactly what we need. The result? You can print variable values (local or global), function arguments, complex data structures, even stack backtraces from any point in your program — all without stopping or modifying it.

### The Printf That Should Have Been

GhostScope transforms compiled binaries into observable systems. Place trace points at function entries, specific source lines, or anywhere in between. Print local variables, global variables, function parameters, complex nested structures, even stack backtraces. All with the simplicity of printf debugging, but the power of modern tracing.

The demo below shows GhostScope tracing an nginx worker process with debug information. You can see how GhostScope supports conditional logic, easily extracts information from complex data structures, and operates without disrupting the process.

<br />

<div align="center">
  <img src="assets/demo.gif" alt="GhostScope Demo" width="100%"/>
  <p><sub><i>Real-time tracing of a running nginx worker process</i></sub></p>
</div>

## ✨ Highlights

<div align="center">
  <table>
    <tr>
      <td align="center" width="25%">
        <img src="assets/icons/performance.svg" width="60" alt="Performance"/>
        <br />
        <strong>Zero Overhead</strong>
        <br />
        <sub>One context switch + eBPF execution</sub>
      </td>
      <td align="center" width="25%">
        <img src="assets/icons/realtime.svg" width="60" alt="Real-time"/>
        <br />
        <strong>Real-Time Tracing</strong>
        <br />
        <sub>Live trace streaming</sub>
      </td>
      <td align="center" width="25%">
        <img src="assets/icons/dwarf.svg" width="60" alt="DWARF"/>
        <br />
        <strong>DWARF-Aware</strong>
        <br />
        <sub>Full debug info support</sub>
      </td>
      <td align="center" width="25%">
        <img src="assets/icons/rust.svg" width="60" alt="Rust"/>
        <br />
        <strong>Built with Rust</strong>
        <br />
        <sub>Memory safe & blazing fast</sub>
      </td>
    </tr>
  </table>
</div>

## ⚠️ Experimental Tool Disclaimer

> **GhostScope is currently in early development** and under active iteration. While we strive for data accuracy, trace information may be incorrect or incomplete in certain scenarios, primarily due to unsupported features.
>
> **Recommendation**: Use GhostScope's collected data as an **auxiliary reference** for troubleshooting, not as the sole source of truth. Cross-validate with other debugging tools before making critical decisions.
>
> We are continuously improving stability and accuracy, and look forward to removing this disclaimer in future versions.

## 📚 Documentation

<table>
<tr>
<td width="33%" valign="top">

### 🎯 Getting Started

- [**Installation Guide**](docs/install.md)
  System requirements and setup

- [**Quick Tutorial**](docs/tutorial.md)
  Learn the basics in 10 minutes

- [**FAQ**](docs/faq.md)
  Common questions answered

- [**Limitations**](docs/limitations.md)
  Known limitations and constraints

</td>
<td width="33%" valign="top">

### ⚙️ Configuration

- [**Configuration Reference**](docs/configuration.md)
  All configuration options

- [**TUI Reference**](docs/tui-reference.md)
  Complete keyboard shortcuts and panel navigation
  

- [**Command Reference**](docs/input-commands.md)
  All available commands for Input Mode

- [**Script Language**](docs/scripting.md)
  Write powerful trace scripts

</td>
<td width="33%" valign="top">

### 👨‍💻 Development

- [**Architecture Overview**](docs/architecture.md)
  System design and internals

- [**Development Guide**](docs/development.md)
  Build and extend GhostScope

- [**Contributing Guide**](docs/contributing.md)
  Join the community

- [**Roadmap**](docs/roadmap.md)
  Planned features and milestones

</td>
</tr>
</table>

## 🤝 Contributing

We welcome contributions! Whether it's bug reports, feature requests, documentation improvements, or code contributions, we appreciate your help in making GhostScope better.

Please see our [Contributing Guide](docs/contributing.md) for:
- Code of Conduct
- Development workflow
- Coding standards
- How to submit pull requests

## 📜 License

GhostScope is licensed under the [GNU General Public License](LICENSE).

## 🙏 Acknowledgements

Built with amazing open source projects:

- [**Aya**](https://aya-rs.dev/) - eBPF library for Rust (using its loader functionality)
- [**LLVM**](https://llvm.org/) - Compiler infrastructure
- [**Inkwell**](https://github.com/TheDan64/inkwell) - Safe LLVM bindings for Rust
- [**Gimli**](https://github.com/gimli-rs/gimli) - DWARF parser
- [**Ratatui**](https://ratatui.rs/) - Terminal UI framework
- [**Tokio**](https://tokio.rs/) - Async runtime
- [**Pest**](https://github.com/pest-parser/pest) - PEG parser generator

Inspired by and learned from:

- [**GDB**](https://www.gnu.org/software/gdb/) - DWARF parsing optimizations
- [**bpftrace**](https://github.com/iovisor/bpftrace) - eBPF tracing techniques
- [**cgdb**](https://cgdb.github.io/) - TUI design and user experience

Special thanks to these excellent resources that taught us a lot:

**Blog Posts:**
- [**The Wonderland of Dynamic Tracing**](https://blog.openresty.com/en/dynamic-tracing-part-1/)
- [**Unwinding the Stack the Hard Way**](https://lesenechal.fr/en/linux/unwinding-the-stack-the-hard-way)

**Books:**
- [**Crafting Interpreters**](https://craftinginterpreters.com/)

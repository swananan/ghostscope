# Frequently Asked Questions

## What is GhostScope?

GhostScope is an eBPF-based runtime tracer that allows you to observe and analyze running applications in real-time without modifying source code, recompiling, or restarting processes. Think of it as "printf debugging" for production systems.

## How does GhostScope differ from GDB?

| Feature | GhostScope | GDB |
|---------|------------|-----|
| Type | Tracer (like advanced printf) | Interactive debugger |
| Runtime overhead | Minimal | High (stops execution) |
| Process interruption | Never | Yes (breakpoints) |
| Production use | Yes, designed for it | No |
| Timing preservation | Yes | No (breakpoints change timing) |
| Concurrency debugging | Excellent | Challenging |
| Interactive control | No (but provides TUI interface) | Yes (step, continue, etc.) |

## How do bpftrace and GhostScope differ?

| Aspect | bpftrace | GhostScope |
|---|---|---|
| Positioning | General-purpose eBPF dynamic tracer; event observation/aggregation | DWARF-aware userspace observation; restores source-level semantics |
| DWARF usage | Parses args/structs; does not evaluate location expressions | Evaluates DWARF expressions at runtime; reads params/locals/globals |
| Attachment granularity & symbols | Entry/return, in-function offsets/absolute; no built-in line→addr map | Line-table–driven source-line/instruction attachment and evaluation |
| Observable data | Arguments only at function entry; no locals; globals via `uaddr()` | Supports locals, parameters, and globals; renders values with real types |
| ASLR impact | Using `uaddr()` for globals breaks under ASLR/PIE | Runtime DWARF computation naturally adapts to ASLR/PIE |
| Interaction experience | Script-style output and aggregation; non-interactive | TUI-friendly, observe without interruption |

I started this project after noticing that recent versions of bpftrace removed most of their DWARF functionality. :-)

## How do SystemTap and GhostScope differ?

| Aspect | SystemTap eBPF backend (stapbpf) | GhostScope |
|---|---|---|
| Position & scope | System-level eBPF tracing backend (kernel + userspace), with tradeoffs vs the kernel-module backend | DWARF-aware userspace observation aimed at production printf-style debugging with an interactive experience |
| Source line/statement probes | Supported (.statement resolved to addresses, then attached) | Supported (line table/address/function; line-level attachment is core) |
| Variable access (params/locals/globals) | Supported. DWARF location expr → AST → lowered to eBPF (probe_read/pt_regs offsets); constrained by eBPF stack/verifier and string length | Supported. Evaluate DWARF at runtime with gimli; render by real types; naturally ASLR/PIE friendly |
| DWARF expression handling | loc2stap interprets DW_OP → internal repr, then bpf_unparser lowers to an eBPF instruction sequence | Evaluate DWARF in userspace with gimli; collect via eBPF programs; render in TUI |
| Stack unwinding (CFI) | Not supported (eBPF backend lacks userspace unwinding) | Not supported (planned via .eh_frame unwinding) |
| Event transport/formatting | PERF_EVENT_ARRAY + perf_event_output; userspace interpreter performs printf; BPF_MAXSTRINGLEN≈64, format≈256 | RingBuf (≥5.8) or PerfEventArray; configurable pages/event size; built-in {:x.N}/{:s.N}/{:p} dump helpers |
| BTF/CO‑RE/linkage | No BTF/CO‑RE; minimal libbpf (direct bpf()); no bpf_link/ringbuf | Aya ecosystem, prefer RingBuf; not centered on BTF/CO‑RE |
| eBPF generation pipeline | Custom IR/assembler outputs eBPF bytecode + ELF (.bo); loader performs R_BPF_MAP_FD relocations | Rust/Aya loader; focused on reading userspace DWARF variables and presentation |
| Interaction & UX | CLI + userspace interpreter output; steeper learning curve | TUI-friendly; live/session logs and a scripting DSL; close to “production printf debugging” |

I initially didn’t realize SystemTap already had an eBPF backend—my old impression was carefully crafting SystemTap scripts, testing repeatedly on a staging box, then cautiously probing a low-traffic production node and stopping quickly to avoid outages (of course, that was probably because I hadn’t mastered SystemTap well enough). If I’d known earlier, I might not have started this project. 😂 Still, GhostScope provides an easier TUI focused on userspace tracing, with its own unique value.

## When to use GDB, SystemTap, bpftrace, or GhostScope

- **Use GhostScope when**
  - Userspace source-level diagnosis at function/source-line/address; read the real variable values (locals/globals/parameters) without disrupting service
  - You want production-suitable low overhead and a better interactive experience (cgdb-like TUI)
  - You prefer quick ramp-up with lower script complexity and fewer environment deps
- **Use GDB when**
  - You need to inspect complex data structures interactively
  - You want to modify variables during debugging
  - You need to step through code line by line
  - You’re debugging coredumps
  - You’re in a development environment where stopping is acceptable
- **Use bpftrace when**
  - You mix multiple event sources (kernel + userspace) in one script for system-level observability
  - You’re not strict about userspace source-level variable reconstruction details
- **Use SystemTap when**
  - You mix multiple event sources (kernel + userspace) in one script for system-level observability
  - You already have SystemTap scripts/ecosystem (tapsets) to migrate/reuse
  - You have basic aggregation/statistics needs

## What are the limitations of GhostScope?

See the [Limitations](limitations.md) document for a comprehensive list of hard and soft limitations.

## What is the roadmap?

See the [Roadmap](roadmap.md) document for planned features and future development.

# Tool Comparison

GhostScope is designed for a narrow but high-value job: **source-aware userspace tracing on live processes with DWARF debug info**. It does not try to replace GDB, bpftrace, or SystemTap everywhere. This page explains where each tool fits.

## Quick Recommendation

| If you need... | Prefer... | Why |
|---|---|---|
| Breakpoints, stepping, memory writes, or coredump debugging | GDB | It is an interactive debugger with full execution control |
| Mixed kernel + userspace event aggregation | bpftrace or SystemTap | They are broader system tracing tools |
| Source-line, local-variable, and typed userspace runtime inspection without stopping the target | GhostScope | It combines runtime DWARF evaluation with low-overhead userspace tracing |
| Existing tapsets or a mature SystemTap workflow | SystemTap | Reuse often matters more than switching tools |

## GhostScope vs GDB

| Aspect | GhostScope | GDB |
|---|---|---|
| Execution model | Trace a live process without stopping it | Stop, inspect, and control execution |
| Best at | Production-style runtime observation | Interactive debugging and state mutation |
| Variable access | Reads values at chosen trace points using DWARF + eBPF | Reads state after pausing execution |
| Timing impact | Low | High, because breakpoints change timing |
| When to choose it | You need observability | You need control |

Use GhostScope when preserving process timing matters. Use GDB when you need to stop the world and reason step by step.

## GhostScope vs bpftrace

| Aspect | GhostScope | bpftrace |
|---|---|---|
| Focus | Userspace, source-aware runtime tracing | General-purpose eBPF tracing and aggregation |
| Userspace DWARF handling | Evaluates DWARF location expressions at runtime | Better suited to arguments, structs, and event aggregation than DWARF-based source-level semantic reconstruction of userspace state |
| Attachment style | Function, source line, and instruction-oriented | Probe/event-oriented |
| Best at | Recovering real userspace state from live code paths | Correlating many event sources quickly |
| Tradeoff | Narrower scope | Less focused on source-level userspace diagnosis |

Choose GhostScope when you care about userspace source semantics. Choose bpftrace when you care about broad event coverage and aggregation more than DWARF-based source-level semantic reconstruction.

## GhostScope vs SystemTap

| Aspect | GhostScope | SystemTap |
|---|---|---|
| Focus | Userspace tracing with a TUI and a small tracing DSL | Broad tracing framework with a large existing ecosystem |
| Workflow | Lightweight, source-oriented, production-printf style | More mature and broader, but with a steeper workflow |
| Userspace variable tracing | Built around DWARF-backed userspace observation | Capable, but not centered on the same low-friction workflow |
| Best at | Fast userspace diagnosis on live processes | Reusing tapsets, broad instrumentation, mixed workflows |
| Tradeoff | Narrower than SystemTap overall | Heavier when you only need focused userspace diagnosis |

Choose GhostScope when you want better AI integration or a friendlier TUI-oriented userspace tracing workflow. Choose SystemTap when you already depend on its ecosystem or want its broader tracing model.

## Which Tool Should I Pick?

- Pick GhostScope when you want production-friendly userspace tracing with real source-level variables and low runtime disruption.
- Pick GDB when you need interactive execution control, mutation, or postmortem debugging.
- Pick bpftrace when you want quick aggregation across kernel and userspace events in one place.
- Pick SystemTap when you want a broader tracing framework or already have SystemTap assets to reuse.

For related details and caveats, also see the [FAQ](faq.md) and [Limitations](limitations.md).

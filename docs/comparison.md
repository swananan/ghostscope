# Tool Comparison

GhostScope is designed for a narrow but high-value job: **source-aware userspace tracing on live processes with DWARF debug info**. It does not try to replace GDB, bpftrace, or SystemTap everywhere. This page explains where each tool fits.

## Quick Recommendation

| If you need... | Prefer... | Why |
|---|---|---|
| Interactive debugging with breakpoints, stepping, memory writes, or coredump debugging | GDB | It is an interactive debugger with full execution control |
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

## GhostScope vs GDB Performance Snapshot

We now ship a reproducible single-thread benchmark for one narrow question: "what does it cost to evaluate the same local variable on every hot-function hit?" The harness lives in [`../scripts/compare/compare_hot_function_bench.py`](../scripts/compare/compare_hot_function_bench.py), the target program is [`../scripts/compare/compare_hot_function_target.c`](../scripts/compare/compare_hot_function_target.c), and the runner-service entrypoint is [`../ghostscope/tests/manual_gdb_ghostscope_benchmark.rs`](../ghostscope/tests/manual_gdb_ghostscope_benchmark.rs).

### Method

- Measured on April 6, 2026 on one x86_64 Ubuntu host: Intel i7-8700K, Linux `6.14.0-37-generic`, GDB `15.0.50`, GhostScope `0.1.2`.
- The target is compiled with `-O2 -g -fno-omit-frame-pointer -fno-pie -no-pie`.
- Each run executes `2000` hits of `bench_hot_fn`, with `4096` inner work units per hit, and reports target-internal elapsed time only after the observer is ready, so setup cost is separated from steady-state slowdown.
- Shared observation intent: evaluate local variable `local_probe` on source line `21` inside `bench_hot_fn`, without steady-state output.
  GhostScope uses `trace compare_hot_function_target.c:21 { if local_probe == 0 { print "never"; } }`.
  GDB uses a batch line-breakpoint script on the same source line with `if local_probe == 0`, `silent`, and `continue`.
- The target stays blocked until the observer reports ready.
  For GhostScope, the ready marker is emitted only after `compile_and_load_script_for_cli` completes, so DWARF indexing and script-load time are counted in the separate ready-latency column, not in steady-state target time.
- Results below are medians over `5` repetitions. GDB pause cost is intentionally included in the target runtime because that pause is part of its execution model.

### Result

| Mode | Median steady-state target time (ms) | Target min-max (ms) | Slowdown vs no observer | Median ready latency (ms, excluded) |
|---|---:|---:|---:|---:|
| No observer | 13.36 | 13.34-13.43 | 1.00x | n/a |
| GhostScope | 18.68 | 17.16-19.95 | 1.40x | 153.33 |
| GDB | 527.64 | 517.71-555.77 | 39.48x | 133.25 |

### Reading The Result

- In this scenario, GhostScope had slightly higher attach latency than GDB, but much lower steady-state perturbation once the workload started.
- The `153.33ms` GhostScope ready latency is where DWARF indexing and script load show up. It is reported on purpose, but it is not included in the `18.68ms` steady-state target runtime.
- This is not a generic "which tool is faster" claim. It is a measured answer for one shared task on one host: repeated source-aware observation of one hot-path local variable.
- The GhostScope slowdown here is intentionally measured on a path that is hit thousands of times in a tight loop. That is a stress test, not a recommended production tracing pattern.
- In normal diagnosis work, GhostScope is usually aimed at selective trace points rather than continuously tracing a service hot path. Tracing a latency-critical hot path in an online product is not recommended unless you have explicitly budgeted for that cost.
- Useful follow-up scenarios are multi-thread hot paths, rare error paths, and short-lived processes.

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

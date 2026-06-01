# Tool Comparison

GhostScope is designed for a narrow but high-value job: **source-aware userspace tracing on live processes with DWARF debug info**. It does not try to replace perf, GDB, bpftrace, or SystemTap everywhere. This page explains where each tool fits.

## Quick Recommendation

| Tool | Best at | Less ideal when |
|---|---|---|
| GhostScope | Low-overhead, source-aware userspace tracing on live processes | You need interactive execution control, or broad kernel + userspace aggregation in one tracing workflow |
| perf probe | Quick one-off probes on functions, source lines, and local variables inside the perf ecosystem | You need programmable kernel-side filtering/aggregation or a richer dedicated live-tracing workflow |
| GDB | Breakpoints, stepping, coredumps, and state mutation | The target process cannot be paused in a production environment |
| bpftrace | Mixed kernel + userspace observation and quick event aggregation | You need reliable DWARF-based source-level semantic reconstruction of a userspace process |
| SystemTap | Broad tracing workflows, existing tapset ecosystems, and mixed instrumentation | You want a narrower, more TUI-friendly userspace tracing workflow with lower friction |

## GhostScope vs GDB

| Feature | GhostScope | GDB |
|---|---|---|
| Type | Tracer, closer to production printf debugging | Interactive debugger |
| Execution model | Trace a live process without stopping it | Stop, inspect, and control execution |
| Runtime overhead | Usually low when used selectively | High once breakpoints are involved |
| Process interruption | Never | Yes |
| Production use | Designed for production-friendly observation | Better suited to development and postmortem work |
| Timing preservation | Yes | No, breakpoints and stepping change timing |
| Concurrency debugging | Strong when you need to preserve real timing | Often harder because stop-the-world behavior distorts interleavings |
| Interactive control | TUI and scripting, but not execution control | Full execution control: breakpoints, stepping, continue, mutation |
| Variable access | Reads values at chosen trace points using DWARF + eBPF | Reads state after pausing execution |
| Best at | Production-style runtime observation | Interactive debugging and state mutation |
| When to choose it | You need observability | You need control |

Use GhostScope when preserving process timing matters. Use GDB when you need to stop the world and reason step by step.

## GhostScope vs GDB Performance Snapshot

We now ship a reproducible single-thread benchmark for one narrow question: "what does it cost to evaluate the same local variable on every hot-function hit?" The harness lives in [`../scripts/compare/compare_hot_function_bench.py`](../scripts/compare/compare_hot_function_bench.py), the target program is [`../scripts/compare/compare_hot_function_target.c`](../scripts/compare/compare_hot_function_target.c), and the runner-service entrypoint is [`../e2e-tests/tests/manual_gdb_ghostscope_benchmark.rs`](../e2e-tests/tests/manual_gdb_ghostscope_benchmark.rs).

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
| GhostScope | 18.68 | 17.16-19.95 | **1.40x** | 153.33 |
| GDB | 527.64 | 517.71-555.77 | **39.48x** | 133.25 |

### Reading The Result

- In this scenario, the steady-state runtime gap between GhostScope and GDB is large: GhostScope slowed the target to **1.40x**, while GDB pushed the same workload to **39.48x**. For this kind of repeated live observation, GhostScope is far more suitable for online tracing.
- GhostScope had slightly higher attach latency than GDB, but that one-time setup cost is small compared with GDB's repeated stop-the-world runtime perturbation.
- The `153.33ms` GhostScope ready latency is where DWARF indexing and script load show up. It is reported on purpose, but it is not included in the `18.68ms` steady-state target runtime.
- This is not a generic "which tool is faster" claim. It is a measured answer for one shared task on one host: repeated source-aware observation of one hot-path local variable.
- The GhostScope slowdown here is intentionally measured on a path that is hit thousands of times in a tight loop. That is a stress test, not a recommended production tracing pattern.
- In normal diagnosis work, GhostScope is usually aimed at selective trace points rather than continuously tracing a service hot path. Tracing a latency-critical hot path in an online product is not recommended unless you have explicitly budgeted for that cost.
- Useful follow-up scenarios are multi-thread hot paths, rare error paths, and short-lived processes.

## GhostScope vs perf probe

| Aspect | GhostScope | perf probe / perf uprobes |
|---|---|---|
| Positioning | Purpose-built userspace tracer with PC-context DWARF planning, a small DSL, and a TUI/session workflow | Declarative probe-definition frontend plus the broader perf recording and reporting pipeline |
| Programmability and safety model | eBPF-backed collection logic with programmable filtering and formatting; flexibility is constrained by the verifier | Narrower, more declarative capability surface: define probe points and fetchargs, but not an eBPF-style "run custom logic on each hit" programming model |
| Source-level frontend | Function, source-line, and instruction-oriented tracing are core workflows | Strong native support for functions, source lines, locals, and inline-related probe discovery inside `perf probe` |
| Variable access style | Compile/load-time DWARF read planning for locals, parameters, and globals, followed by eBPF runtime reads and typed rendering | Declarative fetchargs for locals, parameters, registers, symbols, arrays, and return values |
| Inline and discovery workflow | Good source-driven attachment, but within GhostScope's tracer model | Mature discovery workflow for lines, functions, and inline-related probe search such as `--line`, `--vars`, and `--no-inlines` |
| What happens after a hit | Structured data can be filtered, sampled, and shaped before delivery to userspace | Mostly fixed event-field extraction, then hand off to the perf recording and reporting toolchain |
| Output and consumption | RingBuf or PerfEventArray to a custom realtime reader/TUI | Common path is `perf probe` -> `perf record` -> `perf.data` -> `perf report` or `perf script` |
| Best at | Production-oriented live userspace diagnosis with structured output and a dedicated runtime workflow | Quick one-off probes and reuse of the existing perf ecosystem |
| Tradeoff | More opinionated; not meant to be the general perf toolkit | Less programmable than eBPF-based tracers and less centered on custom realtime processing |

Choose GhostScope when you want a purpose-built online tracer with PC-context DWARF semantics, programmable filtering, and a friendlier live diagnosis workflow. Choose perf when you want to quickly place a function, source-line, or local-variable probe and stay inside the perf ecosystem.

Background: a practical shorthand is `perf probe` = more fixed-semantics and ready-to-use, not "zero configurability"; GhostScope's eBPF-backed tracer model trades that simplicity for more programmable hit handling and a richer live workflow.

## GhostScope vs bpftrace

| Aspect | GhostScope | bpftrace |
|---|---|---|
| Positioning | DWARF-aware userspace observation; restores source-level semantics | General-purpose eBPF dynamic tracer; event observation and aggregation |
| DWARF usage | Plans variable reads from DWARF at compile/load time, then emits eBPF reads for params, locals, and globals | Parses args and structs; not centered on PC-context variable read planning |
| Attachment granularity and symbols | Line-table-driven source-line and instruction attachment, plus function-oriented tracing | Entry/return, in-function offsets, absolute locations, and event probes; no built-in line-to-address workflow |
| Observable data | Supports locals, parameters, and globals; renders values with real types | Strong for arguments, structs, and event streams; less focused on recovering arbitrary live userspace state |
| ASLR impact | DWARF read plans preserve rebasing requirements for PIE, shared libraries, and absolute-address values | `uaddr()`-style global reads become awkward or unavailable under ASLR and PIE |
| Interaction experience | TUI-friendly, observe without interruption | Script-style output and aggregation; less interactive |
| Best at | Recovering real userspace state from live code paths | Correlating many event sources quickly |
| Tradeoff | Narrower scope | Less focused on source-level userspace diagnosis |

Choose GhostScope when you care about userspace source semantics. Choose bpftrace when you care about broad event coverage and aggregation more than DWARF-based source-level semantic reconstruction.

Background: one motivation for GhostScope was that newer bpftrace versions no longer focused on the richer DWARF-heavy workflow this project targets.

## GhostScope vs SystemTap

| Aspect | GhostScope | SystemTap |
|---|---|---|
| Position and scope | DWARF-aware userspace observation aimed at production printf-style debugging with an interactive workflow | Broad tracing framework with kernel and userspace coverage, including an eBPF backend |
| Source line and statement probes | Supported; line-level attachment is a core path | Supported; statement probes can be resolved and attached |
| Variable access (params, locals, globals) | Supported. Build PC-context read plans with gimli-backed DWARF data; render by real types; naturally ASLR and PIE friendly | Supported. DWARF location expressions are lowered through SystemTap's pipeline into eBPF-compatible logic, with verifier and stack constraints |
| DWARF expression handling | Convert DWARF locations into semantic read plans and lower supported plans into eBPF runtime reads | Translate DWARF operations into internal representations and lower them into eBPF instruction sequences |
| Stack unwinding (CFI) | Supported through DWARF-only `bt`/`backtrace` for compact CFI rows that can be executed safely in eBPF | Not supported in the eBPF backend |
| Event transport and formatting | RingBuf (on newer kernels) or PerfEventArray; configurable pages and event size; built-in dump helpers such as `{:x.N}`, `{:s.N}`, and `{:p}` | PERF_EVENT_ARRAY plus userspace formatting/interpreter flow; formatting and string handling are more constrained |
| BTF, CO-RE, linkage | Aya ecosystem, prefer RingBuf; not centered on BTF or CO-RE | No BTF or CO-RE focus; minimal libbpf-style backend |
| eBPF generation pipeline | Rust and Aya loader; focused on reading userspace DWARF variables and presentation | Custom IR and assembler pipeline that emits eBPF bytecode and ELF artifacts |
| Interaction and UX | TUI-friendly; live and session logs; small tracing DSL; close to production printf debugging | CLI and userspace interpreter output; steeper learning curve |
| Best at | Fast userspace diagnosis on live processes | Reusing tapsets, broad instrumentation, mixed workflows |
| Tradeoff | Narrower than SystemTap overall | Heavier when you only need focused userspace diagnosis |

Choose GhostScope when you want better AI integration or a friendlier TUI-oriented userspace tracing workflow. Choose SystemTap when you already depend on its ecosystem or want its broader tracing model.

Background: SystemTap's eBPF backend overlaps more with GhostScope than many people expect, but GhostScope stays deliberately narrower and lower-friction for userspace diagnosis.

## Which Tool Should I Pick?

- Start with execution model: if you need to stop, step, mutate, or debug a coredump, use GDB. If you must keep the process running, stay in the GhostScope/perf/bpftrace/SystemTap side of the comparison.
- Then decide whether you need source-aware userspace diagnosis or broader event processing. GhostScope is the better fit when you want real userspace variables, typed rendering, and a production-oriented live tracing workflow. bpftrace and SystemTap are better fits when you want mixed kernel + userspace aggregation, with SystemTap making more sense when you already have tapsets or a SystemTap-heavy workflow.
- perf sits between those worlds as the quick one-off option: use it when you want to place a function, source-line, or local-variable probe quickly and stay inside the perf ecosystem, but do not need eBPF-style programmable hit handling.

For related details and caveats, also see the [FAQ](faq.md) and [Limitations](limitations.md).

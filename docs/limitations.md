# Limitations

This document describes conditions outside the supported operating envelope or
cases that degrade explicitly. The guarantees that remain mandatory inside the
supported envelope are defined in the
[Design Guarantees and Trust Model](design-contract.md).

## Hard Limitations

### 1. Privilege Requirements
The underlying eBPF mechanism requires elevated privileges to access kernel tracing infrastructure. Root access or CAP_BPF/CAP_SYS_ADMIN capabilities are needed.

### 2. Do Not Use with GDB Simultaneously
Both uprobes and GDB install breakpoint-based instrumentation in the target process. Using them together may lead to conflicts and unpredictable behavior.

### 3. Read-Only Access, Cannot Modify Program Behavior
GhostScope's script and compiler surface is observational: it does not provide operations that intentionally modify application-visible state, variable values, or control flow. This does not mean the target is untouched. Uprobes install trap points, and each hit synchronously adds uprobe and eBPF execution to the target thread.

### 4. Platform and Architecture Support
Official builds and correctness testing currently support **Linux x86_64 (AMD64)** only because GhostScope depends on Linux **eBPF** and **uprobes** and currently implements x86_64 register, ABI, TLS, and unwind behavior. Other architectures are outside the support contract even if the source happens to compile on them.

## Soft Limitations

### 1. Language Support
Primary focus is on **C language**, which currently has the best end-to-end support. **C++** and **Rust** are supported in a more limited, DWARF-layout-oriented way: GhostScope can automatically demangle function names and global/static symbols, but most language-specific features are not modeled yet. In practice, simple C-like layouts work best, while advanced Rust and C++ features still require substantial future work.

For interpreted languages (Lua, Python, Ruby, etc.), only the interpreter itself can be traced (since interpreters are typically implemented in compiled languages). Tracing script code is technically feasible but requires substantial development time. JIT language support is an even more distant goal.

### 2. User-Memory Reads via `bpf_probe_read_user`
In traditional non-sleepable probe paths, helpers such as `bpf_probe_read_user` cannot resolve user-space page faults, so reads from a target virtual address may still fail if the page is not resident or otherwise faults on access.

This is no longer an absolute eBPF limitation. Linux now supports sleepable uprobes (`uprobe.s` / `uretprobe.s`), and sleepable programs can use helpers such as `bpf_copy_from_user_task()` for fault-capable user-memory reads. GhostScope currently emits regular `uprobe` programs, so this remains a practical limitation today, but it is better described as a soft implementation limitation rather than a fundamental design limit of eBPF.

**References**:
- https://lists.iovisor.org/g/iovisor-dev/topic/accessing_user_memory_and/21386221
- https://docs.kernel.org/bpf/libbpf/program_types.html
- https://man7.org/linux/man-pages/man7/bpf-helpers.7.html

### 3. Performance Impact
Each uprobe hit synchronously runs trap handling and the generated eBPF program. Even though per-event work is bounded, probes on hot paths may significantly affect the monitored process. GhostScope does not guarantee unchanged timing or a fixed total overhead; use targeted probes and include hit rate in the performance budget.

### 4. Event Loss (Backpressure)
GhostScope uses RingBuf when available and PerfEventArray as a fallback. Either transport can reject output when event generation exceeds available capacity. Generated programs increment a per-trace output-failure counter, and the CLI and TUI periodically report the interval and cumulative loss totals.

This provides loss visibility, not a lossless guarantee. The counters cover failures at the eBPF output helper; they cannot identify which events were lost or prove that no loss occurred outside that measurement point. Treat any nonzero loss report as an incomplete observation interval and avoid placing large or numerous probes on high-frequency paths.

### 5. DWARF Support Coverage
Primarily tested and validated with DWARF 5 format. Theoretically supports DWARF 2-5, but other versions may have compatibility issues. Some DWARF expression instructions are not yet supported for conversion to eBPF (purely due to implementation not being completed yet) and will provide clear error messages when encountered.

GhostScope recognizes `DW_OP_form_tls_address`, but the runtime TLS address resolver currently handles only x86_64 executable static TLS. GhostScope resolves the current thread's TLS base at probe time, so a trace running on different pthreads reads each thread's own TLS instance for that supported executable case. The same DWARF operation is also used for dynamic/shared-library TLS; those cases require DTV/module TLS lookup and are not modeled yet, so GhostScope rejects shared-object TLS instead of guessing an address.

GhostScope strictly checks any available `.gnu_debuglink` CRC and comparable Build ID for separate debug files by default. Enabling `--allow-loose-debug-match` permits a mismatch with a warning and weakens the source-semantic evidence guarantee. An explicitly supplied debug file with neither an available CRC nor a comparable Build ID is also accepted with a warning, but its identity is then a user-supplied trust assumption rather than a verified match.

### 6. Stack Backtrace Coverage
`bt` uses DWARF CFI only. GhostScope does not fall back to kernel stack helpers or frame-pointer walking, and it reports an explicit stop status when CFI is unavailable, not supported by the compact eBPF fast path, or a user-stack memory read fails. Cross-module frames can be symbolized from their raw IPs when the process module map is available, and runtime module refresh can append compact DWARF rows for newly mapped modules up to `backtrace_unwind_rows_max_entries`. A trace event that fires before the map-change refresh reaches userspace can still stop at the newly loaded module until a later event observes the appended rows. Deep DWARF unwinding is split through an eBPF tail-call step program so the default `backtrace_depth = 128` avoids LLVM branch-distance and verifier-size limits; `status=truncated` means the configured depth or the tail-call unwind budget was reached before a natural stop.

Runtime mode also affects `bt` coverage. `-p <pid>` is a process-level view, so GhostScope loads the modules already mapped in that PID's `/proc/<pid>/maps`; cross-module unwinding and symbolization are usually best in this mode. Standalone `-t <path>` is a target-file, multi-process trace view that primarily guarantees probes and variables in the target module. Once the call stack leaves that module, backtrace quality is best-effort and depends on runtime module mappings, maintained `proc_module_offsets`, and compact DWARF CFI being available for the other modules. If you need both target-module scoping and a fuller single-process backtrace, prefer `-t <path> -p <pid>`.

### 7. Highly Optimized Code Support
Compiler optimizations (-O2, -O3) can cause variables to be optimized away or generate complex DWARF expressions. GhostScope will attempt to parse them, including inline function support, but some variables may be inaccessible (shown as OptimizedOut) because the compiler optimized them away.

### 8. Dynamically Loaded Libraries (dlopen)
GhostScope scans `/proc/PID/maps` at startup, and runtime map-change monitoring now refreshes module mappings for `-p <pid>` and standalone `-t <path>` runs while sysmon is enabled. For `bt`/`backtrace`, this can add compact DWARF CFI rows and module offsets for libraries loaded later through `dlopen`, subject to `backtrace_unwind_rows_max_entries` and the map-change race noted above.

`-p <pid>` has one startup edge case: trace setup snapshots the PID's
current `/proc/<pid>/maps` before resolving function-name targets. If
GhostScope attaches immediately after launching a process and the dynamic
loader has not mapped a shared library yet, a trace whose target function
lives in that library can fail setup before runtime map-change monitoring has
anything to refresh. This mainly affects launch-and-immediately-attach
workflows; attaching to an already-running process, waiting until the library
appears in `/proc/<pid>/maps`, or using `-t <path> -p <pid>` for a known
library target avoids the race.

This runtime refresh does not automatically create new trace probes or make print/global-variable targets available for a library that was unknown when the script was compiled and attached. Those targets still depend on the target module and debug information being available during trace setup.

### 9. Global Variables in `-t` Mode

- **Executable targets**: When `-t` points to an executable (`-t /path/to/app`), GhostScope treats that binary as the primary module and globals are supported by default.
- **Shared-library targets (existing processes)**: If GhostScope starts after the library has already been mapped (e.g., tracing a running process that loaded `libfoo.so` earlier), globals work without extra steps.
- **Shared-library targets (new or later-mapped processes)**: Standalone `-t` starts sysmon by default so globals can be resolved for later-started processes and for processes that map the target library later through `dlopen`. This incurs extra system-wide work, so expect higher overhead on hosts with frequent process churn or frequent memory-map changes; set `enable_sysmon_for_target = false` in config to disable it.
- **Target-scoped PID runs (`-t ... -p ...`)**: `-t` chooses the module used for function/source/address target resolution, while `-p` supplies the concrete process mappings, PID filter, and watched-PID module refresh. Target-mode lifecycle sysmon is not used.

In `-t` mode, globals depend on `proc_module_offsets`, which tracks runtime address offsets by `(pid, module)`. Standalone `-t` maintains target-module offsets for multiple PIDs, so it is suitable for observing globals in that module; it is not a complete process view, and `bt` after leaving the target module is not equivalent to `-p`. Use `-p <pid>` when you need the full module context for one process. Use `-t <path> -p <pid>` when you need target-module trace resolution while keeping that process context.

### 10. Container / WSL Limitations for `-p <pid>` Mode

- See [Container Environments](container.md) for the full explanation of container / WSL scenarios, PID namespace terminology, the scenario matrix, and current implementation limits.
- See [PID namespaces manual](https://www.man7.org/linux/man-pages/man7/pid_namespaces.7.html), [WSL issue #12408](https://github.com/microsoft/WSL/issues/12408), and [WSL issue #12115](https://github.com/microsoft/WSL/issues/12115) for background.

### 11. Observation Consistency

A trace event is not a process-wide atomic snapshot. Register values and the current thread's frame correspond to the uprobe hit, but other threads can modify shared memory while GhostScope reads multiple fields. Values collected in one event can therefore represent a short observation interval rather than one globally synchronized instant.

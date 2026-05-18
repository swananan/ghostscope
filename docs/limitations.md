# Limitations

## Hard Limitations

### 1. Privilege Requirements
The underlying eBPF mechanism requires elevated privileges to access kernel tracing infrastructure. Root access or CAP_BPF/CAP_SYS_ADMIN capabilities are needed.

### 2. Do Not Use with GDB Simultaneously
Both uprobe and GDB modify target process instructions (inserting breakpoints). Using them together may lead to conflicts and unpredictable behavior.

### 3. Read-Only Access, Cannot Modify Program Behavior
Although eBPF technically supports modifying process behavior to some extent, GhostScope is designed as a read-only tool and cannot modify program state, variable values, or control flow. This ensures safety in production environments.

### 4. Platform Support
Currently only supports **Linux** operating system due to its core dependency on **eBPF** and **uprobe**.

## Soft Limitations

### 1. Language Support
Primary focus is on **C language**, which currently has the best end-to-end support. **C++** and **Rust** are supported in a more limited, DWARF-layout-oriented way: GhostScope can automatically demangle function names and global/static symbols, but most language-specific features are not modeled yet. In practice, simple C-like layouts work best, while advanced Rust and C++ features still require substantial future work.

For interpreted languages (Lua, Python, Ruby, etc.), only the interpreter itself can be traced (since interpreters are typically implemented in compiled languages). Tracing script code is technically feasible but requires substantial development time. JIT language support is an even more distant goal.

### 2. Architecture Support
Currently only supports **x86_64 (AMD64)** architecture. Other platforms (such as ARM64) are technically feasible but require time for adaptation and testing.

### 3. User-Memory Reads via `bpf_probe_read_user`
In traditional non-sleepable probe paths, helpers such as `bpf_probe_read_user` cannot resolve user-space page faults, so reads from a target virtual address may still fail if the page is not resident or otherwise faults on access.

This is no longer an absolute eBPF limitation. Linux now supports sleepable uprobes (`uprobe.s` / `uretprobe.s`), and sleepable programs can use helpers such as `bpf_copy_from_user_task()` for fault-capable user-memory reads. GhostScope currently emits regular `uprobe` programs, so this remains a practical limitation today, but it is better described as a soft implementation limitation rather than a fundamental design limit of eBPF.

**References**:
- https://lists.iovisor.org/g/iovisor-dev/topic/accessing_user_memory_and/21386221
- https://docs.kernel.org/bpf/libbpf/program_types.html
- https://man7.org/linux/man-pages/man7/bpf-helpers.7.html

### 4. Performance Impact
Based on uprobe implementation, each probe trigger incurs a context switch overhead plus eBPF program execution time. If probes are set on hot paths, they may significantly impact the monitored process performance. Use with caution.

### 5. Event Loss (Backpressure)
Uses ring buffer to pass events between eBPF programs and userspace. If event generation rate exceeds userspace consumption capacity, the kernel will drop events, leading to trace data loss. GhostScope's error reporting is not yet comprehensive (will learn from bpftrace's approach in the future); avoid setting too many probes on high-frequency paths.

### 6. DWARF Support Coverage
Primarily tested and validated with DWARF 5 format. Theoretically supports DWARF 2-5, but other versions may have compatibility issues. Some DWARF expression instructions are not yet supported for conversion to eBPF (purely due to implementation not being completed yet) and will provide clear error messages when encountered.

### 7. Highly Optimized Code Support
Compiler optimizations (-O2, -O3) can cause variables to be optimized away or generate complex DWARF expressions. GhostScope will attempt to parse them, including inline function support, but some variables may be inaccessible (shown as OptimizedOut) because the compiler optimized them away.

### 8. Dynamically Loaded Libraries (dlopen)
GhostScope scans `/proc/PID/maps` at startup to obtain loaded dynamic library information. As long as GhostScope is started after `dlopen`, tracing works normally. Future plans include dynamically monitoring process `dlopen` behavior for better user experience.

### 9. Global Variables in `-t` Mode

- **Executable targets**: When `-t` points to an executable (`-t /path/to/app`), GhostScope treats that binary as the primary module and globals are supported by default.
- **Shared-library targets (existing processes)**: If GhostScope starts after the library has already been mapped (e.g., tracing a running process that loaded `libfoo.so` earlier), globals work without extra steps.
- **Shared-library targets (new processes)**: For processes that start after GhostScope, enable `--enable-sysmon-shared-lib` (or the matching config option) so globals can be resolved. This incurs extra system-wide work, so expect higher overhead on hosts with frequent process churn.
- **Target-scoped PID runs (`-t ... -p ...`)**: sysmon is not needed or started. `-t` chooses the module used for function/source/address target resolution, while `-p` supplies the concrete process mappings and PID filter.

> **Note**: The current sysmon pipeline still assumes the library is mapped when the exec event is handled; if a loader pulls it in much later, offsets are not retried yet.

### 10. Thread-Local Storage (TLS) Variables

Thread-local variables are not ordinary globals: each thread owns a distinct instance. Static TLS variables are the supported subset when the compiler/debug info represents them as a fixed current-thread TLS location that GhostScope can lower for the target architecture.

Dynamic TLS from shared libraries is currently unsupported. This includes variables compiled with ELF `general-dynamic` or `local-dynamic` TLS models, such as many shared-library `__thread` variables and Rust `thread_local!` values.

GhostScope must not resolve these variables as `module_base + symbol_offset`, because that can read the wrong address. Correct dynamic TLS resolution requires following the current thread's thread pointer through the runtime DTV (dynamic thread vector) to the module-specific TLS block, then applying the variable offset. GhostScope does not currently reconstruct that libc / dynamic-linker lookup path or call `__tls_get_addr()` inside the target process.

If a TLS variable is detected but cannot be modeled, treat it as unsupported or unavailable rather than as a normal global variable.

### 11. `-p <pid>` Mode inside Containers or WSL

- See [Container Environments](container.md) for the full explanation of container / WSL scenarios, PID namespace terminology, the scenario matrix, and current implementation limits.
- See [PID namespaces manual](https://www.man7.org/linux/man-pages/man7/pid_namespaces.7.html), [WSL issue #12408](https://github.com/microsoft/WSL/issues/12408), and [WSL issue #12115](https://github.com/microsoft/WSL/issues/12115) for background.

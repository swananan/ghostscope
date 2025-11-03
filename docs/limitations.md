# Limitations

## Hard Limitations

### 1. Privilege Requirements
The underlying eBPF mechanism requires elevated privileges to access kernel tracing infrastructure. Root access or CAP_BPF/CAP_SYS_ADMIN capabilities are needed.

### 2. Do Not Use with GDB Simultaneously
Both uprobe and GDB modify target process instructions (inserting breakpoints). Using them together may lead to conflicts and unpredictable behavior.

### 3. eBPF bpf_probe_read_user Limitations
eBPF helper functions do not support handling page faults, which may cause failures when reading virtual addresses in the target process. This is a design limitation of eBPF.

**Reference**: https://lists.iovisor.org/g/iovisor-dev/topic/accessing_user_memory_and/21386221

### 4. Read-Only Access, Cannot Modify Program Behavior
Although eBPF technically supports modifying process behavior to some extent, GhostScope is designed as a read-only tool and cannot modify program state, variable values, or control flow. This ensures safety in production environments.

### 5. Platform Support
Currently only supports **Linux** operating system due to its core dependency on **eBPF** and **uprobe**.

## Soft Limitations

### 1. Language Support
Primary focus is on **C language**, which has the best support. C++ and Rust are supported with limitations - advanced language features such as Rust async functions and C++ templates have limited support and require significant effort to improve gradually.

For interpreted languages (Lua, Python, Ruby, etc.), only the interpreter itself can be traced (since interpreters are typically implemented in compiled languages). Tracing script code is technically feasible but requires substantial development time. JIT language support is an even more distant goal.

### 2. Architecture Support
Currently only supports **x86_64 (AMD64)** architecture. Other platforms (such as ARM64) are technically feasible but require time for adaptation and testing.

### 3. Performance Impact
Based on uprobe implementation, each probe trigger incurs a context switch overhead plus eBPF program execution time. If probes are set on hot paths, they may significantly impact the monitored process performance. Use with caution.

### 4. Event Loss (Backpressure)
Uses ring buffer to pass events between eBPF programs and userspace. If event generation rate exceeds userspace consumption capacity, the kernel will drop events, leading to trace data loss. GhostScope's error reporting is not yet comprehensive (will learn from bpftrace's approach in the future); avoid setting too many probes on high-frequency paths.

### 5. DWARF Support Coverage
Primarily tested and validated with DWARF 5 format. Theoretically supports DWARF 2-5, but other versions may have compatibility issues. Some DWARF expression instructions are not yet supported for conversion to eBPF (purely due to implementation not being completed yet) and will provide clear error messages when encountered.

### 6. Highly Optimized Code Support
Compiler optimizations (-O2, -O3) can cause variables to be optimized away or generate complex DWARF expressions. GhostScope will attempt to parse them, including inline function support, but some variables may be inaccessible (shown as OptimizedOut) because the compiler optimized them away.

### 7. Dynamically Loaded Libraries (dlopen)
GhostScope scans `/proc/PID/maps` at startup to obtain loaded dynamic library information. As long as GhostScope is started after `dlopen`, tracing works normally. Future plans include dynamically monitoring process `dlopen` behavior for better user experience.

### 8. Global Variables in `-t` Mode

- **Executable targets**: When `-t` points to an executable (`-t /path/to/app`), GhostScope treats that binary as the primary module and globals are supported by default.
- **Shared-library targets (existing processes)**: If GhostScope starts after the library has already been mapped (e.g., tracing a running process that loaded `libfoo.so` earlier), globals work without extra steps.
- **Shared-library targets (new processes)**: For processes that start after GhostScope, enable `--enable-sysmon-shared-lib` (or the matching config option) so globals can be resolved. This incurs extra system-wide work, so expect higher overhead on hosts with frequent process churn.

> **Note**: The current sysmon pipeline still assumes the library is mapped when the exec event is handled; if a loader pulls it in much later, offsets are not retried yet.

### 9. `-p <pid>` Mode inside Containers or WSL

- The `-p` workflow filters events using `bpf_get_current_pid_tgid`, which returns the host kernel PID/ TGID. Inside PID namespaces (e.g., Docker, Kubernetes) or Windows Subsystem for Linux, the PID visible inside the container often differs from the host PID.
- See [PID namespaces manual](https://www.man7.org/linux/man-pages/man7/pid_namespaces.7.html), [WSL issue #12408](https://github.com/microsoft/WSL/issues/12408), and [WSL issue #12115](https://github.com/microsoft/WSL/issues/12115) for details.
- In these environments, either map the container/WSL PID to the host PID before using `-p`, or prefer `-t <binary>`/`-t <shared library>` where we attach uprobes by module path instead of PID.

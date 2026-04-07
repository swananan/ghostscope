# Frequently Asked Questions

## What is GhostScope?

GhostScope is an eBPF-based runtime tracer that allows you to observe and analyze running applications in real-time without modifying source code, recompiling, or restarting processes. Think of it as "printf debugging" for production systems.

## How does GhostScope differ from GDB?

See [Tool Comparison - GhostScope vs GDB](comparison.md#ghostscope-vs-gdb).
For measured steady-state overhead on one shared benchmark, also see [GhostScope vs GDB Performance Snapshot](comparison.md#ghostscope-vs-gdb-performance-snapshot).

## How do perf probe and GhostScope differ?

See [Tool Comparison - GhostScope vs perf probe](comparison.md#ghostscope-vs-perf-probe).

## How do bpftrace and GhostScope differ?

See [Tool Comparison - GhostScope vs bpftrace](comparison.md#ghostscope-vs-bpftrace).

## How do SystemTap and GhostScope differ?

See [Tool Comparison - GhostScope vs SystemTap](comparison.md#ghostscope-vs-systemtap).

## When to use perf, GDB, SystemTap, bpftrace, or GhostScope

See [Tool Comparison - Quick Recommendation](comparison.md#quick-recommendation) for a short matrix, and [Which Tool Should I Pick?](comparison.md#which-tool-should-i-pick) for the full decision guide.

## What is debug information? Can I use GhostScope with Release builds?

- What it is
  - DWARF `.debug_*` sections that contain source line tables, type information, location expressions for parameters/locals/globals, and inlining/optimization metadata. This is different from exported symbol tables. GhostScope relies on it to attach at source/instruction granularity and to compute+read variable locations/values.

- Can I use it with Release builds?
  - Yes. “Release” typically just enables higher compiler optimizations and does not imply the absence of debug info. As long as debug info is available for the target executables/libraries. Common options:
    - Keep `-g` in Release: e.g., `-O2/-O3 + -g`. Binaries are larger, but GhostScope can use the embedded debug sections directly.
    - Use separate debug files: ship a stripped production binary and put debug info in `your_program.debug` linked via `.gnu_debuglink`. Deploy the debug file in the same directory, a `.debug` subdirectory, or under `/usr/lib/debug`; GhostScope will discover it automatically.

- System libraries
  - Install distro debuginfo packages (e.g., Ubuntu/Debian `libc6-dbg`, Fedora/RHEL `debuginfo-install glibc`). These typically place files under `/usr/lib/debug/`, where GhostScope looks by default.

- Effects of optimization
  - In highly optimized builds, some variables may be “optimized out” or only have locations at certain instruction points (location lists). GhostScope evaluates DWARF at runtime, but if the compiler didn’t emit a location (no `DW_AT_location`), that variable cannot be read.

- Quick check and further details
  - Use `readelf -S` to check for `.debug_*` sections, or `readelf -x .gnu_debuglink` to check for a separate debug file link. For commands, search paths, and step-by-step instructions, see the [Installation Guide – Debug Symbols (Required)](install.md#3-debug-symbols-required).

## What are the limitations of GhostScope?

See the [Limitations](limitations.md) document for a comprehensive list of hard and soft limitations.

## What is the roadmap?

See the [Roadmap](roadmap.md) document for planned features and future development.

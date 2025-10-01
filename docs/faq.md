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

## When should I use GhostScope vs GDB?

**Use GhostScope when:**
- Debugging production systems
- Analyzing timing-sensitive issues
- Debugging race conditions or concurrency bugs
- You need to see the flow of execution over time
- You prefer printf-style debugging
- The bug only appears under real load

**Use GDB when:**
- You need to inspect complex data structures interactively
- You want to modify variables during debugging
- You need to step through code line by line
- You're debugging a crash with a core dump
- You're in a development environment where stopping is acceptable

## What are the limitations of GhostScope?

See the [Limitations](limitations.md) document for a comprehensive list of hard and soft limitations.

## What is the roadmap?

See the [Roadmap](roadmap.md) document for planned features and future development.


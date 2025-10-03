# GhostScope Roadmap (Milestones)

## Global variables in `-p <pid>` mode — stability and compatibility improvements
  - Automatic ASLR section offset computation and population
  - Runtime null-pointer dereference protection

## Global variables in `-t <exec_path>` mode (planned)
  - Background: resolving globals requires per-module ASLR offsets computed from `/proc/<pid>/maps`, while `-t` mode has no PID context.
  - Direction: introduce PID discovery/subscription in the attach flow, or compute and populate offsets once a PID is known at trigger time; ensure safety and ordering.
  - Until this is available, globals remain disabled in `-t` mode (see “Limitations”).

## Chained array access (`a.b[idx].c`) and dynamic indices (planned)
  - Support constant indices first; later extend to expression-based indices within eBPF verifier limits.

## Stack Unwinding
  - Capture full call stacks at trace points, implemented via `.eh_frame` parsing.
  
  Reference: https://lesenechal.fr/en/linux/unwinding-the-stack-the-hard-way#h5.1-parsing-eh_frame-and-eh_frame_hdr-with-gimli

## Stability and Accuracy Improvements
  - As a debugging tool, continue fixing defects, improving error handling and data consistency, and raising overall reliability.

## Performance Optimization with bpftime
  - Evaluate migrating from kernel uprobe to userspace eBPF via [bpftime](https://github.com/eunomia-bpf/bpftime) to reduce context switches.

## Advanced Language Features
  - Compiled direction: prioritize Rust advanced features (async functions, trait objects, etc.)
  - Interpreted direction: explore tracing support for specific interpreted languages (e.g., Lua)

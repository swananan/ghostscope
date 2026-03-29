# GhostScope Roadmap (Milestones)

GhostScope is still evolving quickly. The milestones below are ordered from “strengthen core capabilities” to “polish experience” and finally “expand language and deployment coverage”.

## Chained array access & dynamic indices
- First unlock constant-index access such as `a.b[idx].c`.
- Once verifier limits are well understood, roll out expression-based/dynamic indices in staged fashion.

## Container tracing enhancements
- PID-based tracing inside containerized environments (Docker/WSL) still faces soft limitations; see [Limitations](limitations.md#10-container--wsl-limitations-for--p-pid-mode).
- Once foundational work settles, we’ll revisit improving compatibility in these isolated setups.

## Uprobe enhancements
- Add support for sleepable uprobes (`uprobe.s` / `uretprobe.s`) so GhostScope can use sleepable helpers where appropriate, especially for more reliable user-memory reads.
- Add support for multi-attach uprobes (`uprobe.multi` / `uretprobe.multi`) to scale better when a script expands into many probe points.
- Keep compatibility fallbacks for kernels or libbpf/Aya paths that still require regular `uprobe` attachments.

## Stack Unwinding
- Capture full call stacks at each trace point by parsing `.eh_frame`/`.eh_frame_hdr`.
- Surface the stack in the TUI with symbol/source awareness.  
  Reference: <https://lesenechal.fr/en/linux/unwinding-the-stack-the-hard-way#h5.1-parsing-eh_frame-and-eh_frame_hdr-with-gimli>

## Stability & accuracy
- Keep fixing defects, hardening error handling, and ensuring data consistency.
- Grow automated and regression coverage so the core workflows stay dependable.

## Performance via bpftime
- Evaluate switching from kernel uprobes to userspace eBPF with [bpftime](https://github.com/eunomia-bpf/bpftime) to cut context-switch overhead.

## Advanced language features
- Compiled languages: prioritize modern Rust features (async functions, trait objects, etc.).
- Interpreted languages: explore cooperation with runtimes such as Lua to surface variables/stack state.

## Client-server execution model
- Typical scenario: sources and debug info live in the cloud, while binaries run on test rigs or local hosts.
- Goal: keep GhostScope’s TUI on the control side and run the eBPF agent on the target machine, similar to `gdb`/`gdbserver`.
- This will come after the core functionality stabilizes to avoid diluting near-term focus.

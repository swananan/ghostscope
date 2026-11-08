# ghostscope-process

`ghostscope-process` drives low-level process orchestration for GhostScope. It selects attachment points, prepares loader state, and exposes helpers consumed by both user-space and eBPF code.

## eBPF Artifacts
Prebuilt CO-RE objects live under `ebpf/obj/`. The `build.rs` script copies them into the Cargo output directory. If you need to regenerate the objects:

```bash
$ ./ghostscope-process/ebpf/build_sysmon_bpf.sh
```

The script expects:
- Rust nightly toolchain (default `nightly-2024-07-01`) with the `bpfel-unknown-none` and `bpfeb-unknown-none` targets
- `rust-src` component installed for that toolchain
- `clang`, `llc`, and `bpftool` available on `PATH`

Additional details are documented in the workspace README: <https://github.com/swananan/ghostscope#readme>.

## Sysmon lifecycle tracking

Fork and exit tracking requires kernel BTF at `/sys/kernel/btf/vmlinux`
(`CONFIG_DEBUG_INFO_BTF`). Sysmon resolves task and PID-namespace field offsets
before attaching its prebuilt probes; it does not assume a particular kernel
layout or the newer `sched_process_exit` `group_dead` argument. If BTF is
unavailable, lifecycle startup reports an error. PID-mode map-change monitoring
does not require these offsets.

Fork probes use raw or BTF tracepoints to access the child task. The classic
tracepoint fallback also uses a raw fork hook, because a classic fork record
only supplies the child TID, not its TGID and namespace identity.

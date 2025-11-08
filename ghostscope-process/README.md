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

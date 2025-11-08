# ghostscope-loader

`ghostscope-loader` manages eBPF program lifecycles for GhostScope sessions. It loads bytecode emitted by `ghostscope-compiler`, attaches uprobes, and coordinates per-session resources.

## Build Notes
- Requires libbpf-compatible kernel headers and the `aya` user-space stack
- Optional `tokio` features (`io-util`, `mio`, `net`) are enabled to support async device IO

See the root project guide for usage examples: <https://github.com/swananan/ghostscope#readme>.

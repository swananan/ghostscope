# ghostscope

`ghostscope` is the CLI entrypoint for the GhostScope workspace. It wires together the compiler, loader, and TUI so you can inject DWARF-aware eBPF tracepoints with a single command.

## Highlights
- Parses `.gs` trace scripts and drives `ghostscope-compiler`
- Coordinates `ghostscope-loader` to inject generated eBPF programs into target processes
- Streams structured trace output through `ghostscope-ui`

For screenshots, tutorials, and in-depth docs visit the [main GhostScope repository](https://github.com/swananan/ghostscope#readme).

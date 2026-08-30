# ghostscope-compiler

`ghostscope-compiler` turns GhostScope trace definitions into DWARF-aware eBPF
programs. It parses the DSL, asks `ghostscope-dwarf` for PC-context read plans,
and lowers those plans into IR that targets LLVM's BPF backend.

The compiler should not reinterpret raw DWARF location expressions itself. DWARF
visibility, optimized-out state, ASLR-sensitive address handling, and semantic
diagnostics belong in `ghostscope-dwarf`; this crate consumes the resulting plan
and focuses on safe code generation.

## Build Requirements
- LLVM 22.1.x with `llvm-config` available on `PATH`
- The `inkwell` crate's `llvm22-1` feature expects LLVM libraries from your package manager or a source build with the BPF target enabled

If LLVM lives in a non-standard directory, export `LLVM_SYS_221_PREFIX` before invoking Cargo. The top-level documentation explains the full workflow: <https://github.com/swananan/ghostscope#readme>.

# ghostscope-compiler

`ghostscope-compiler` turns GhostScope trace definitions into DWARF-aware eBPF
programs. It parses the DSL, asks `ghostscope-dwarf` for PC-context read plans,
and lowers those plans into IR that targets LLVM's BPF backend.

The compiler should not reinterpret raw DWARF location expressions itself. DWARF
visibility, optimized-out state, ASLR-sensitive address handling, and semantic
diagnostics belong in `ghostscope-dwarf`; this crate consumes the resulting plan
and focuses on safe code generation.

## Build Requirements
- LLVM 18.x with `llvm-config` available on `PATH` (or set `LLVM_CONFIG_PATH`)
- The `inkwell` crate's `llvm18-1` feature expects a shared build; consult your package manager or build from source with `-DLLVM_ENABLE_PROJECTS=clang;lld`

If LLVM lives in a non-standard directory, export `LLVM_SYS_180_PREFIX` or `LLVM_CONFIG_PATH` before invoking Cargo. The top-level documentation explains the full workflow: <https://github.com/swananan/ghostscope#readme>.

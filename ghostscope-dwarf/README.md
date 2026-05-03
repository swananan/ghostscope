# ghostscope-dwarf

`ghostscope-dwarf` is GhostScope's PC-context DWARF semantic layer. It loads
ELF/DWARF data from process modules, resolves source locations, visible
variables, type layouts, globals, and address mappings, then produces semantic
read plans for the compiler.

Those read plans describe how a value can be read at a specific probe PC, or why
it is unavailable. This keeps DWARF location expressions, optimized-out state,
ASLR-sensitive addresses, shadowing, and unsupported expression diagnostics in
the DWARF crate instead of spreading those decisions through the eBPF compiler.

The crate wraps `gimli`, `object`, `memmap2`, and symbol demanglers, and exposes
async-friendly helpers for the rest of the workspace. Consumers should prefer
the PC-context planning APIs over interpreting raw DWARF locations directly.

Consumers typically do not use this crate directly; it is re-exported via higher-level components. See the main GhostScope docs for usage examples: <https://github.com/swananan/ghostscope#readme>.

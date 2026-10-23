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

Supplementary DWARF objects referenced by `.gnu_debugaltlink` (GNU/dwz) or
`.debug_sup` (DWARF 5) are loaded alongside the selected primary debug file.
References retain the object identity through type queries and member projection.
Imported units contribute reachable type declarations. Primary-file accelerator
indexes remain available with a supplement; imported type names are indexed on
the first type query and retained as further compilation units are parsed.

Supplement discovery searches relative to the primary debug file (including its
resolved symlink location), then the configured debug search directories. GNU
links validate the supplement's Build-ID; DWARF 5 links validate its `.debug_sup`
role and supplied checksum. Matching remains strict in loose debug-file mode.
A missing or mismatched required supplement is a module-loading error. Supplement
fetching through debuginfod and Split DWARF `.dwo`/`.dwp` loading are not included.

For GDB2 `.debug_names` with supplementary DWARF, imported definitions can carry
DIE offsets from a different unit or object than the attributed importing CU.
These entries select CUs for lazy materialization; they are not treated as
primary-object DIE locations. Ordinary `.debug_names` keeps its existing path.

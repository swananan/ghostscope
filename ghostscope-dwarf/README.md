# ghostscope-dwarf

`ghostscope-dwarf` parses DWARF data from ELF binaries so GhostScope can resolve variables, types, and addresses at runtime. It wraps `gimli`, `object`, `memmap2`, and symbol demanglers, and exposes async-friendly helpers for the rest of the workspace.

Consumers typically do not use this crate directly; it is re-exported via higher-level components. See the main GhostScope docs for usage examples: <https://github.com/swananan/ghostscope#readme>.

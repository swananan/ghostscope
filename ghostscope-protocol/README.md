# ghostscope-protocol

`ghostscope-protocol` defines the shared data structures, serialization, and message formats that connect GhostScope components. It relies on `serde`, `zerocopy`, and DWARF metadata pulled in through `ghostscope-dwarf`/`ghostscope-platform`.

This crate has no binaries; it is a pure Rust library meant to be consumed by other workspace members. Documentation and examples live in the main repo: <https://github.com/swananan/ghostscope#readme>.

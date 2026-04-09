# GhostScope E2E Tests

This crate contains the workspace-level end-to-end test suite for the
`ghostscope` CLI.

Routine workspace commands exclude this crate via workspace
`default-members`, so standard `cargo test` stays focused on unit and
integration coverage for the main workspace crates.

Typical local flow:

```bash
cargo build -p ghostscope -p dwarf-tool --all-features
sudo cargo test -p ghostscope-e2e-tests --tests --all-features -- --nocapture
```

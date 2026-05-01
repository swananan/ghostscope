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

Routine host-host e2e skips the explicit container-topology cases. Run them by
setting `E2E_RUN_CONTAINER_TOPOLOGY=1` or by using one of the docker-backed
`E2E_GHOSTSCOPE_SANDBOX`/`E2E_TARGET_SANDBOX` topology settings.

# GhostScope E2E Tests

This crate contains the workspace-level end-to-end test suite for the
`ghostscope` CLI.

The suite provides runtime evidence for the project's
[Design Guarantees and Trust Model](../docs/design-contract.md). E2E tests
should assert a domain oracle, such as an exact source-level value, target PID,
explicit failure state, loss report, or backtrace stop reason. Process exit
status alone is not sufficient evidence for an invariant.

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

## Value diagnostic contracts

[value_diagnostics_execution.rs](tests/value_diagnostics_execution.rs) checks
the CLI behavior described in the [value diagnostics guide](../docs/value-diagnostics.md).
Run this suite on its own with:

```bash
cargo build -p ghostscope -p dwarf-tool --all-features
sudo cargo test -p ghostscope-e2e-tests --test value_diagnostics_execution --all-features -- --nocapture
```

All cases use the `test_value_diagnostics_` prefix and are included automatically
in the normal CI e2e run. The Rust fixtures require the pinned `1.88.0` toolchain
from [rust-compat-toolchains.txt](rust-compat-toolchains.txt). The optimized-out
case uses the existing C fixture and first verifies its DWARF location state.

| Scenario | Required observable behavior |
| --- | --- |
| Optimized-out variable | Printing shows `unavailable`; using it in an expression fails compilation and names the variable and probe-location limitation. |
| Failed memory read | Root values, nested fields, and explicit memory dumps retain `unreadable`, errno, and the attempted address; readable siblings survive. Checked with both RingBuf and PerfEventArray. |
| Null dereference | Explicit dereference reports its own error, separately from a failed memory read. |
| Unsupported layout / read plan | Successful DWARF fallback retains raw fields and identifies the distinct reason. Failed fallback reports the underlying compilation error and adapter details. |
| Byte / element limit | Captured prefixes remain visible, with the correct truncation reason; empty strings remain valid empty values. |
| Depth / recursive-type limit | Static notes identify affected paths without claiming an inactive enum variant was read or a finite tree contains a runtime cycle. |
| Diagnostic-only aggregate | Static depth notes retain the ordinary read path; null dereference and failed reads remain distinct, and neither failure is labeled as a depth limit. |
| Register-backed argument | A DWARF location check proves the argument is in a register; its depth note survives just as it does for an address-backed peer. |
| Capture budget | Root fields remain visible when nested expansion cannot fit; a static note identifies the budget limit. |
| Event capture limit | Omitted payloads report capture truncation, without claiming a memory read failed. |
| Offline documentation | `--value-diagnostics-help` matches the shipped English guide and bypasses invalid runtime inputs; both language guides contain every public reason. |

Keep assertions on the stable marker, reason, retained data, exit status, and
output stream. Static notes must remain available with `--no-log --no-status`,
include a documentation entry point, and avoid duplicate notes for repeated
prints. Ordinary structs and valid empty values serve as controls against
false diagnostics. Do not snapshot timestamps, ASLR addresses, decoration, or
whole explanatory paragraphs. Deliberately invalid fixture addresses are fixed
constants, not application dereferences or corrupted standard-library values.
Fixtures touch readable globals before the probe so that untouched page mappings
do not accidentally turn a healthy control into another non-sleepable read error.

When changing a public diagnostic, update its case here and both language
guides together. Keep renderer and protocol edge cases in unit tests; this
suite exercises the compiled CLI, real DWARF, eBPF capture, and final output.

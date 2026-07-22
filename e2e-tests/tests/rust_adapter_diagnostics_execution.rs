//! CLI diagnostics for rejected Rust value adapters.

mod common;

use std::path::{Path, PathBuf};

use common::{
    init,
    rust_toolchain::{compile_standalone_fixture, fixture_tempdir, rustc_for_toolchain},
};

const TOOLCHAIN: &str = "1.88.0";

fn compile_fixture(rustc: &Path, output_dir: &Path) -> anyhow::Result<PathBuf> {
    // The source filename makes rustc use `alloc` as the crate name, producing
    // the qualified type identity `alloc::string::String` in target DWARF.
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rust_adapter_rejection_program/alloc.rs");
    let binary = output_dir.join("rust_adapter_rejection_program");
    compile_standalone_fixture(rustc, TOOLCHAIN, &source, &binary)?;
    Ok(binary)
}

#[tokio::test]
async fn test_cli_reports_rust_adapter_rejection_when_dwarf_fallback_fails() -> anyhow::Result<()> {
    init();

    let rustc = rustc_for_toolchain(TOOLCHAIN)
        .ok_or_else(|| anyhow::anyhow!("required Rust toolchain {TOOLCHAIN} is not installed"))?;
    let temp_dir = fixture_tempdir()?;
    let binary = compile_fixture(&rustc, temp_dir.path())?;
    let target = common::targets::TargetLauncher::binary(&binary)
        .current_dir(temp_dir.path())
        .spawn()
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;

    let script = r#"
trace observe_adapter_rejection {
    print "SHOULD_NOT_LOAD:{}", G_REJECTED_STRING;
}
"#;
    let result = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .attach_to(&target)
        .timeout_secs(5)
        .enable_sysmon_for_target(false)
        .run()
        .await;
    target.terminate().await?;

    let (exit_code, stdout, stderr) = result?;
    let output = format!("{stdout}\n{stderr}");
    assert_ne!(exit_code, 0, "expected compilation failure: {output}");
    for expected in [
        "Variable 'G_REJECTED_STRING' has no concrete DWARF size",
        "Rust value adapter diagnostic (ordinary DWARF fallback also failed):",
        "adapter: String",
        "type: alloc::string::String",
        "rejected at: layout-validation",
        "reason: expected `vec.buf[.inner].ptr` and `vec.len`",
        "target rustc: 1.88.0",
        "target DWARF:",
        "producer:",
    ] {
        assert!(output.contains(expected), "missing '{expected}': {output}");
    }

    Ok(())
}

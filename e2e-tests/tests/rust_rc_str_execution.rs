//! Runtime coverage for DWARF-described Rust `Rc<str>` and `Arc<str>` values.

mod common;

use std::path::{Path, PathBuf};

use common::{
    init,
    rust_toolchain::{compile_standalone_fixture, fixture_tempdir, rustc_for_toolchain},
};
use regex::Regex;

const TOOLCHAIN: &str = "1.88.0";
const REQUIRE_TOOLCHAIN_ENV: &str = "GHOSTSCOPE_REQUIRE_RUST_188_E2E";

fn compile_fixture(rustc: &Path, output_dir: &Path) -> anyhow::Result<PathBuf> {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rust_rc_str_program/main.rs");
    let binary = output_dir.join("rust_rc_str_program");
    compile_standalone_fixture(rustc, TOOLCHAIN, &source, &binary)?;
    Ok(binary)
}

#[tokio::test]
async fn test_rust_188_reference_counted_str_pointers() -> anyhow::Result<()> {
    init();

    let Some(rustc) = rustc_for_toolchain(TOOLCHAIN) else {
        anyhow::ensure!(
            std::env::var_os(REQUIRE_TOOLCHAIN_ENV).is_none(),
            "required Rust toolchain {TOOLCHAIN} is not installed"
        );
        eprintln!("skipping unavailable Rust toolchain {TOOLCHAIN}");
        return Ok(());
    };

    let temp_dir = fixture_tempdir()?;
    let binary = compile_fixture(&rustc, temp_dir.path())?;
    let target = common::targets::TargetLauncher::binary(&binary)
        .current_dir(temp_dir.path())
        .spawn()
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(750)).await;

    let script = r#"
trace observe_reference_counted_str {
    print "R188_RC_ARC_STR:{}:{}", value, shared;
}
"#;
    let result = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .with_config_content(
            r#"
[ebpf]
mem_dump_cap = 16
"#,
        )
        .attach_to(&target)
        .timeout_secs(9)
        .enable_sysmon_for_target(false)
        .run()
        .await;
    target.terminate().await?;

    let (exit_code, stdout, stderr) = result?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    let output = Regex::new(concat!(
        r"R188_RC_ARC_STR:",
        r"Rc\(strong=3, weak=1\) \{ ptr: 0x[0-9a-f]+ \([^)]*\), ",
        r"strong: 3, weak: 1 \}:",
        r"Arc\(strong=3, weak=1\) \{ ptr: 0x[0-9a-f]+ \([^)]*\), ",
        r"strong: 3, weak: 1 \}",
    ))?;
    assert!(output.is_match(&stdout), "missing pointer output: {stdout}");
    assert!(
        !stdout.contains("ExprError"),
        "unexpected ExprError: {stdout}"
    );
    assert!(!stdout.contains("<INVALID_"), "invalid payload: {stdout}");

    Ok(())
}

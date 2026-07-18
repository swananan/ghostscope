//! Runtime coverage for DWARF-described Rust `PathBuf` and `&Path` values.

mod common;

use std::path::{Path, PathBuf};

use common::{
    init,
    rust_toolchain::{compile_standalone_fixture, fixture_tempdir, rustc_for_toolchain},
};

const TOOLCHAIN: &str = "1.88.0";
const REQUIRE_TOOLCHAIN_ENV: &str = "GHOSTSCOPE_REQUIRE_RUST_188_E2E";

fn compile_fixture(rustc: &Path, output_dir: &Path) -> anyhow::Result<PathBuf> {
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rust_path_program/main.rs");
    let binary = output_dir.join("rust_path_program");
    compile_standalone_fixture(rustc, TOOLCHAIN, &source, &binary)?;
    Ok(binary)
}

#[tokio::test]
async fn test_rust_188_path_values() -> anyhow::Result<()> {
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
trace observe_paths {
    print "R188_PATH:{}:{}:{}:{}", borrowed, owned, empty, long;
    print "R188_PATH_RAW:{:s}:{:x}", borrowed, owned;
    print "R188_PATH_LONG_RAW:{:s}:{:x}", long, long;
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
    for expected in [
        concat!(
            "R188_PATH:\"borrowed/path\":\"owned/path\":\"\":",
            "\"abcdefghijklmnop\" <truncated>"
        ),
        concat!(
            "R188_PATH:\"borrowed/path\":\"bad/\\xff/path\":\"\":",
            "\"abcdefghijklmnop\" <truncated>"
        ),
        concat!(
            "R188_PATH_RAW:borrowed/path:",
            "62 61 64 2f ff 2f 70 61 74 68"
        ),
        concat!(
            "R188_PATH_LONG_RAW:abcdefghijklmnop <truncated>:",
            "61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f 70 <truncated>"
        ),
    ] {
        assert!(stdout.contains(expected), "missing '{expected}': {stdout}");
    }
    assert!(
        !stdout.contains("ExprError"),
        "unexpected ExprError: {stdout}"
    );
    assert!(!stdout.contains("<INVALID_"), "invalid payload: {stdout}");

    Ok(())
}

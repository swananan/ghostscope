//! Runtime coverage for Rust 1.35 string-family layouts.

mod common;

use std::path::{Path, PathBuf};

use common::{
    init,
    rust_toolchain::{compile_standalone_fixture, fixture_tempdir, rustc_for_toolchain},
};

const TOOLCHAIN: &str = "1.35.0";
const REQUIRE_TOOLCHAIN_ENV: &str = "GHOSTSCOPE_REQUIRE_RUST_135_E2E";

fn compile_fixture(rustc: &Path, output_dir: &Path) -> anyhow::Result<PathBuf> {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rust_legacy_string_program/main.rs");
    let binary = output_dir.join("rust_legacy_string_program");
    compile_standalone_fixture(rustc, TOOLCHAIN, &source, &binary)?;
    Ok(binary)
}

#[tokio::test]
async fn test_rust_135_string_family_values() -> anyhow::Result<()> {
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
trace observe_legacy_strings {
    print "R135_STRING:{}", owned;
    print "R135_STRING_RAW:{:s}:{:x}", owned, owned;
    print "R135_OS:{}:{}", valid_os, invalid_os;
    print "R135_STR:{}", text;
    print "R135_BOX_STR:{}", boxed;
    print "R135_EMPTY:{}:{}:{}:{}", empty_owned, empty_os, empty_text, empty_boxed;
}
"#;
    let result = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .with_config_content(
            r#"
[ebpf]
mem_dump_cap = 64
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
        r#"R135_STRING:"legacy = string""#,
        concat!(
            "R135_STRING_RAW:legacy = string:",
            "6c 65 67 61 63 79 20 3d 20 73 74 72 69 6e 67"
        ),
        r#"R135_OS:"os from 1.35":"os\xffx""#,
        r#"R135_STR:"legacy\0str""#,
        r#"R135_BOX_STR:"boxed from 1.35""#,
        r#"R135_EMPTY:"":"":"":"""#,
    ] {
        assert!(stdout.contains(expected), "missing '{expected}': {stdout}");
    }
    assert!(
        !stdout.contains("ExprError"),
        "unexpected ExprError: {stdout}"
    );
    assert!(!stdout.contains("<INVALID_"), "invalid payload: {stdout}");
    assert!(
        !stdout.contains("<truncated>"),
        "truncated payload: {stdout}"
    );

    Ok(())
}

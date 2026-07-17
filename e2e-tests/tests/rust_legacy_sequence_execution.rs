//! Runtime coverage for Rust 1.35 sequence and ring-buffer layouts.

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
        .join("tests/fixtures/rust_legacy_sequence_program/main.rs");
    let binary = output_dir.join("rust_legacy_sequence_program");
    compile_standalone_fixture(rustc, TOOLCHAIN, &source, &binary)?;
    Ok(binary)
}

#[tokio::test]
async fn test_rust_135_sequence_family_values() -> anyhow::Result<()> {
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
trace observe_legacy_sequences {
    print "R135_SLICE:{}:{}", slice, empty_slice;
    print "R135_VEC:{}:{}:{}", vector, empty_vector, unit_vector;
    print "R135_DEQUE:{}:{}:{}:{}", wrapped, contiguous, empty_deque, unit_deque;
    print "R135_DEQUE_RAW:{:x}", wrapped;
}
"#;
    let result = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .with_config_content(
            r#"
[ebpf]
mem_dump_cap = 256
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
        "R135_SLICE:[-3, 5, 8]:[]",
        "R135_VEC:[10, -20, 30]:[]:[(), (), ()]",
        "R135_DEQUE:[3, 4, 5, 6, 7, 8]:[7, 8, 9]:[]:[(), (), ()]",
        concat!(
            "R135_DEQUE_RAW:",
            "03 00 00 00 04 00 00 00 05 00 00 00 ",
            "06 00 00 00 07 00 00 00 08 00 00 00"
        ),
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

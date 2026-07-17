//! Runtime coverage for Rust 1.35's direct-root B-Tree layout.

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
        .join("tests/fixtures/rust_legacy_btree_program/main.rs");
    let binary = output_dir.join("rust_legacy_btree_program");
    compile_standalone_fixture(rustc, TOOLCHAIN, &source, &binary)?;
    Ok(binary)
}

#[tokio::test]
async fn test_rust_135_btree_map_and_btree_set_values() -> anyhow::Result<()> {
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

    let node_script = r#"
trace observe_legacy_btree_nodes {
    print "R135_BTREE_MAP:{}", map;
    print "R135_BTREE_SET:{}", set;
}
"#;
    let node_result = common::runner::GhostscopeRunner::new()
        .with_script(node_script)
        .with_config_content(
            r#"
[ebpf]
mem_dump_cap = 450
"#,
        )
        .attach_to(&target)
        .timeout_secs(9)
        .enable_sysmon_for_target(false)
        .run()
        .await;

    let edge_script = r#"
trace observe_legacy_btree_edge_cases {
    print "R135_BTREE_EMPTY_MAP:{}", empty_map;
    print "R135_BTREE_EMPTY_SET:{}", empty_set;
    print "R135_BTREE_UNIT_MAP:{}", unit_map;
    print "R135_BTREE_UNIT_SET:{}", unit_set;
}
"#;
    let edge_result = common::runner::GhostscopeRunner::new()
        .with_script(edge_script)
        .with_config_content(
            r#"
[ebpf]
mem_dump_cap = 90
"#,
        )
        .attach_to(&target)
        .timeout_secs(9)
        .enable_sysmon_for_target(false)
        .run()
        .await;
    target.terminate().await?;

    let (exit_code, node_stdout, node_stderr) = node_result?;
    assert_eq!(exit_code, 0, "stderr={node_stderr} stdout={node_stdout}");
    let expected_map = (0_i32..20)
        .map(|key| format!("{key}: {}", key * 3 + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let expected_set = (0_i32..20)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    assert!(
        node_stdout.contains(&format!(
            "R135_BTREE_MAP:BTreeMap(size=20) {{{expected_map}}}"
        )),
        "missing complete Rust 1.35 BTreeMap: {node_stdout}"
    );
    assert!(
        node_stdout.contains(&format!(
            "R135_BTREE_SET:BTreeSet(size=20) {{{expected_set}}}"
        )),
        "missing complete Rust 1.35 BTreeSet: {node_stdout}"
    );

    let (exit_code, edge_stdout, edge_stderr) = edge_result?;
    assert_eq!(exit_code, 0, "stderr={edge_stderr} stdout={edge_stdout}");
    for expected in [
        "R135_BTREE_EMPTY_MAP:BTreeMap(size=0) {}",
        "R135_BTREE_EMPTY_SET:BTreeSet(size=0) {}",
        "R135_BTREE_UNIT_MAP:BTreeMap(size=1) {(): ()}",
        "R135_BTREE_UNIT_SET:BTreeSet(size=1) {()}",
    ] {
        assert!(
            edge_stdout.contains(expected),
            "missing '{expected}': {edge_stdout}"
        );
    }
    for stdout in [&node_stdout, &edge_stdout] {
        assert!(
            !stdout.contains("ExprError"),
            "unexpected ExprError: {stdout}"
        );
        assert!(!stdout.contains("<INVALID_"), "invalid payload: {stdout}");
        assert!(
            !stdout.contains("<truncated>"),
            "truncated payload: {stdout}"
        );
    }

    Ok(())
}

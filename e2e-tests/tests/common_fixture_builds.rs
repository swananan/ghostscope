mod common;

use common::{init, FixtureCompiler};
use std::path::PathBuf;
use std::process::Command;

fn clean_fixture_outputs(fixture_name: &str) -> anyhow::Result<()> {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(fixture_name);
    let status = Command::new("make")
        .arg("clean")
        .current_dir(&base)
        .status()
        .map_err(|e| anyhow::anyhow!("Failed to run make clean for {fixture_name}: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("make clean failed for {fixture_name} with status {status}");
    }
}

#[test]
fn compiler_specific_builds_keep_sibling_fixture_outputs() -> anyhow::Result<()> {
    init();

    if !common::fixture_compiler_available(FixtureCompiler::ClangDwarf5) {
        eprintln!("Skipping fixture coexistence regression test because clang is unavailable");
        return Ok(());
    }

    let fixtures = [
        ("inline_callsite_program", "-Wall -Wextra -gdwarf-5 -O3"),
        ("static_scope_program", "-Wall -Wextra -gdwarf-5 -O0"),
    ];

    for (fixture_name, clang_dwarf5_cflags) in fixtures {
        clean_fixture_outputs(fixture_name)?;

        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture_name);
        let default_binary = base.join(FixtureCompiler::Default.binary_name(fixture_name));
        let clang_binary = base.join(FixtureCompiler::ClangDwarf5.binary_name(fixture_name));

        common::compile_c_make_fixture(
            fixture_name,
            FixtureCompiler::Default,
            clang_dwarf5_cflags,
        )?;
        assert!(
            default_binary.exists(),
            "default binary should exist after default build for {fixture_name}"
        );

        common::compile_c_make_fixture(
            fixture_name,
            FixtureCompiler::ClangDwarf5,
            clang_dwarf5_cflags,
        )?;
        assert!(
            default_binary.exists(),
            "default binary should survive clang build for {fixture_name}"
        );
        assert!(
            clang_binary.exists(),
            "clang binary should exist after clang build for {fixture_name}"
        );

        clean_fixture_outputs(fixture_name)?;
    }

    Ok(())
}

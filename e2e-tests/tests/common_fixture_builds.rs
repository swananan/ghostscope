mod common;

use common::{init, FixtureCompiler, OptimizationLevel};
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

    let fixtures = [
        (
            "inline_callsite_program",
            FixtureCompiler::ClangDwarf5,
            "-Wall -Wextra -gdwarf-5 -O3",
        ),
        (
            "static_scope_program",
            FixtureCompiler::ClangDwarf5,
            "-Wall -Wextra -gdwarf-5 -O0",
        ),
        (
            "entry_value_recovery_program",
            FixtureCompiler::ClangDwarf5,
            "-Wall -Wextra -gdwarf-5 -O3",
        ),
        (
            "partitioned_ranges_program",
            FixtureCompiler::GccDwarf5FunctionSections,
            "-Wall -Wextra -gdwarf-5 -O3 -DNDEBUG -ffunction-sections -freorder-blocks-and-partition",
        ),
        (
            "partitioned_ranges_program",
            FixtureCompiler::ClangDwarf5Rnglistx,
            "-Wall -Wextra -gdwarf-5 -O3 -DNDEBUG -ffunction-sections -fbasic-block-sections=all",
        ),
    ];

    for (fixture_name, compiler, compiler_cflags) in fixtures {
        if !common::fixture_compiler_available(compiler) {
            eprintln!(
                "Skipping fixture coexistence regression for {fixture_name} because {compiler:?} is unavailable"
            );
            continue;
        }

        clean_fixture_outputs(fixture_name)?;

        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(fixture_name);
        let default_binary = base.join(FixtureCompiler::Default.binary_name(fixture_name));
        let compiler_binary = base.join(compiler.binary_name(fixture_name));

        common::compile_c_make_fixture(fixture_name, FixtureCompiler::Default, compiler_cflags)?;
        assert!(
            default_binary.exists(),
            "default binary should exist after default build for {fixture_name}"
        );

        common::compile_c_make_fixture(fixture_name, compiler, compiler_cflags)?;
        assert!(
            default_binary.exists(),
            "default binary should survive compiler-specific build for {fixture_name}"
        );
        assert!(
            compiler_binary.exists(),
            "compiler-specific binary should exist after build for {fixture_name}"
        );

        clean_fixture_outputs(fixture_name)?;
    }

    Ok(())
}

#[test]
fn sample_program_optimized_build_compiles_all_variants() -> anyhow::Result<()> {
    init();

    clean_fixture_outputs("sample_program")?;

    common::ensure_test_program_compiled_with_opt(OptimizationLevel::O2)?;

    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join("sample_program");
    for binary_name in [
        "sample_program_o1",
        "sample_program_o2",
        "sample_program_o3",
    ] {
        assert!(
            base.join(binary_name).exists(),
            "{binary_name} should exist after compiling optimized sample variants"
        );
    }

    clean_fixture_outputs("sample_program")?;
    Ok(())
}

#[test]
fn complex_program_optimized_build_compiles_all_variants() -> anyhow::Result<()> {
    init();

    clean_fixture_outputs("complex_types_program")?;

    common::TestFixtures::new()
        .get_test_binary_with_opt("complex_types_program", OptimizationLevel::O2)?;

    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join("complex_types_program");
    for binary_name in [
        "complex_types_program_o1",
        "complex_types_program_o2",
        "complex_types_program_o3",
    ] {
        assert!(
            base.join(binary_name).exists(),
            "{binary_name} should exist after compiling optimized complex variants"
        );
    }

    clean_fixture_outputs("complex_types_program")?;
    Ok(())
}

#[test]
fn globals_program_optimized_build_compiles_all_variants() -> anyhow::Result<()> {
    init();

    clean_fixture_outputs("globals_program")?;

    common::TestFixtures::new()
        .get_test_binary_with_opt("globals_program", OptimizationLevel::O2)?;

    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join("globals_program");
    for binary_name in [
        "globals_program_o1",
        "globals_program_o2",
        "globals_program_o3",
        "libgvars.so",
    ] {
        assert!(
            base.join(binary_name).exists(),
            "{binary_name} should exist after compiling optimized globals variants"
        );
    }

    clean_fixture_outputs("globals_program")?;
    Ok(())
}

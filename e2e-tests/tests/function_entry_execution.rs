mod common;

use common::{fixture_compiler_available, init, FixtureCompiler, FIXTURES};
use object::{Object, ObjectSymbol};
use regex::Regex;
use std::collections::BTreeSet;
use std::path::Path;

async fn assert_both_branches_and_parameters(binary_path: &Path) -> anyhow::Result<()> {
    let target = common::targets::TargetLauncher::binary(binary_path)
        .spawn()
        .await?;
    let result = common::runner::GhostscopeRunner::new()
        .with_script(
            r#"
trace register_branch { print "REGISTER:{}:{}", x, y; }
trace loclist_branch { print "LOCLIST:{}:{}", x, y; }
trace stack_branch { print "STACK:{}:{}", x, y; }
trace aggregate_branch { print "AGGREGATE:{}:{}:{}", value.x, value.y, value.z; }
"#,
        )
        .attach_to(&target)
        .timeout_secs(4)
        .enable_sysmon_for_target(false)
        .run()
        .await;
    target.terminate().await?;
    let (exit_code, stdout, stderr) = result?;
    assert_eq!(exit_code, 0, "stderr={stderr}\nstdout={stdout}");

    for marker in ["REGISTER", "LOCLIST", "STACK", "AGGREGATE"] {
        let re = Regex::new(&format!(r"{marker}:(-?\d+):(-?\d+)"))?;
        let samples: BTreeSet<(i32, i32)> = re
            .captures_iter(&stdout)
            .map(|caps| Ok((caps[1].parse()?, caps[2].parse()?)))
            .collect::<anyhow::Result<_>>()?;
        assert_eq!(
            samples,
            BTreeSet::from([(-7, 31), (7, 31)]),
            "{marker} must trace both branches with entry parameter values. \
             samples={samples:?}\nstderr={stderr}"
        );
    }
    let re = Regex::new(r"AGGREGATE:-?7:31:(\d+)")?;
    let tail: BTreeSet<i32> = re
        .captures_iter(&stdout)
        .map(|caps| caps[1].parse())
        .collect::<Result<_, _>>()?;
    assert_eq!(tail, BTreeSet::from([99]), "stdout={stdout}");
    Ok(())
}

async fn assert_probe_addresses(
    binary: &Path,
    skip_prologue: bool,
    stack_entry: bool,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(binary)?;
    let obj = object::File::parse(bytes.as_slice())?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(binary).await?;
    let mut names = vec!["register_branch", "loclist_branch"];
    if stack_entry {
        names.push("stack_branch");
        names.push("aggregate_branch");
    }
    for name in names {
        let symbol = obj.symbols().find(|s| s.name().ok() == Some(name)).unwrap();
        let addresses = analyzer.lookup_function_addresses(name);
        assert_eq!(addresses.len(), 1, "{name}: {addresses:?}");
        let address = addresses[0].address;
        if skip_prologue {
            assert!(
                address > symbol.address() && address < symbol.address() + symbol.size(),
                "{name} must wait for -O0 parameter spills: {address:#x}"
            );
        } else {
            assert_eq!(
                address,
                symbol.address(),
                "{name} must use its actual entry"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_function_entry_gcc_o2_captures_both_branches() -> anyhow::Result<()> {
    init();
    let binary = FIXTURES
        .get_test_binary_with_opt("function_entry_program", common::OptimizationLevel::O2)?;
    assert_probe_addresses(&binary, false, true).await?;
    assert_both_branches_and_parameters(&binary).await
}

#[tokio::test]
async fn test_function_entry_gcc_o0_preserves_spilled_parameters() -> anyhow::Result<()> {
    init();
    let binary = FIXTURES.get_test_binary("function_entry_program")?;
    assert_probe_addresses(&binary, true, false).await?;
    assert_both_branches_and_parameters(&binary).await
}

async fn assert_fixed_spill_parameters(binary: &Path, name: &str) -> anyhow::Result<()> {
    let bytes = std::fs::read(binary)?;
    let object = object::File::parse(bytes.as_slice())?;
    let symbol = object
        .symbols()
        .find(|s| s.name().ok() == Some(name))
        .unwrap();
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(binary).await?;
    let addresses = analyzer.lookup_function_addresses(name);
    assert_eq!(addresses.len(), 1, "{name}: {addresses:?}");
    assert!(
        addresses[0].address > symbol.address()
            && addresses[0].address < symbol.address() + symbol.size(),
        "{name} must wait for callee-frame stores: {addresses:?}"
    );

    let target = common::targets::TargetLauncher::binary(binary)
        .spawn()
        .await?;
    let result = common::runner::GhostscopeRunner::new()
        .with_script(&format!(
            "trace {name} {{ print \"SPILL:{{}}:{{}}\", x, y; }}"
        ))
        .attach_to(&target)
        .timeout_secs(4)
        .enable_sysmon_for_target(false)
        .run()
        .await;
    target.terminate().await?;
    let (exit_code, stdout, stderr) = result?;
    assert_eq!(exit_code, 0, "stderr={stderr}\nstdout={stdout}");
    let regex = Regex::new(r"SPILL:(-?\d+):(-?\d+)")?;
    let samples: BTreeSet<(i32, i32)> = regex
        .captures_iter(&stdout)
        .map(|caps| Ok((caps[1].parse()?, caps[2].parse()?)))
        .collect::<anyhow::Result<_>>()?;
    assert_eq!(
        samples,
        BTreeSet::from([(-7, 31), (7, 31)]),
        "{name}: samples={samples:?}\nstdout={stdout}\nstderr={stderr}"
    );
    Ok(())
}

#[tokio::test]
async fn test_function_entry_gcc_o0_realigned_parameters() -> anyhow::Result<()> {
    init();
    let binary = FIXTURES.get_test_binary("function_entry_program")?;
    assert_fixed_spill_parameters(&binary, "realigned_spill").await
}

#[tokio::test]
async fn test_function_entry_gcc_o0_ms_abi_home_slots() -> anyhow::Result<()> {
    init();
    let binary = FIXTURES.get_test_binary("function_entry_program")?;
    assert_fixed_spill_parameters(&binary, "home_slot_spill").await
}

#[tokio::test]
async fn test_function_entry_gcc_o0_spills_without_frame_pointer() -> anyhow::Result<()> {
    init();
    let binary = FIXTURES
        .get_test_binary("function_entry_program")?
        .with_file_name("function_entry_program_omit_fp");
    assert_fixed_spill_parameters(&binary, "realigned_spill").await?;
    assert_fixed_spill_parameters(&binary, "home_slot_spill").await
}

#[tokio::test]
async fn test_function_entry_clang_preserves_parameters_at_o0_and_o2() -> anyhow::Result<()> {
    init();
    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5) {
        eprintln!("Skipping clang function entry regression: clang is unavailable");
        return Ok(());
    }
    let binary = FIXTURES
        .get_test_binary_with_compiler("function_entry_program", FixtureCompiler::ClangDwarf5)?;
    assert_probe_addresses(&binary, true, false).await?;
    assert_both_branches_and_parameters(&binary).await?;
    let optimized = binary.with_file_name(format!(
        "{}_o2",
        binary.file_name().unwrap().to_string_lossy()
    ));
    assert_probe_addresses(&optimized, false, false).await?;
    assert_both_branches_and_parameters(&optimized).await
}

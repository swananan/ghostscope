//! Runtime coverage for native Rust backtraces.

mod common;

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use common::{
    init,
    rust_toolchain::{
        compile_standalone_fixture, compile_standalone_fixture_with_codegen_options,
        fixture_tempdir, rustc_for_toolchain,
    },
};
use serial_test::serial;

const TOOLCHAIN: &str = "1.88.0";
const REQUIRE_TOOLCHAIN_ENV: &str = "GHOSTSCOPE_REQUIRE_RUST_188_E2E";
const BACKTRACE_DEPTH: u8 = 10;
const INLINE_TRACE_MARKER: &str = "INLINE_BACKTRACE_TRACE_POINT";

#[derive(Clone, Copy)]
enum BuildProfile {
    DebugLegacy,
    OptimizedV0,
}

fn fixture_source_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rust_backtrace_program/main.rs")
}

fn inline_trace_line() -> anyhow::Result<u32> {
    let source = std::fs::read_to_string(fixture_source_path())?;
    let line = source
        .lines()
        .position(|line| line.contains(INLINE_TRACE_MARKER))
        .ok_or_else(|| anyhow::anyhow!("missing inline trace marker {INLINE_TRACE_MARKER:?}"))?
        + 1;
    Ok(u32::try_from(line)?)
}

fn compile_fixture(
    rustc: &Path,
    output_dir: &Path,
    profile: BuildProfile,
) -> anyhow::Result<PathBuf> {
    let source = fixture_source_path();
    let binary = match profile {
        BuildProfile::DebugLegacy => output_dir.join("rust_backtrace_program"),
        BuildProfile::OptimizedV0 => output_dir.join("rust_backtrace_program_optimized_v0"),
    };
    match profile {
        BuildProfile::DebugLegacy => {
            compile_standalone_fixture(rustc, TOOLCHAIN, &source, &binary)?;
        }
        BuildProfile::OptimizedV0 => compile_standalone_fixture_with_codegen_options(
            rustc,
            TOOLCHAIN,
            &source,
            &binary,
            &["opt-level=3", "symbol-mangling-version=v0"],
        )?,
    }
    Ok(binary)
}

fn first_backtrace_block_after<'a>(stdout: &'a str, marker: &str) -> anyhow::Result<&'a str> {
    let marker_pos = stdout
        .find(marker)
        .ok_or_else(|| anyhow::anyhow!("missing marker {marker:?}\nSTDOUT: {stdout}"))?;
    let after_marker = &stdout[marker_pos..];
    let header_pos = after_marker
        .find("backtrace:")
        .ok_or_else(|| anyhow::anyhow!("missing backtrace after {marker:?}\nSTDOUT: {stdout}"))?;
    let block = &after_marker[header_pos..];
    let end = block.find("\n[").unwrap_or(block.len());
    Ok(&block[..end])
}

fn backtrace_blocks_after(stdout: &str, marker: &str) -> anyhow::Result<Vec<String>> {
    let marker_pos = stdout
        .find(marker)
        .ok_or_else(|| anyhow::anyhow!("missing marker {marker:?}\nSTDOUT: {stdout}"))?;
    let mut blocks = Vec::new();
    let mut current: Option<String> = None;

    for line in stdout[marker_pos..].lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("backtrace:") {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            current = Some(format!("{trimmed}\n"));
            continue;
        }
        if line.starts_with('[') {
            if let Some(block) = current.take() {
                blocks.push(block);
            }
            continue;
        }
        if let Some(block) = current.as_mut() {
            block.push_str(trimmed);
            block.push('\n');
        }
    }
    if let Some(block) = current {
        blocks.push(block);
    }

    anyhow::ensure!(
        !blocks.is_empty(),
        "missing backtrace block after marker {marker:?}\nSTDOUT: {stdout}"
    );
    for block in &blocks {
        anyhow::ensure!(
            block.contains(&format!("(max {BACKTRACE_DEPTH})")),
            "backtrace block has wrong configured depth\nBLOCK:\n{block}"
        );
    }
    Ok(blocks)
}

fn assert_ordered_patterns(block: &str, patterns: &[&str]) -> anyhow::Result<()> {
    let mut cursor = 0usize;
    for pattern in patterns {
        let Some(relative) = block[cursor..].find(pattern) else {
            anyhow::bail!("missing ordered pattern {pattern:?}\nBLOCK:\n{block}");
        };
        cursor += relative + pattern.len();
    }
    Ok(())
}

async fn run_rust_backtrace_case(profile: BuildProfile) -> anyhow::Result<()> {
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
    let binary = compile_fixture(&rustc, temp_dir.path(), profile)?;
    let target = common::targets::TargetLauncher::binary(&binary)
        .current_dir(temp_dir.path())
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(750)).await;

    let backtrace_statement = match profile {
        BuildProfile::DebugLegacy => "bt;",
        BuildProfile::OptimizedV0 => "bt full;",
    };
    let script = format!(
        r#"
trace rust_backtrace_probe {{
    print "RUST_BACKTRACE";
    {backtrace_statement}
}}
"#
    );
    let result = common::runner::GhostscopeRunner::new()
        .with_script(&script)
        .attach_to(&target)
        .timeout_secs(6)
        .enable_sysmon_for_target(false)
        .with_cli_args(vec![
            OsString::from("--script-output-events-per-sec"),
            OsString::from("2"),
            OsString::from("--backtrace-depth"),
            OsString::from(BACKTRACE_DEPTH.to_string()),
        ])
        .run()
        .await;

    target.terminate().await?;
    let (exit_code, stdout, stderr) = result?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let block = first_backtrace_block_after(&stdout, "RUST_BACKTRACE")?;
    assert!(
        block.contains(&format!("(max {BACKTRACE_DEPTH})")),
        "backtrace block has wrong configured depth\nBLOCK:\n{block}"
    );
    assert_ordered_patterns(
        block,
        &[
            "#0 rust_backtrace_probe",
            "#1 rust_backtrace_program",
            "rust_backtrace_middle",
            "#2 rust_backtrace_program",
            "rust_backtrace_outer",
            "#3 rust_backtrace_program",
            "::main",
        ],
    )?;
    if matches!(profile, BuildProfile::DebugLegacy) {
        // Keep the unoptimized profile as an explicit contract for physical
        // frames from core and std. Optimized builds may inline these frames.
        assert_ordered_patterns(
            block,
            &[
                "#4 core::ops::function::FnOnce::call_once",
                "#5 std::sys::backtrace::__rust_begin_short_backtrace",
                "#6 std::rt::lang_start::{{closure}}",
                "#7 std::rt::lang_start_internal",
                "#8 std::rt::lang_start",
            ],
        )?;
        assert!(
            !block.contains("::h"),
            "default bt should hide Rust symbol hashes\nBLOCK:\n{block}"
        );
    } else {
        assert!(
            block.contains("rust_backtrace_program["),
            "bt full should retain Rust v0 crate disambiguators\nBLOCK:\n{block}"
        );
    }
    assert!(
        !block.contains("_ZN") && !block.contains(" _R"),
        "Rust physical frames should be demangled\nBLOCK:\n{block}"
    );

    Ok(())
}

async fn run_rust_inline_backtrace_display_case() -> anyhow::Result<()> {
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
    let binary = compile_fixture(&rustc, temp_dir.path(), BuildProfile::OptimizedV0)?;
    let trace_line = inline_trace_line()?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary).await?;
    let inline_address = analyzer
        .lookup_addresses_by_source_line("main.rs", trace_line)
        .into_iter()
        .find(|address| {
            analyzer.resolve_pc(address).ok().is_some_and(|context| {
                context
                    .inline_chain
                    .iter()
                    .any(|frame| frame.function_name.as_deref() == Some("rust_backtrace_inline"))
            })
        })
        .ok_or_else(|| {
            anyhow::anyhow!("missing rust_backtrace_inline context for main.rs:{trace_line}")
        })?;

    let concise_context = analyzer.resolve_pc_for_display(&inline_address, false)?;
    let concise_inline_name = concise_context
        .inline_chain
        .iter()
        .find_map(|frame| {
            frame
                .function_name
                .as_deref()
                .filter(|name| name.ends_with("::rust_backtrace_inline"))
        })
        .ok_or_else(|| anyhow::anyhow!("missing concise Rust inline name: {concise_context:?}"))?;
    assert_eq!(
        concise_inline_name, "rust_backtrace_program::rust_backtrace_inline",
        "concise inline name should hide the v0 crate disambiguator"
    );

    let full_context = analyzer.resolve_pc_for_display(&inline_address, true)?;
    let full_inline_name = full_context
        .inline_chain
        .iter()
        .find_map(|frame| {
            frame
                .function_name
                .as_deref()
                .filter(|name| name.ends_with("::rust_backtrace_inline"))
        })
        .ok_or_else(|| anyhow::anyhow!("missing full Rust inline name: {full_context:?}"))?;
    assert!(
        full_inline_name.starts_with("rust_backtrace_program["),
        "full inline name should retain the v0 crate disambiguator: {full_inline_name}"
    );

    let target = common::targets::TargetLauncher::binary(&binary)
        .current_dir(temp_dir.path())
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(750)).await;

    let source = fixture_source_path();
    let script = format!(
        r#"
trace {}:{trace_line} {{
    print "RUST_INLINE_BACKTRACE";
    bt;
    bt full;
}}
"#,
        source.display()
    );
    let result = common::runner::GhostscopeRunner::new()
        .with_script(&script)
        .attach_to(&target)
        .timeout_secs(6)
        .enable_sysmon_for_target(false)
        .with_cli_args(vec![
            OsString::from("--script-output-events-per-sec"),
            OsString::from("2"),
            OsString::from("--backtrace-depth"),
            OsString::from(BACKTRACE_DEPTH.to_string()),
        ])
        .run()
        .await;

    target.terminate().await?;
    let (exit_code, stdout, stderr) = result?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let blocks = backtrace_blocks_after(&stdout, "RUST_INLINE_BACKTRACE")?;
    anyhow::ensure!(
        blocks.len() >= 2,
        "expected concise and full inline backtraces\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    let concise_inline = blocks[0]
        .lines()
        .find(|line| line.contains("#0.inline") && line.contains("rust_backtrace_inline"))
        .ok_or_else(|| anyhow::anyhow!("missing concise inline frame\nBLOCK:\n{}", blocks[0]))?;
    assert!(
        !concise_inline.contains("rust_backtrace_program[") && !concise_inline.contains("::h"),
        "default bt should hide inline Rust disambiguators\nLINE:\n{concise_inline}"
    );

    let full_inline = blocks[1]
        .lines()
        .find(|line| line.contains("#0.inline") && line.contains("rust_backtrace_inline"))
        .ok_or_else(|| anyhow::anyhow!("missing full inline frame\nBLOCK:\n{}", blocks[1]))?;
    assert!(
        full_inline.contains("rust_backtrace_program[")
            && full_inline.contains("::rust_backtrace_inline"),
        "bt full should retain inline Rust disambiguators\nLINE:\n{full_inline}"
    );

    Ok(())
}

// Backtrace programs load verifier-heavy eBPF, so serialize them with the
// existing native backtrace suite.
#[tokio::test]
#[serial(backtrace_execution)]
async fn test_rust_188_backtrace_hides_hashes_in_application_and_std_frames() -> anyhow::Result<()>
{
    run_rust_backtrace_case(BuildProfile::DebugLegacy).await
}

#[tokio::test]
#[serial(backtrace_execution)]
async fn test_rust_188_full_v0_backtrace_unwinds_with_disambiguators() -> anyhow::Result<()> {
    run_rust_backtrace_case(BuildProfile::OptimizedV0).await
}

#[tokio::test]
#[serial(backtrace_execution)]
async fn test_rust_188_inline_frames_follow_concise_and_full_display_modes() -> anyhow::Result<()> {
    run_rust_inline_backtrace_display_case().await
}

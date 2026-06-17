//! Backtrace execution and performance regression tests.

mod common;

use common::{init, targets::TargetHandle, FIXTURES};
use ghostscope_dwarf::{CfaRulePlan, ModuleAddress, RegisterRecoveryPlan};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

async fn spawn_backtrace_fixture_program(
    binary_path: &Path,
) -> anyhow::Result<common::targets::TargetHandle> {
    let bin_dir = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("backtrace fixture has no parent directory"))?;
    let target = common::targets::TargetLauncher::binary(binary_path)
        .current_dir(bin_dir)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(250)).await;
    Ok(target)
}

async fn run_hot_backtrace_with_depth(
    script: &str,
    depth: u8,
) -> anyhow::Result<(usize, String, String)> {
    run_hot_backtrace_with_depth_and_rate(script, depth, 250, 3).await
}

async fn run_hot_backtrace_with_depth_and_rate(
    script: &str,
    depth: u8,
    output_events_per_sec: u32,
    timeout_secs: u64,
) -> anyhow::Result<(usize, String, String)> {
    run_backtrace_fixture_with_depth_and_rate(
        "backtrace_hot_program",
        script,
        depth,
        output_events_per_sec,
        timeout_secs,
    )
    .await
}

async fn run_backtrace_fixture_with_depth_and_rate(
    fixture: &str,
    script: &str,
    depth: u8,
    output_events_per_sec: u32,
    timeout_secs: u64,
) -> anyhow::Result<(usize, String, String)> {
    let depth_arg = depth.to_string();
    run_backtrace_fixture_with_args(
        fixture,
        script,
        output_events_per_sec,
        timeout_secs,
        vec![
            OsString::from("--backtrace-depth"),
            OsString::from(depth_arg),
        ],
        None,
    )
    .await
}

async fn run_backtrace_fixture_with_args(
    fixture: &str,
    script: &str,
    output_events_per_sec: u32,
    timeout_secs: u64,
    extra_args: Vec<OsString>,
    config_content: Option<&str>,
) -> anyhow::Result<(usize, String, String)> {
    let binary_path = FIXTURES.get_test_binary(fixture)?;
    run_backtrace_binary_with_args(
        &binary_path,
        script,
        output_events_per_sec,
        timeout_secs,
        extra_args,
        config_content,
    )
    .await
}

async fn run_backtrace_binary_with_args(
    binary_path: &Path,
    script: &str,
    output_events_per_sec: u32,
    timeout_secs: u64,
    extra_args: Vec<OsString>,
    config_content: Option<&str>,
) -> anyhow::Result<(usize, String, String)> {
    let target = spawn_backtrace_fixture_program(binary_path).await?;
    let rate_arg = output_events_per_sec.to_string();

    let mut cli_args = vec![
        OsString::from("--script-output-events-per-sec"),
        OsString::from(rate_arg),
    ];
    cli_args.extend(extra_args);

    let mut runner = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .attach_to(&target)
        .timeout_secs(timeout_secs)
        .enable_sysmon_for_target(false)
        .with_cli_args(cli_args);
    if let Some(config_content) = config_content {
        runner = runner.with_config_content(config_content);
    }

    let result = runner.run().await;

    target.terminate().await?;
    let (exit_code, stdout, stderr) = result?;
    if exit_code != 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok((0, stdout, stderr));
    }
    anyhow::ensure!(exit_code == 0, "stderr={stderr} stdout={stdout}");
    let count = stdout.matches("backtrace: ").count();
    Ok((count, stdout, stderr))
}

async fn run_backtrace_target_mode_library_with_depth(
    binary_path: &Path,
    target_path: &Path,
    script: &str,
    depth: u8,
    output_events_per_sec: u32,
    timeout_secs: u64,
) -> anyhow::Result<(usize, String, String)> {
    let target = spawn_backtrace_fixture_program(binary_path).await?;
    let rate_arg = output_events_per_sec.to_string();
    let depth_arg = depth.to_string();

    let result = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .with_target(target_path)
        .timeout_secs(timeout_secs)
        .with_cli_args([
            OsString::from("--script-output-events-per-sec"),
            OsString::from(rate_arg),
            OsString::from("--backtrace-depth"),
            OsString::from(depth_arg),
        ])
        .run()
        .await;

    target.terminate().await?;
    let (exit_code, stdout, stderr) = result?;
    if exit_code != 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok((0, stdout, stderr));
    }
    anyhow::ensure!(exit_code == 0, "stderr={stderr} stdout={stdout}");
    let count = stdout.matches("backtrace: ").count();
    Ok((count, stdout, stderr))
}

fn get_backtrace_hot_nopie_binary() -> anyhow::Result<std::path::PathBuf> {
    let program_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/backtrace_hot_program");
    let binary_path = program_dir.join("backtrace_hot_program_nopie");
    if binary_path.exists() {
        return Ok(binary_path);
    }

    let output = Command::new("make")
        .arg("backtrace_hot_program_nopie")
        .current_dir(&program_dir)
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "failed to build backtrace_hot_program_nopie\nSTDOUT: {}\nSTDERR: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(binary_path)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'"'"'"#))
}

async fn spawn_backtrace_dlopen_program() -> anyhow::Result<(TargetHandle, PathBuf)> {
    let binary_path = FIXTURES.get_test_binary("backtrace_dlopen_program")?;
    let bin_dir = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("backtrace_dlopen_program has no parent directory"))?;
    let trigger_path = bin_dir.join("dlopen.trigger");
    let _ = fs::remove_file(&trigger_path);
    let target = common::targets::TargetLauncher::binary(&binary_path)
        .current_dir(bin_dir)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(250)).await;
    Ok((target, trigger_path))
}

fn touch_dlopen_trigger_in_target_sandbox(
    target: &TargetHandle,
    trigger_path: &Path,
) -> anyhow::Result<()> {
    let sandbox_path = target.sandbox().path_in_sandbox(trigger_path)?;
    let command = format!(": > {}", shell_quote(&sandbox_path.display().to_string()));
    let output = target.sandbox().run_shell(&command)?;
    anyhow::ensure!(
        output.status.success(),
        "failed to create dlopen trigger in target sandbox\nSTDOUT: {}\nSTDERR: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn skip_if_nested_t_mode_unsupported() -> bool {
    let target_mode = match env::var("E2E_TARGET_MODE") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return false,
        Err(err) => {
            eprintln!("continuing nested -t test despite unreadable E2E_TARGET_MODE: {err}");
            return false;
        }
    };
    let nested_child_container = matches!(
        target_mode.trim().to_ascii_lowercase().as_str(),
        "child-container" | "child" | "nested" | "descendant"
    );
    if nested_child_container {
        eprintln!(
            "skipping nested child-container -t backtrace test: nested target-path mode is \
             currently unsupported"
        );
    }
    nested_child_container
}

async fn run_hot_backtrace(script: &str) -> anyhow::Result<(usize, String, String)> {
    run_hot_backtrace_with_depth(script, 5).await
}

async fn run_inline_callsite_backtrace(
    script: &str,
    depth: u8,
) -> anyhow::Result<(usize, String, String)> {
    let binary_path = FIXTURES.get_test_binary("inline_callsite_program")?;
    let depth_arg = depth.to_string();
    run_backtrace_binary_with_args(
        &binary_path,
        script,
        50,
        4,
        vec![
            OsString::from("--backtrace-depth"),
            OsString::from(depth_arg),
        ],
        None,
    )
    .await
}

fn first_backtrace_block_after<'a>(
    stdout: &'a str,
    marker: &str,
    depth: u8,
) -> anyhow::Result<&'a str> {
    let marker_pos = stdout
        .find(marker)
        .ok_or_else(|| anyhow::anyhow!("missing marker {marker:?}\nSTDOUT: {stdout}"))?;
    let after_marker = &stdout[marker_pos..];
    let header = "backtrace:";
    let header_pos = after_marker
        .find(header)
        .ok_or_else(|| anyhow::anyhow!("missing backtrace header {header:?}\nSTDOUT: {stdout}"))?;
    let block = &after_marker[header_pos..];
    let end = block.find("\n[").unwrap_or(block.len());
    let block = &block[..end];
    anyhow::ensure!(
        block.contains(&format!("(max {depth})")),
        "backtrace block has wrong depth, expected max {depth}\nBLOCK:\n{block}"
    );
    Ok(block)
}

fn backtrace_blocks_after(stdout: &str, marker: &str, depth: u8) -> anyhow::Result<Vec<String>> {
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
            block.contains(&format!("(max {depth})")),
            "backtrace block has wrong depth, expected max {depth}\nBLOCK:\n{block}"
        );
    }
    Ok(blocks)
}

fn matching_backtrace_block_with_ordered_patterns_after(
    stdout: &str,
    stderr: &str,
    marker: &str,
    depth: u8,
    description: &str,
    patterns: &[&str],
) -> anyhow::Result<String> {
    let chunks = event_chunks_with_marker(stdout, marker);
    anyhow::ensure!(
        !chunks.is_empty(),
        "missing marker {marker:?}\nSTDOUT: {stdout}"
    );
    let mut blocks = Vec::new();
    for chunk in chunks {
        blocks.extend(backtrace_blocks_after(chunk, marker, depth)?);
    }
    blocks
        .into_iter()
        .find(|block| assert_ordered_patterns(block, patterns).is_ok())
        .ok_or_else(|| {
            anyhow::anyhow!("expected {description}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}")
        })
}

fn event_chunks_with_marker<'a>(stdout: &'a str, marker: &str) -> Vec<&'a str> {
    stdout
        .split("\n[")
        .filter(|chunk| chunk.contains(marker))
        .collect()
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

fn assert_no_adjacent_duplicate_frame_locations(block: &str) -> anyhow::Result<()> {
    let mut previous: Option<(String, String)> = None;
    for line in block.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('#') {
            continue;
        }
        let frame_id = trimmed.split_whitespace().next().unwrap_or(trimmed);
        let location = match trimmed.rsplit_once('[') {
            Some((_, location)) if location.ends_with(']') => location.trim_end_matches(']'),
            _ => continue,
        };
        let current = (trimmed.to_string(), location.to_string());
        if let Some((previous_line, previous_location)) = previous.as_ref() {
            anyhow::ensure!(
                previous_location != location,
                "adjacent backtrace frames repeated the same module offset at {frame_id}\nPREVIOUS: {previous_line}\nCURRENT: {trimmed}\nBLOCK:\n{block}"
            );
        }
        previous = Some(current);
    }

    Ok(())
}

#[tokio::test]
async fn test_hot_backtrace_compact_unwind_rows_cover_call_sites() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("backtrace_hot_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let leaf = analyzer
        .lookup_function_address_by_name("hot_bt_leaf")
        .ok_or_else(|| anyhow::anyhow!("missing hot_bt_leaf function"))?;
    let lookup_pc = leaf.address + 0x19;
    let ctx = analyzer.resolve_pc(&ModuleAddress::new(leaf.module_path, lookup_pc))?;
    let row = analyzer
        .compact_unwind_row_for_context(&ctx)?
        .ok_or_else(|| anyhow::anyhow!("missing compact unwind row for hot_bt_leaf+0x19"))?;
    assert!(
        row.pc_start <= lookup_pc && lookup_pc < row.pc_end,
        "row should cover hot_bt_leaf call-site PC 0x{lookup_pc:x}: {row:?}"
    );
    assert!(
        matches!(
            row.cfa,
            CfaRulePlan::RegPlusOffset {
                register: 7,
                offset: 32
            }
        ),
        "hot_bt_leaf call-site CFA should be rsp+32: {row:?}"
    );
    assert!(
        matches!(
            row.return_address,
            RegisterRecoveryPlan::AtCfaOffset { offset: -8 }
        ),
        "hot_bt_leaf return address should be at CFA-8: {row:?}"
    );

    let dummy = analyzer
        .lookup_function_address_by_name("dummy_touch")
        .ok_or_else(|| anyhow::anyhow!("missing dummy_touch function"))?;
    let dummy_probe_pc = dummy.address + 0x10;
    let ctx = analyzer.resolve_pc(&ModuleAddress::new(dummy.module_path, dummy_probe_pc))?;
    let row = analyzer
        .compact_unwind_row_for_context(&ctx)?
        .ok_or_else(|| anyhow::anyhow!("missing compact unwind row for dummy_touch+0x10"))?;
    assert!(
        matches!(
            row.cfa,
            CfaRulePlan::RegPlusOffset {
                register: 7,
                offset: 240
            }
        ),
        "dummy_touch probe-site CFA should be rsp+240: {row:?}"
    );
    assert!(
        matches!(
            row.return_address,
            RegisterRecoveryPlan::AtCfaOffset { offset: -8 }
        ),
        "dummy_touch return address should be at CFA-8: {row:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_special_stack_and_program_counter_registers_are_printable() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("backtrace_hot_program")?;
    let target = spawn_backtrace_fixture_program(&binary_path).await?;
    let script = r#"
trace hot_bt_probe {
    print "SPECIAL_SP={:p}", cast($sp, "unsigned char *");
    print "SPECIAL_PC={:p}", cast($pc, "unsigned char *");
}
"#;

    let result = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .attach_to(&target)
        .timeout_secs(3)
        .enable_sysmon_for_target(false)
        .run()
        .await;

    target.terminate().await?;
    let (exit_code, stdout, stderr) = result?;
    if exit_code != 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout.contains("SPECIAL_SP=0x"),
        "expected printable stack pointer value\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        stdout.contains("SPECIAL_PC=0x"),
        "expected printable program counter value\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn test_hot_backtrace_full_unwinds_complete_user_stack() -> anyhow::Result<()> {
    init();

    let script = r#"
trace dummy_touch {
    print "HOT_STACK";
    bt full;
}
"#;

    let (count, stdout, stderr) = run_hot_backtrace_with_depth(script, 5).await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let block = first_backtrace_block_after(&stdout, "HOT_STACK", 5)?;
    assert!(
        block.contains("backtrace: truncated, 5 frames (max 5)"),
        "expected exactly the full in-binary stack prefix with intentional depth truncation\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert_ordered_patterns(
        block,
        &[
            "#0 dummy_touch",
            "#1 hot_bt_leaf",
            "#2 hot_bt_mid",
            "#3 hot_bt_probe",
            "#4 main",
        ],
    )?;
    assert!(
        !block.contains("stopped: invalid frame")
            && !block.contains("stopped: read error")
            && !block.contains("stopped: unsupported CFI")
            && !block.contains("stopped: no unwind rows for PC"),
        "full user stack should not stop on an unwind error\nBLOCK:\n{block}\nSTDERR:\n{stderr}"
    );
    assert_no_adjacent_duplicate_frame_locations(block)?;

    Ok(())
}

#[tokio::test]
async fn test_hot_backtrace_defaults_to_max_depth_128() -> anyhow::Result<()> {
    init();

    let script = r#"
trace dummy_touch {
    print "HOT_DEFAULT_DEPTH";
    bt full;
}
"#;

    let (count, stdout, stderr) =
        run_backtrace_fixture_with_args("backtrace_hot_program", script, 250, 3, Vec::new(), None)
            .await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let block = first_backtrace_block_after(&stdout, "HOT_DEFAULT_DEPTH", 128)?;
    assert!(
        block.contains("backtrace: complete") || block.contains("backtrace: truncated"),
        "default-depth backtrace should render a normal status\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        block.contains("#4 main"),
        "default depth should not behave like a shallow script-local depth\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn test_hot_backtrace_depth_from_config_file() -> anyhow::Result<()> {
    init();

    let script = r#"
trace dummy_touch {
    print "HOT_CONFIG_DEPTH";
    bt full;
}
"#;

    let (count, stdout, stderr) = run_backtrace_fixture_with_args(
        "backtrace_hot_program",
        script,
        250,
        3,
        Vec::new(),
        Some("[ebpf]\nbacktrace_depth = 4\n"),
    )
    .await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let block = first_backtrace_block_after(&stdout, "HOT_CONFIG_DEPTH", 4)?;
    assert!(
        block.contains("backtrace: truncated, 4 frames (max 4)"),
        "config-file depth should bound bt frames\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert_ordered_patterns(
        block,
        &[
            "#0 dummy_touch",
            "#1 hot_bt_leaf",
            "#2 hot_bt_mid",
            "#3 hot_bt_probe",
        ],
    )?;
    assert!(
        !block.contains("#4 "),
        "config-file depth=4 should not emit a fifth frame\nBLOCK:\n{block}"
    );

    Ok(())
}

#[tokio::test]
async fn test_hot_backtrace_depth_one_stops_after_current_frame() -> anyhow::Result<()> {
    init();

    let script = r#"
trace dummy_touch {
    print "HOT_DEPTH_ONE";
    bt full;
}
"#;

    let (count, stdout, stderr) = run_hot_backtrace_with_depth(script, 1).await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let block = first_backtrace_block_after(&stdout, "HOT_DEPTH_ONE", 1)?;
    assert!(
        block.contains("backtrace: truncated, 1 frame (max 1)"),
        "depth=1 should render exactly one truncated frame\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        block.contains("#0 dummy_touch") && !block.contains("#1 "),
        "depth=1 should include only the current frame\nBLOCK:\n{block}"
    );

    Ok(())
}

#[tokio::test]
async fn test_hot_backtrace_non_power_of_two_depth_keeps_frame_slots_ordered() -> anyhow::Result<()>
{
    init();

    let script = r#"
trace dummy_touch {
    print "HOT_DEPTH_SEVEN";
    bt full;
}
"#;

    let (count, stdout, stderr) = run_hot_backtrace_with_depth(script, 7).await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let block = first_backtrace_block_after(&stdout, "HOT_DEPTH_SEVEN", 7)?;
    assert!(
        block.contains("backtrace: truncated, 7 frames (max 7)"),
        "depth=7 should keep the requested non-power-of-two depth\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert_ordered_patterns(
        block,
        &[
            "#0 dummy_touch",
            "#1 hot_bt_leaf",
            "#2 hot_bt_mid",
            "#3 hot_bt_probe",
            "#4 main",
            "#5 ",
            "#6 ",
        ],
    )?;
    assert!(
        !block.contains("#5 0x0") && !block.contains("#6 0x0"),
        "dynamic frame indexes should not collapse non-power-of-two slots to zero frames\nBLOCK:\n{block}"
    );

    Ok(())
}

#[tokio::test]
async fn test_multiple_deep_backtrace_statements_use_tail_calls() -> anyhow::Result<()> {
    init();

    let script = r#"
trace dummy_touch {
    print "HOT_MULTI_DEEP";
    bt full;
    bt raw noinline;
}
"#;

    let (count, stdout, stderr) = run_hot_backtrace_with_depth(script, 128).await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let blocks = backtrace_blocks_after(&stdout, "HOT_MULTI_DEEP", 128)?;
    assert!(
        blocks.len() >= 2,
        "two bt statements should render two backtrace blocks\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    for block in blocks.iter().take(2) {
        assert!(
            block.contains("#5 ") && block.contains("libc.so.6+"),
            "each deep bt statement should unwind past the inline frame limit\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        );
        assert!(
            !block.contains("stopped: invalid frame")
                && !block.contains("stopped: read error")
                && !block.contains("stopped: unsupported CFI")
                && !block.contains("stopped: no unwind rows for PC"),
            "deep multi-bt stack should not stop on an unwind error\nBLOCK:\n{block}\nSTDERR:\n{stderr}"
        );
    }
    assert!(
        blocks[1].contains(" raw=0x") && blocks[1].contains(" cookie=0x"),
        "second raw bt should retain raw debug metadata\nBLOCK:\n{}",
        blocks[1]
    );

    Ok(())
}

#[tokio::test]
async fn test_conditional_tail_call_backtrace_ignores_skipped_slots() -> anyhow::Result<()> {
    init();

    let script = r#"
trace dummy_touch {
    if value % 2 == 0 {
        print "HOT_COND_EVEN";
        bt full;
    }
    if value % 2 != 0 {
        print "HOT_COND_ODD";
        bt raw noinline;
    }
}
"#;

    let (count, stdout, stderr) =
        run_hot_backtrace_with_depth_and_rate(script, 128, 500, 4).await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let even_events = event_chunks_with_marker(&stdout, "HOT_COND_EVEN");
    let odd_events = event_chunks_with_marker(&stdout, "HOT_COND_ODD");
    assert!(
        !even_events.is_empty() && !odd_events.is_empty(),
        "conditional bt test should observe both mutually exclusive branches\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );

    for event in even_events.iter().chain(odd_events.iter()).take(8) {
        let bt_count = event.matches("backtrace:").count();
        assert_eq!(
            bt_count, 1,
            "each event should process only the executed bt slot\nEVENT:\n{event}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        );
        assert!(
            event.contains("#5 ") && event.contains("libc.so.6+"),
            "executed conditional bt should unwind past the inline prefix\nEVENT:\n{event}"
        );
        assert!(
            !event.contains("stopped: invalid frame")
                && !event.contains("stopped: read error")
                && !event.contains("stopped: unsupported CFI")
                && !event.contains("stopped: no unwind rows for PC"),
            "conditional bt should not consume stale slot state\nEVENT:\n{event}"
        );
    }

    assert!(
        even_events.iter().any(|event| !event.contains(" raw=0x")),
        "even branch uses `bt full` and should not require raw metadata\nSTDOUT:\n{stdout}"
    );
    assert!(
        odd_events
            .iter()
            .any(|event| event.contains(" raw=0x") && event.contains(" cookie=0x")),
        "odd branch uses `bt raw noinline` and should include raw metadata\nSTDOUT:\n{stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_default_bt_and_backtrace_alias_render_distinct_modes() -> anyhow::Result<()> {
    init();

    let script = r#"
trace dummy_touch {
    print "HOT_BT_ALIAS";
    bt;
    backtrace raw noinline;
}
"#;

    let (count, stdout, stderr) = run_hot_backtrace_with_depth(script, 5).await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let blocks = backtrace_blocks_after(&stdout, "HOT_BT_ALIAS", 5)?;
    assert!(
        blocks.len() >= 2,
        "`bt;` and `backtrace ...;` should emit separate backtrace blocks\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );

    let default_bt = &blocks[0];
    assert!(
        default_bt.contains("#0 dummy_touch(long unsigned int value)")
            && default_bt.contains("#1 hot_bt_leaf(long unsigned int value)"),
        "default `bt;` should symbolize frames and parameters\nBLOCK:\n{default_bt}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        !default_bt.contains(" raw=0x") && !default_bt.contains(" cookie=0x"),
        "default `bt;` should not expose raw debug metadata\nBLOCK:\n{default_bt}"
    );

    let raw_alias = &blocks[1];
    assert!(
        raw_alias.contains(" raw=0x") && raw_alias.contains(" cookie=0x"),
        "`backtrace raw noinline;` should preserve raw debug metadata\nBLOCK:\n{raw_alias}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        !raw_alias.contains(".inline"),
        "`noinline` should suppress inline pseudo-frames\nBLOCK:\n{raw_alias}"
    );

    Ok(())
}

#[tokio::test]
async fn test_inline_and_noinline_bt_modes_control_inline_frames() -> anyhow::Result<()> {
    init();

    let script = r#"
trace inline_callsite_program.c:43 {
    print "INLINE_BT_MODES";
    bt inline;
    bt noinline;
}
"#;

    let (count, stdout, stderr) = run_inline_callsite_backtrace(script, 5).await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let blocks = backtrace_blocks_after(&stdout, "INLINE_BT_MODES", 5)?;
    assert!(
        blocks.len() >= 2,
        "`bt inline;` and `bt noinline;` should emit separate backtrace blocks\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );

    let inline_bt = &blocks[0];
    assert!(
        inline_bt.contains("#0.inline add3"),
        "`bt inline;` should include the inlined add3 pseudo-frame\nBLOCK:\n{inline_bt}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        inline_bt.contains("#0 "),
        "`bt inline;` should also include the physical frame after inline pseudo-frames\nBLOCK:\n{inline_bt}"
    );

    let noinline_bt = &blocks[1];
    assert!(
        !noinline_bt.contains(".inline"),
        "`bt noinline;` should suppress inline pseudo-frames\nBLOCK:\n{noinline_bt}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        noinline_bt.contains("#0 "),
        "`bt noinline;` should still include the physical current frame\nBLOCK:\n{noinline_bt}"
    );

    Ok(())
}

#[tokio::test]
async fn test_non_pie_pid_backtrace_uses_load_bias_for_runtime_cfi_rows() -> anyhow::Result<()> {
    init();

    let binary_path = get_backtrace_hot_nopie_binary()?;
    let script = r#"
trace dummy_touch {
    print "HOT_NOPIE";
    bt full;
}
"#;
    let depth_arg = OsString::from("7");
    let (count, stdout, stderr) = run_backtrace_binary_with_args(
        &binary_path,
        script,
        250,
        3,
        vec![OsString::from("--backtrace-depth"), depth_arg],
        None,
    )
    .await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let block = first_backtrace_block_after(&stdout, "HOT_NOPIE", 7)?;
    assert!(
        block.contains("#1 hot_bt_leaf") && block.contains("#4 main"),
        "non-PIE PID-mode CFI rows should match raw ET_EXEC PCs and unwind callers\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        !block.contains("stopped: unsupported CFI")
            && !block.contains("stopped: no unwind rows for PC"),
        "non-PIE PID-mode rows should not be shifted by mapping base\nBLOCK:\n{block}\nSTDERR:\n{stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn test_cross_module_backtrace_resolves_so_and_exe_frames() -> anyhow::Result<()> {
    init();

    let script = r#"
trace cross_module_lib_leaf {
    print "CROSS_MODULE_STACK";
    bt full;
}
"#;

    let (count, stdout, stderr) = run_backtrace_fixture_with_depth_and_rate(
        "backtrace_cross_module_program",
        script,
        5,
        250,
        3,
    )
    .await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let block = first_backtrace_block_after(&stdout, "CROSS_MODULE_STACK", 5)?;
    assert!(
        block.contains("backtrace: truncated, 5 frames (max 5)"),
        "expected a bounded cross-module stack prefix\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert_ordered_patterns(
        block,
        &[
            "#0 cross_module_lib_leaf",
            "#1 cross_module_lib_probe",
            "#2 cross_module_main_caller",
            "#3 cross_module_main_loop",
            "#4 main",
        ],
    )?;
    assert!(
        block.contains("[libbacktrace_cross_module.so+"),
        "expected at least one shared-library frame\nBLOCK:\n{block}"
    );
    assert!(
        block.contains("[backtrace_cross_module_program+"),
        "expected at least one executable frame\nBLOCK:\n{block}"
    );
    assert!(
        !block.contains("stopped: invalid frame")
            && !block.contains("stopped: read error")
            && !block.contains("stopped: unsupported CFI")
            && !block.contains("stopped: no unwind rows for PC"),
        "cross-module stack should not stop on an unwind error\nBLOCK:\n{block}\nSTDERR:\n{stderr}"
    );
    assert_no_adjacent_duplicate_frame_locations(block)?;

    Ok(())
}

#[tokio::test]
async fn test_t_mode_cross_module_backtrace_resolves_so_and_exe_frames() -> anyhow::Result<()> {
    init();
    if skip_if_nested_t_mode_unsupported() {
        return Ok(());
    }

    let binary_path = FIXTURES.get_test_binary("backtrace_cross_module_program")?;
    let lib_path = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cross-module fixture has no parent directory"))?
        .join("libbacktrace_cross_module.so");
    let script = r#"
trace cross_module_lib_leaf {
    print "T_MODE_CROSS_MODULE_STACK";
    bt full;
}
"#;

    let (count, stdout, stderr) =
        run_backtrace_target_mode_library_with_depth(&binary_path, &lib_path, script, 5, 250, 3)
            .await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let expected_frames = [
        "#0 cross_module_lib_leaf",
        "#1 cross_module_lib_probe",
        "#2 cross_module_main_caller",
        "#3 cross_module_main_loop",
        "#4 main",
    ];
    let block = matching_backtrace_block_with_ordered_patterns_after(
        &stdout,
        &stderr,
        "T_MODE_CROSS_MODULE_STACK",
        5,
        "a bounded target-mode cross-module stack prefix",
        &expected_frames,
    )?;
    assert!(
        block.contains("backtrace: truncated, 5 frames (max 5)"),
        "expected a bounded target-mode cross-module stack prefix\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert_ordered_patterns(&block, &expected_frames)?;
    assert!(
        block.contains("[libbacktrace_cross_module.so+"),
        "expected at least one shared-library frame\nBLOCK:\n{block}"
    );
    assert!(
        block.contains("[backtrace_cross_module_program+"),
        "expected at least one executable frame\nBLOCK:\n{block}"
    );
    assert!(
        !block.contains("stopped: invalid frame")
            && !block.contains("stopped: read error")
            && !block.contains("stopped: unsupported CFI")
            && !block.contains("stopped: no unwind rows for PC"),
        "target-mode cross-module stack should not stop on an unwind error\nBLOCK:\n{block}\nSTDERR:\n{stderr}"
    );
    assert_no_adjacent_duplicate_frame_locations(&block)?;

    Ok(())
}

#[tokio::test]
async fn test_t_mode_multiple_backtrace_traces_share_cross_module_cfi() -> anyhow::Result<()> {
    init();
    if skip_if_nested_t_mode_unsupported() {
        return Ok(());
    }

    let binary_path = FIXTURES.get_test_binary("backtrace_cross_module_program")?;
    let lib_path = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cross-module fixture has no parent directory"))?
        .join("libbacktrace_cross_module.so");
    let script = r#"
trace cross_module_lib_probe {
    print "T_MODE_SHARED_CFI_PROBE";
    bt full;
}

trace cross_module_lib_leaf {
    print "T_MODE_SHARED_CFI_LEAF";
    bt full;
}
"#;

    let (count, stdout, stderr) =
        run_backtrace_target_mode_library_with_depth(&binary_path, &lib_path, script, 5, 250, 3)
            .await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }
    assert!(
        count >= 2,
        "expected both target-mode backtrace traces to emit events\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );

    let expected_probe_frames = [
        "#0 cross_module_lib_probe",
        "#1 cross_module_main_caller",
        "#2 cross_module_main_loop",
        "#3 main",
    ];
    let probe_block = matching_backtrace_block_with_ordered_patterns_after(
        &stdout,
        &stderr,
        "T_MODE_SHARED_CFI_PROBE",
        5,
        "a target-mode shared-CFI probe stack",
        &expected_probe_frames,
    )?;
    assert_ordered_patterns(&probe_block, &expected_probe_frames)?;
    assert!(
        probe_block.contains("[libbacktrace_cross_module.so+")
            && probe_block.contains("[backtrace_cross_module_program+"),
        "probe trace should unwind across the shared library and executable\nBLOCK:\n{probe_block}"
    );

    let expected_leaf_frames = [
        "#0 cross_module_lib_leaf",
        "#1 cross_module_lib_probe",
        "#2 cross_module_main_caller",
        "#3 cross_module_main_loop",
        "#4 main",
    ];
    let leaf_block = matching_backtrace_block_with_ordered_patterns_after(
        &stdout,
        &stderr,
        "T_MODE_SHARED_CFI_LEAF",
        5,
        "a target-mode shared-CFI leaf stack",
        &expected_leaf_frames,
    )?;
    assert_ordered_patterns(&leaf_block, &expected_leaf_frames)?;
    assert!(
        leaf_block.contains("[libbacktrace_cross_module.so+")
            && leaf_block.contains("[backtrace_cross_module_program+"),
        "leaf trace should unwind across the shared library and executable\nBLOCK:\n{leaf_block}"
    );
    assert_no_adjacent_duplicate_frame_locations(&probe_block)?;
    assert_no_adjacent_duplicate_frame_locations(&leaf_block)?;

    Ok(())
}

#[tokio::test]
async fn test_pid_backtrace_reports_frame_from_library_loaded_by_dlopen() -> anyhow::Result<()> {
    init();

    let (target, trigger_path) = spawn_backtrace_dlopen_program().await?;
    let script = r#"
trace dlopen_main_callback {
    print "DLOPEN_CALLBACK_STACK";
    bt full;
}
"#;

    let trigger_target = target.clone();
    let trigger_for_callback = trigger_path.clone();
    let result = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .attach_to(&target)
        .timeout_secs(5)
        .enable_sysmon_for_target(false)
        .with_cli_args([
            OsString::from("--script-output-events-per-sec"),
            OsString::from("200"),
            OsString::from("--backtrace-depth"),
            OsString::from("6"),
        ])
        .run_after_ready(move || async move {
            touch_dlopen_trigger_in_target_sandbox(&trigger_target, &trigger_for_callback)
        })
        .await;

    target.terminate().await?;
    let _ = fs::remove_file(trigger_path);
    let (exit_code, stdout, stderr, ()) = result?;
    if exit_code != 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }
    anyhow::ensure!(exit_code == 0, "stderr={stderr} stdout={stdout}");

    let blocks = backtrace_blocks_after(&stdout, "DLOPEN_CALLBACK_STACK", 6)?;
    let dlopen_block = blocks
        .first()
        .ok_or_else(|| anyhow::anyhow!("expected a dlopen callback backtrace block"))?;
    assert!(
        dlopen_block.contains("[libbacktrace_dlopen_target.so+"),
        "expected first backtrace block to include a frame from dlopen-loaded library\nBLOCK:\n{dlopen_block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        dlopen_block.contains("dlopen_main_callback"),
        "expected traced callback frame from main executable\nBLOCK:\n{dlopen_block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        !dlopen_block.contains("<proc offsets unavailable>"),
        "dlopen backtrace should refresh proc maps before rendering the library frame\nBLOCK:\n{dlopen_block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );

    let refreshed_block = blocks
        .iter()
        .find(|block| block.contains("dlopen_lib_middle") && block.contains("dlopen_lib_driver"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "expected a refreshed dlopen backtrace block to unwind inside the library\n\
                 STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )
        })?;
    assert_ordered_patterns(
        refreshed_block,
        &[
            "#0 dlopen_main_callback",
            "#1 dlopen_lib_leaf",
            "#2 dlopen_lib_middle",
            "#3 dlopen_lib_driver",
            "#4 main",
        ],
    )?;
    assert!(
        !refreshed_block.contains("stopped: no unwind rows for PC"),
        "dlopen backtrace should append CFI rows for the loaded library\n\
         BLOCK:\n{refreshed_block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn test_t_mode_backtrace_unwinds_library_loaded_by_dlopen() -> anyhow::Result<()> {
    init();
    if skip_if_nested_t_mode_unsupported() {
        return Ok(());
    }

    let binary_path = FIXTURES.get_test_binary("backtrace_dlopen_program")?;
    let (target, trigger_path) = spawn_backtrace_dlopen_program().await?;
    let script = r#"
trace dlopen_main_callback {
    print "T_MODE_DLOPEN_CALLBACK_STACK";
    bt full;
}
"#;

    let trigger_target = target.clone();
    let trigger_for_callback = trigger_path.clone();
    let result = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .with_target(&binary_path)
        .timeout_secs(5)
        .with_cli_args([
            OsString::from("--script-output-events-per-sec"),
            OsString::from("200"),
            OsString::from("--backtrace-depth"),
            OsString::from("6"),
        ])
        .run_after_ready(move || async move {
            touch_dlopen_trigger_in_target_sandbox(&trigger_target, &trigger_for_callback)
        })
        .await;

    target.terminate().await?;
    let _ = fs::remove_file(trigger_path);
    let (exit_code, stdout, stderr, ()) = result?;
    if exit_code != 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }
    anyhow::ensure!(exit_code == 0, "stderr={stderr} stdout={stdout}");

    let blocks = backtrace_blocks_after(&stdout, "T_MODE_DLOPEN_CALLBACK_STACK", 6)?;
    let refreshed_block = blocks
        .iter()
        .find(|block| block.contains("dlopen_lib_middle") && block.contains("dlopen_lib_driver"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "expected a target-mode dlopen backtrace block to unwind inside the library\n\
                 STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )
        })?;
    assert_ordered_patterns(
        refreshed_block,
        &[
            "#0 dlopen_main_callback",
            "#1 dlopen_lib_leaf",
            "#2 dlopen_lib_middle",
            "#3 dlopen_lib_driver",
        ],
    )?;
    assert!(
        !refreshed_block.contains("<proc offsets unavailable>")
            && !refreshed_block.contains("stopped: no unwind rows for PC"),
        "target-mode dlopen backtrace should refresh module offsets and append CFI rows\n\
         BLOCK:\n{refreshed_block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn test_t_mode_backtrace_unwinds_shared_library_loaded_by_dlopen() -> anyhow::Result<()> {
    init();
    if skip_if_nested_t_mode_unsupported() {
        return Ok(());
    }

    let binary_path = FIXTURES.get_test_binary("backtrace_dlopen_program")?;
    let lib_path = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("backtrace_dlopen_program has no parent directory"))?
        .join("libbacktrace_dlopen_target.so");
    let (target, trigger_path) = spawn_backtrace_dlopen_program().await?;
    let script = r#"
trace dlopen_lib_leaf {
    print "T_MODE_DLOPEN_SHARED_LIBRARY_STACK";
    bt full;
}
"#;

    let trigger_target = target.clone();
    let trigger_for_callback = trigger_path.clone();
    let result = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .with_target(&lib_path)
        .timeout_secs(5)
        .with_cli_args([
            OsString::from("--script-output-events-per-sec"),
            OsString::from("200"),
            OsString::from("--backtrace-depth"),
            OsString::from("6"),
        ])
        .run_after_ready(move || async move {
            touch_dlopen_trigger_in_target_sandbox(&trigger_target, &trigger_for_callback)
        })
        .await;

    target.terminate().await?;
    let _ = fs::remove_file(trigger_path);
    let (exit_code, stdout, stderr, ()) = result?;
    if exit_code != 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }
    anyhow::ensure!(exit_code == 0, "stderr={stderr} stdout={stdout}");

    let blocks = backtrace_blocks_after(&stdout, "T_MODE_DLOPEN_SHARED_LIBRARY_STACK", 6)?;
    let refreshed_block = blocks
        .iter()
        .find(|block| {
            block.contains("dlopen_lib_driver")
                && block.contains("[backtrace_dlopen_program+")
                && !block.contains("<proc offsets unavailable>")
                && !block.contains("stopped: offsets unavailable")
                && !block.contains("stopped: no unwind rows for PC")
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "expected a shared-library target dlopen backtrace block to unwind into the main executable\n\
                 STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
            )
        })?;
    assert_ordered_patterns(
        refreshed_block,
        &[
            "#0 dlopen_lib_leaf",
            "#1 dlopen_lib_middle",
            "#2 dlopen_lib_driver",
            "#3 main",
        ],
    )?;
    assert!(
        !refreshed_block.contains("<proc offsets unavailable>")
            && !refreshed_block.contains("stopped: no unwind rows for PC"),
        "shared-library target dlopen backtrace should publish the first target mapping refresh\n\
         BLOCK:\n{refreshed_block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn test_hot_backtrace_full_renders_function_parameters() -> anyhow::Result<()> {
    init();

    let script = r#"
trace dummy_touch {
    print "HOT_PARAMS";
    bt full;
}
"#;

    let (count, stdout, stderr) = run_hot_backtrace_with_depth(script, 5).await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let block = first_backtrace_block_after(&stdout, "HOT_PARAMS", 5)?;
    assert!(
        block.contains("#0 dummy_touch(long unsigned int value)"),
        "current frame should render its formal parameter signature\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        block.contains("#1 hot_bt_leaf(long unsigned int value)"),
        "caller frame should render its formal parameter signature\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        block.contains("#2 hot_bt_mid(long unsigned int value)"),
        "deeper caller frame should render its formal parameter signature\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        !block.contains(" raw=0x") && !block.contains(" cookie=0x"),
        "bt full should stay human-readable and must not print raw/cookie debug metadata\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn test_function_parameters_use_signature_lookup_path() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("backtrace_hot_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let dummy = analyzer
        .lookup_function_address_by_name("dummy_touch")
        .ok_or_else(|| anyhow::anyhow!("missing dummy_touch function"))?;
    let ctx = analyzer.resolve_pc(&ModuleAddress::new(dummy.module_path, dummy.address + 0x10))?;
    let params = analyzer.function_parameters(&ctx)?;

    assert_eq!(params.len(), 1, "expected one dummy_touch parameter");
    assert_eq!(params[0].name, "value");
    assert_eq!(params[0].type_name, "long unsigned int");
    assert!(
        !params[0].is_artificial,
        "dummy_touch parameter should be a real source parameter"
    );

    Ok(())
}

#[tokio::test]
async fn test_hot_backtrace_raw_renders_debug_metadata() -> anyhow::Result<()> {
    init();

    let script = r#"
trace dummy_touch {
    print "HOT_RAW_META";
    bt raw;
}
"#;

    let (count, stdout, stderr) = run_hot_backtrace_with_depth(script, 5).await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    let block = first_backtrace_block_after(&stdout, "HOT_RAW_META", 5)?;
    assert!(
        block.contains(" raw=0x"),
        "bt raw should print the raw instruction pointer for debugging\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        block.contains(" cookie=0x"),
        "bt raw should print the module cookie for debugging\nBLOCK:\n{block}\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn test_hot_backtrace_full_keeps_up_with_raw() -> anyhow::Result<()> {
    init();

    let raw_script = r#"
trace hot_bt_probe {
    print "HOT_RAW";
    bt raw;
}
"#;
    let full_script = r#"
trace hot_bt_probe {
    print "HOT_FULL";
    bt full;
}
"#;

    let (raw_count, raw_stdout, raw_stderr) = run_hot_backtrace(raw_script).await?;
    let (full_count, full_stdout, full_stderr) = run_hot_backtrace(full_script).await?;

    if raw_count == 0 && raw_stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    assert!(
        raw_count >= 100,
        "raw backtrace run did not receive enough events: raw_count={raw_count}\nSTDOUT: {raw_stdout}\nSTDERR: {raw_stderr}"
    );
    assert!(
        full_count >= 100,
        "full backtrace run fell behind badly: raw_count={raw_count} full_count={full_count}\nSTDOUT: {full_stdout}\nSTDERR: {full_stderr}"
    );
    assert!(
        full_count * 2 >= raw_count,
        "full backtrace symbolization is much slower than raw: raw_count={raw_count} full_count={full_count}\nFULL STDOUT: {full_stdout}\nFULL STDERR: {full_stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn test_backtrace_depth_128_loads_with_tail_calls() -> anyhow::Result<()> {
    init();

    let script = r#"
trace hot_bt_probe {
    print "HOT_DEEP";
    bt full;
}
"#;

    let (count, stdout, stderr) = run_hot_backtrace_with_depth(script, 128).await?;
    assert!(
        !stderr.contains("LLVM ERROR"),
        "depth=128 should not hit LLVM branch range errors\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        count > 0,
        "depth=128 backtrace did not produce events\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        stdout.contains("#1 "),
        "depth=128 tail-call backtrace should unwind at least one caller frame\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        stdout.contains("#2 "),
        "depth=128 tail-call backtrace should continue past the first caller frame\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        stdout.contains("libc.so.6+"),
        "depth=128 full backtrace should cross into libc instead of stopping at the executable boundary\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        !stdout.contains("stopped: invalid frame")
            && !stdout.contains("stopped: read error")
            && !stdout.contains("stopped: unsupported CFI")
            && !stdout.contains("stopped: no unwind rows for PC"),
        "depth=128 full backtrace should not stop on an unwind error\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn test_deep_full_backtrace_stays_warm_under_event_load() -> anyhow::Result<()> {
    init();

    let script = r#"
trace hot_bt_probe {
    print "HOT_DEEP_WARM";
    bt full;
}
"#;

    let (count, stdout, stderr) =
        run_hot_backtrace_with_depth_and_rate(script, 128, 2000, 3).await?;
    if count == 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    assert!(
        count >= 500,
        "deep full backtrace should keep rendering after caches are warm: count={count}\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        !stdout.contains("stopped: invalid frame")
            && !stdout.contains("stopped: read error")
            && !stdout.contains("stopped: unsupported CFI")
            && !stdout.contains("stopped: no unwind rows for PC"),
        "deep full backtrace should not regress into unwind errors under event load\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        !stderr.contains("script output saturated"),
        "deep full backtrace rendering should not saturate the script output path at the regression-test rate\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        stdout.contains("libc.so.6+"),
        "deep full backtrace should keep symbolizing cross-module frames under event load\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );

    Ok(())
}

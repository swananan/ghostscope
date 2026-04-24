//! C++ program script execution tests (end-to-end)

mod common;

use common::{init, FIXTURES};

const CPP_NESTED_MEMBER_TRACE_LINE: u32 = 44;

async fn compile_cpp_complex_script(
    script: &str,
) -> anyhow::Result<ghostscope_compiler::CompilationResult> {
    let binary_path = FIXTURES.get_test_binary("cpp_complex_program")?;
    let mut analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load DWARF for cpp_complex_program: {e}"))?;
    let compile_options = ghostscope_compiler::CompileOptions {
        binary_path_hint: Some(binary_path.to_string_lossy().into_owned()),
        ..Default::default()
    };

    ghostscope_compiler::compile_script(script, &mut analyzer, None, Some(1), &compile_options)
        .map_err(|e| anyhow::anyhow!("compile_script failed: {e}"))
}

async fn run_ghostscope_with_script_for_target(
    script_content: &str,
    timeout_secs: u64,
    target: &common::targets::TargetHandle,
) -> anyhow::Result<(i32, String, String)> {
    common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .attach_to(target)
        .timeout_secs(timeout_secs)
        .enable_sysmon_shared_lib(false)
        .run()
        .await
}

async fn spawn_cpp_complex_program() -> anyhow::Result<common::targets::TargetHandle> {
    let binary_path = FIXTURES.get_test_binary("cpp_complex_program")?;
    let bin_dir = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cpp_complex_program has no parent directory"))?;
    let target = common::targets::TargetLauncher::binary(&binary_path)
        .current_dir(bin_dir)
        .spawn()
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    Ok(target)
}

#[tokio::test]
async fn test_cpp_nested_type_direct_child_member_access_is_not_recursive() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("cpp_complex_program")?;
    let source_path = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("cpp_complex_program has no parent directory"))?
        .join("main.cpp");

    let valid_script = format!(
        r#"
trace {}:{CPP_NESTED_MEMBER_TRACE_LINE} {{
    print o.nested.shadow;
}}
"#,
        source_path.display()
    );
    let valid = compile_cpp_complex_script(&valid_script).await?;
    assert!(
        !valid.uprobe_configs.is_empty(),
        "expected valid o.nested.shadow to compile; target_info={} failed_targets={:?}",
        valid.target_info,
        valid.failed_targets
    );

    let invalid_script = format!(
        r#"
trace {}:{CPP_NESTED_MEMBER_TRACE_LINE} {{
    print o.shadow;
}}
"#,
        source_path.display()
    );
    if let Ok(invalid) = compile_cpp_complex_script(&invalid_script).await {
        assert!(
            invalid.uprobe_configs.is_empty(),
            "expected o.shadow to be rejected because shadow is only a member of o.nested; target_info={} failed_targets={:?}",
            invalid.target_info,
            invalid.failed_targets
        );
        assert!(
            !invalid.failed_targets.is_empty(),
            "expected at least one failed target for invalid o.shadow access"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_cpp_script_print_globals() -> anyhow::Result<()> {
    init();

    let target = spawn_cpp_complex_program().await?;

    // Attach at a hot function using DW_AT_name (add), print several globals
    let script = r#"
trace add {
    print "GCNT:{}", g_counter;
    print "SINT:{}", s_internal;
    print "SVAL:{}", s_val;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("GCNT:"),
        "Expected GCNT output. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("SINT:"),
        "Expected SINT output. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("SVAL:"),
        "Expected SVAL output. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_cpp_script_counter_increments() -> anyhow::Result<()> {
    init();

    let target = spawn_cpp_complex_program().await?;

    let script = r#"
trace add {
    print "CNT:{}", g_counter;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 5, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let mut vals: Vec<i64> = Vec::new();
    for line in stdout.lines() {
        if let Some(pos) = line.find("CNT:") {
            if let Some(num_str) = line[pos + 4..].split_whitespace().next() {
                if let Ok(v) = num_str.parse::<i64>() {
                    vals.push(v);
                }
            }
        }
    }
    assert!(vals.len() >= 2, "Insufficient CNT events. STDOUT: {stdout}");
    let mut non_decreasing = true;
    let mut has_increase = false;
    for w in vals.windows(2) {
        if w[1] < w[0] {
            non_decreasing = false;
            break;
        }
        if w[1] > w[0] {
            has_increase = true;
        }
    }
    assert!(
        non_decreasing,
        "Counter decreased unexpectedly. vals={vals:?}"
    );
    assert!(
        has_increase,
        "Counter did not increase across events. vals={vals:?}"
    );
    Ok(())
}

#[tokio::test]
async fn test_cpp_script_addresses_and_static_member() -> anyhow::Result<()> {
    init();

    let target = spawn_cpp_complex_program().await?;

    let script = r#"
trace add {
    print "&GC:{}", &g_counter;  // '{}' prints pointer as hex
    print "SV:{}", s_val;
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let mut gc_addrs: Vec<String> = Vec::new();
    let mut sv_vals: Vec<i64> = Vec::new();
    for line in stdout.lines() {
        let t = line.trim();
        if let Some(pos) = t.find("&GC:") {
            if let Some(ptr) = t[pos + 4..].split_whitespace().next() {
                if ptr.starts_with("0x") {
                    gc_addrs.push(ptr.to_string());
                }
            }
        }
        if let Some(pos) = t.find("SV:") {
            if let Some(num_str) = t[pos + 3..].split_whitespace().next() {
                if let Ok(v) = num_str.parse::<i64>() {
                    sv_vals.push(v);
                }
            }
        }
    }
    assert!(
        gc_addrs.iter().any(|a| a.starts_with("0x")),
        "Expected GC address. STDOUT: {stdout}"
    );
    if gc_addrs.len() >= 2 {
        assert_eq!(gc_addrs[0], gc_addrs[1], "Address should be stable.");
    }
    assert!(!sv_vals.is_empty(), "Expected static member value.");
    Ok(())
}

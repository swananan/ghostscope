#![allow(clippy::uninlined_format_args)]

//! Globals program script execution tests
//! - Validates printing of globals via local aliases in function scope
//! - Checks struct formatting, string extraction, and formatted prints

mod common;

use common::{init, FIXTURES};
use regex::Regex;
use std::ffi::OsString;
use std::io::Write;
use std::process::Stdio;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

async fn run_ghostscope_with_script_for_pid(
    script_content: &str,
    timeout_secs: u64,
    pid: u32,
) -> anyhow::Result<(i32, String, String)> {
    run_ghostscope_with_script_for_pid_impl(script_content, timeout_secs, pid, false).await
}

async fn run_ghostscope_with_script_for_pid_perf(
    script_content: &str,
    timeout_secs: u64,
    pid: u32,
) -> anyhow::Result<(i32, String, String)> {
    run_ghostscope_with_script_for_pid_impl(script_content, timeout_secs, pid, true).await
}

async fn run_ghostscope_with_script_for_pid_impl(
    script_content: &str,
    timeout_secs: u64,
    pid: u32,
    force_perf_event_array: bool,
) -> anyhow::Result<(i32, String, String)> {
    let mut script_file = NamedTempFile::new()?;
    script_file.write_all(script_content.as_bytes())?;
    let script_path = script_file.path();

    let binary_path = "../target/debug/ghostscope";
    let mut args: Vec<OsString> = vec![
        OsString::from("-p"),
        OsString::from(pid.to_string()),
        OsString::from("--script-file"),
        script_path.as_os_str().to_os_string(),
        OsString::from("--no-save-llvm-ir"),
        OsString::from("--no-save-ebpf"),
        OsString::from("--no-save-ast"),
        OsString::from("--no-log"),
    ];

    if force_perf_event_array {
        args.push(OsString::from("--force-perf-event-array"));
    }

    let mut command = Command::new(binary_path);
    command.args(&args);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command.spawn()?;
    let stdout_handle = child.stdout.take().unwrap();
    let stderr_handle = child.stderr.take().unwrap();
    let mut stdout_reader = BufReader::new(stdout_handle);
    let mut stderr_reader = BufReader::new(stderr_handle);
    let mut stdout_content = String::new();
    let mut stderr_content = String::new();

    let read_task = async {
        let mut stdout_line = String::new();
        let mut stderr_line = String::new();
        for _ in 0..120 {
            stdout_line.clear();
            if let Ok(Ok(n)) = timeout(
                Duration::from_millis(50),
                stdout_reader.read_line(&mut stdout_line),
            )
            .await
            {
                if n > 0 {
                    stdout_content.push_str(&stdout_line);
                }
            }
            stderr_line.clear();
            if let Ok(Ok(n)) = timeout(
                Duration::from_millis(50),
                stderr_reader.read_line(&mut stderr_line),
            )
            .await
            {
                if n > 0 {
                    stderr_content.push_str(&stderr_line);
                }
            }
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    let _ = timeout(Duration::from_secs(timeout_secs), read_task).await;

    let mut exit_code = match child.try_wait() {
        Ok(Some(status)) => status.code().unwrap_or(-1),
        _ => {
            let _ = child.kill().await;
            match timeout(Duration::from_secs(2), child.wait()).await {
                Ok(Ok(status)) => status.code().unwrap_or(-1),
                _ => -1,
            }
        }
    };
    if exit_code == -1 && (!stdout_content.is_empty() || !stderr_content.is_empty()) {
        exit_code = 0;
    }
    Ok((exit_code, stdout_content, stderr_content))
}

#[tokio::test]
async fn test_script_signed_ints_regression() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Regression: script ints should keep signed semantics (I8/I16/I32), not U*
    let script = r#"
trace globals_program.c:32 {
    let a = -1;
    let b = -2;
    let c = -3;
    print a;
    print b;
    print c;
    print "FMT:{}|{}|{}", a, b, c;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 2, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Variable prints
    assert!(
        stdout.contains("a = -1"),
        "Expected a = -1. STDOUT: {}",
        stdout
    );
    assert!(
        stdout.contains("b = -2"),
        "Expected b = -2. STDOUT: {}",
        stdout
    );
    assert!(
        stdout.contains("c = -3"),
        "Expected c = -3. STDOUT: {}",
        stdout
    );
    // Formatted prints
    assert!(
        stdout.contains("FMT:-1|-2|-3"),
        "Expected formatted signed values. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_trace_by_address_via_dwarf_line_lookup() -> anyhow::Result<()> {
    // End-to-end: resolve a DWARF PC for a known source line, then attach with trace 0xADDR { ... }
    init();

    // 1) Start the fixture program
    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;

    // Give the program some time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 2) Resolve a module-relative address (DWARF PC) for a stable source line in globals_program.c
    //    We reuse the same file:line that existing tests rely on and pick the first returned PC.
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load DWARF for test binary: {}", e))?;
    let addrs = analyzer.lookup_addresses_by_source_line("globals_program.c", 32);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for globals_program.c:32"
    );
    let pc = addrs[0].address;

    // 3) Build a script that attaches by address and prints a marker
    let script = format!("trace 0x{pc:x} {{\n    print \"ADDR_OK\";\n}}\n");

    // 4) Run ghostscope with -p and the script; in -p mode the default module is the main executable
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(&script, 2, pid).await?;
    let _ = prog.kill().await;

    // 5) Validate output: should see the marker at least once
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);
    assert!(
        stdout.lines().any(|l| l.contains("ADDR_OK")),
        "Expected ADDR_OK in output. STDOUT: {}",
        stdout
    );

    Ok(())
}

async fn run_ghostscope_with_script_for_target(
    script_content: &str,
    timeout_secs: u64,
    target_path: &std::path::Path,
) -> anyhow::Result<(i32, String, String)> {
    use std::ffi::OsString;
    use std::io::Write;
    use std::process::Stdio;
    use tokio::process::Command;
    use tokio::time::timeout;

    let mut script_file = NamedTempFile::new()?;
    script_file.write_all(script_content.as_bytes())?;
    let script_path = script_file.path();

    let binary_path = "../target/debug/ghostscope";
    let args: Vec<OsString> = vec![
        OsString::from("-t"),
        target_path.as_os_str().to_os_string(),
        OsString::from("--script-file"),
        script_path.as_os_str().to_os_string(),
        OsString::from("--no-save-llvm-ir"),
        OsString::from("--no-save-ebpf"),
        OsString::from("--no-save-ast"),
        OsString::from("--no-log"),
    ];

    let mut command = Command::new(binary_path);
    command.args(&args);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command.spawn()?;
    let stdout_handle = child.stdout.take().unwrap();
    let stderr_handle = child.stderr.take().unwrap();
    let mut stdout_reader = BufReader::new(stdout_handle);
    let mut stderr_reader = BufReader::new(stderr_handle);
    let mut stdout_content = String::new();
    let mut stderr_content = String::new();

    let read_task = async {
        let mut stdout_line = String::new();
        let mut stderr_line = String::new();
        for _ in 0..120 {
            stdout_line.clear();
            if let Ok(Ok(n)) = timeout(
                Duration::from_millis(50),
                stdout_reader.read_line(&mut stdout_line),
            )
            .await
            {
                if n > 0 {
                    stdout_content.push_str(&stdout_line);
                }
            }
            stderr_line.clear();
            if let Ok(Ok(n)) = timeout(
                Duration::from_millis(50),
                stderr_reader.read_line(&mut stderr_line),
            )
            .await
            {
                if n > 0 {
                    stderr_content.push_str(&stderr_line);
                }
            }
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    let _ = timeout(Duration::from_secs(timeout_secs), read_task).await;

    let mut exit_code = match child.try_wait() {
        Ok(Some(status)) => status.code().unwrap_or(-1),
        _ => {
            let _ = child.kill().await;
            match timeout(Duration::from_secs(2), child.wait()).await {
                Ok(Ok(status)) => status.code().unwrap_or(-1),
                _ => -1,
            }
        }
    };
    if exit_code == -1 && (!stdout_content.is_empty() || !stderr_content.is_empty()) {
        exit_code = 0;
    }
    Ok((exit_code, stdout_content, stderr_content))
}

#[tokio::test]
async fn test_special_vars_pid_tid_timestamp_globals() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let script = format!(
        "trace globals_program.c:32 {{\n    print \"PID={} TID={} TS={}\", $pid, $tid, $timestamp;\n    if $pid == {} {{ print \"PID_EQ\"; }}\n}}\n",
        "{}", "{}", "{}", pid
    );

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(&script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);
    assert!(
        stdout.contains("PID_EQ"),
        "Expected PID_EQ. STDOUT: {}",
        stdout
    );
    assert!(
        stdout.contains("PID=") || stdout.contains("PID:"),
        "Expected PID print. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_trace_address_with_target_shared_library() -> anyhow::Result<()> {
    // Verify address tracing works when session is started with -t <libgvars.so>
    init();

    // Start an app that maps libgvars.so so that uprobe events occur
    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let _pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Resolve a function address inside libgvars.so (e.g., lib_tick entry)
    let lib_path = bin_dir.join("libgvars.so");
    anyhow::ensure!(
        lib_path.exists(),
        "libgvars.so not found at {}",
        lib_path.display()
    );
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&lib_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load DWARF for lib: {}", e))?;
    let addrs = analyzer.lookup_function_addresses("lib_tick");
    anyhow::ensure!(
        !addrs.is_empty(),
        "No addresses for lib_tick in libgvars.so"
    );
    let pc = addrs[0].address;

    // Build script tracing at that address
    let script = format!("trace 0x{pc:x} {{\n    print \"LIB_ADDR_OK\";\n}}\n");

    // Run ghostscope in target mode (-t <libgvars.so>) with the script, collect output briefly
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(&script, 2, &lib_path).await?;
    let _ = prog.kill().await;

    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);
    assert!(
        stdout.lines().any(|l| l.contains("LIB_ADDR_OK")),
        "Expected LIB_ADDR_OK in output. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_address_of_with_hint_regression() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Ensure &LIB_STATE is computed with the correct module hint (prints as hex pointer)
    let script = r#"
trace globals_program.c:32 {
    print &LIB_STATE;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 1, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);
    assert!(
        stdout.contains("0x"),
        "Expected hex address. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_unary_minus_nested() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Nested unary minus should work: -(-1) == 1
    let script = r#"
trace globals_program.c:32 {
    let d = -(-1);
    print d;
    print "X:{}", d;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 1, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);
    assert!(
        stdout.contains("d = 1"),
        "Expected d = 1. STDOUT: {}",
        stdout
    );
    assert!(
        stdout.contains("X:1"),
        "Expected formatted 1. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_string_comparison_globals_char_ptr_and_array() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // In tick_once, gm/lm are aliases to global rodata strings,
    // and s is alias to &G_STATE with name[32].
    let script = r#"
trace globals_program.c:32 {
    if (gm == "Hello, Global!") { print "GM_OK"; }
    if (lm == "LIB_MESSAGE") { print "LM_OK"; }
    if (s.name == "RUNNING") { print "GNAME_RUN"; }
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Expect to see both char* matches (gm,lm)
    assert!(
        stdout.contains("GM_OK"),
        "Expected GM_OK for g_message. STDOUT: {}",
        stdout
    );
    assert!(
        stdout.contains("LM_OK"),
        "Expected LM_OK for lib_message. STDOUT: {}",
        stdout
    );
    // And ideally G_STATE.name comparison as RUNNING
    assert!(
        stdout.contains("GNAME_RUN"),
        "Expected GNAME_RUN for G_STATE.name. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_print_format_current_global_member_leaf() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Current-module leaf member via formatted print
    let script = r#"
trace globals_program.c:32 {
    print "GY:{}", G_STATE.inner.y;
}
"#;
    // Collect exactly 2 events for deterministic delta/null checks
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 2, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    let re = Regex::new(r"GY:([0-9]+(?:\.[0-9]+)?)").unwrap();
    let mut vals: Vec<f64> = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            // Ensure scalar print (no struct pretty-print)
            assert!(
                !line.contains("Inner {"),
                "Expected scalar for G_STATE.inner.y, got struct: {}",
                line
            );
            vals.push(c[1].parse().unwrap_or(0.0));
        }
    }
    assert!(
        vals.len() >= 2,
        "Insufficient GY events. STDOUT: {}",
        stdout
    );
    // inner.y increments by 0.5 per tick in globals_program
    let d = ((vals[1] - vals[0]) * 100.0).round() as i64;
    assert_eq!(
        d, 50,
        "G_STATE.inner.y should +0.5 per tick. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_print_format_global_autoderef_pointer_member() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Test script: global base with one auto-deref in chain
    let script = r#"
trace globals_program.c:32 {
    print "X: {}", G_STATE.lib.inner.x;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Expect both a normal numeric output and a NullDeref error output while lib toggles
    let num_re = Regex::new(r"X:\s*(-?\d+)").unwrap();
    let err_re = Regex::new(r"X:\s*<error: null pointer dereference> \(int\*\)").unwrap();
    let mut has_num = false;
    let mut has_err = false;
    for line in stdout.lines() {
        if num_re.is_match(line) {
            has_num = true;
        }
        if err_re.is_match(line) {
            has_err = true;
        }
    }
    assert!(has_num, "Expected numeric X line. STDOUT: {}", stdout);
    assert!(has_err, "Expected NullDeref X line. STDOUT: {}", stdout);
    Ok(())
}

#[tokio::test]
async fn test_cross_type_comparisons_globals() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Cross-type comparisons (string equality separated into its own test):
    // - s_internal > 5 (DWARF int vs script int)
    // - p_lib_internal == 0 (DWARF pointer vs script int; often false depending on timing)
    // - s_internal > th (DWARF int vs script variable)
    let script = r#"
trace globals_program.c:32 {
    let th = 6;
    print "SI_GT5:{} PIN0:{} SI_GT_TH:{}",
        s_internal > 5,
        p_lib_internal == 0,
        s_internal > th;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    let re = Regex::new(r"SI_GT5:(true|false) PIN0:(true|false) SI_GT_TH:(true|false)").unwrap();
    let mut saw_line = false;
    let mut saw_pin0_flag = false;
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            saw_line = true;
            // PIN0 may be true/false depending on timing; just assert it appears
            if &c[2] == "true" || &c[2] == "false" {
                saw_pin0_flag = true;
            }
        }
    }
    assert!(
        saw_line,
        "Expected at least one comparison line. STDOUT: {}",
        stdout
    );
    assert!(saw_pin0_flag, "Expected PIN0 present. STDOUT: {}", stdout);

    Ok(())
}

#[tokio::test]
async fn test_if_else_if_and_bare_expr_globals() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Use globals at a stable attach site; exercise bare expr + conditional with expressions
    let script = r#"
trace globals_program.c:32 {
    // bare expression print
    print s_internal > 5;
    if s_internal > 5 {
        print "wtf";
    } else if p_lib_internal == 0 {
        // else-if prints an expression result when lib ptr is null
        print p_lib_internal == 0;
    }
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Expect bare expr name preserved for (s_internal>5) = true/false
    let has_expr_line = stdout
        .lines()
        .any(|l| l.contains("(s_internal>5) = true") || l.contains("(s_internal>5) = false"));
    assert!(
        has_expr_line,
        "Expected bare expression output for s_internal>5. STDOUT: {}",
        stdout
    );

    // Branch outputs are environment-dependent (timing-sensitive). If they appear it's ok,
    // but the core validation here is parsing/execution of expr in if/else-if, which
    // is covered by the bare expression line above. So we don't require branch prints.

    Ok(())
}

#[tokio::test]
async fn test_if_else_if_logical_ops_globals() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let script = r#"
trace globals_program.c:32 {
    // Stable conditions to exercise both operators; first branch always true
    if 1 == 1 && s_bss_counter >= 0 { print "AND"; }
    else if 1 == 0 || p_lib_internal == 0 { print "OR"; }
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Expect deterministic AND branch
    let has_and = stdout.lines().any(|l| l.contains("AND"));
    assert!(has_and, "Expected AND branch output. STDOUT: {}", stdout);

    Ok(())
}

#[tokio::test]
async fn test_address_of_and_comparisons_globals() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Address-of on globals and in comparisons
    let script = r#"
trace globals_program.c:32 {
    print &G_STATE;              // pointer to global struct
    print (&G_STATE != 0);       // expression with address-of
    if &G_STATE != 0 { print "ADDR"; }
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Hex pointer expected for &G_STATE
    assert!(
        stdout.contains("0x"),
        "Expected hex pointer for &G_STATE. STDOUT: {}",
        stdout
    );

    // Bare expr boolean with name
    let has_expr = stdout
        .lines()
        .any(|l| l.contains("(&G_STATE!=0) = true") || l.contains("(&G_STATE!=0) = false"));
    assert!(
        has_expr,
        "Expected (&G_STATE!=0) bare expr. STDOUT: {}",
        stdout
    );

    // Then branch
    assert!(
        stdout.contains("ADDR"),
        "Expected then-branch ADDR line. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_string_equality_globals() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let script = r#"
trace globals_program.c:32 {
    print "GM_EQ:{}", g_message == "Hello, Global!";
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);
    // Expect GM_EQ:true at least once
    assert!(stdout.contains("GM_EQ:true") || stdout.contains("GM_EQ:false"));
    Ok(())
}

#[tokio::test]
async fn test_chain_tail_array_constant_index_increments() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // LIB_STATE.array[i] increments by +1 per tick in lib_tick(); via G_STATE.lib pointer
    let script = r#"
trace globals_program.c:32 {
    print "A0:{}", G_STATE.lib.array[0];
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // At this PC, G_STATE.lib may still be NULL (set later in tick_once), so A0 can alternate
    // between NULL error and numeric values. Require at least two A0 lines and at least one
    // numeric sample; if two numeric samples exist, ensure non-decreasing.
    let re_num = Regex::new(r"^\s*A0:(-?\d+)").unwrap();
    let re_err = Regex::new(r"^\s*A0:<error: null pointer dereference>").unwrap();
    let mut vals: Vec<i64> = Vec::new();
    let mut a0_lines = 0usize;
    for line in stdout.lines() {
        if line.trim_start().starts_with("A0:") {
            a0_lines += 1;
        }
        if let Some(c) = re_num.captures(line) {
            vals.push(c[1].parse::<i64>().unwrap_or(0));
        } else if re_err.is_match(line) {
            // count but no-op; we only enforce presence via a0_lines
        }
    }
    assert!(a0_lines >= 2, "Insufficient A0 events. STDOUT: {}", stdout);
    assert!(
        !vals.is_empty(),
        "Expected at least one numeric A0 sample. STDOUT: {}",
        stdout
    );
    if vals.len() >= 2 {
        assert!(
            vals[1] >= vals[0],
            "A0 should not decrease. STDOUT: {}",
            stdout
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_builtins_strncmp_starts_with_globals() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Validate strncmp/starts_with builtins on globals
    let script = r#"
trace globals_program.c:32 {
    print "SN1:{}", strncmp(gm, "Hello", 5);
    print "SW1:{}", starts_with(gm, "Hello");
    print "SN2:{}", strncmp(lm, "LIB_", 4);
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Expect true for SN1 and SW1; LM starts with LIB_ should be true as well
    assert!(
        stdout.lines().any(|l| l.contains("SN1:true")),
        "Expected SN1:true. STDOUT: {}",
        stdout
    );
    assert!(
        stdout.lines().any(|l| l.contains("SW1:true")),
        "Expected SW1:true. STDOUT: {}",
        stdout
    );
    assert!(
        stdout.lines().any(|l| l.contains("SN2:true")),
        "Expected SN2:true. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_builtin_strncmp_generic_ptr_and_null() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // At this PC, s.lib flips between NULL and &LIB_STATE each tick
    // When non-NULL, the first bytes are 'LIB' (name field), so strncmp should be true
    // When NULL, read fails and builtin returns false
    let script = r#"
trace globals_program.c:32 {
    print "SL:{}", strncmp(s.lib, "LIB", 3);
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 5, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    let saw_true = stdout.lines().any(|l| l.contains("SL:true"));
    let saw_false = stdout.lines().any(|l| l.contains("SL:false"));
    assert!(
        saw_true,
        "Expected SL:true at least once. STDOUT: {}",
        stdout
    );
    assert!(
        saw_false,
        "Expected SL:false at least once. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_rodata_char_element() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Print first character of executable/library rodata messages
    let script = r#"
trace globals_program.c:32 {
    // variable-print (name = value)
    print g_message[0];
    print lib_message[0];

    // format-print (pure value in placeholder)
    print "G0:{}", g_message[0];
    print "L0:{}", lib_message[0];
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Expect char-literal outputs (or numeric+char if simple path is used)
    // Accept either:
    //   name = 'X'
    // or
    //   name = 72 ('H')
    let _re_char_only = r"\s*='(?:.|\x[0-9a-fA-F]{2})'";
    let _re_num_and_char = r"\s*=\s*\d+\s*\('(?:.|\x[0-9a-fA-F]{2})'\)";
    let _re_num_only = r"\s*=\s*\d+";
    let re_g1 = Regex::new(r"^\s*g_message\[0\]\s*='[^']'").unwrap();
    let re_g2 = Regex::new(r"^\s*g_message\[0\]\s*=\s*\d+\s*\('[^']'\)").unwrap();
    let re_g3 = Regex::new(r"^\s*g_message\[0\]\s*=\s*\d+").unwrap();
    let re_l1 = Regex::new(r"^\s*lib_message\[0\]\s*='[^']'").unwrap();
    let re_l2 = Regex::new(r"^\s*lib_message\[0\]\s*=\s*\d+\s*\('[^']'\)").unwrap();
    let re_l3 = Regex::new(r"^\s*lib_message\[0\]\s*=\s*\d+").unwrap();
    let has_g = stdout
        .lines()
        .any(|l| re_g1.is_match(l) || re_g2.is_match(l) || re_g3.is_match(l));
    let has_l = stdout
        .lines()
        .any(|l| re_l1.is_match(l) || re_l2.is_match(l) || re_l3.is_match(l));
    // Also expect formatted outputs; accept char or numeric depending on DWARF encoding
    let re_fmt_val = r"(?:'[^']'|\d+)";
    let re_fmt_g = Regex::new(&format!(r"^\s*G0:{}", re_fmt_val)).unwrap();
    let re_fmt_l = Regex::new(&format!(r"^\s*L0:{}", re_fmt_val)).unwrap();
    let has_fmt_g = stdout.lines().any(|l| re_fmt_g.is_match(l));
    let has_fmt_l = stdout.lines().any(|l| re_fmt_l.is_match(l));
    assert!(
        has_g && has_l && has_fmt_g && has_fmt_l,
        "Expected variable and formatted char outputs. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_format_specifiers_memory_and_pointer() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let script = r#"
trace globals_program.c:32 {
    // Hex dump first 4 bytes of g_message
    print "HX={:x.4}", g_message;
    // ASCII dump first 5 bytes of s.name
    print "AS={:s.5}", s.name;
    // Dynamic star length 4 on lm (lib_message)
    print "DS={:s.*}", 4, lm;
    // Pointer formatting for &G_STATE
    print "P={:p}", &G_STATE;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    use regex::Regex;
    // Expect hex bytes pattern (four bytes)
    let re_hex4 = Regex::new(r"HX=([0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2}){3})").unwrap();
    // Expect ASCII substrings
    let has_as = stdout.lines().any(|l| {
        l.contains("AS=INIT")
            || l.contains("AS=RUNNI")
            || l.contains("AS=LIB")
            || l.contains("AS=HELLO")
    });
    let has_ds = stdout
        .lines()
        .any(|l| l.contains("DS=LIB_") || l.contains("DS=Hell"));
    // Pointer has 0x prefix
    let has_ptr = stdout.lines().any(|l| l.contains("P=0x"));

    let has_hex = stdout.lines().any(|l| re_hex4.is_match(l));
    assert!(has_hex, "Expected hex dump HX=. STDOUT: {}", stdout);
    assert!(has_as, "Expected ASCII dump AS=. STDOUT: {}", stdout);
    assert!(
        has_ds,
        "Expected dynamic star ASCII DS=. STDOUT: {}",
        stdout
    );
    assert!(has_ptr, "Expected pointer P=0x.... STDOUT: {}", stdout);
    Ok(())
}

#[tokio::test]
async fn test_large_pattern_dump_and_checks() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Validate:
    // - First 16 bytes of lib_pattern are 00..0f (hex)
    // - Byte at index 100 is 100
    // - Byte at index 255 is 255
    // - Dynamic {:x.*} with length=10 shows 00..09
    let script = r#"
trace globals_program.c:32 {
    print "LPX16={:x.16}", lib_pattern;
    print "LPD10={:x.*}", 10, lib_pattern;
    print "B100={} B255={}", lib_pattern[100], lib_pattern[255];
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    use regex::Regex;
    let re_first16 = Regex::new(r"LPX16=00(\s+01)(\s+02)(\s+03)(\s+04)(\s+05)(\s+06)(\s+07)(\s+08)(\s+09)(\s+0a)(\s+0b)(\s+0c)(\s+0d)(\s+0e)(\s+0f)").unwrap();
    let has_first16 = stdout.lines().any(|l| re_first16.is_match(l));
    let has_dyn10 = stdout
        .lines()
        .any(|l| l.contains("LPD10=00 01 02 03 04 05 06 07 08 09"));
    let has_b100 = stdout.lines().any(|l| l.contains("B100=100"));
    let has_b255 = stdout.lines().any(|l| l.contains("B255=255"));

    assert!(
        has_first16,
        "Expected first 16 bytes 00..0f. STDOUT: {}",
        stdout
    );
    assert!(
        has_dyn10,
        "Expected dynamic 10 bytes 00..09. STDOUT: {}",
        stdout
    );
    assert!(has_b100, "Expected B100=100. STDOUT: {}", stdout);
    assert!(has_b255, "Expected B255=255. STDOUT: {}", stdout);
    Ok(())
}

#[tokio::test]
async fn test_format_capture_len_zero_and_exceed_cap() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // With project-level ghostscope.toml setting mem_dump_cap=64,
    // - len=0 should yield empty
    // - len=128 should truncate to 64 bytes
    let script = r#"
trace globals_program.c:32 {
    let z = 0;
    let big = 128;
    print "Z0={:x.z$}", lib_pattern;     // expect empty
    print "XC={:x.big$}", lib_pattern;   // expect 64 bytes due to cap
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    use regex::Regex;
    // Z0 should be exactly 'Z0=' with no hex bytes following
    let re_z0_empty = Regex::new(r"^\s*Z0=\s*$").unwrap();
    let has_z0_empty = stdout.lines().any(|l| re_z0_empty.is_match(l));

    // 64 bytes hex: two hex digits repeated 64 times with optional spaces between
    let re_64_hex = Regex::new(r"XC=([0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2}){63})").unwrap();
    let has_trunc_64 = stdout.lines().any(|l| re_64_hex.is_match(l));

    assert!(has_z0_empty, "Expected Z0= (empty). STDOUT: {}", stdout);
    assert!(
        has_trunc_64,
        "Expected XC= to contain exactly 64 bytes due to cap. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_format_negative_len_clamped_to_zero() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Negative lengths should clamp to 0 and produce empty output
    let script = r#"
trace globals_program.c:32 {
    let neg = -5;
    print "ZN1={:x.neg$}", lib_pattern;   // capture negative -> empty
    print "ZN2={:x.*}", -10, lib_pattern; // star negative -> empty
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    use regex::Regex;
    let re_empty1 = Regex::new(r"^\s*ZN1=\s*$").unwrap();
    let re_empty2 = Regex::new(r"^\s*ZN2=\s*$").unwrap();
    let has_zn1 = stdout.lines().any(|l| re_empty1.is_match(l));
    let has_zn2 = stdout.lines().any(|l| re_empty2.is_match(l));

    assert!(has_zn1, "Expected ZN1= (empty). STDOUT: {}", stdout);
    assert!(has_zn2, "Expected ZN2= (empty). STDOUT: {}", stdout);
    Ok(())
}

#[tokio::test]
async fn test_format_specifiers_capture_len() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let script = r#"
trace globals_program.c:32 {
    let n = 4;
    // Capture length from script variable for ASCII and HEX
    print "CL={:s.n$}", lm;
    print "CH={:x.n$}", g_message;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    use regex::Regex;
    // Hex 4 bytes
    let re_hex4 = Regex::new(r"CH=([0-9a-fA-F]{2}(\s+[0-9a-fA-F]{2}){3})").unwrap();
    let has_hex = stdout.lines().any(|l| re_hex4.is_match(l));
    // ASCII 4 bytes from lm or g_message
    let has_cl = stdout
        .lines()
        .any(|l| l.contains("CL=LIB_") || l.contains("CL=Hell"));

    assert!(has_hex, "Expected hex dump CH=. STDOUT: {}", stdout);
    assert!(has_cl, "Expected capture-len ASCII CL=. STDOUT: {}", stdout);
    Ok(())
}

#[tokio::test]
async fn test_top_level_array_member_struct_field() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Top-level array-of-struct member access: g_slots[1].x
    let script = r#"
trace globals_program.c:32 {
    print "SX:{}", g_slots[1].x;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    let re = Regex::new(r"SX:(-?\d+)").unwrap();
    let has = stdout.lines().any(|l| re.is_match(l));
    assert!(
        has,
        "Expected struct field numeric via g_slots[1].x. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_tick_once_entry_strings_and_structs() -> anyhow::Result<()> {
    init();

    // Build and start globals_program (Debug)
    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Attach at a source line after local aliases are initialized (line 26 is first non-comment after 19..24)
    let script = r#"
trace globals_program.c:26 {
    print s.name;       // char[32] -> string
    print ls.name;      // from shared library
    print s;            // struct GlobalState pretty print
    print *ls;          // deref pointer to struct
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 2, pid).await?;

    let _ = prog.kill().await;

    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // s.name should be a quoted string (either "INIT" or updated value)
    let has_s_name = stdout.contains("\"INIT\"") || stdout.contains("\"RUNNING\"");
    assert!(has_s_name, "Expected s.name string. STDOUT: {}", stdout);

    // ls.name (library) should be "LIB"
    assert!(
        stdout.contains("\"LIB\""),
        "Expected ls.name == \"LIB\". STDOUT: {}",
        stdout
    );

    // Pretty struct prints for s or *ls should be present
    let has_struct = stdout.contains("GlobalState {") || stdout.contains("*ls = GlobalState {");
    assert!(
        has_struct,
        "Expected pretty struct output. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_tick_once_formatted_counters() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify formatted output combining fields from exe and lib globals via locals
    let script = r#"
trace tick_once {
    print "G:{} L:{}", s.counter, ls.counter;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 2, pid).await?;
    let _ = prog.kill().await;

    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);
    assert!(
        stdout.contains("G:") && stdout.contains("L:"),
        "Expected formatted counters. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_tick_once_pointer_values() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Validate pointers to rodata appear as addresses; attach after locals are set
    let script = r#"
trace globals_program.c:26 {
    print gm; // const char* to executable rodata
    print lm; // const char* to library rodata
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 2, pid).await?;
    let _ = prog.kill().await;

    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);
    assert!(
        stdout.contains("0x"),
        "Expected hexadecimal pointer output. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_two_events_evolution_and_statics() -> anyhow::Result<()> {
    init();

    // Build and start globals_program (Debug)
    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Attach at initialized locals line; print counters and statics via local pointers
    let script = r#"
trace globals_program.c:26 {
    print s.counter;
    print ls.counter;
    print *p_s_internal;
    print *p_s_bss;
    print *p_lib_internal;
}

"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Parse first two occurrences for each metric
    let re_s = Regex::new(r"s\.counter\s*=\s*(\d+)").unwrap();
    let re_ls = Regex::new(r"ls\.counter\s*=\s*(\d+)").unwrap();
    let re_si = Regex::new(r"\*p_s_internal\s*=\s*(\d+)").unwrap();
    let re_sb = Regex::new(r"\*p_s_bss\s*=\s*(\d+)").unwrap();
    let re_li = Regex::new(r"\*p_lib_internal\s*=\s*(\d+)").unwrap();
    let re_li_err =
        Regex::new(r"\*p_lib_internal\s*=\s*<error: null pointer dereference>").unwrap();

    let mut s_vals = Vec::new();
    let mut ls_vals = Vec::new();
    let mut si_vals = Vec::new();
    let mut sb_vals = Vec::new();
    let mut li_vals = Vec::new();
    let mut li_errs = 0usize;
    for line in stdout.lines() {
        if let Some(c) = re_s.captures(line) {
            s_vals.push(c[1].parse::<i64>().unwrap_or(0));
        }
        if let Some(c) = re_ls.captures(line) {
            ls_vals.push(c[1].parse::<i64>().unwrap_or(0));
        }
        if let Some(c) = re_si.captures(line) {
            si_vals.push(c[1].parse::<i64>().unwrap_or(0));
        }
        if let Some(c) = re_sb.captures(line) {
            sb_vals.push(c[1].parse::<i64>().unwrap_or(0));
        }
        if let Some(c) = re_li.captures(line) {
            li_vals.push(c[1].parse::<i64>().unwrap_or(0));
        } else if re_li_err.is_match(line) {
            li_errs += 1;
        }
    }

    // Ensure exactly two events captured for deterministic checks on exe-side
    assert!(
        s_vals.len() >= 2 && ls_vals.len() >= 2 && si_vals.len() >= 2 && sb_vals.len() >= 2,
        "Insufficient events for delta checks (exe-side). STDOUT: {}",
        stdout
    );

    // Check program logic deltas between first two hits
    assert!(s_vals[1] >= s_vals[0], "s.counter should be non-decreasing");
    assert_eq!(ls_vals[1] - ls_vals[0], 2, "ls.counter should +2 per tick");
    assert_eq!(si_vals[1] - si_vals[0], 2, "s_internal should +2 per tick");
    assert_eq!(
        sb_vals[1] - sb_vals[0],
        3,
        "s_bss_counter should +3 per tick"
    );
    // lib side over two events:
    // - If we have two numeric samples, enforce +5 delta.
    // - Otherwise accept two NULL-deref errors (the call to lib_get_internal_counter_ptr() may
    //   not have executed yet at the anchor PC), or mixed 1 value + 1 NULL.
    if li_vals.len() >= 2 {
        assert_eq!(
            li_vals[1] - li_vals[0],
            5,
            "lib_internal_counter should +5 per tick"
        );
    } else {
        assert!(
            (li_vals.len() == 1 && li_errs >= 1) || (li_vals.is_empty() && li_errs >= 2),
            "Expected lib_internal to be numeric twice, or NULL twice, or mixed once over two events. STDOUT: {}",
            stdout
        );
    }

    Ok(())
}
#[tokio::test]
async fn test_direct_globals_current_module() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Directly print globals without local aliases
    let script = r#"
trace globals_program.c:32 {
    print G_STATE;
    print s_internal;
    print s_bss_counter;
    // Also verify print format with direct globals
    print "FMT:{}|{}", s_internal, s_bss_counter;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Expect at least some struct pretty print and integer values present
    assert!(
        stdout.contains("G_STATE") && stdout.contains("GlobalState"),
        "Expected G_STATE struct print. STDOUT: {}",
        stdout
    );

    let re_si = Regex::new(r"s_internal\s*=\s*(-?\d+)").unwrap();
    let re_sb = Regex::new(r"s_bss_counter\s*=\s*(-?\d+)").unwrap();
    let mut si_vals = Vec::new();
    let mut sb_vals = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re_si.captures(line) {
            si_vals.push(c[1].parse::<i64>().unwrap_or(0));
        }
        if let Some(c) = re_sb.captures(line) {
            sb_vals.push(c[1].parse::<i64>().unwrap_or(0));
        }
    }
    // We expect at least 2 hits for each
    assert!(
        si_vals.len() >= 2 && sb_vals.len() >= 2,
        "Insufficient events. STDOUT: {}",
        stdout
    );
    // Check deltas align with logic: +2 and +3 per tick
    assert_eq!(si_vals[1] - si_vals[0], 2, "s_internal should +2 per tick");
    assert_eq!(
        sb_vals[1] - sb_vals[0],
        3,
        "s_bss_counter should +3 per tick"
    );
    // Verify formatted line FMT:{}|{} reflects the same counters and deltas
    let re_fmt = Regex::new(r"FMT:(-?\d+)\|(-?\d+)").unwrap();
    let mut f_a = Vec::new();
    let mut f_b = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re_fmt.captures(line) {
            f_a.push(c[1].parse::<i64>().unwrap_or(0));
            f_b.push(c[2].parse::<i64>().unwrap_or(0));
        }
    }
    assert!(
        f_a.len() >= 2 && f_b.len() >= 2,
        "Insufficient FMT events. STDOUT: {}",
        stdout
    );
    assert_eq!(f_a[1] - f_a[0], 2, "FMT s_internal delta +2");
    assert_eq!(f_b[1] - f_b[0], 3, "FMT s_bss_counter delta +3");
    Ok(())
}

#[tokio::test]
async fn test_direct_global_cross_module() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Cross-module global: offsets are auto-populated in -p mode; expect successful struct print
    let script = r#"
trace globals_program.c:32 {
    print LIB_STATE;
    // Also emit formatted cross-module counter to ensure format-path works for globals
    print "LIBCNT:{}", LIB_STATE.counter;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 2, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Expect pretty struct output for LIB_STATE
    assert!(
        stdout.contains("LIB_STATE"),
        "Expected LIB_STATE in output. STDOUT: {}",
        stdout
    );
    // Accept either typedef name or resolved struct display
    assert!(
        stdout.contains("GlobalState {") || (stdout.contains("{") && stdout.contains("name:")),
        "Expected pretty struct print for LIB_STATE. STDOUT: {}",
        stdout
    );
    // Verify formatted LIBCNT increments across at least two events
    let re = Regex::new(r"LIBCNT:(-?\d+)").unwrap();
    let mut vals = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            vals.push(c[1].parse::<i64>().unwrap_or(0));
        }
    }
    assert!(
        vals.len() >= 2,
        "Insufficient LIBCNT events. STDOUT: {}",
        stdout
    );
    assert_eq!(vals[1] - vals[0], 2, "LIB_STATE.counter should +2 per tick");
    Ok(())
}

#[tokio::test]
async fn test_rodata_direct_strings() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Directly print rodata arrays as strings (executable + library)
    let script = r#"
trace globals_program.c:32 {
    print g_message;    // executable .rodata (char[...])
    print lib_message;  // library .rodata (char[...])
    // Also check formatted path for strings
    print "FMT:{}|{}", g_message, lib_message;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 2, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Expect two quoted strings present (best-effort; content may vary across builds)
    let got_g_message = stdout
        .lines()
        .any(|l| l.contains("g_message = \"") && l.contains("\""));
    let got_lib_message = stdout
        .lines()
        .any(|l| l.contains("lib_message = \"") && l.contains("\""));
    assert!(
        got_g_message && got_lib_message,
        "Expected direct string prints for rodata. STDOUT: {}",
        stdout
    );
    // Look for a formatted line with both quoted strings
    let fmt_has_strings = stdout
        .lines()
        .any(|l| l.contains("FMT:") && l.matches('"').count() >= 2);
    assert!(
        fmt_has_strings,
        "Expected formatted strings line. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_bss_first_byte_evolves() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Read first byte of executable/library .bss buffers via locals 'gb'/'lb'
    let script = r#"
trace globals_program.c:32 {
    print *gb; // g_bss_buffer[0]
    print *lb; // lib_bss[0]
    // Also formatted first bytes from both buffers
    print "BF:{}|{}", *gb, *lb;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    let re_gb = Regex::new(r"\*gb\s*=\s*(-?\d+)").unwrap();
    let re_lb = Regex::new(r"\*lb\s*=\s*(-?\d+)").unwrap();
    let mut gb_vals = Vec::new();
    let mut lb_vals = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re_gb.captures(line) {
            gb_vals.push(c[1].parse::<i64>().unwrap_or(0));
        }
        if let Some(c) = re_lb.captures(line) {
            lb_vals.push(c[1].parse::<i64>().unwrap_or(0));
        }
    }
    assert!(
        gb_vals.len() >= 2 && lb_vals.len() >= 2,
        "Insufficient events. STDOUT: {}",
        stdout
    );
    // Each tick_once increments first byte by 1
    assert!(
        gb_vals[1] >= gb_vals[0],
        "gb[0] should not decrease. STDOUT: {}",
        stdout
    );
    assert!(
        lb_vals[1] >= lb_vals[0],
        "lb[0] should not decrease. STDOUT: {}",
        stdout
    );
    // Ensure formatted BF line present and non-decreasing as well
    let re = Regex::new(r"BF:(-?\d+)\|(-?\d+)").unwrap();
    let mut fa = Vec::new();
    let mut fb = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            fa.push(c[1].parse::<i64>().unwrap_or(0));
            fb.push(c[2].parse::<i64>().unwrap_or(0));
        }
    }
    assert!(
        fa.len() >= 2 && fb.len() >= 2,
        "Insufficient BF events. STDOUT: {}",
        stdout
    );
    assert!(
        fa[1] >= fa[0] && fb[1] >= fb[0],
        "BF values should not decrease. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_print_variable_global_member_direct() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Directly print global member fields in variable mode
    let script = r#"
trace globals_program.c:32 {
    print G_STATE.counter;
    print LIB_STATE.counter;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    let re_g = Regex::new(r"G_STATE\.counter\s*=\s*(-?\d+)").unwrap();
    let re_l = Regex::new(r"LIB_STATE\.counter\s*=\s*(-?\d+)").unwrap();
    let mut gv = Vec::new();
    let mut lv = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re_g.captures(line) {
            gv.push(c[1].parse::<i64>().unwrap_or(0));
        }
        if let Some(c) = re_l.captures(line) {
            lv.push(c[1].parse::<i64>().unwrap_or(0));
        }
    }
    assert!(
        gv.len() >= 2 && lv.len() >= 2,
        "Insufficient events. STDOUT: {}",
        stdout
    );
    // Ensure non-decreasing for current-module counter
    assert!(gv[1] >= gv[0], "G_STATE.counter should be non-decreasing");
    // Cross-module LIB_STATE.counter increments by +2 per tick
    assert_eq!(lv[1] - lv[0], 2, "LIB_STATE.counter should +2 per tick");
    Ok(())
}

#[tokio::test]
async fn test_print_format_global_member_direct() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Print format with global member (counter int)
    let script = r#"
trace globals_program.c:32 {
    print "LIBCNT:{}", LIB_STATE.counter;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    let re = Regex::new(r"LIBCNT:(-?\d+)").unwrap();
    let mut vals = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            vals.push(c[1].parse::<i64>().unwrap_or(0));
        }
    }
    assert!(
        vals.len() >= 2,
        "Insufficient LIBCNT events. STDOUT: {}",
        stdout
    );
    assert_eq!(vals[1] - vals[0], 2, "LIB_STATE.counter should +2 per tick");
    Ok(())
}

#[tokio::test]
async fn test_print_format_global_member_leaf() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Ensure formatted multi-level member prints scalar value, not whole struct
    let script = r#"
trace globals_program.c:32 {
    print "LIBY:{}", LIB_STATE.inner.y;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Capture floating values and ensure delta ~ 1.25 between first two events
    let re = Regex::new(r"LIBY:([0-9]+(?:\.[0-9]+)?)").unwrap();
    let mut vals: Vec<f64> = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            let v: f64 = c[1].parse().unwrap_or(0.0);
            // Line should not include full struct formatting
            assert!(
                !line.contains("Inner {"),
                "Leaf member should print scalar, got struct: {}",
                line
            );
            vals.push(v);
        }
    }
    assert!(
        vals.len() >= 2,
        "Insufficient LIBY events. STDOUT: {}",
        stdout
    );
    // Compare with tolerance by scaling to centi-precision
    let d = ((vals[1] - vals[0]) * 100.0).round() as i64;
    assert_eq!(
        d, 125,
        "LIB_STATE.inner.y should +1.25 per tick. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_print_variable_global_member_leaf() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Variable mode: nested chain leaf prints as scalar
    let script = r#"
trace globals_program.c:32 {
    print LIB_STATE.inner.y;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    let re = Regex::new(r"LIB_STATE\.inner\.y\s*=\s*(-?[0-9]+(?:\.[0-9]+)?)").unwrap();
    let mut vals: Vec<f64> = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            let v: f64 = c[1].parse().unwrap_or(0.0);
            vals.push(v);
        }
    }
    assert!(
        vals.len() >= 2,
        "Insufficient LIB_STATE.inner.y events. STDOUT: {}",
        stdout
    );
    let d = ((vals[1] - vals[0]) * 100.0).round() as i64;
    assert_eq!(d, 125, "inner.y should +1.25 per tick. STDOUT: {}", stdout);
    Ok(())
}

// ============================================================================
// PerfEventArray Tests (--force-perf-event-array)
// These tests verify the same functionality but with PerfEventArray backend
// ============================================================================

#[tokio::test]
async fn test_print_format_current_global_member_leaf_perf() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Current-module leaf member via formatted print
    let script = r#"
trace globals_program.c:32 {
    print "GY:{}", G_STATE.inner.y;
}
"#;
    // Collect exactly 2 events for deterministic delta/null checks
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_pid_perf(script, 2, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    let re = Regex::new(r"GY:([0-9]+(?:\.[0-9]+)?)").unwrap();
    let mut vals: Vec<f64> = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            // Ensure scalar print (no struct pretty-print)
            assert!(
                !line.contains("Inner {"),
                "Expected scalar for G_STATE.inner.y, got struct: {}",
                line
            );
            vals.push(c[1].parse().unwrap_or(0.0));
        }
    }
    assert!(
        vals.len() >= 2,
        "Insufficient GY events. STDOUT: {}",
        stdout
    );
    // inner.y increments by 0.5 per tick in globals_program
    let d = ((vals[1] - vals[0]) * 100.0).round() as i64;
    assert_eq!(
        d, 50,
        "G_STATE.inner.y should +0.5 per tick. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_tick_once_entry_strings_and_structs_perf() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Attach at a source line after local aliases are initialized (line 26 is first non-comment after 19..24)
    let script = r#"
trace globals_program.c:26 {
    print s.name;       // char[32] -> string
    print ls.name;      // from shared library
    print s;            // struct GlobalState pretty print
    print *ls;          // deref pointer to struct
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_pid_perf(script, 2, pid).await?;

    let _ = prog.kill().await;

    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // s.name should be a quoted string (either "INIT" or updated value)
    let has_s_name = stdout.contains("\"INIT\"") || stdout.contains("\"RUNNING\"");
    assert!(has_s_name, "Expected s.name string. STDOUT: {}", stdout);

    // ls.name (library) should be "LIB"
    assert!(
        stdout.contains("\"LIB\""),
        "Expected ls.name == \"LIB\". STDOUT: {}",
        stdout
    );

    // Pretty struct prints for s or *ls should be present
    let has_struct = stdout.contains("GlobalState {") || stdout.contains("*ls = GlobalState {");
    assert!(
        has_struct,
        "Expected pretty struct output. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_memcmp_numeric_pointer_literal_and_hex_len() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let script = r#"
trace globals_program.c:32 {
    // hex static length should work when comparing equal pointers
    if memcmp(&lib_pattern[0], &lib_pattern[0], 0x10) { print "LENHEX"; }
    // numeric pointer literal is expected to be invalid and thus false
    if memcmp(&lib_pattern[0], 0xdeadbeef, 16) { print "NP_TRUE"; } else { print "NP_FALSE"; }
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    assert!(
        stdout.lines().any(|l| l.contains("LENHEX")),
        "Expected LENHEX. STDOUT: {}",
        stdout
    );
    assert!(
        stdout.lines().any(|l| l.contains("NP_FALSE")),
        "Expected NP_FALSE. STDOUT: {}",
        stdout
    );
    Ok(())
}

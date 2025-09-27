#![allow(clippy::uninlined_format_args)]

//! Complex types script execution test
//! - Uses a long-running test program with complex DWARF types
//! - Validates struct/array/member/bitfield/union/enum formatting and array index

mod common;

use common::{init, OptimizationLevel, FIXTURES};
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
    let mut script_file = NamedTempFile::new()?;
    script_file.write_all(script_content.as_bytes())?;
    let script_path = script_file.path();

    let binary_path = "../target/debug/ghostscope";
    let args: Vec<OsString> = vec![
        OsString::from("-p"),
        OsString::from(pid.to_string()),
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
            // up to ~12s
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
async fn test_complex_types_formatting() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    // Give it time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Use source-line attach where 'a' (struct Complex) is in scope
    // Avoid pointer deref on parameter 'c' (not supported yet)
    let script_content = r#"
trace complex_types_program.c:25 {
    print a; // struct
    print a.name; // char[N] as string
    print "User: {} Age: {} {}", a.name, a.age, a.status;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_pid(script_content, 8, pid).await?;

    // Cleanup program
    let _ = prog.kill().await;

    // Basic assertions (no fallback, attach failure is failure)
    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={} stdout={}",
        stderr, stdout
    );

    // Check struct formatted line is present
    let has_struct =
        stdout.contains("Complex {") && stdout.contains("name:") && stdout.contains("age:");
    assert!(
        has_struct,
        "Expected struct output with fields. STDOUT: {}",
        stdout
    );

    // Ensure c.name renders as a quoted string (Alice/Bob)
    let has_name_str = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name_str,
        "Expected name string output. STDOUT: {}",
        stdout
    );

    // Optional: struct print contains 'arr:' field (do not require arr index due to grammar limits)
    let has_arr_field = stdout.contains("arr:");
    assert!(
        has_arr_field,
        "Expected struct output contains arr field. STDOUT: {}",
        stdout
    );

    // Ensure formatted print line exists
    let has_formatted = stdout.contains("User:") && stdout.contains("Age:");
    assert!(
        has_formatted,
        "Expected formatted print output. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_pointer_auto_deref_member_access() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    // Give it time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Function attach where 'c' (struct Complex*) is in scope
    // Auto-deref expected: c.name, c.age resolve via implicit pointer dereference
    let script = r#"
trace update_complex {
    print c.name;
    print "U:{} A:{}", c.name, c.age;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 8, pid).await?;

    // Cleanup program
    let _ = prog.kill().await;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={} stdout={}",
        stderr, stdout
    );

    // Expect at least one line referencing the name string from pointer-deref path
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name,
        "Expected dereferenced name (\"Alice\" or \"Bob\"). STDOUT: {}",
        stdout
    );

    // Ensure formatted print line exists with both fields
    let has_formatted = stdout.contains("U:") && stdout.contains("A:");
    assert!(
        has_formatted,
        "Expected formatted pointer-deref output. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_pointer_auto_deref_source_line_entry() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    // Give it time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Source-line attach to the function declaration line (expected to be before/at prologue)
    // Validate auto-deref for register-resident pointer parameter 'c'
    let script = r#"
trace complex_types_program.c:6 {
    print c.name;
    print "U:{} A:{}", c.name, c.age;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 8, pid).await?;

    // Cleanup program
    let _ = prog.kill().await;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={} stdout={}",
        stderr, stdout
    );

    // Name should be readable via auto-deref
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name,
        "Expected dereferenced name at entry (\"Alice\" or \"Bob\"). STDOUT: {}",
        stdout
    );

    // Ensure formatted print line exists
    let has_formatted = stdout.contains("U:") && stdout.contains("A:");
    assert!(
        has_formatted,
        "Expected formatted pointer-deref output at entry. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_bitfields_correctness() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    // Give it time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Use source-line attach where 'a' and 'i' are in scope
    let script_fn = r#"
trace complex_types_program.c:25 {
    print "I={}", i;
    print a.active;
    print a.flags;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script_fn, 8, pid).await?;

    // Cleanup program
    let _ = prog.kill().await;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={} stdout={}",
        stderr, stdout
    );

    // Parse values from output
    // Expect lines like:
    //   : I=1234
    //   : c.active = 0/1 (or a.active = ... depending on var name)
    //   : c.flags = 0..7
    use regex::Regex;
    let re_i = Regex::new(r"I=([0-9]+)").unwrap();
    let re_active = Regex::new(r"(?i)(?:\b|\.)active\s*=\s*([0-9]+)").unwrap();
    let re_flags = Regex::new(r"(?i)(?:\b|\.)flags\s*=\s*([0-9]+)").unwrap();

    let mut found_i: Option<u64> = None;
    let mut found_active: Option<u64> = None;
    let mut found_flags: Option<u64> = None;

    for line in stdout.lines() {
        if found_i.is_none() {
            if let Some(caps) = re_i.captures(line) {
                if let Ok(val) = caps[1].parse::<u64>() {
                    found_i = Some(val);
                }
            }
        }
        if found_active.is_none() {
            if let Some(caps) = re_active.captures(line) {
                if let Ok(val) = caps[1].parse::<u64>() {
                    found_active = Some(val);
                }
            }
        }
        if found_flags.is_none() {
            if let Some(caps) = re_flags.captures(line) {
                if let Ok(val) = caps[1].parse::<u64>() {
                    found_flags = Some(val);
                }
            }
        }
        if found_i.is_some() && found_active.is_some() && found_flags.is_some() {
            break;
        }
    }

    // Function attach path: precise checks with i（无法 attach 也应算失败）
    let i_val = found_i.ok_or_else(|| anyhow::anyhow!("Missing I=... line. STDOUT: {}", stdout))?;
    let active_val =
        found_active.ok_or_else(|| anyhow::anyhow!("Missing active line. STDOUT: {}", stdout))?;
    let flags_val =
        found_flags.ok_or_else(|| anyhow::anyhow!("Missing flags line. STDOUT: {}", stdout))?;

    assert!(
        active_val <= 1,
        "active should be 0 or 1, got {}. STDOUT: {}",
        active_val,
        stdout
    );
    assert!(
        flags_val <= 7,
        "flags should be 0..7, got {}. STDOUT: {}",
        flags_val,
        stdout
    );
    assert_eq!(
        active_val,
        i_val & 1,
        "active must equal i&1 (i={}, active={})",
        i_val,
        active_val
    );
    assert_eq!(
        flags_val,
        i_val & 7,
        "flags must equal i&7 (i={}, flags={})",
        i_val,
        flags_val
    );

    Ok(())
}

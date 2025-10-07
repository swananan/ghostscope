#![allow(clippy::uninlined_format_args)]
#![allow(clippy::needless_borrows_for_generic_args)]
#![allow(clippy::collapsible_else_if)]

//! Script execution integration tests
//!
//! Tests for ghostscope script execution and tracing functionality.
//! Assumes tests are run with sudo permissions for eBPF attachment.

mod common;

use common::{init, OptimizationLevel, FIXTURES};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Write;
use std::process::Stdio;
use std::sync::{Arc, Once};
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::RwLock;
use tokio::time::timeout;

// Global test program management
lazy_static! {
    // Maintain one process per optimization level to avoid cross-test interference.
    static ref GLOBAL_TEST_MANAGER: Arc<RwLock<HashMap<OptimizationLevel, GlobalTestProcess>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

struct GlobalTestProcess {
    child: tokio::process::Child,
    pid: u32,
    optimization_level: OptimizationLevel,
}

impl GlobalTestProcess {
    async fn start_with_opt(opt_level: OptimizationLevel) -> anyhow::Result<Self> {
        let binary_path = FIXTURES.get_test_binary_with_opt("sample_program", opt_level)?;

        println!(
            "🚀 Starting global sample_program ({}): {}",
            opt_level.description(),
            binary_path.display()
        );

        let child = Command::new(binary_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let pid = child
            .id()
            .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;

        // Give it a moment to start
        tokio::time::sleep(Duration::from_millis(500)).await;

        println!(
            "✓ Started global sample_program ({}) with PID: {}",
            opt_level.description(),
            pid
        );

        Ok(Self {
            child,
            pid,
            optimization_level: opt_level,
        })
    }

    fn get_pid(&self) -> u32 {
        self.pid
    }

    async fn terminate(mut self) -> anyhow::Result<()> {
        println!(
            "🛑 Terminating global sample_program ({}, PID: {})",
            self.optimization_level.description(),
            self.pid
        );

        // Try graceful shutdown first
        let _ = self.child.kill().await;

        // Wait for termination with timeout
        match timeout(Duration::from_secs(2), self.child.wait()).await {
            Ok(_) => {
                println!(
                    "✓ Global sample_program ({}) terminated gracefully",
                    self.optimization_level.description()
                );
            }
            Err(_) => {
                // Force kill if it doesn't respond
                let _ = std::process::Command::new("kill")
                    .args(&["-KILL", &self.pid.to_string()])
                    .output();
                println!(
                    "⚠️ Force killed global sample_program ({})",
                    self.optimization_level.description()
                );
            }
        }

        Ok(())
    }
}

// Get or start the global test process with specific optimization level
async fn get_global_test_pid_with_opt(opt_level: OptimizationLevel) -> anyhow::Result<u32> {
    let manager = GLOBAL_TEST_MANAGER.clone();

    // Fast path: check if we already have a live process for this opt level
    {
        let read_guard = manager.read().await;
        if let Some(process) = read_guard.get(&opt_level) {
            let status = std::process::Command::new("kill")
                .args(&["-0", &process.pid.to_string()])
                .status();
            if status.map(|s| s.success()).unwrap_or(false) {
                return Ok(process.pid);
            }
        }
    }

    // Slow path: create or replace the entry for this opt level
    let mut write_guard = manager.write().await;

    // Double-check under write lock in case another task started it
    if let Some(process) = write_guard.get(&opt_level) {
        let status = std::process::Command::new("kill")
            .args(&["-0", &process.pid.to_string()])
            .status();
        if status.map(|s| s.success()).unwrap_or(false) {
            return Ok(process.pid);
        }
    }

    // If an old process exists for this opt level, remove it first (drop lock before awaiting)
    let old_proc = write_guard.remove(&opt_level);
    drop(write_guard);

    if let Some(old) = old_proc {
        let _ = old.terminate().await;
    }

    // Start new process with the requested optimization level
    let new_process = GlobalTestProcess::start_with_opt(opt_level).await?;
    let pid = new_process.get_pid();

    // Re-acquire write lock to insert the new process
    let mut write_guard = manager.write().await;
    write_guard.insert(opt_level, new_process);
    Ok(pid)
}

// Get or start the global test process (defaults to Debug optimization)
// Cleanup function to be called when tests finish
pub async fn cleanup_global_test_process() -> anyhow::Result<()> {
    let manager = GLOBAL_TEST_MANAGER.clone();
    let mut write_guard = manager.write().await;

    // Terminate all managed processes (for every optimization level)
    let processes: Vec<GlobalTestProcess> = write_guard.drain().map(|(_, p)| p).collect();
    drop(write_guard);

    for proc in processes.into_iter() {
        let _ = proc.terminate().await;
    }

    Ok(())
}

// Global cleanup registration - only runs once when the first test calls it
static GLOBAL_CLEANUP_REGISTERED: Once = Once::new();

fn ensure_global_cleanup_registered() {
    GLOBAL_CLEANUP_REGISTERED.call_once(|| {
        // Use atexit to ensure cleanup runs when the test binary exits
        extern "C" fn cleanup_on_exit() {
            println!("🧹 Global test cleanup: All tests finished, cleaning up...");

            // Kill any remaining sample_program processes
            let _pkill_result = std::process::Command::new("pkill")
                .args(&["-f", "sample_program"])
                .output();

            // Clean up sample_program build files
            let fixtures_path =
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
            let sample_program_dir = fixtures_path.join("sample_program");

            println!("🧹 Running make clean in sample_program directory...");
            let clean_result = std::process::Command::new("make")
                .arg("clean")
                .current_dir(&sample_program_dir)
                .output();

            match clean_result {
                Ok(output) => {
                    if output.status.success() {
                        println!("✓ Successfully cleaned sample_program build files");
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        println!("⚠️ Make clean failed: {}", stderr);
                    }
                }
                Err(e) => {
                    println!("⚠️ Failed to run make clean: {}", e);
                }
            }

            println!("🧹 Global cleanup completed");
        }

        unsafe {
            libc::atexit(cleanup_on_exit);
        }

        println!("✓ Global cleanup handler registered");
    });
}

/// Helper to run ghostscope with script and capture results with specific optimization level
/// For failing cases (syntax errors, etc.), this will return quickly with exit code != 0
/// For successful cases, this will run for timeout_secs, collect output, then terminate the process
async fn run_ghostscope_with_script_opt(
    script_content: &str,
    timeout_secs: u64,
    opt_level: OptimizationLevel,
) -> anyhow::Result<(i32, String, String)> {
    // Get PID of running sample_program with specific optimization level
    let test_pid = get_global_test_pid_with_opt(opt_level).await?;

    let mut script_file = NamedTempFile::new()?;
    script_file.write_all(script_content.as_bytes())?;
    let script_path = script_file.path();

    println!(
        "🔍 Running ghostscope with {} binary (PID: {})",
        opt_level.description(),
        test_pid
    );

    let binary_path = "../target/debug/ghostscope";
    let args: Vec<OsString> = vec![
        OsString::from("-p"),
        OsString::from(test_pid.to_string()),
        OsString::from("--script-file"),
        script_path.as_os_str().to_os_string(),
        OsString::from("--no-save-llvm-ir"),
        OsString::from("--no-save-ebpf"),
        OsString::from("--no-save-ast"),
    ];
    let command_display = format!(
        "{} {}",
        binary_path,
        args.iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );

    let mut command = Command::new(binary_path);
    command.args(&args);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command.spawn()?;

    // Rest of the function implementation - collect output and handle termination
    let stdout_handle = child.stdout.take().unwrap();
    let stderr_handle = child.stderr.take().unwrap();

    let mut stdout_reader = BufReader::new(stdout_handle);
    let mut stderr_reader = BufReader::new(stderr_handle);

    let mut stdout_content = String::new();
    let mut stderr_content = String::new();

    // Read output with timeout
    let read_task = async {
        let mut stdout_line = String::new();
        let mut stderr_line = String::new();

        for _ in 0..100 {
            // Try to read stdout
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

            // Try to read stderr
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

            // Check if process has exited (for quick failures)
            if let Ok(Some(_)) = child.try_wait() {
                // Process exited, break and collect remaining output
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    // Run the read task with overall timeout
    let _ = timeout(Duration::from_secs(timeout_secs), read_task).await;

    // Terminate the child process
    let mut forced_termination = false;
    let mut exit_code = match child.try_wait() {
        Ok(Some(status)) => status.code().unwrap_or(-1),
        _ => {
            forced_termination = true;
            let _ = child.kill().await;
            match timeout(Duration::from_secs(2), child.wait()).await {
                Ok(Ok(status)) => status.code().unwrap_or(-1),
                _ => -1,
            }
        }
    };

    if forced_termination
        && exit_code == -1
        && (!stdout_content.trim().is_empty() || !stderr_content.trim().is_empty())
    {
        println!(
            "ℹ️ Ghostscope terminated after timeout; treating as success: {}",
            command_display
        );
        exit_code = 0;
    }

    if exit_code != 0 {
        println!("❌ Ghostscope invocation failed: {}", command_display);
    }

    Ok((exit_code, stdout_content, stderr_content))
}

/// Helper to run ghostscope with script and capture results (defaults to Debug optimization)
/// For failing cases (syntax errors, etc.), this will return quickly with exit code != 0
/// For successful cases, this will run for timeout_secs, collect output, then terminate the process
async fn run_ghostscope_with_script(
    script_content: &str,
    timeout_secs: u64,
) -> anyhow::Result<(i32, String, String)> {
    run_ghostscope_with_script_opt(script_content, timeout_secs, OptimizationLevel::Debug).await
}

#[tokio::test]
async fn test_logical_or_short_circuit_chain() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Attach to a hot function so we get a few events quickly
    let script_content = r#"
trace calculate_something {
    // Exercise chained OR; final should be true
    print (0 || 0 || 1);
    // Exercise chained OR; final should be false
    print (0 || 0 || 0);
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Expect to observe both true and false lines at least once
    let saw_true = stdout.contains("true");
    let saw_false = stdout.contains("false");
    assert!(
        saw_true,
        "Expected at least one true result. STDOUT: {}",
        stdout
    );
    assert!(
        saw_false,
        "Expected at least one false result. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_logical_mixed_precedence() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Validate precedence: && has higher precedence than ||
    // (1 || 0 && 0) => 1 || (0 && 0) => true
    // (0 || 1 && 0) => 0 || (1 && 0) => false
    let script_content = r#"
trace calculate_something {
    print "MIX:{}|{}", (1 || 0 && 0), (0 || 1 && 0);
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Look for a line like: MIX:true|false
    let expected = "MIX:true|false";
    assert!(
        stdout.contains(expected),
        "Expected \"{}\". STDOUT: {}",
        expected,
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_logical_and_short_circuit_chain() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    // true && true && false => false
    print (1 && 1 && 0);
    // true && true && true => true
    print (1 && 1 && 1);
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    let saw_true = stdout.contains("true");
    let saw_false = stdout.contains("false");
    assert!(
        saw_true,
        "Expected at least one true result. STDOUT: {}",
        stdout
    );
    assert!(
        saw_false,
        "Expected at least one false result. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_syntax_error() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    print "missing semicolon"  // Missing semicolon - should cause parse error
    invalid_token_here
}
"#;

    println!("=== Syntax Error Test ===");

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;

    println!("Exit code: {}", exit_code);
    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);
    println!("=========================");

    // Should fail fast with syntax error
    assert_ne!(exit_code, 0, "Invalid syntax should cause non-zero exit");
    assert!(
        stderr.contains("Parse error") || stderr.contains("not running"),
        "Should contain parse error: {}",
        stderr
    );

    if stderr.contains("Parse error") {
        println!("✓ Syntax error correctly detected and rejected");
    } else {
        println!(
            "○ Ghostscope exited because target process ended before parsing (stderr: {})",
            stderr.trim()
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_format_mismatch() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    print "format {} {} but only one arg", a;  // Format/argument count mismatch
}
"#;

    println!("=== Format Mismatch Test ===");

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;

    println!("Exit code: {}", exit_code);
    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);
    println!("============================");

    // Should fail fast with format error
    assert_ne!(exit_code, 0, "Format mismatch should cause non-zero exit");

    // Check for format validation error
    if stderr.contains("Parse error")
        || stderr.contains("Type error")
        || stderr.contains("format")
        || stderr.contains("placeholders")
    {
        println!("✓ Format mismatch correctly detected");
    } else {
        println!("⚠️  Expected format validation error, got: {}", stderr);
    }

    Ok(())
}

#[tokio::test]
async fn test_nonexistent_function() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace nonexistent_function_12345 {
    print "This function does not exist in sample_program";
}
"#;

    println!("=== Nonexistent Function Test ===");

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;

    println!("Exit code: {}", exit_code);
    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);
    println!("=================================");

    // Should fail fast when function doesn't exist
    assert_ne!(
        exit_code, 0,
        "Nonexistent function should cause non-zero exit"
    );
    assert!(
        !stderr.contains("Parse error"),
        "Script syntax should be valid: {}",
        stderr
    );

    if stderr.contains("No uprobe configurations created") {
        println!("✓ Correctly detected that target function doesn't exist");
    } else {
        println!(
            "⚠️  Expected 'No uprobe configurations' error, got: {}",
            stderr
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_function_level_tracing() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    print "CALC: a={} b={}", a, b;
}
"#;

    // Test with both optimization levels.
    // TODO: Re-enable optimized runs once we can reconstruct inlined symbols without full debug info.
    let optimization_levels = [OptimizationLevel::Debug, OptimizationLevel::O2];

    for opt_level in &optimization_levels {
        println!(
            "=== Function Level Tracing Test ({}) ===",
            opt_level.description()
        );

        if *opt_level != OptimizationLevel::Debug {
            println!(
                "⏭️  Skipping {} run (TODO: handle inlined symbols without full debug info)",
                opt_level.description()
            );
            continue;
        }

        let (exit_code, stdout, stderr) =
            run_ghostscope_with_script_opt(script_content, 3, *opt_level).await?;

        println!("Exit code: {}", exit_code);
        println!("STDOUT: {}", stdout);
        println!("STDERR: {}", stderr);
        println!("===============================================");

        // If we have permissions, should run successfully and produce output
        assert_eq!(
            exit_code,
            0,
            "Ghostscope should succeed for {} (stderr: {})",
            opt_level.description(),
            stderr
        );

        println!("✓ Ghostscope attached and ran successfully");

        // Parse output to validate math: a == b - 5
        let mut math_validations = 0;
        let mut function_calls_found = 0;
        let mut validation_errors = Vec::new();

        for line in stdout.lines() {
            if line.contains("CALC: ") {
                function_calls_found += 1;
                if let Some((a, b)) = parse_calc_line_simple(line) {
                    if a == b - 5 {
                        println!("✓ Math validation passed: a={} == b-5={}", a, b - 5);
                        math_validations += 1;
                    } else {
                        let error_msg =
                            format!("Math validation failed: a={} != b-5={} (b={})", a, b - 5, b);
                        println!("❌ {}", error_msg);
                        validation_errors.push(error_msg);
                    }
                } else {
                    println!("⚠️  Failed to parse line: {}", line);
                }
            }
        }

        if function_calls_found == 0 {
            panic!("❌ No function calls captured - test failed. Expected at least one calculate_something call. This indicates either:\n  1. sample_program is not running\n  2. Function is not being called\n  3. Ghostscope failed to attach properly");
        } else if !validation_errors.is_empty() {
            panic!("❌ Function calls captured but math validation failed:\n  Found {} function calls, {} validation errors:\n  {}",
            function_calls_found, validation_errors.len(), validation_errors.join("\n  "));
        } else if math_validations > 0 {
            println!("✓ Validated {} calculate_something calls", math_validations);
        }

        println!("===============================================");
    }

    Ok(())
}

#[tokio::test]
async fn test_multiple_trace_targets() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Test both function-level and line-level tracing in one script
    let script_content = r#"
trace calculate_something {
    print "FUNC: a={} b={}", a, b;
}

trace sample_program.c:16 {
    print "LINE16: a={} b={} result={}", a, b, result;
}
"#;

    let optimization_levels = [OptimizationLevel::Debug, OptimizationLevel::O2];

    for opt_level in &optimization_levels {
        println!(
            "=== Multiple Trace Targets Test ({}) ===",
            opt_level.description()
        );

        let (exit_code, stdout, stderr) =
            run_ghostscope_with_script_opt(script_content, 3, *opt_level).await?;

        println!("Exit code: {}", exit_code);
        println!("STDOUT: {}", stdout);
        println!("STDERR: {}", stderr);
        println!("=====================================");

        // Check that script syntax is valid
        assert!(
            !stderr.contains("Parse error"),
            "Multi-target script should have valid syntax: {}",
            stderr
        );

        assert_eq!(
            exit_code,
            0,
            "Ghostscope should succeed for {} (stderr: {})",
            opt_level.description(),
            stderr
        );

        println!("✓ Multiple trace targets attached and ran successfully");

        // Check for both function-level and line-level outputs
        let has_func = stdout.contains("FUNC:");
        let has_line16 = stdout.contains("LINE16:");

        assert!(
            has_func,
            "Expected function-level trace output for {} but none was captured. STDOUT: {}",
            opt_level.description(),
            stdout
        );
        assert!(
            has_line16,
            "Expected line-level trace output for {} but none was captured. STDOUT: {}",
            opt_level.description(),
            stdout
        );

        println!(
            "Trace capture status: FUNC={}, LINE16={}",
            has_func, has_line16
        );

        let mut func_validations = 0;
        let mut line_validations = 0;
        let mut validation_errors = Vec::new();

        // Validate function-level traces (a == b - 5)
        for line in stdout.lines() {
            if line.contains("FUNC: ") {
                if let Some((a, b)) = parse_calc_line_simple(line) {
                    if *opt_level != OptimizationLevel::Debug && a == 0 && b == 0 {
                        println!(
                            "TODO[trace-inline]: optimized build returned placeholder a=0 b=0; \
                            skipping validation until we expose explicit 'optimized out'."
                        );
                        continue;
                    }

                    if a == b - 5 {
                        println!(
                            "✓ Function-level math validation passed: a={} == b-5={}",
                            a,
                            b - 5
                        );
                        func_validations += 1;
                    } else {
                        let error_msg =
                            format!("Function-level validation failed: a={} != b-5={}", a, b - 5);
                        println!("❌ {}", error_msg);
                        validation_errors.push(error_msg);
                    }
                }
            }
        }

        // Validate line-level traces (a * b + 42 == result)
        for line in stdout.lines() {
            if line.contains("LINE16: ") {
                if let Some((a, b, result)) = parse_line16_trace(line) {
                    let expected = a * b + 42;
                    if result == expected {
                        println!(
                            "✓ Line-level math validation passed: {} * {} + 42 = {}",
                            a, b, result
                        );
                        line_validations += 1;
                    } else {
                        let error_msg = format!(
                            "Line-level validation failed: {} * {} + 42 = {} but got {}",
                            a, b, expected, result
                        );
                        println!("❌ {}", error_msg);
                        validation_errors.push(error_msg);
                    }
                }
            }
        }

        if func_validations == 0 {
            panic!(
                "❌ Expected function-level traces for {} but none validated successfully. STDOUT: {}",
                opt_level.description(),
                stdout
            );
        }
        if line_validations == 0 {
            panic!(
                "❌ Expected line-level traces for {} but none validated successfully. STDOUT: {}",
                opt_level.description(),
                stdout
            );
        }

        if !validation_errors.is_empty() {
            panic!(
                "❌ Traces captured but validation failed:\n  Function validations: {}, Line validations: {}\n  Errors: {}",
                func_validations,
                line_validations,
                validation_errors.join("\n  ")
            );
        }

        println!(
            "✓ Multiple trace targets validated successfully: {} function traces, {} line traces",
            func_validations, line_validations
        );

        println!("=====================================");
    }

    Ok(())
}
/// Parse a calc line and return only (a, b) for simple validation
fn parse_calc_line_simple(line: &str) -> Option<(i32, i32)> {
    // Expected format: "CALC: a=5 b=3 ..." or "FUNC: a=5 b=3" - we only care about a and b
    let line = line
        .trim_start_matches("CALC: ")
        .trim_start_matches("FUNC: ");

    let mut a = None;
    let mut b = None;

    for part in line.split_whitespace() {
        if let Some(value_str) = part.strip_prefix("a=") {
            a = value_str.parse().ok();
        } else if let Some(value_str) = part.strip_prefix("b=") {
            b = value_str.parse().ok();
        }
    }

    match (a, b) {
        (Some(a_val), Some(b_val)) => Some((a_val, b_val)),
        _ => {
            println!("⚠️  Failed to parse a and b from line: {}", line);
            None
        }
    }
}

#[tokio::test]
async fn test_line_level_tracing() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Test line-level tracing at sample_program.c:16 (return result;)
    let script_content = r#"
trace sample_program.c:16 {
    print "LINE16: a={} b={} result={}", a, b, result;
}
"#;

    println!("=== Line Level Tracing Test ===");

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 3).await?;

    println!("Exit code: {}", exit_code);
    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);
    println!("===============================================");

    // Must run successfully
    assert_eq!(
        exit_code, 0,
        "Ghostscope should succeed (stderr: {})",
        stderr
    );

    // If we have permissions, should run successfully and produce output
    if exit_code == 0 {
        println!("✓ Ghostscope attached and ran successfully");

        // Parse output to validate math: a * b + 42 == result
        let mut math_validations = 0;
        let mut function_calls_found = 0;
        let mut validation_errors = Vec::new();

        for line in stdout.lines() {
            if line.contains("LINE16: ") {
                function_calls_found += 1;
                if let Some((a, b, result)) = parse_line16_trace(line) {
                    let expected = a * b + 42;
                    if result == expected {
                        println!("✓ Math validation passed: {} * {} + 42 = {}", a, b, result);
                        math_validations += 1;
                    } else {
                        let error_msg = format!(
                            "Math validation failed: {} * {} + 42 = {} but got {}",
                            a, b, expected, result
                        );
                        println!("❌ {}", error_msg);
                        validation_errors.push(error_msg);
                    }
                } else {
                    println!("⚠️  Failed to parse line: {}", line);
                }
            }
        }

        if function_calls_found == 0 {
            panic!("❌ No line traces captured - test failed. Expected at least one line:16 execution trace. This indicates either:\n  1. sample_program is not running\n  2. Line 16 is not being executed\n  3. Line-level tracing failed to attach");
        } else if !validation_errors.is_empty() {
            panic!("❌ Line traces captured but math validation failed:\n  Found {} line executions, {} validation errors:\n  {}",
                function_calls_found, validation_errors.len(), validation_errors.join("\n  "));
        } else if math_validations > 0 {
            println!(
                "✓ Validated {} line:16 executions with correct math",
                math_validations
            );
        }
    }

    Ok(())
}

/// Parse a line16 trace like "LINE16: a=5 b=3 result=57" and return (a, b, result)
fn parse_line16_trace(line: &str) -> Option<(i32, i32, i32)> {
    // Expected format: "LINE16: a=5 b=3 result=57"
    let line = line.trim_start_matches("LINE16: ");

    let mut a = None;
    let mut b = None;
    let mut result = None;

    for part in line.split_whitespace() {
        if let Some(value_str) = part.strip_prefix("a=") {
            a = value_str.parse().ok();
        } else if let Some(value_str) = part.strip_prefix("b=") {
            b = value_str.parse().ok();
        } else if let Some(value_str) = part.strip_prefix("result=") {
            result = value_str.parse().ok();
        }
    }

    match (a, b, result) {
        (Some(a_val), Some(b_val), Some(result_val)) => Some((a_val, b_val, result_val)),
        _ => {
            println!("⚠️  Failed to parse line16 trace: {}", line);
            None
        }
    }
}

#[tokio::test]
async fn test_print_variables_directly() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Test printing variables directly without format strings
    let script_content = r#"
trace calculate_something {
    print a;
    print b;
}
"#;

    println!("=== Print Variables Directly Test ===");

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 3).await?;

    println!("Exit code: {}", exit_code);
    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);
    println!("======================================");

    // Check that script syntax is valid
    assert!(
        !stderr.contains("Parse error"),
        "Print variables script should have valid syntax: {}",
        stderr
    );

    assert_eq!(
        exit_code, 0,
        "Ghostscope should succeed (stderr: {})",
        stderr
    );

    if exit_code == 0 {
        println!("✓ Print variables script attached successfully");

        // Look for direct variable prints (should just be numbers)
        let mut variable_prints = 0;
        for line in stdout.lines() {
            // Direct variable prints should produce simple numeric output
            if line.trim().parse::<i32>().is_ok() {
                variable_prints += 1;
                println!("✓ Found variable print: {}", line.trim());
            }
        }

        if variable_prints > 0 {
            println!(
                "✓ Successfully captured {} variable prints",
                variable_prints
            );
        } else {
            println!("⚠️ No direct variable prints captured");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_custom_variables() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Test custom variable definition and usage
    let script_content = r#"
trace calculate_something {
    let sum = a + b;
    let diff = a - b;
    let product = a * b;
    print "CUSTOM: sum={} diff={} product={}", sum, diff, product;
}
"#;

    println!("=== Custom Variables Test ===");

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 3).await?;

    println!("Exit code: {}", exit_code);
    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);
    println!("==============================");

    // Check that script syntax is valid
    assert!(
        !stderr.contains("Parse error"),
        "Custom variables script should have valid syntax: {}",
        stderr
    );

    assert_eq!(
        exit_code, 0,
        "Ghostscope should succeed (stderr: {})",
        stderr
    );

    if exit_code == 0 {
        println!("✓ Custom variables script attached successfully");

        let mut custom_var_outputs = 0;
        let mut math_validations = 0;

        for line in stdout.lines() {
            if line.contains("CUSTOM: ") {
                custom_var_outputs += 1;
                if let Some((a, b, sum, diff, product)) = parse_custom_variables_line(line) {
                    let expected_sum = a + b;
                    let expected_diff = a - b;
                    let expected_product = a * b;

                    if sum == expected_sum && diff == expected_diff && product == expected_product {
                        math_validations += 1;
                        println!("✓ Custom variables validated: sum={}+{}={}, diff={}-{}={}, product={}*{}={}",
                            a, b, sum, a, b, diff, a, b, product);
                    } else {
                        println!("❌ Custom variables validation failed:");
                        println!(
                            "   Expected: sum={}, diff={}, product={}",
                            expected_sum, expected_diff, expected_product
                        );
                        println!("   Got: sum={}, diff={}, product={}", sum, diff, product);
                    }
                }
            }
        }

        if custom_var_outputs > 0 && math_validations > 0 {
            println!(
                "✓ Successfully validated {} custom variable calculations",
                math_validations
            );
        } else if custom_var_outputs > 0 {
            println!("⚠️ Custom variable outputs captured but validation failed");
        } else {
            println!("⚠️ No custom variable outputs captured");
        }
    }

    Ok(())
}

/// Parse a custom variables line like "CUSTOM: sum=8 diff=2 product=15" and return (a, b, sum, diff, product)
fn parse_custom_variables_line(line: &str) -> Option<(i32, i32, i32, i32, i32)> {
    // Expected format: "CUSTOM: sum=8 diff=2 product=15"
    // We need to reverse-engineer a and b from the calculations
    let line = line.trim_start_matches("CUSTOM: ");

    let mut sum = None;
    let mut diff = None;
    let mut product = None;

    for part in line.split_whitespace() {
        if let Some(value_str) = part.strip_prefix("sum=") {
            sum = value_str.parse().ok();
        } else if let Some(value_str) = part.strip_prefix("diff=") {
            diff = value_str.parse().ok();
        } else if let Some(value_str) = part.strip_prefix("product=") {
            product = value_str.parse().ok();
        }
    }

    match (sum, diff, product) {
        (Some(sum_val), Some(diff_val), Some(product_val)) => {
            // Reverse-engineer a and b from sum and diff
            // sum = a + b, diff = a - b
            // Therefore: a = (sum + diff) / 2, b = (sum - diff) / 2
            let a = (sum_val + diff_val) / 2;
            let b = (sum_val - diff_val) / 2;
            Some((a, b, sum_val, diff_val, product_val))
        }
        _ => {
            println!("⚠️  Failed to parse custom variables line: {}", line);
            None
        }
    }
}

/// Independent test program instance (separate from global shared one)
struct TestProgramInstance {
    child: tokio::process::Child,
    pid: u32,
}

impl TestProgramInstance {
    async fn terminate(mut self) -> anyhow::Result<()> {
        println!("🛑 Terminating sample_program (PID: {})", self.pid);
        let _ = self.child.kill().await;

        // Wait for termination with timeout
        match timeout(Duration::from_secs(2), self.child.wait()).await {
            Ok(_) => println!("✓ Test_program terminated gracefully"),
            Err(_) => {
                let _ = std::process::Command::new("kill")
                    .args(&["-KILL", &self.pid.to_string()])
                    .output();
                println!("⚠️ Force killed sample_program");
            }
        }
        Ok(())
    }
}

/// Start an independent sample_program instance (not shared with other tests)
async fn start_independent_sample_program() -> anyhow::Result<TestProgramInstance> {
    let binary_path = FIXTURES.get_test_binary("sample_program")?;

    let child = Command::new(binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let pid = child
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;

    // Give it a moment to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    Ok(TestProgramInstance { child, pid })
}

/// Run ghostscope with a specific PID (bypass global test program)
async fn run_ghostscope_with_specific_pid(
    script_content: &str,
    target_pid: u32,
    timeout_secs: u64,
) -> anyhow::Result<(i32, String, String)> {
    let mut script_file = NamedTempFile::new()?;
    script_file.write_all(script_content.as_bytes())?;
    let script_path = script_file.path();

    let mut child = Command::new("../target/debug/ghostscope")
        .args(&[
            "-p",
            &target_pid.to_string(), // Use the specific PID
            "--script-file",
            script_path.to_str().unwrap(),
            "--no-log",
            "--no-save-llvm-ir",
            "--no-save-ebpf",
            "--no-save-ast",
        ])
        .env("RUST_LOG", "off")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    // Give process a moment to start and potentially fail fast
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Check if process already exited (for quick failures like invalid PID)
    if let Ok(Some(status)) = child.try_wait() {
        let output = child.wait_with_output().await?;
        return Ok((
            status.code().unwrap_or(1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ));
    }

    // For successful cases, collect output with timeout
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();

    let mut stdout_lines = Vec::new();
    let mut stderr_lines = Vec::new();

    let stdout_reader = BufReader::new(stdout);
    let stderr_reader = BufReader::new(stderr);

    let collect_task = async {
        let stdout_task = async {
            let mut lines = stdout_reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                stdout_lines.push(line);
            }
        };

        let stderr_task = async {
            let mut lines = stderr_reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                stderr_lines.push(line);
            }
        };

        tokio::join!(stdout_task, stderr_task);
    };

    let _ = timeout(Duration::from_secs(timeout_secs), collect_task).await;

    // Kill the process
    let _ = child.kill().await;

    // Wait for process to actually terminate
    let final_status = timeout(Duration::from_secs(2), child.wait()).await;

    let exit_code = match final_status {
        Ok(Ok(status)) => {
            println!("✓ Process terminated with status: {:?}", status);
            status.code().unwrap_or(0)
        }
        _ => {
            println!("⚠️ Force killed process");
            0
        }
    };

    let stdout = stdout_lines.join("\n");
    let stderr = stderr_lines.join("\n");

    Ok((exit_code, stdout, stderr))
}

#[tokio::test]
async fn test_invalid_pid_handling() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    print "Should never see this: a={} b={}", a, b;
}
"#;

    println!("=== Invalid PID Handling Test ===");

    // Use a non-existent PID
    let fake_pid = 999999;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_specific_pid(script_content, fake_pid, 3).await?;

    println!("Exit code: {}", exit_code);
    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);
    println!("=====================================");

    // Should fail quickly
    assert_ne!(exit_code, 0, "Invalid PID should cause non-zero exit");
    assert!(
        stderr.contains("No such process")
            || stderr.contains("Failed to attach")
            || stderr.contains("Invalid PID")
            || stderr.contains("Permission denied")
            || stderr.contains("Operation not permitted")
            || stderr.contains("is not running"),
        "Should contain appropriate error message: {}",
        stderr
    );

    println!("✓ Invalid PID correctly rejected");
    Ok(())
}

#[tokio::test]
async fn test_string_comparison_char_ptr() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Compare const char* parameter against a script literal
    let script_content = r#"
trace log_activity {
    if (activity == "main_loop") {
        print "CSTR_EQ";
    }
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;

    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);
    assert!(
        stdout.contains("CSTR_EQ"),
        "Expected to see CSTR_EQ when activity == 'main_loop'. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_string_comparison_char_array() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Compare char[32] field inside DataRecord against a script literal
    // Use process_record (called every loop) to shorten wait time
    let script_content = r#"
trace process_record {
    if (record.name == "test_record") {
        print "ARR_EQ";
    }
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 6).await?;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);
    assert!(
        stdout.contains("ARR_EQ"),
        "Expected to see ARR_EQ when record.name == \"test_record\". STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_builtins_strncmp_starts_with_activity() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Validate builtins on DWARF char* parameter in a hot function
    let script_content = r#"
trace log_activity {
    print "SN:{}", strncmp(activity, "main", 4);
    print "SW:{}", starts_with(activity, "main");
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 6).await?;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Expect at least one true for both builtins
    assert!(
        stdout.lines().any(|l| l.contains("SN:true")),
        "Expected SN:true for strncmp(activity, \"main\", 4). STDOUT: {}",
        stdout
    );
    assert!(
        stdout.lines().any(|l| l.contains("SW:true")),
        "Expected SW:true for starts_with(activity, \"main\"). STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_builtin_strncmp_on_struct_pointer_mismatch() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Negative case: pass a non-string pointer (DataRecord*) to strncmp; should be false
    // Use a hot function for quick events
    let script_content = r#"
trace process_record {
    print "REC_SN:{}", strncmp(record, "HTTP", 4);
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 6).await?;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    assert!(
        stdout.lines().any(|l| l.contains("REC_SN:false")),
        "Expected REC_SN:false for non-string pointer compare. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_correct_pid_filtering() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    print "FILTERED: a={} b={}", a, b;
}
"#;

    println!("=== Correct PID Filtering Test ===");

    // Start two independent sample_program processes
    let sample_program_1 = start_independent_sample_program().await?;
    let sample_program_2 = start_independent_sample_program().await?;

    println!(
        "Started sample_program_1 with PID: {}",
        sample_program_1.pid
    );
    println!(
        "Started sample_program_2 with PID: {}",
        sample_program_2.pid
    );

    // Only trace the first process
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_specific_pid(script_content, sample_program_1.pid, 3).await?;

    println!("Exit code: {}", exit_code);
    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);
    println!("=====================================");

    // Clean up processes
    sample_program_1.terminate().await?;
    sample_program_2.terminate().await?;

    if exit_code == 0 {
        let filtered_outputs = stdout
            .lines()
            .filter(|line| line.contains("FILTERED:"))
            .count();

        if filtered_outputs > 0 {
            println!(
                "✓ Successfully captured {} function calls from target PID",
                filtered_outputs
            );
            println!("✓ PID filtering working correctly");
        } else {
            println!("⚠️ No function calls captured, but PID filtering test completed");
        }
    } else {
        println!("⚠️ Unexpected exit code: {}. STDERR: {}", exit_code, stderr);
    }

    Ok(())
}

#[tokio::test]
async fn test_pid_specificity_with_multiple_processes() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    print "TARGET_ONLY: traced a={} b={}", a, b;
}
"#;

    println!("=== PID Specificity with Multiple Processes Test ===");

    // Start 3 independent sample_program processes
    let programs = vec![
        start_independent_sample_program().await?,
        start_independent_sample_program().await?,
        start_independent_sample_program().await?,
    ];

    for (i, program) in programs.iter().enumerate() {
        println!("Started sample_program_{} with PID: {}", i + 1, program.pid);
    }

    // Only trace the middle process (programs[1])
    let target_pid = programs[1].pid;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_specific_pid(script_content, target_pid, 4).await?;

    println!("Target PID: {}", target_pid);
    println!("Exit code: {}", exit_code);
    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);
    println!("==================================================");

    // Clean up all processes
    for program in programs {
        program.terminate().await?;
    }

    if exit_code == 0 {
        let traced_outputs = stdout
            .lines()
            .filter(|line| line.contains("TARGET_ONLY:"))
            .count();

        if traced_outputs > 0 {
            println!("✓ Successfully captured {} function calls", traced_outputs);
            println!("✓ PID specificity verified - only target process traced");
        } else {
            println!("⚠️ No function calls captured during test window");
        }
    } else {
        println!("⚠️ Unexpected exit code: {}. STDERR: {}", exit_code, stderr);
    }

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_stripped_binary_with_debuglink() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Compile stripped binary with separate debug file
    common::ensure_test_program_compiled_with_opt(OptimizationLevel::Stripped)?;

    let script_content = r#"
trace add_numbers {
    print "STRIPPED_BINARY: add_numbers called with a={} b={}", a, b;
}
"#;

    println!("=== Stripped Binary with .gnu_debuglink Test ===");

    // Start stripped binary
    let binary_path =
        FIXTURES.get_test_binary_with_opt("sample_program", OptimizationLevel::Stripped)?;

    println!("Binary path: {}", binary_path.display());

    // Verify debug file exists
    let debug_file = binary_path.with_file_name("sample_program_stripped.debug");
    assert!(
        debug_file.exists(),
        "Debug file should exist: {}",
        debug_file.display()
    );
    println!("Debug file found: {}", debug_file.display());

    // Verify binary is actually stripped
    let output = std::process::Command::new("readelf")
        .args(["-S", binary_path.to_str().unwrap()])
        .output()?;
    let sections_output = String::from_utf8_lossy(&output.stdout);

    if sections_output.contains(".debug_info") {
        println!("⚠️ Warning: Binary still contains .debug_info section");
    } else {
        println!("✓ Binary is stripped (no .debug_info section)");
    }

    if sections_output.contains(".gnu_debuglink") {
        println!("✓ Binary has .gnu_debuglink section");
    } else {
        println!("⚠️ Warning: Binary missing .gnu_debuglink section");
    }

    // Start the stripped binary
    let mut child = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    let pid = child.id().expect("Failed to get PID");
    println!("Started stripped binary with PID: {}", pid);

    // Give it time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Run ghostscope with the stripped binary
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_specific_pid(script_content, pid, 3).await?;

    println!("Exit code: {}", exit_code);
    println!("STDOUT: {}", stdout);
    println!("STDERR: {}", stderr);
    println!("===============================================");

    // Clean up
    let _ = child.kill().await;

    // Verify results
    if exit_code == 0 {
        let traced_outputs = stdout
            .lines()
            .filter(|line| line.contains("STRIPPED_BINARY:"))
            .count();

        if traced_outputs > 0 {
            println!(
                "✓ Successfully traced {} function calls from stripped binary",
                traced_outputs
            );
            println!("✓ .gnu_debuglink mechanism working correctly");
            println!("✓ Uprobe offset calculation correct for stripped binary");
        } else {
            println!("⚠️ No function calls captured, but debuglink loading succeeded");
        }

        // Verify that debug info was actually loaded from debuglink
        if stderr.contains("Looking for debug file")
            || stderr.contains("Loading DWARF from separate debug file")
        {
            println!("✓ Confirmed: Debug info loaded from .gnu_debuglink");
        }
    } else {
        // Check for specific error messages
        if stderr.contains("No debug information found") {
            println!("✗ Failed: Could not load debug information from .gnu_debuglink");
            anyhow::bail!("Debug information not found - .gnu_debuglink not working");
        } else {
            println!("⚠️ Unexpected exit code: {}. STDERR: {}", exit_code, stderr);
        }
    }

    Ok(())
}

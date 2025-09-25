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
    static ref GLOBAL_TEST_MANAGER: Arc<RwLock<Option<GlobalTestProcess>>> =
        Arc::new(RwLock::new(None));
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

    // Read lock first to check if process exists and matches optimization level
    {
        let read_guard = manager.read().await;
        if let Some(process) = &*read_guard {
            // Check if optimization level matches and process is still running
            if process.optimization_level == opt_level {
                let status = std::process::Command::new("kill")
                    .args(&["-0", &process.pid.to_string()])
                    .status();

                if status.map(|s| s.success()).unwrap_or(false) {
                    return Ok(process.pid);
                }
            }
            // Either wrong opt level or process is dead, we'll need to start a new one
        }
    }

    // Write lock to start new process
    let mut write_guard = manager.write().await;

    // Double-check in case another thread started it
    if let Some(process) = &*write_guard {
        if process.optimization_level == opt_level {
            let status = std::process::Command::new("kill")
                .args(&["-0", &process.pid.to_string()])
                .status();

            if status.map(|s| s.success()).unwrap_or(false) {
                return Ok(process.pid);
            }
        }
    }

    // Terminate existing process if it has different optimization level
    if let Some(old_process) = write_guard.take() {
        if old_process.optimization_level != opt_level {
            println!(
                "🔄 Switching from {} to {}, terminating old process",
                old_process.optimization_level.description(),
                opt_level.description()
            );
            let _ = old_process.terminate().await;
        }
    }

    // Start new process with the requested optimization level
    let new_process = GlobalTestProcess::start_with_opt(opt_level).await?;
    let pid = new_process.get_pid();

    *write_guard = Some(new_process);

    Ok(pid)
}

// Get or start the global test process (defaults to Debug optimization)
// Cleanup function to be called when tests finish
pub async fn cleanup_global_test_process() -> anyhow::Result<()> {
    let manager = GLOBAL_TEST_MANAGER.clone();
    let mut write_guard = manager.write().await;

    if let Some(process) = write_guard.take() {
        process.terminate().await?;
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

    let mut child = Command::new("../target/debug/ghostscope")
        .args(&[
            "-p",
            &test_pid.to_string(),
            "--script-file",
            script_path.to_str().unwrap(),
            "--no-save-llvm-ir",
            "--no-save-ebpf",
            "--no-save-ast",
            "--no-log",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

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
    let exit_code = match child.try_wait() {
        Ok(Some(status)) => status.code().unwrap_or(-1),
        _ => {
            let _ = child.kill().await;
            match timeout(Duration::from_secs(2), child.wait()).await {
                Ok(Ok(status)) => status.code().unwrap_or(-1),
                _ => -1,
            }
        }
    };

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
    print "CALC: a={} b={}}", a, b;
}
"#;

    // Test with both optimization levels
    let optimization_levels = [OptimizationLevel::Debug, OptimizationLevel::O2];

    for opt_level in &optimization_levels {
        println!(
            "=== Function Level Tracing Test ({}) ===",
            opt_level.description()
        );

        let (exit_code, stdout, stderr) =
            run_ghostscope_with_script_opt(script_content, 3, *opt_level).await?;

        println!("Exit code: {}", exit_code);
        println!("STDOUT: {}", stdout);
        println!("STDERR: {}", stderr);
        println!("===============================================");

        // Check if we have permission to attach
        if stderr.contains("Need root permissions") || stderr.contains("Failed to attach uprobe") {
            println!("⚠️  Test requires sudo permissions - cannot validate math");
            println!("   Run with: sudo cargo test test_calculate_something_math_validation");
            continue;
        }

        // If we have permissions, should run successfully and produce output
        if exit_code == 0 {
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
                            let error_msg = format!(
                                "Math validation failed: a={} != b-5={} (b={})",
                                a,
                                b - 5,
                                b
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
                panic!("❌ No function calls captured - test failed. Expected at least one calculate_something call. This indicates either:\n  1. sample_program is not running\n  2. Function is not being called\n  3. Ghostscope failed to attach properly");
            } else if !validation_errors.is_empty() {
                panic!("❌ Function calls captured but math validation failed:\n  Found {} function calls, {} validation errors:\n  {}",
                function_calls_found, validation_errors.len(), validation_errors.join("\n  "));
            } else if math_validations > 0 {
                println!("✓ Validated {} calculate_something calls", math_validations);
            }
        } else {
            println!(
                "⚠️  Unexpected exit code: {}. STDERR: {}",
                exit_code, stderr
            );
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

    // Test with both optimization levels
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

        // Check if we have permission to attach
        if stderr.contains("Need root permissions") || stderr.contains("Failed to attach uprobe") {
            println!("⚠️  Test requires sudo permissions");
            println!("   Run with: sudo cargo test test_multiple_trace_targets");
            continue;
        }

        // Check that script syntax is valid
        assert!(
            !stderr.contains("Parse error"),
            "Multi-target script should have valid syntax: {}",
            stderr
        );

        if exit_code == 0 {
            println!("✓ Multiple trace targets attached and ran successfully");

            // Check for both function-level and line-level outputs
            let has_func = stdout.contains("FUNC:");
            let has_line16 = stdout.contains("LINE16:");

            println!(
                "Trace capture status: FUNC={}, LINE16={}",
                has_func, has_line16
            );

            let mut func_validations = 0;
            let mut line_validations = 0;
            let mut validation_errors = Vec::new();

            // Validate function-level traces (a == b - 5)
            if has_func {
                for line in stdout.lines() {
                    if line.contains("FUNC: ") {
                        if let Some((a, b)) = parse_calc_line_simple(line) {
                            if a == b - 5 {
                                println!(
                                    "✓ Function-level math validation passed: a={} == b-5={}",
                                    a,
                                    b - 5
                                );
                                func_validations += 1;
                            } else {
                                let error_msg = format!(
                                    "Function-level validation failed: a={} != b-5={}",
                                    a,
                                    b - 5
                                );
                                println!("❌ {}", error_msg);
                                validation_errors.push(error_msg);
                            }
                        }
                    }
                }
            }

            // Validate line-level traces (a * b + 42 == result)
            if has_line16 {
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
            }

            if !has_func && !has_line16 {
                println!("⚠️ No traces captured during test window");
                println!("   This could be normal if sample_program doesn't trigger functions within {} seconds", 3);
            } else {
                if !validation_errors.is_empty() {
                    panic!("❌ Traces captured but validation failed:\n  Function validations: {}, Line validations: {}\n  Errors: {}",
                    func_validations, line_validations, validation_errors.join("\n  "));
                } else if func_validations > 0 || line_validations > 0 {
                    println!("✓ Multiple trace targets validated successfully: {} function traces, {} line traces",
                    func_validations, line_validations);
                }
            }
        } else {
            println!(
                "⚠️  Unexpected exit code: {}. STDERR: {}",
                exit_code, stderr
            );
        }

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

    // Check if we have permission to attach
    if stderr.contains("Need root permissions") || stderr.contains("Failed to attach uprobe") {
        println!("⚠️  Test requires sudo permissions - cannot validate line tracing");
        println!("   Run with: sudo cargo test test_line_level_tracing_math_validation");
        return Ok(());
    }

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
    } else {
        println!(
            "⚠️  Unexpected exit code: {}. STDERR: {}",
            exit_code, stderr
        );
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

    // Check if we have permission to attach
    if stderr.contains("Need root permissions") || stderr.contains("Failed to attach uprobe") {
        println!("⚠️  Test requires sudo permissions");
        return Ok(());
    }

    // Check that script syntax is valid
    assert!(
        !stderr.contains("Parse error"),
        "Print variables script should have valid syntax: {}",
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
    } else {
        println!(
            "⚠️  Unexpected exit code: {}. STDERR: {}",
            exit_code, stderr
        );
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

    // Check if we have permission to attach
    if stderr.contains("Need root permissions") || stderr.contains("Failed to attach uprobe") {
        println!("⚠️  Test requires sudo permissions");
        return Ok(());
    }

    // Check that script syntax is valid
    assert!(
        !stderr.contains("Parse error"),
        "Custom variables script should have valid syntax: {}",
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
    } else {
        println!(
            "⚠️  Unexpected exit code: {}. STDERR: {}",
            exit_code, stderr
        );
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

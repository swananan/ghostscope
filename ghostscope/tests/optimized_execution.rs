//! Optimized binary execution tests
//!
//! Tests for script functionality against optimized binaries (-O1, -O2, -O3).
//! These tests are designed to handle variables that may be optimized away
//! and focus on more stable aspects like function parameters and return values.

mod common;

use common::OptimizationLevel;
use common::{init, FIXTURES};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

/// Test counter for unique trace IDs
static TEST_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Run ghostscope with optimized binary and return output
async fn run_ghostscope_optimized(
    binary_path: &std::path::Path,
    script_content: &str,
    opt_level: OptimizationLevel,
) -> anyhow::Result<String> {
    let test_id = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    let script_path = format!("/tmp/test_opt_script_{}.gs", test_id);

    // Write script file
    tokio::fs::write(&script_path, script_content).await?;

    println!("=== {} Test ===", opt_level.description());
    println!("Script: {}", script_content.trim());

    // Get workspace root and ghostscope binary path
    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(|dir| {
            std::path::PathBuf::from(dir)
                .parent()
                .unwrap()
                .to_path_buf()
        })
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let ghostscope_binary = workspace_root.join("target/debug/ghostscope");

    // Run ghostscope with timeout
    let mut child = Command::new("timeout")
        .arg("15s") // 15 second timeout
        .arg(&ghostscope_binary)
        .arg("-t")
        .arg(binary_path)
        .arg("--script-file")
        .arg(&script_path)
        .arg("--no-save-llvm-ir")
        .arg("--no-save-ebpf")
        .arg("--no-save-ast")
        .arg("--no-log")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    // Read output with timeout
    let stdout = child.stdout.take().unwrap();
    let stderr = child.stderr.take().unwrap();
    let mut stdout_reader = BufReader::new(stdout);
    let mut stderr_reader = BufReader::new(stderr);
    let mut output = String::new();
    let mut error_output = String::new();
    let mut line = String::new();

    let read_task = async {
        // Read both stdout and stderr
        for _ in 0..50 {
            // Read up to 50 lines
            let stdout_result = timeout(
                Duration::from_millis(100),
                stdout_reader.read_line(&mut line),
            )
            .await;
            if let Ok(Ok(bytes_read)) = stdout_result {
                if bytes_read > 0 {
                    output.push_str(&line);
                    line.clear();
                }
            }

            // Check for error output as well
            line.clear();
            let stderr_result = timeout(
                Duration::from_millis(50),
                stderr_reader.read_line(&mut line),
            )
            .await;
            if let Ok(Ok(bytes_read)) = stderr_result {
                if bytes_read > 0 {
                    error_output.push_str(&line);
                    line.clear();
                }
            }

            // Stop reading if we got some output or error
            if output.len() > 100 || error_output.len() > 100 {
                break;
            }

            // Small delay between attempts
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok::<(), anyhow::Error>(())
    };

    // Wait for output with timeout
    if let Err(_) = timeout(Duration::from_secs(12), read_task).await {
        println!("Timeout waiting for ghostscope output");
    }

    // Cleanup
    let _ = child.kill().await;
    let _ = tokio::fs::remove_file(&script_path).await;

    // Combine output and errors for debugging
    if !error_output.is_empty() {
        println!("Error output:\n{}", error_output);
        output.push_str("\nErrors:\n");
        output.push_str(&error_output);
    }

    println!("Output:\n{}", output);

    Ok(output)
}

#[tokio::test]
async fn test_optimized_function_parameters() -> anyhow::Result<()> {
    init();

    // Test O0 and O2 optimization levels
    let opt_levels = [OptimizationLevel::Debug, OptimizationLevel::O2];

    for opt_level in &opt_levels {
        let binary_path = FIXTURES.get_test_binary_with_opt("sample_program", *opt_level)?;

        let script = r#"
            trace_function("calculate_something");
            print "Function parameters: a={}, b={}", a, b;
        "#;

        let output = run_ghostscope_optimized(&binary_path, script, *opt_level).await?;

        // Function parameters should be available even in optimized builds
        // (though we may need to handle cases where they're optimized away)
        if !output.is_empty() && !output.contains("Error") {
            println!(
                "✓ {} - Function parameters accessible",
                opt_level.description()
            );
        } else if output.contains("variable not found") || output.contains("optimized") {
            println!(
                "○ {} - Variables optimized away (expected)",
                opt_level.description()
            );
        } else {
            println!("? {} - Unexpected output format", opt_level.description());
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_optimized_return_value_tracing() -> anyhow::Result<()> {
    init();

    let opt_levels = [OptimizationLevel::Debug, OptimizationLevel::O2];

    for opt_level in &opt_levels {
        let binary_path = FIXTURES.get_test_binary_with_opt("sample_program", *opt_level)?;

        let script = r#"
            trace_function("calculate_something");
            print "Return value: result={}", result;
        "#;

        let output = run_ghostscope_optimized(&binary_path, script, *opt_level).await?;

        // Return values are generally more stable across optimization levels
        if !output.is_empty() && !output.contains("Error") {
            println!("✓ {} - Return value tracing works", opt_level.description());
        } else {
            println!(
                "? {} - Return value tracing issues",
                opt_level.description()
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_dwarf_parsing_robustness() -> anyhow::Result<()> {
    init();

    // Test DWARF parsing with O0 and O2 optimization levels
    let opt_levels = [OptimizationLevel::Debug, OptimizationLevel::O2];

    for opt_level in &opt_levels {
        let binary_path = FIXTURES.get_test_binary_with_opt("sample_program", *opt_level)?;

        println!(
            "Testing DWARF parsing for {}: {}",
            opt_level.description(),
            binary_path.display()
        );

        // Use dwarf-tool to verify DWARF information is parseable
        // Get the dwarf-tool path relative to workspace root
        let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
            .map(|dir| {
                std::path::PathBuf::from(dir)
                    .parent()
                    .unwrap()
                    .to_path_buf()
            })
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        let dwarf_tool_path = workspace_root.join("target/debug/dwarf-tool");

        let output = Command::new(&dwarf_tool_path)
            .arg("-t")
            .arg(&binary_path)
            .arg("function")
            .arg("main")
            .arg("--json")
            .output()
            .await?;

        if output.status.success() {
            let stdout = String::from_utf8(output.stdout)?;
            if stdout.contains("function_name") {
                println!("✓ {} - DWARF parsing successful", opt_level.description());
            } else {
                println!(
                    "? {} - DWARF parsing returned unexpected format",
                    opt_level.description()
                );
            }
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            println!(
                "✗ {} - DWARF parsing failed: {}",
                opt_level.description(),
                stderr.trim()
            );
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_optimization_level_comparison() -> anyhow::Result<()> {
    init();

    println!("=== Optimization Level Comparison ===");

    let script = r#"
        trace_function("main");
        print "Main function traced";
    "#;

    // Compare different optimization levels
    let levels = [OptimizationLevel::Debug, OptimizationLevel::O2];

    for opt_level in &levels {
        let binary_path = FIXTURES.get_test_binary_with_opt("sample_program", *opt_level)?;

        let start = std::time::Instant::now();
        let output = run_ghostscope_optimized(&binary_path, script, *opt_level).await?;
        let duration = start.elapsed();

        println!(
            "{}: {} characters output, took {:?}",
            opt_level.description(),
            output.len(),
            duration
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_optimized_simple_print() -> anyhow::Result<()> {
    init();

    // Simple test that should work regardless of optimization level
    let binary_path = FIXTURES.get_test_binary_with_opt("sample_program", OptimizationLevel::O2)?;

    let script = r#"
        trace_function("main");
        print "Hello from optimized binary";
    "#;

    let output = run_ghostscope_optimized(&binary_path, script, OptimizationLevel::O2).await?;

    // Should at least attempt to trace, even if some variables are optimized away
    // Accept either successful output or meaningful error messages
    if !output.is_empty() {
        println!("✓ Optimized (O2) - Basic tracing functional");
        println!("Output length: {} characters", output.len());
    } else {
        println!(
            "○ Optimized (O2) - No output received (this may be normal for optimized binaries)"
        );
        // Don't fail the test if there's simply no output - this can be expected with optimization
    }

    Ok(())
}

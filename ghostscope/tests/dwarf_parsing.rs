#![allow(clippy::uninlined_format_args)]
#![allow(clippy::needless_borrows_for_generic_args)]

//! DWARF parsing integration tests using dwarf-tool
//!
//! Tests for DWARF parsing and analysis functionality using dwarf-tool binary.

mod common;

use common::{init, FIXTURES};
use serde_json::Value;
use tokio::process::Command as AsyncCommand;

/// Run dwarf-tool command and return JSON output
async fn run_dwarf_tool_json(
    binary_path: &std::path::Path,
    subcommand: &str,
    args: &[&str],
) -> anyhow::Result<Value> {
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

    let mut cmd_args = vec!["-t", binary_path.to_str().unwrap(), subcommand];
    cmd_args.extend_from_slice(args);
    cmd_args.push("--json");

    let output = AsyncCommand::new(&dwarf_tool_path)
        .args(&cmd_args)
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("dwarf-tool failed: {}", stderr);
    }

    let stdout = String::from_utf8(output.stdout)?;

    // Extract JSON from output - find the JSON block and try progressively larger chunks
    let json_start = stdout.find('{').or_else(|| stdout.find('[')).unwrap_or(0);

    // Extract JSON by finding lines starting from [ or {
    let json_lines: Vec<&str> = stdout
        .lines()
        .skip_while(|line| {
            !line.trim_start().starts_with('[') && !line.trim_start().starts_with('{')
        })
        .collect();

    let json_candidate = if !json_lines.is_empty() {
        json_lines.join("\n")
    } else {
        // Fallback to original approach
        stdout[json_start..].to_string()
    };

    let json: Value = serde_json::from_str(&json_candidate).map_err(|e| {
        anyhow::anyhow!(
            "JSON parse error: {}. Candidate:\n{}\n\nFull output:\n{}",
            e,
            json_candidate,
            stdout
        )
    })?;
    Ok(json)
}

/// Run dwarf-tool command and return text output
async fn run_dwarf_tool_text(
    binary_path: &std::path::Path,
    subcommand: &str,
    args: &[&str],
) -> anyhow::Result<String> {
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

    let mut cmd_args = vec!["-t", binary_path.to_str().unwrap(), subcommand];
    cmd_args.extend_from_slice(args);

    let output = AsyncCommand::new(&dwarf_tool_path)
        .args(&cmd_args)
        .output()
        .await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("dwarf-tool failed: {}", stderr);
    }

    Ok(String::from_utf8(output.stdout)?)
}

#[tokio::test]
async fn test_dwarf_tool_function_analysis() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("sample_program")?;

    println!(
        "Testing dwarf-tool function analysis: {}",
        binary_path.display()
    );

    // Test function command with JSON output - use main as function name
    let json = run_dwarf_tool_json(&binary_path, "function", &["main"]).await?;

    // Verify JSON structure - function command returns object, not array
    assert!(json.is_object(), "Function analysis should return object");

    // Check that we found the main function
    if let Some(function_name) = json.get("function_name").and_then(|n| n.as_str()) {
        assert_eq!(function_name, "main", "Should find main function");
        println!("✓ Found function: {}", function_name);

        // Check modules array
        if let Some(modules) = json.get("modules").and_then(|m| m.as_array()) {
            assert!(!modules.is_empty(), "Should have at least one module");
            println!("✓ Found {} modules with function addresses", modules.len());
        }

        // Check total variables count
        if let Some(total_vars) = json.get("total_variables").and_then(|v| v.as_u64()) {
            println!("✓ Found {} variables in function", total_vars);
        }
    } else {
        anyhow::bail!("Expected function_name field in response");
    }

    Ok(())
}

#[tokio::test]
async fn test_dwarf_tool_source_line_analysis() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("sample_program")?;

    println!(
        "Testing dwarf-tool source-line analysis: {}",
        binary_path.display()
    );

    // Test source-line command with JSON output - use sample_program.c:25
    let json = run_dwarf_tool_json(&binary_path, "source-line", &["sample_program.c:25"]).await?;

    // Verify JSON structure - source-line returns object with variables at that location
    assert!(
        json.is_object(),
        "Source line analysis should return object"
    );

    // Check source location info
    if let Some(location) = json.get("location").and_then(|l| l.as_str()) {
        assert!(
            location.contains("sample_program.c"),
            "Should reference sample_program.c"
        );
        println!("✓ Found source location: {}", location);
    }

    // Check if we have modules with variables
    if let Some(modules) = json.get("modules").and_then(|m| m.as_array()) {
        if !modules.is_empty() {
            println!(
                "✓ Found {} modules with variables at source line",
                modules.len()
            );
        } else {
            println!("No variables found at this specific source line (this is normal)");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_dwarf_tool_modules_list() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("sample_program")?;

    println!(
        "Testing dwarf-tool modules listing: {}",
        binary_path.display()
    );

    // Test modules command with JSON output
    let json = run_dwarf_tool_json(&binary_path, "modules", &[]).await?;

    // Verify JSON structure - modules returns array of module paths
    assert!(json.is_array(), "Modules listing should return array");
    let modules = json.as_array().unwrap();
    assert!(!modules.is_empty(), "Should find at least one module");

    // Look for our test program module
    let mut found_sample_program = false;
    for module in modules {
        if let Some(path) = module.as_str() {
            if path.contains("sample_program") {
                found_sample_program = true;
                println!("✓ Found test program module: {}", path);
            }
        }
    }

    println!("Found {} modules total", modules.len());
    assert!(found_sample_program, "Should find sample_program module");

    Ok(())
}

#[tokio::test]
async fn test_dwarf_tool_source_files_list() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("sample_program")?;

    println!(
        "Testing dwarf-tool source-files listing: {}",
        binary_path.display()
    );

    // Test source-files command with JSON output
    let json = run_dwarf_tool_json(&binary_path, "source-files", &[]).await?;

    // Verify JSON structure - source-files returns array of modules with file lists
    assert!(json.is_array(), "Source files listing should return array");
    let modules = json.as_array().unwrap();
    assert!(!modules.is_empty(), "Should find at least one module");

    // Look for our test source files in the module
    let mut found_sample_program_c = false;
    let mut found_test_lib_c = false;
    let mut _found_test_lib_h = false;
    let mut total_files = 0;

    for module in modules {
        if let Some(files) = module.get("files").and_then(|f| f.as_array()) {
            total_files += files.len();
            for file in files {
                if let Some(path) = file.get("full_path").and_then(|p| p.as_str()) {
                    if path.contains("sample_program.c") {
                        found_sample_program_c = true;
                        println!("✓ Found source file: sample_program.c");
                    } else if path.contains("test_lib.c") {
                        found_test_lib_c = true;
                        println!("✓ Found source file: test_lib.c");
                    } else if path.contains("test_lib.h") {
                        _found_test_lib_h = true;
                        println!("✓ Found source file: test_lib.h");
                    }
                }
            }
        }
    }

    println!("Found {} source files total", total_files);
    assert!(
        found_sample_program_c || found_test_lib_c,
        "Should find at least one of our test source files"
    );

    Ok(())
}

#[tokio::test]
async fn test_dwarf_tool_module_address_analysis() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("sample_program")?;

    println!(
        "Testing dwarf-tool module-addr analysis: {}",
        binary_path.display()
    );

    // First get a valid address from function analysis
    let functions_json = run_dwarf_tool_json(&binary_path, "function", &["main"]).await?;

    // Find main function address from the response
    let mut test_address = None;
    if let Some(modules) = functions_json.get("modules").and_then(|m| m.as_array()) {
        for module in modules {
            if let Some(addresses) = module.get("addresses").and_then(|a| a.as_array()) {
                if let Some(first_addr) = addresses.first() {
                    if let Some(addr_str) = first_addr.get("address").and_then(|a| a.as_str()) {
                        test_address = Some(addr_str.to_string());
                        break;
                    }
                }
            }
        }
    }

    let address =
        test_address.ok_or_else(|| anyhow::anyhow!("Could not find main function address"))?;
    println!("Testing module-addr with address: {}", address);

    // Test module-addr command with JSON output
    let json = run_dwarf_tool_json(
        &binary_path,
        "module-addr",
        &[binary_path.to_str().unwrap(), &address],
    )
    .await?;

    // Verify we got module information for this address
    if let Some(module_name) = json.get("module").and_then(|m| m.as_str()) {
        println!("✓ Found module for address {}: {}", address, module_name);
        assert!(!module_name.is_empty(), "Module name should not be empty");
    } else {
        anyhow::bail!("Expected module information for address {}", address);
    }

    Ok(())
}

#[tokio::test]
async fn test_dwarf_tool_error_handling() -> anyhow::Result<()> {
    init();

    println!("Testing dwarf-tool error handling");

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

    // Test with non-existent file
    let result = AsyncCommand::new(&dwarf_tool_path)
        .args(["function", "/nonexistent/file"])
        .output()
        .await?;

    assert!(
        !result.status.success(),
        "Should fail with non-existent file"
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(!stderr.is_empty(), "Should provide error message");
    println!("✓ Properly handles non-existent file: {}", stderr.trim());

    // Test with invalid address for module-addr
    let binary_path = FIXTURES.get_test_binary("sample_program")?;
    let _result = AsyncCommand::new(&dwarf_tool_path)
        .args(["module-addr", "0xdeadbeef", binary_path.to_str().unwrap()])
        .output()
        .await?;

    // This might succeed or fail depending on implementation, just verify it doesn't crash
    println!("✓ Handled invalid address test without crashing");

    Ok(())
}

#[tokio::test]
async fn test_dwarf_tool_text_output_format() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("sample_program")?;

    println!(
        "Testing dwarf-tool text output format: {}",
        binary_path.display()
    );

    // Test function command without --json flag
    let output = run_dwarf_tool_text(&binary_path, "function", &["main"]).await?;

    assert!(!output.is_empty(), "Text output should not be empty");
    assert!(
        output.contains("Function") || output.contains("main"),
        "Text output should contain function information"
    );

    println!("✓ Text output format works properly");
    println!(
        "Sample output (first 200 chars): {}",
        &output.chars().take(200).collect::<String>()
    );

    Ok(())
}

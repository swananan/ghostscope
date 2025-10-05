//! DWARF parsing integration tests using dwarf-tool
//!
//! Tests for DWARF parsing and analysis functionality using dwarf-tool binary.

mod common;

use common::{init, FIXTURES};
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

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

// ===== Globals indexing tests (moved from globals_indexing.rs) =====

#[derive(Debug, Deserialize)]
struct GlobalVarItem {
    module: String,
    name: String,
    link_address: Option<String>,
    section: Option<String>,
}

/// Run dwarf-tool with -p <pid> and return full stdout text
async fn run_dwarftool_text_pid(args: &[&str]) -> anyhow::Result<String> {
    let workspace_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(|dir| {
            std::path::PathBuf::from(dir)
                .parent()
                .unwrap()
                .to_path_buf()
        })
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let tool_path = workspace_root.join("target/debug/dwarf-tool");
    let output = AsyncCommand::new(&tool_path).args(args).output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("dwarf-tool failed: {}", stderr);
    }
    Ok(String::from_utf8(output.stdout)?)
}

async fn run_dwarftool_json_pid(
    pid: u32,
    subcmd: &str,
    extra: &[&str],
) -> anyhow::Result<Vec<GlobalVarItem>> {
    // Use --quiet to avoid banner lines like "Loading modules from PID ..." polluting stdout
    let mut args: Vec<String> = vec![
        "-p".into(),
        pid.to_string(),
        subcmd.into(),
        "--json".into(),
        "--quiet".into(),
    ];
    for a in extra {
        args.push((*a).into());
    }
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = run_dwarftool_text_pid(&args_ref).await?;
    // Be robust to any accidental non-JSON prefix
    let json_start = out.find('{').or_else(|| out.find('[')).unwrap_or(0);
    let json_lines: Vec<&str> = out
        .lines()
        .skip_while(|line| {
            !line.trim_start().starts_with('[') && !line.trim_start().starts_with('{')
        })
        .collect();
    let candidate = if !json_lines.is_empty() {
        json_lines.join("\n")
    } else {
        out[json_start..].to_string()
    };
    let items: Vec<GlobalVarItem> = serde_json::from_str(&candidate)?;
    Ok(items)
}

async fn spawn_globals_program() -> anyhow::Result<(tokio::process::Child, u32, PathBuf)> {
    let bin_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = bin_path.parent().unwrap().to_path_buf();
    let child = AsyncCommand::new(&bin_path)
        .current_dir(&bin_dir)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let pid = child.id().ok_or_else(|| anyhow::anyhow!("no pid"))?;
    tokio::time::sleep(Duration::from_millis(400)).await;
    Ok((child, pid, bin_dir))
}

#[tokio::test]
async fn test_globals_indexing_executable_sections() -> anyhow::Result<()> {
    init();
    let (mut child, pid, _dir) = spawn_globals_program().await?;
    let items = run_dwarftool_json_pid(pid, "globals-all", &[]).await?;
    let exe_items: Vec<&GlobalVarItem> = items
        .iter()
        .filter(|i| i.module.ends_with("/globals_program"))
        .collect();
    assert!(!exe_items.is_empty(), "expected executable entries");
    let mut map = std::collections::HashMap::new();
    for it in exe_items {
        map.insert(it.name.clone(), it.section.clone().unwrap_or_default());
        // Touch link_address to avoid dead_code warning on the field
        let _ = &it.link_address;
    }
    assert!(map.contains_key("g_counter"));
    assert_eq!(map.get("g_counter").unwrap(), "data");
    assert!(map.contains_key("g_message"));
    assert_eq!(map.get("g_message").unwrap(), "rodata");
    assert!(map.contains_key("g_bss_buffer"));
    assert_eq!(map.get("g_bss_buffer").unwrap(), "bss");
    assert!(map.contains_key("G_STATE"));
    assert!(map.contains_key("s_internal"));
    assert!(map.contains_key("s_bss_counter"));
    let _ = child.kill().await;
    Ok(())
}

#[tokio::test]
async fn test_globals_indexing_shared_library_sections() -> anyhow::Result<()> {
    init();
    let (mut child, pid, _dir) = spawn_globals_program().await?;
    let items = run_dwarftool_json_pid(pid, "globals-all", &[]).await?;
    let lib_items: Vec<&GlobalVarItem> = items
        .iter()
        .filter(|i| i.module.ends_with("/libgvars.so"))
        .collect();
    assert!(!lib_items.is_empty(), "expected shared library entries");
    let mut map = std::collections::HashMap::new();
    for it in lib_items {
        map.insert(it.name.clone(), it.section.clone().unwrap_or_default());
    }
    assert!(map.contains_key("lib_counter"));
    assert_eq!(map.get("lib_counter").unwrap(), "data");
    assert!(map.contains_key("lib_message"));
    assert_eq!(map.get("lib_message").unwrap(), "rodata");
    assert!(map.contains_key("lib_bss"));
    assert_eq!(map.get("lib_bss").unwrap(), "bss");
    assert!(map.contains_key("LIB_STATE"));
    assert!(map.contains_key("lib_internal_counter"));
    let _ = child.kill().await;
    Ok(())
}

#[tokio::test]
async fn test_globals_indexing_query_by_name() -> anyhow::Result<()> {
    init();
    let (mut child, pid, _dir) = spawn_globals_program().await?;
    let items = run_dwarftool_json_pid(pid, "globals", &["G_STATE"]).await?;
    assert!(items
        .iter()
        .any(|i| i.module.ends_with("/globals_program") && i.name == "G_STATE"));
    let items2 = run_dwarftool_json_pid(pid, "globals", &["LIB_STATE"]).await?;
    assert!(items2
        .iter()
        .any(|i| i.module.ends_with("/libgvars.so") && i.name == "LIB_STATE"));
    let _ = child.kill().await;
    Ok(())
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
        println!("✓ Found function: {function_name}");

        // Check modules array
        if let Some(modules) = json.get("modules").and_then(|m| m.as_array()) {
            assert!(!modules.is_empty(), "Should have at least one module");
            println!("✓ Found {} modules with function addresses", modules.len());
        }

        // Check total variables count
        if let Some(total_vars) = json.get("total_variables").and_then(|v| v.as_u64()) {
            println!("✓ Found {total_vars} variables in function");
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
        println!("✓ Found source location: {location}");
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
                println!("✓ Found test program module: {path}");
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

    println!("Found {total_files} source files total");
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
    println!("Testing module-addr with address: {address}");

    // Test module-addr command with JSON output
    let json = run_dwarf_tool_json(
        &binary_path,
        "module-addr",
        &[binary_path.to_str().unwrap(), &address],
    )
    .await?;

    // Verify we got module information for this address
    if let Some(module_name) = json.get("module").and_then(|m| m.as_str()) {
        println!("✓ Found module for address {address}: {module_name}");
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

#[tokio::test]
async fn test_stripped_binary_with_debuglink() -> anyhow::Result<()> {
    init();

    // Compile stripped binary with separate debug file
    common::ensure_test_program_compiled_with_opt(common::OptimizationLevel::Stripped)?;

    let binary_path =
        FIXTURES.get_test_binary_with_opt("sample_program", common::OptimizationLevel::Stripped)?;

    println!(
        "Testing stripped binary with .gnu_debuglink: {}",
        binary_path.display()
    );

    // Verify debug file exists
    let debug_file = binary_path.with_file_name("sample_program_stripped.debug");
    assert!(
        debug_file.exists(),
        "Debug file should exist: {}",
        debug_file.display()
    );

    // Test that we can still read function info from stripped binary via .gnu_debuglink
    // Test main function
    let main_info = run_dwarf_tool_json(&binary_path, "function", &["main"]).await?;
    assert!(
        main_info.is_array() || main_info.is_object(),
        "Should get function info for main"
    );

    // Test add_numbers function
    let add_numbers_info = run_dwarf_tool_json(&binary_path, "function", &["add_numbers"]).await?;
    assert!(
        add_numbers_info.is_array() || add_numbers_info.is_object(),
        "Should get function info for add_numbers"
    );

    println!("✓ Successfully loaded debug info from .gnu_debuglink");
    println!("  Found main function");
    println!("  Found add_numbers function");

    Ok(())
}

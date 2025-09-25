#![allow(clippy::uninlined_format_args)]

mod cli;
mod config;
mod core;
mod logging;
mod runtime;
mod script;
mod tracing;

use anyhow::Result;
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
use std::io::{self, Write};

fn setup_panic_hook() {
    // Use existing RUST_BACKTRACE setting from environment

    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // Flush any pending output before terminal restore
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();

        // Attempt to restore terminal state
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = io::stdout().flush();

        // Print panic information to stderr with immediate flushing
        eprintln!("\n=== GHOSTSCOPE PANIC ===");
        let _ = io::stderr().flush();

        eprintln!(
            "Location: {}",
            panic_info
                .location()
                .unwrap_or_else(|| std::panic::Location::caller())
        );
        let _ = io::stderr().flush();

        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            eprintln!("Message: {s}");
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            eprintln!("Message: {s}");
        } else {
            eprintln!("Message: (no message available)");
        }
        let _ = io::stderr().flush();

        // Print backtrace if available
        eprintln!("\nBacktrace:");
        let _ = io::stderr().flush();

        let backtrace = std::backtrace::Backtrace::force_capture();
        eprintln!("{backtrace}");
        let _ = io::stderr().flush();

        eprintln!("======================");
        eprintln!("Terminal state has been restored. You can now see this panic message.");
        eprintln!("Please report this issue at: https://github.com/swananan/ghostscope/issues");
        let _ = io::stderr().flush();

        // Call the original hook to preserve any additional panic handling
        original_hook(panic_info);
    }));
}

#[tokio::main]
async fn main() -> Result<()> {
    // Setup panic hook before doing anything else
    setup_panic_hook();

    // Parse command line arguments
    let parsed_args = config::Args::parse_args();

    // Load and merge configuration
    let config_path = parsed_args.config.clone();
    let merged_config =
        match config::MergedConfig::new_with_explicit_config(parsed_args, config_path) {
            Ok(config) => config,
            Err(e) => {
                eprintln!("❌ Configuration Error:\n{e}");
                eprintln!("\n💡 Tips:");
                eprintln!("  • Check the example config.toml in the project root");
                eprintln!("  • Verify TOML syntax is correct");
                eprintln!("  • Ensure all values use the correct format");
                std::process::exit(1);
            }
        };

    // Initialize logging with full configuration
    let log_file_string = merged_config.log_file.to_string_lossy().to_string();
    let log_file_path = Some(log_file_string.as_str());
    if let Err(e) = logging::initialize_logging_with_config(
        log_file_path,
        merged_config.enable_logging,
        merged_config.log_level,
        merged_config.tui_mode,
    ) {
        eprintln!("Failed to initialize logging: {e}");
        return Err(anyhow::anyhow!("Failed to initialize logging: {}", e));
    }

    // Validate core arguments (TODO: move validation to MergedConfig)
    // For now, create a temporary ParsedArgs for validation
    let temp_args = config::ParsedArgs {
        binary_path: merged_config.binary_path.clone(),
        target_path: merged_config.target_path.clone(),
        binary_args: merged_config.binary_args.clone(),
        log_file: Some(merged_config.log_file.clone()),
        enable_logging: merged_config.enable_logging,
        log_level: merged_config.log_level,
        config: None, // Not needed for validation
        debug_file: merged_config.debug_file.clone(),
        script: merged_config.script.clone(),
        script_file: merged_config.script_file.clone(),
        pid: merged_config.pid,
        tui_mode: merged_config.tui_mode,
        should_save_llvm_ir: merged_config.should_save_llvm_ir,
        should_save_ebpf: merged_config.should_save_ebpf,
        should_save_ast: merged_config.should_save_ast,
        layout_mode: merged_config.layout_mode,
        has_explicit_log_flag: false, // Not needed for validation
    };
    temp_args.validate()?;

    // Route to appropriate runtime mode
    if merged_config.tui_mode {
        runtime::run_tui_coordinator_with_config(merged_config).await
    } else {
        cli::run_command_line_runtime_with_config(merged_config).await
    }
}

mod args;
mod cli;
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
            eprintln!("Message: {}", s);
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            eprintln!("Message: {}", s);
        } else {
            eprintln!("Message: (no message available)");
        }
        let _ = io::stderr().flush();

        // Print backtrace if available
        eprintln!("\nBacktrace:");
        let _ = io::stderr().flush();

        let backtrace = std::backtrace::Backtrace::force_capture();
        eprintln!("{}", backtrace);
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

    let parsed_args = args::Args::parse_args();

    // Initialize logging
    let log_file_path = parsed_args.log_file.as_ref().and_then(|p| p.to_str());
    if let Err(e) = logging::initialize_logging(
        log_file_path,
        if parsed_args.tui_mode { true } else { false },
    ) {
        eprintln!("Failed to initialize logging: {}", e);
        return Err(anyhow::anyhow!("Failed to initialize logging: {}", e));
    }

    // Validate arguments
    parsed_args.validate()?;

    // Route to appropriate runtime mode
    if parsed_args.tui_mode {
        runtime::run_tui_coordinator(parsed_args).await
    } else {
        cli::run_command_line_runtime(parsed_args).await
    }
}

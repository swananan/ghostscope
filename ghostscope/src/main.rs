mod args;
mod command_line;
mod logging;
mod script_compiler;
mod session;
mod trace_manager;
mod tui_coordinator;

use anyhow::Result;
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
use std::io::{self, Write};

fn setup_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        // Attempt to restore terminal state
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);

        // Print panic information to stderr (which should be visible after terminal restore)
        eprintln!("\n=== GHOSTSCOPE PANIC ===");
        eprintln!(
            "Location: {}",
            panic_info
                .location()
                .unwrap_or_else(|| std::panic::Location::caller())
        );

        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            eprintln!("Message: {}", s);
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            eprintln!("Message: {}", s);
        } else {
            eprintln!("Message: (no message available)");
        }

        eprintln!("======================");
        eprintln!("Terminal state has been restored. You can now see this panic message.");
        eprintln!("Please report this issue at: https://github.com/anthropics/claude-code/issues");

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
        tui_coordinator::run_tui_coordinator(parsed_args).await
    } else {
        command_line::run_command_line_runtime(parsed_args).await
    }
}

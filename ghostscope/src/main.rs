mod args;
mod command_line;
mod logging;
mod script_compiler;
mod session;
mod trace_manager;
mod tui_coordinator;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
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

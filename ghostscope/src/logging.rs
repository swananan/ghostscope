use anyhow::Result;
use std::path::PathBuf;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

const DEFAULT_LOG_FILE: &str = "ghostscope.log";

pub fn initialize_logging(log_file_path: Option<&str>, tui_mode: bool) -> Result<()> {
    eprintln!("Starting logging initialization...");

    // Initialize log to tracing adapter to capture aya's log:: output
    match tracing_log::LogTracer::init() {
        Ok(()) => eprintln!("LogTracer initialized successfully"),
        Err(e) => eprintln!("Warning: Failed to initialize log tracer: {}", e),
    }

    // Set up the log level for detailed debugging - include aya debug logs
    let rust_log = "debug,ghostscope=debug,ghostscope_compiler=debug,ghostscope_loader=debug,aya=debug,aya_obj=debug";
    std::env::set_var("RUST_LOG", rust_log);
    eprintln!("Set RUST_LOG to: {}", rust_log);

    // Determine log file path: use provided path or default to current directory
    let log_path = match log_file_path {
        Some(path) => PathBuf::from(path),
        None => std::env::current_dir()?.join(DEFAULT_LOG_FILE),
    };

    // Try to create log file, but continue if it fails
    let maybe_log_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&log_path);

    match maybe_log_file {
        Ok(log_file) => {
            eprintln!("Successfully created log file: {}", log_path.display());

            // Configure file output
            let file_subscriber = tracing_subscriber::fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_writer(log_file)
                .with_target(true)
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::EnvFilter::from_default_env());

            if tui_mode {
                // TUI mode: only log to file
                match tracing_subscriber::registry()
                    .with(file_subscriber)
                    .try_init()
                {
                    Ok(()) => eprintln!(
                        "Tracing subscriber initialized successfully (file-only for TUI mode)"
                    ),
                    Err(e) => eprintln!("Warning: Failed to initialize tracing subscriber: {}", e),
                }
            } else {
                // Non-TUI mode: dual output to file and stdout
                match tracing_subscriber::registry()
                    .with(file_subscriber)
                    .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
                    .try_init()
                {
                    Ok(()) => eprintln!(
                        "Tracing subscriber initialized successfully with file and stdout output"
                    ),
                    Err(e) => eprintln!("Warning: Failed to initialize tracing subscriber: {}", e),
                }
            }

            eprintln!("Tracing subscriber initialized successfully");
        }
        Err(_) => {
            // Fallback to stdout only if file creation fails
            match tracing_subscriber::fmt()
                .with_file(true)
                .with_line_number(true)
                .with_target(true)
                .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
                .try_init()
            {
                Ok(()) => eprintln!("Tracing subscriber initialized successfully (stdout only)"),
                Err(e) => eprintln!("Warning: Failed to initialize tracing subscriber: {}", e),
            }

            eprintln!("Warning: Could not create log file, using stdout only");
        }
    }

    Ok(())
}

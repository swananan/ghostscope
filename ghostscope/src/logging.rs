use anyhow::Result;
use std::path::PathBuf;
use std::sync::OnceLock;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

const DEFAULT_LOG_FILE: &str = "ghostscope.log";

static INIT_GUARD: OnceLock<()> = OnceLock::new();

/// Initialize logging with enhanced configuration options
pub fn initialize_logging_with_config(
    log_file_path: Option<&str>,
    enable_logging: bool,
    log_level: crate::config::LogLevel,
    tui_mode: bool,
) -> Result<()> {
    if INIT_GUARD.set(()).is_err() {
        // Already initialized elsewhere; do nothing and succeed
        return Ok(());
    }

    // If logging is disabled, set up a minimal subscriber that discards everything
    if !enable_logging {
        let init_res = tracing_subscriber::registry()
            .with(tracing_subscriber::filter::LevelFilter::OFF)
            .try_init();
        let _ = init_res;
        return Ok(());
    }

    // Initialize log to tracing adapter to capture aya's log:: output
    // Initialize LogTracer but ignore 'already set' errors to avoid noisy output
    let _ = tracing_log::LogTracer::init();

    // Convert our LogLevel to tracing LevelFilter
    let level_filter = log_level.to_tracing_level_filter();

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
            // Configure file output with level filter
            let file_subscriber = tracing_subscriber::fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_writer(log_file)
                .with_target(true)
                .with_ansi(false)
                .with_filter(level_filter);

            if tui_mode {
                // TUI mode: only log to file
                let init_res = tracing_subscriber::registry()
                    .with(file_subscriber)
                    .try_init();
                let _ = init_res; // ignore AlreadyInit errors silently
            } else {
                // Non-TUI mode: dual output to file and stdout with level filter
                let stdout_subscriber = tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stdout)
                    .with_filter(level_filter);

                let init_res = tracing_subscriber::registry()
                    .with(file_subscriber)
                    .with(stdout_subscriber)
                    .try_init();
                let _ = init_res;
            }
        }
        Err(_) => {
            // Fallback to stdout only if file creation fails
            let init_res = tracing_subscriber::fmt()
                .with_file(true)
                .with_line_number(true)
                .with_target(true)
                .with_max_level(level_filter)
                .try_init();
            let _ = init_res;
        }
    }

    Ok(())
}

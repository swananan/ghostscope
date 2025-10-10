use anyhow::Result;
use std::path::PathBuf;
use std::sync::OnceLock;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const DEFAULT_LOG_FILE: &str = "ghostscope.log";

static INIT_GUARD: OnceLock<()> = OnceLock::new();

/// Initialize logging with enhanced configuration options
pub fn initialize_logging_with_config(
    log_file_path: Option<&str>,
    enable_logging: bool,
    enable_console_logging: bool,
    log_level: crate::config::LogLevel,
    _tui_mode: bool,
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

    // Build EnvFilter from RUST_LOG if present; otherwise fall back to configured log_level
    // This enables module-level filtering like: RUST_LOG="info,ghostscope_loader=debug,ghostscope_protocol=debug"
    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level.to_string()));

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
            // Configure file output
            let file_layer = tracing_subscriber::fmt::layer()
                .with_file(true)
                .with_line_number(true)
                .with_writer(log_file)
                .with_target(true)
                .with_ansi(false);

            if enable_console_logging {
                // Console logging enabled: dual output to file and stdout with level filter
                let stdout_layer = tracing_subscriber::fmt::layer().with_writer(std::io::stdout);

                let init_res = tracing_subscriber::registry()
                    .with(env_filter)
                    .with(file_layer)
                    .with(stdout_layer)
                    .try_init();
                let _ = init_res;
            } else {
                // Console logging disabled: only log to file
                let init_res = tracing_subscriber::registry()
                    .with(env_filter)
                    .with(file_layer)
                    .try_init();
                let _ = init_res; // ignore AlreadyInit errors silently
            }
        }
        Err(_) => {
            // Fallback to stdout only if file creation fails and console logging is enabled
            if enable_console_logging {
                let stdout_layer = tracing_subscriber::fmt::layer()
                    .with_file(true)
                    .with_line_number(true)
                    .with_target(true)
                    .with_writer(std::io::stdout);
                let init_res = tracing_subscriber::registry()
                    .with(env_filter)
                    .with(stdout_layer)
                    .try_init();
                let _ = init_res;
            } else {
                // No file and no console logging - set up minimal subscriber that discards everything
                let init_res = tracing_subscriber::registry()
                    .with(tracing_subscriber::filter::LevelFilter::OFF)
                    .try_init();
                let _ = init_res;
            }
        }
    }

    Ok(())
}

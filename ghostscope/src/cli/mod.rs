//! CLI module - handles command line interface and non-TUI mode runtime

pub mod runtime;

// Re-export main functions for convenience
pub use runtime::{run_command_line_runtime, run_command_line_runtime_with_config};

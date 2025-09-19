//! Script module - handles script compilation and processing

pub mod compiler;

// Re-export main functions for convenience
pub use compiler::{compile_and_load_script_for_cli, compile_and_load_script_for_tui};

//! Script module - handles script compilation and processing

mod attach;
mod cli;
mod compile;
mod runtime_maps;
mod runtime_prep;
mod tui;

// Re-export main functions for convenience
pub use cli::{compile_and_load_script_for_cli, compile_script_for_cli};
pub use tui::compile_and_load_script_for_tui;

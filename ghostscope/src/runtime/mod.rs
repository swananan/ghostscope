//! Runtime module - handles TUI coordination and command processing

pub mod coordinator;
pub mod dwarf_loader;
pub mod info_handlers;
pub mod source_handlers;
pub mod source_path_resolver;
pub mod trace_handlers;

// Re-export main function for convenience
pub use coordinator::run_tui_coordinator_with_config;

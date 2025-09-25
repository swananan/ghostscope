//! Tracing module - manages trace instances and their lifecycle

pub mod instance;
pub mod manager;
pub mod snapshot;

// Re-export main types for convenience
pub use manager::TraceManager;

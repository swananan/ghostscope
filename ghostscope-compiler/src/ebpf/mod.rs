//! eBPF code generation module
//!
//! This module handles LLVM IR generation and eBPF bytecode compilation
//! for GhostScope tracing programs.

pub mod context;
pub mod debug_logger;
pub mod dwarf_bridge;
pub mod expression;
pub mod helper_functions;
pub mod maps;
pub mod protocol;
pub mod variables;

// Re-export main types for convenience
pub use context::*;

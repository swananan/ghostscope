//! eBPF code generation module
//!
//! This module handles LLVM IR generation and eBPF bytecode compilation
//! for GhostScope tracing programs.

pub mod codegen; // New instruction analysis and variable resolution
pub mod context;
pub mod dwarf_bridge;
pub mod expression;
pub mod helper_functions;
pub mod instruction; // New staged transmission and ringbuf messaging
pub mod maps;
pub mod variables;

// Re-export main types for convenience
pub use context::*;

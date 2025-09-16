/// Platform-specific utilities for the GhostScope eBPF debugging tool
///
/// This crate provides platform-specific abstractions for:
/// - Register mappings between DWARF and eBPF pt_regs
/// - Calling convention analysis and parameter location detection
/// - Function prologue analysis for accurate parameter access
/// - Type definitions for cross-crate compatibility
pub mod calling_convention;
pub mod register_mapping;
pub mod types;

// Re-export key types and traits for convenience
pub use calling_convention::{get_parameter_register_in_context, CallingConvention, X86_64SystemV};
pub use register_mapping::{
    dwarf_reg_to_name, dwarf_reg_to_name_x86_64, dwarf_reg_to_pt_regs_byte_offset,
    dwarf_reg_to_pt_regs_byte_offset_x86_64, pt_regs_indices,
};
pub use types::{CodeReader, PlatformError, SourceLocation};

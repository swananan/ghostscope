//! Ghostscope DWARF Analysis Library
//!
//! High-performance DWARF analysis library with on-demand loading architecture
//! inspired by GDB's cooked index system.

// Core modules
pub mod core;

// Internal implementation modules
pub(crate) mod data;
pub(crate) mod debuglink;
pub(crate) mod loader;
pub(crate) mod module;
pub(crate) mod parser;
pub(crate) mod planner;
pub(crate) mod proc_mapping;

// Main entry point
pub mod analyzer;

// Re-export main public API only
pub use analyzer::{
    DwarfAnalyzer, MainExecutableInfo, ModuleLoadingEvent, ModuleLoadingStats, ModuleStats,
    SharedLibraryInfo, SimpleFileInfo,
};

// Re-export essential core types
pub use core::{
    // Evaluation types for LLVM codegen
    CfaResult,
    ComputeStep,
    DirectValueResult,
    DwarfError,
    EvaluationResult,
    FunctionInfo,
    LocationResult,
    MemoryAccessSize,
    ModuleAddress,
    PieceResult,
    Result,
    SourceLocation,
    VariableInfo,
};

// Re-export type definitions from protocol (avoiding circular dependencies)
pub use ghostscope_protocol::{
    EnumVariant, StructMember, TypeCache, TypeInfo, TypeKind, TypeQualifier,
};

// Re-export data types needed by external users
pub use data::VariableWithEvaluation;

// Re-export gimli types that external users need
pub use gimli::{constants, DwAte};

//! Ghostscope DWARF Analysis Library
//!
//! High-performance DWARF analysis library with on-demand loading architecture
//! inspired by GDB's cooked index system.

// Core implementation modules
pub(crate) mod core;

// Internal implementation modules
pub(crate) mod binary;
pub(crate) mod dwarf_expr;
pub(crate) mod index;
pub(crate) mod loader;
pub(crate) mod objfile;
pub(crate) mod parser;
pub mod semantics;

// Main entry point
pub mod analyzer;

// Re-export main public API only
pub use analyzer::{
    AddressQueryResult, DwarfAnalyzer, FunctionQueryResult, MainExecutableInfo, ModuleLoadingEvent,
    ModuleLoadingStats, ModuleStats, SharedLibraryInfo, SimpleFileInfo,
};

// Re-export essential core and semantic support types.
pub use core::{
    AddressExpr, AmbiguityReason, Availability, CallerFrameRecovery, CfaResult, ComputeStep, CuId,
    DieRef, DwarfError, EntryValueCase, FunctionId, FunctionInfo, GlobalVariableInfo, HelperMode,
    InlineContextId, MemoryAccessSize, ModuleAddress, ModuleId, PieceLocation, Provenance, Result,
    RuntimeCapabilities, RuntimeRequirement, ScopeId, SectionType, SourceLocation, TargetArch,
    TypeId, UnsupportedReason, VariableId, VariableInfo, VariableLocation, VerifierRisk,
};

// Re-export semantic contract types.
pub use semantics::{
    AddressOrigin, AddressSpaceInfo, CfaRulePlan, CompactUnwindRow, CompactUnwindStats,
    CompactUnwindTable, InlineFrame, PcContext, PcLineInfo, PcRange, PlannedAddress,
    RegisterRecoveryPlan, UnwindDiagnostic, UnwindDiagnosticKind, VariableAccessPath,
    VariableAccessSegment, VariableLoweringKind, VariableLoweringPlan, VariableMaterialization,
    VariableMaterializationPlan, VariablePlan, VariableQueryDiagnostic, VariableReadPlan,
    VisibleVariable, VisibleVariablesResult,
};

// Re-export type definitions from protocol (avoiding circular dependencies)
pub use ghostscope_protocol::{
    EnumVariant, StructMember, TypeCache, TypeInfo, TypeKind, TypeQualifier,
};

// Re-export gimli types that external users need
pub use gimli::{constants, DwAte};

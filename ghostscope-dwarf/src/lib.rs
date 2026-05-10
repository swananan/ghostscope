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
    AddressExpr, AmbiguityReason, Availability, CallerFrameRecovery, CfaResult, CuId, DieRef,
    DwarfError, EntryValueCase, FunctionId, FunctionInfo, GlobalVariableInfo, HelperMode,
    InlineContextId, MemoryAccessSize, ModuleAddress, ModuleId, PieceLocation, PlanExprOp,
    Provenance, Result, RuntimeCapabilities, RuntimeRequirement, ScopeId, SectionType,
    SourceLocation, TargetArch, TypeId, UnsupportedReason, VariableId, VariableLocation,
    VerifierRisk,
};

// Re-export semantic contract types.
pub use semantics::{
    c_integer_comparison_type, is_c_aggregate_type, is_c_pointer_or_array_type,
    is_c_signed_integer_type, strip_type_aliases, usual_c_arithmetic_comparison_plan,
    AddressOrigin, AddressSpaceInfo, CIntegerComparisonPlan, CIntegerComparisonType, CfaRulePlan,
    CompactUnwindRow, CompactUnwindStats, CompactUnwindTable, InlineFrame, LvalueAddressPlan,
    PcContext, PcLineInfo, PcRange, PlannedAddress, PlannedAddressKind, PlannedValue,
    RegisterRecoveryPlan, RuntimeComputedExpr, RuntimeComputedKind, UnwindDiagnostic,
    UnwindDiagnosticKind, VariableAccessPath, VariableAccessSegment, VariableLoweringKind,
    VariableLoweringPlan, VariableMaterialization, VariableMaterializationPlan, VariablePlan,
    VariableQueryDiagnostic, VariableReadPlan, VisibleVariable, VisibleVariablesResult,
};

// Re-export type definitions from protocol (avoiding circular dependencies)
pub use ghostscope_protocol::{
    EnumVariant, StructMember, TypeCache, TypeInfo, TypeKind, TypeQualifier,
};

// Re-export gimli types that external users need
pub use gimli::{constants, DwAte};

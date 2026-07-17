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
pub(crate) mod language;
pub(crate) mod loader;
pub(crate) mod objfile;
pub(crate) mod parser;
pub(crate) mod path_match;
pub(crate) mod semantics;
pub(crate) mod type_syntax;

// Main entry point
pub(crate) mod analyzer;

// Re-export main public API only
pub use analyzer::{
    AddressQueryResult, AnalyzerStats, DwarfAnalyzer, DwarfIndexStatus, ExecutableFileInfo,
    FunctionQueryResult, LoadedModuleRuntimeInfo, MainExecutableInfo, ModuleDefaultPolicy,
    ModuleLoadingEvent, ModuleLoadingStats, ModuleStats, SectionInfo, SharedLibraryInfo,
    SimpleFileInfo, SourceLineAddressSearch, SourceLineQuerySearch, TypeLookupAmbiguity,
};
pub use loader::ExplicitDebugFile;

// Re-export essential core and semantic support types.
pub use core::{
    AddressExpr, AmbiguityReason, Availability, CallerFrameRecovery, CfaResult, CuId,
    DebugInfoSource, DieRef, DwarfError, EntryValueCase, FunctionId, FunctionInfo,
    GlobalVariableInfo, HelperMode, InlineContextId, MemoryAccessSize, ModuleAddress, ModuleId,
    PieceLocation, PlanExprOp, Provenance, Result, RuntimeCapabilities, RuntimeRequirement,
    ScopeId, SectionType, SourceLocation, TargetArch, TypeId, UnsupportedReason, VariableId,
    VariableLocation, VerifierRisk,
};

// Re-export semantic contract types.
pub use semantics::{
    indexable_element_layout, is_aggregate_type, is_pointer_or_array_type, member_layout,
    strip_type_aliases, AddressOrigin, AddressSpaceInfo, BTreeArrayCapture, BTreeEdgesCapture,
    CfaRulePlan, CompactUnwindRow, CompactUnwindStats, CompactUnwindTable, CompilationUnitMetadata,
    FunctionParameter, IndexableElementLayout, InlineFrame, LvalueAddressPlan, MemberLayout,
    PcContext, PcLineInfo, PcRange, PlannedAddress, PlannedAddressKind, PlannedValue, ProducerInfo,
    ProjectedValueRead, ProjectedValueStep, ProjectedViewField, RegisterRecoveryPlan, ResolvedType,
    RingSequenceLength, RuntimeComputedExpr, RuntimeComputedKind, RustcVersion, SemanticType,
    SourceLanguage,
    SyntheticTypeKind, TypeIdentity, TypeLayoutError, TypeOrigin, TypeProjection,
    TypeProjectionLayout, UnwindDiagnostic, UnwindDiagnosticKind, ValueCapturePlan, ValueReadPlan,
    VariableAccessPath, VariableAccessSegment, VariableLoweringKind, VariableLoweringPlan,
    VariableMaterialization, VariableMaterializationPlan, VariablePlan, VariableQueryDiagnostic,
    VariableReadPlan, VisibleVariable, VisibleVariablesResult,
};

pub use semantics::{
    c_integer_comparison_type, is_c_signed_integer_type, usual_c_arithmetic_comparison_plan,
    CIntegerComparisonPlan, CIntegerComparisonType,
};

#[deprecated(note = "use is_aggregate_type; physical aggregate layout is language-neutral")]
pub use semantics::is_aggregate_type as is_c_aggregate_type;
#[deprecated(note = "use is_pointer_or_array_type; physical type layout is language-neutral")]
pub use semantics::is_pointer_or_array_type as is_c_pointer_or_array_type;

// Re-export type definitions from protocol (avoiding circular dependencies)
pub use ghostscope_protocol::{
    BTreeEntryPresentation, BTreeFieldPresentation, EnumVariant, HashTableBucketOrder,
    HashTableEntryPresentation, HashTableFieldPresentation, StructMember, TypeCache, TypeInfo,
    TypeKind, TypeQualifier, ValuePresentation,
};

// Re-export gimli types that external users need
pub use gimli::{constants, DwAte};

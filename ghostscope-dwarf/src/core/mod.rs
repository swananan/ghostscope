//! Core types and utilities for ghostscope-dwarf

use crate::binary::DwarfReader;

pub mod demangle;
pub mod diagnostic;
pub mod errors;
pub mod evaluation;
pub mod ids;
pub mod mapping;
pub mod plan;
pub mod symbol_names;
pub mod types;

pub use demangle::is_likely_mangled;
pub use diagnostic::{
    AmbiguityReason, Availability, DebugInfoSource, HelperMode, Provenance, RuntimeCapabilities,
    RuntimeRequirement, TargetArch, UnsupportedReason, VerifierRisk,
};
pub use errors::{DwarfError, Result};
pub(crate) use evaluation::{
    plan_expr_steps_to_expression, DirectValueResult, LocationResult, PieceResult,
    RawExpressionResult,
};
pub use evaluation::{
    CallerFrameRecovery, CfaResult, EntryValueCase, MemoryAccessSize, PlanExprOp,
};
pub use ids::{CuId, DieRef, FunctionId, InlineContextId, ModuleId, ScopeId, TypeId, VariableId};
pub(crate) use plan::ParsedLocation;
pub use plan::{AddressExpr, PieceLocation, VariableLocation};
pub(crate) use symbol_names::{
    demangled_name, extract_name_fragments, normalize_demangled_signature,
    symbol_name_matches_query,
};
pub use types::{
    FunctionDieKind, FunctionInfo, GlobalVariableInfo, IndexEntry, IndexFlags, LineEntry,
    ModuleAddress, SectionType, SourceLocation,
};

pub(crate) fn attr_u64(value: gimli::AttributeValue<DwarfReader>) -> Option<u64> {
    match value {
        gimli::AttributeValue::Udata(v) => Some(v),
        gimli::AttributeValue::Sdata(v) if v >= 0 => Some(v as u64),
        gimli::AttributeValue::Data1(v) => Some(v as u64),
        gimli::AttributeValue::Data2(v) => Some(v as u64),
        gimli::AttributeValue::Data4(v) => Some(v as u64),
        gimli::AttributeValue::Data8(v) => Some(v),
        _ => None,
    }
}

pub mod c_integer;
pub mod pc_context;
pub mod type_context;
pub mod type_layout;
pub mod unwind_plan;
pub mod value;
pub mod variable_plan;

pub(crate) mod origins;
pub(crate) mod pc;
pub(crate) mod types;

pub use c_integer::{
    c_integer_comparison_type, is_c_signed_integer_type, usual_c_arithmetic_comparison_plan,
    CIntegerComparisonPlan, CIntegerComparisonType,
};
pub(crate) use origins::{
    resolve_attr_with_unit_origins, resolve_name_with_origins, resolve_origin_entry,
};
pub(crate) use pc::{range_contains_pc, ranges_contain_pc};
pub use pc_context::{
    AddressSpaceInfo, FunctionParameter, InlineFrame, PcContext, PcLineInfo, PcRange,
};
pub use type_context::{
    CompilationUnitMetadata, ProducerInfo, ResolvedType, SemanticType, SourceLanguage,
    SyntheticTypeKind, TypeIdentity, TypeOrigin, TypeProjection, TypeProjectionLayout,
};
pub use type_layout::{
    indexable_element_layout, is_aggregate_type, is_pointer_or_array_type, member_layout,
    strip_type_aliases, IndexableElementLayout, MemberLayout, TypeLayoutError,
};
pub(crate) use types::{
    resolve_type_ref_in_same_unit_with_origins, resolve_type_ref_with_origins, TypeLoc,
};
pub use unwind_plan::{
    CfaRulePlan, CompactUnwindRow, CompactUnwindStats, CompactUnwindTable, RegisterRecoveryPlan,
    UnwindDiagnostic, UnwindDiagnosticKind,
};
pub use value::{
    ProjectedValueRead, ProjectedValueStep, ProjectedViewField, RingSequenceLength,
    ValueCapturePlan, ValueReadPlan,
};
pub(crate) use variable_plan::PlanError;
pub use variable_plan::{
    AddressOrigin, LvalueAddressPlan, PlannedAddress, PlannedAddressKind, PlannedValue,
    RuntimeComputedExpr, RuntimeComputedKind, VariableAccessPath, VariableAccessSegment,
    VariableLoweringKind, VariableLoweringPlan, VariableMaterialization,
    VariableMaterializationPlan, VariablePlan, VariableQueryDiagnostic, VariableReadPlan,
    VisibleVariable, VisibleVariablesResult,
};

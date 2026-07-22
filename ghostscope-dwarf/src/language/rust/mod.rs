mod access;
mod plan;
mod value;
mod variant;

pub(crate) use plan::{btree_value_read_plan, hash_table_value_read_plan, RustPlanContext};
pub(crate) use value::{
    CompositeStructFieldCapture, IndirectSequenceAddressing, IndirectSequenceKind,
    ProjectedPathSegment, ProjectedStructPresentation, ProjectedValuePresentation,
    ProjectedValueRequirement, RingSequenceLengthKind, ValueLayout, ValueLayoutResolution,
};

pub(super) fn resolve_tuple_index(index: u32) -> crate::VariableAccessSegment {
    access::resolve_tuple_index(index)
}

pub(super) fn annotate_type_info(type_info: &mut crate::TypeInfo) {
    variant::annotate_type_info(type_info);
}

pub(super) fn resolve_value_layout(
    current: &crate::ResolvedType,
    dwarf_qualified_name: Option<&str>,
) -> ValueLayoutResolution {
    value::diagnose_value_layout(current, dwarf_qualified_name)
}

pub(super) fn requires_dwarf_qualified_name(current: &crate::ResolvedType) -> bool {
    value::requires_dwarf_qualified_name(current)
}

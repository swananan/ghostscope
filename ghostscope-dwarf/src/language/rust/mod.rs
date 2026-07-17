mod access;
mod value;

pub(crate) use value::{
    IndirectSequenceAddressing, IndirectSequenceKind, ProjectedStructPresentation,
    ProjectedValuePresentation, RingSequenceLengthKind, ValueLayout,
};

pub(super) fn resolve_tuple_index(index: u32) -> crate::VariableAccessSegment {
    access::resolve_tuple_index(index)
}

pub(super) fn resolve_value_layout(
    current: &crate::ResolvedType,
    dwarf_qualified_name: Option<&str>,
) -> Option<ValueLayout> {
    value::resolve_value_layout(current, dwarf_qualified_name)
}

pub(super) fn requires_dwarf_qualified_name(current: &crate::ResolvedType) -> bool {
    value::requires_dwarf_qualified_name(current)
}

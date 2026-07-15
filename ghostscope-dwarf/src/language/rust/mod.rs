mod access;
mod value;

pub(crate) use value::IndirectBytesLayout;

pub(super) fn resolve_tuple_index(index: u32) -> crate::VariableAccessSegment {
    access::resolve_tuple_index(index)
}

pub(super) fn resolve_value_layout(current: &crate::ResolvedType) -> Option<IndirectBytesLayout> {
    value::resolve_value_layout(current)
}

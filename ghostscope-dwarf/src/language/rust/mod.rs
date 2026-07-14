mod access;

pub(super) fn resolve_tuple_index(index: u32) -> crate::VariableAccessSegment {
    access::resolve_tuple_index(index)
}

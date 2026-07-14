use crate::VariableAccessSegment;

pub(super) fn resolve_tuple_index(index: u32) -> VariableAccessSegment {
    VariableAccessSegment::Field(format!("__{index}"))
}

use crate::VariableAccessSegment;

pub(super) fn tuple_field_name(index: u32) -> String {
    format!("__{index}")
}

pub(super) fn is_tuple_field_name(name: &str, index: u32) -> bool {
    name == tuple_field_name(index)
}

pub(super) fn resolve_tuple_index(index: u32) -> VariableAccessSegment {
    VariableAccessSegment::Field(tuple_field_name(index))
}

//! Source-language dispatch for semantic DWARF projections.

mod rust;

use crate::{semantics::PlanError, SourceLanguage, TypeOrigin, VariableAccessSegment};

pub(crate) use rust::{
    btree_value_read_plan, hash_table_value_read_plan, CompositeStructFieldCapture,
    IndirectSequenceAddressing, IndirectSequenceKind, ProjectedPathSegment,
    ProjectedStructPresentation, ProjectedValuePresentation, ProjectedValueRequirement,
    RingSequenceLengthKind, RustPlanContext, ValueLayout, ValueLayoutResolution,
};

pub(crate) fn resolve_value_layout(
    current: &crate::ResolvedType,
    dwarf_qualified_name: Option<&str>,
) -> ValueLayoutResolution {
    rust::resolve_value_layout(current, dwarf_qualified_name)
}

pub(crate) fn requires_dwarf_qualified_name(current: &crate::ResolvedType) -> bool {
    rust::requires_dwarf_qualified_name(current)
}

pub(crate) fn annotate_type_info(language: SourceLanguage, type_info: &mut crate::TypeInfo) {
    if language == SourceLanguage::Rust {
        rust::annotate_type_info(type_info);
    }
}

pub(crate) fn resolve_access_segment(
    origin: &TypeOrigin,
    segment: &VariableAccessSegment,
) -> crate::Result<VariableAccessSegment> {
    match segment {
        VariableAccessSegment::TupleIndex(index) => match origin.language {
            SourceLanguage::Rust => Ok(rust::resolve_tuple_index(*index)),
            language => Err(PlanError::TupleIndexUnsupportedLanguage {
                index: *index,
                language,
            }
            .into()),
        },
        _ => Ok(segment.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CuId, ModuleId};

    fn origin(language: SourceLanguage) -> TypeOrigin {
        TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language,
            producer: None,
            dwarf_version: 5,
        }
    }

    #[test]
    fn maps_rust_tuple_index_to_producer_field() {
        assert_eq!(
            resolve_access_segment(
                &origin(SourceLanguage::Rust),
                &VariableAccessSegment::TupleIndex(3),
            )
            .unwrap(),
            VariableAccessSegment::Field("__3".to_string())
        );
    }

    #[test]
    fn rejects_tuple_index_for_non_rust_language() {
        let error = resolve_access_segment(
            &origin(SourceLanguage::C),
            &VariableAccessSegment::TupleIndex(0),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("not supported for source language C"));
    }
}

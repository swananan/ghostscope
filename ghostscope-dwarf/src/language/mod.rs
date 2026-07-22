//! Source-language dispatch for semantic DWARF projections.

mod adapter;
mod rust;

use crate::{semantics::PlanError, SourceLanguage, TypeOrigin, VariableAccessSegment};
use std::path::Path;

pub(crate) use adapter::{ProjectedPathSegment, ValueAdapterContext};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueLayout {
    Rust(rust::ValueLayout),
}

pub(crate) type ValueLayoutResolution = adapter::ValueLayoutResolution<ValueLayout>;

/// Select an adapter only after dispatching on the type's DWARF language.
///
/// This boundary prevents C, C++, and unknown-language values from entering
/// Rust standard-library recognition or plan construction.
pub(crate) fn resolve_value_layout(
    current: &crate::ResolvedType,
    dwarf_qualified_name: Option<&str>,
) -> ValueLayoutResolution {
    match source_language(current) {
        SourceLanguage::Rust => {
            rust::resolve_value_layout(current, dwarf_qualified_name).map_layout(ValueLayout::Rust)
        }
        SourceLanguage::C
        | SourceLanguage::Cpp
        | SourceLanguage::Other(_)
        | SourceLanguage::Unknown => ValueLayoutResolution::NotApplicable,
    }
}

pub(crate) fn requires_dwarf_qualified_name(current: &crate::ResolvedType) -> bool {
    match source_language(current) {
        SourceLanguage::Rust => rust::requires_dwarf_qualified_name(current),
        SourceLanguage::C
        | SourceLanguage::Cpp
        | SourceLanguage::Other(_)
        | SourceLanguage::Unknown => false,
    }
}

pub(crate) fn build_value_read_plan(
    context: &dyn ValueAdapterContext,
    current: &crate::ResolvedType,
    type_module_path: Option<&Path>,
    layout: ValueLayout,
) -> crate::Result<Option<crate::ValueReadPlan>> {
    match layout {
        ValueLayout::Rust(layout) => {
            rust::build_value_read_plan(context, current, layout, type_module_path)
        }
    }
}

pub(crate) fn annotate_type_info(language: SourceLanguage, type_info: &mut crate::TypeInfo) {
    if language == SourceLanguage::Rust {
        rust::annotate_type_info(type_info);
    }
}

fn source_language(current: &crate::ResolvedType) -> SourceLanguage {
    current
        .origin
        .as_ref()
        .map_or(SourceLanguage::Unknown, |origin| origin.language)
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
    use crate::{CuId, ModuleId, ResolvedType, TypeIdentity, TypeInfo};

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

    #[test]
    fn non_rust_values_bypass_rust_adapters() {
        let current = ResolvedType::new(
            TypeInfo::StructType {
                name: "&str".to_string(),
                size: 0,
                members: Vec::new(),
            },
            TypeIdentity::Unknown,
            Some(origin(SourceLanguage::C)),
        );

        assert_eq!(
            resolve_value_layout(&current, None),
            ValueLayoutResolution::NotApplicable
        );
        assert!(!requires_dwarf_qualified_name(&current));
    }
}

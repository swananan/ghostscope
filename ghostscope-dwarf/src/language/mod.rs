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

pub(crate) fn build_aggregate_value_read_plan(
    context: &dyn ValueAdapterContext,
    current: &crate::ResolvedType,
    type_module_path: Option<&Path>,
) -> Option<crate::ValueReadPlan> {
    match source_language(current) {
        SourceLanguage::Rust => {
            rust::build_aggregate_value_read_plan(context, current, type_module_path)
        }
        SourceLanguage::C
        | SourceLanguage::Cpp
        | SourceLanguage::Other(_)
        | SourceLanguage::Unknown => None,
    }
}

pub(crate) fn build_variant_nested_plan(
    context: &dyn ValueAdapterContext,
    current: &crate::ResolvedType,
    type_module_path: Option<&Path>,
    resolve_nested: &mut dyn FnMut(&crate::ResolvedType) -> Option<crate::ValueReadPlan>,
) -> Option<crate::ValueNestedPlan> {
    match source_language(current) {
        SourceLanguage::Rust => {
            rust::build_variant_nested_plan(context, current, type_module_path, resolve_nested)
        }
        SourceLanguage::C
        | SourceLanguage::Cpp
        | SourceLanguage::Other(_)
        | SourceLanguage::Unknown => None,
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
    use crate::{
        CuId, MemberLayout, ModuleId, ProjectedValueRead, ResolvedType, TypeId, TypeIdentity,
        TypeInfo, TypeProjection,
    };

    struct PanicValueAdapterContext;

    impl ValueAdapterContext for PanicValueAdapterContext {
        fn project_type(
            &self,
            _current: &ResolvedType,
            _segment: &VariableAccessSegment,
            _type_module_path: Option<&Path>,
        ) -> crate::Result<TypeProjection> {
            panic!("non-Rust composition must not query DWARF")
        }

        fn project_member_path(
            &self,
            _current: &ResolvedType,
            _path: &[String],
            _type_module_path: Option<&Path>,
        ) -> crate::Result<TypeProjection> {
            panic!("non-Rust composition must not query DWARF")
        }

        fn project_value_path(
            &self,
            _current: &ResolvedType,
            _path: &[ProjectedPathSegment],
            _type_module_path: Option<&Path>,
            _capture_address: bool,
        ) -> crate::Result<Option<ProjectedValueRead>> {
            panic!("non-Rust composition must not query DWARF")
        }

        fn template_type_parameter(
            &self,
            _type_id: TypeId,
            _index: usize,
        ) -> crate::Result<Option<ResolvedType>> {
            panic!("non-Rust composition must not query DWARF")
        }

        fn variant_member_resolved_type(
            &self,
            _current: TypeId,
            _part_index: usize,
            _variant_index: usize,
            _member_index: usize,
        ) -> crate::Result<Option<ResolvedType>> {
            panic!("non-Rust composition must not query DWARF")
        }

        fn type_alignment(&self, _type_id: TypeId) -> crate::Result<Option<u64>> {
            panic!("non-Rust composition must not query DWARF")
        }

        fn tuple_member_layout(
            &self,
            _type_id: TypeId,
            _aggregate_type: &TypeInfo,
            _index: u32,
        ) -> crate::Result<MemberLayout> {
            panic!("non-Rust composition must not query DWARF")
        }

        fn resolve_aggregate_type_in_module(
            &self,
            _anchor: TypeId,
            _lookup_names: &[&str],
            _exact_qualified_name: Option<&str>,
        ) -> crate::Result<Option<ResolvedType>> {
            panic!("non-Rust composition must not query DWARF")
        }
    }

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

    #[test]
    fn non_rust_aggregates_bypass_rust_composition() {
        let current = ResolvedType::new(
            TypeInfo::StructType {
                name: "Request".to_string(),
                size: 0,
                members: Vec::new(),
            },
            TypeIdentity::Unknown,
            Some(origin(SourceLanguage::C)),
        );
        let context = PanicValueAdapterContext;

        assert_eq!(
            build_aggregate_value_read_plan(&context, &current, None),
            None
        );
        let mut resolve_nested =
            |_child: &ResolvedType| panic!("non-Rust composition must not resolve nested values");
        assert_eq!(
            build_variant_nested_plan(&context, &current, None, &mut resolve_nested),
            None
        );
    }
}

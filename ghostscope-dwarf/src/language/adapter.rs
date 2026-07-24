//! Language-neutral contracts for semantic value adapters.

use crate::{
    strip_type_aliases, MemberLayout, ProjectedValueRead, ProjectedValueStep, ProjectedViewField,
    ProjectedViewFieldCapture, ResolvedType, Result, StructMember, TypeId, TypeInfo,
    TypeProjection, TypeProjectionLayout, ValueCapturePlan, ValueReadPlan, VariableAccessSegment,
};
use std::path::Path;

/// Result of asking one source-language adapter for a semantic value layout.
///
/// Recognition establishes only a candidate type identity. `Applied` means
/// the concrete target DWARF also passed layout validation. `Rejected` keeps
/// identity mismatch separate from an unsafe or unsupported layout so callers
/// can preserve the ordinary DWARF fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueLayoutResolution<L> {
    NotApplicable,
    Applied {
        adapter: &'static str,
        layout: L,
    },
    Rejected {
        adapter: &'static str,
        reason: &'static str,
    },
}

impl<L> ValueLayoutResolution<L> {
    pub(crate) fn map_layout<U>(self, map: impl FnOnce(L) -> U) -> ValueLayoutResolution<U> {
        match self {
            Self::NotApplicable => ValueLayoutResolution::NotApplicable,
            Self::Applied { adapter, layout } => ValueLayoutResolution::Applied {
                adapter,
                layout: map(layout),
            },
            Self::Rejected { adapter, reason } => {
                ValueLayoutResolution::Rejected { adapter, reason }
            }
        }
    }
}

/// Common layouts plus an adapter-owned extension for language-specific plans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueLayout<E> {
    IndirectSequence(IndirectSequenceLayout),
    ProjectedValue {
        value_path: Vec<String>,
        presentation: ProjectedValuePresentation,
    },
    ProjectedStruct(ProjectedStructLayout),
    CompositeStruct(CompositeStructLayout),
    Extension(E),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectedValuePresentation {
    Transparent,
    SingleField {
        type_name: &'static str,
        field_name: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectedStructLayout {
    pub(crate) type_name: &'static str,
    pub(crate) fields: Vec<ProjectedStructField>,
    pub(crate) presentation: ProjectedStructPresentation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectedStructField {
    pub(crate) name: &'static str,
    pub(crate) value_path: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectedStructPresentation {
    SignedState {
        state_field: &'static str,
        non_negative_label: &'static str,
        negative_label: &'static str,
    },
    ReferenceCounted {
        strong_field: &'static str,
        weak_field: &'static str,
        implicit_weak: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompositeStructLayout {
    pub(crate) type_name: &'static str,
    pub(crate) fields: Vec<CompositeStructField>,
    pub(crate) presentation: ProjectedStructPresentation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompositeStructField {
    pub(crate) name: &'static str,
    pub(crate) value_path: Vec<ProjectedPathSegment>,
    pub(crate) capture: CompositeStructFieldCapture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompositeStructFieldCapture {
    Value(ProjectedValueRequirement),
    Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProjectedPathSegment {
    Member(String),
    SoleMember,
    UnwrapScalar,
    Dereference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectedValueRequirement {
    KnownSizedOrZst,
    SignedPointerSizedInteger,
    UnsignedPointerSizedInteger,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndirectSequenceLayout {
    pub(crate) data_path: Vec<String>,
    pub(crate) addressing: IndirectSequenceAddressing,
    pub(crate) kind: IndirectSequenceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IndirectSequenceAddressing {
    Contiguous {
        length_path: Vec<String>,
    },
    Ring {
        start_path: Vec<String>,
        length_path: Vec<String>,
        length_kind: RingSequenceLengthKind,
        capacity_path: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RingSequenceLengthKind {
    Explicit,
    End,
}

impl IndirectSequenceLayout {
    pub(crate) fn contiguous(
        data_path: Vec<String>,
        length_path: Vec<String>,
        kind: IndirectSequenceKind,
    ) -> Self {
        Self {
            data_path,
            addressing: IndirectSequenceAddressing::Contiguous { length_path },
            kind,
        }
    }

    pub(crate) fn ring(
        data_path: Vec<String>,
        start_path: Vec<String>,
        length_path: Vec<String>,
        length_kind: RingSequenceLengthKind,
        capacity_path: Vec<String>,
        kind: IndirectSequenceKind,
    ) -> Self {
        Self {
            data_path,
            addressing: IndirectSequenceAddressing::Ring {
                start_path,
                length_path,
                length_kind,
                capacity_path,
            },
            kind,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndirectSequenceKind {
    Utf8String,
    ByteString,
    OpaqueByteString,
    PointerTarget,
    TypeParameter { index: usize },
}

/// DWARF operations available to every source-language value adapter.
///
/// Implementations keep object-file storage in the analyzer while adapters
/// own source-language identities, producer conventions, and layout checks.
pub(crate) trait ValueAdapterContext {
    fn project_type(
        &self,
        current: &ResolvedType,
        segment: &VariableAccessSegment,
        type_module_path: Option<&Path>,
    ) -> Result<TypeProjection>;

    fn project_member_path(
        &self,
        current: &ResolvedType,
        path: &[String],
        type_module_path: Option<&Path>,
    ) -> Result<TypeProjection>;

    fn project_value_path(
        &self,
        current: &ResolvedType,
        path: &[ProjectedPathSegment],
        type_module_path: Option<&Path>,
        capture_address: bool,
    ) -> Result<Option<ProjectedValueRead>>;

    fn template_type_parameter(
        &self,
        type_id: TypeId,
        index: usize,
    ) -> Result<Option<ResolvedType>>;

    fn type_alignment(&self, type_id: TypeId) -> Result<Option<u64>>;

    fn tuple_member_layout(
        &self,
        type_id: TypeId,
        aggregate_type: &TypeInfo,
        index: u32,
    ) -> Result<MemberLayout>;

    fn resolve_aggregate_type_in_module(
        &self,
        anchor: TypeId,
        lookup_names: &[&str],
        exact_qualified_name: Option<&str>,
    ) -> Result<Option<ResolvedType>>;
}

pub(crate) fn build_value_read_plan<E, F>(
    context: &dyn ValueAdapterContext,
    current: &ResolvedType,
    type_module_path: Option<&Path>,
    layout: ValueLayout<E>,
    build_extension: F,
) -> Result<Option<ValueReadPlan>>
where
    F: FnOnce(
        &dyn ValueAdapterContext,
        &ResolvedType,
        Option<&Path>,
        E,
    ) -> Result<Option<ValueReadPlan>>,
{
    let layout = match layout {
        ValueLayout::ProjectedValue {
            value_path,
            presentation,
        } => {
            let value = context.project_member_path(current, &value_path, type_module_path)?;
            let presentation = match presentation {
                ProjectedValuePresentation::Transparent => crate::ValuePresentation::Dwarf,
                ProjectedValuePresentation::SingleField {
                    type_name,
                    field_name,
                } => crate::ValuePresentation::SingleField {
                    type_name: type_name.to_string(),
                    field_name: field_name.to_string(),
                },
            };
            return Ok(Some(ValueReadPlan::new(
                current.clone(),
                presentation,
                ValueCapturePlan::ProjectedValue { value },
            )));
        }
        ValueLayout::ProjectedStruct(layout) => {
            let root_size = current.summary.size();
            let mut members = Vec::with_capacity(layout.fields.len());
            let mut projected_fields = Vec::with_capacity(layout.fields.len());
            for field in layout.fields {
                let projected =
                    context.project_member_path(current, &field.value_path, type_module_path)?;
                let TypeProjectionLayout::Member { offset } = projected.layout else {
                    return Err(anyhow::anyhow!(
                        "semantic struct field produced a non-member projection"
                    ));
                };
                let member_type = projected.resolved_type.summary.clone();
                let member_end = offset
                    .checked_add(member_type.size())
                    .ok_or_else(|| anyhow::anyhow!("semantic struct field end overflow"))?;
                if member_end > root_size {
                    return Err(anyhow::anyhow!(
                        "semantic struct field '{}' exceeds its DWARF root",
                        field.name
                    ));
                }
                members.push(StructMember {
                    name: field.name.to_string(),
                    member_type,
                    offset,
                    bit_offset: None,
                    bit_size: None,
                });
                projected_fields.push(ProjectedValueRead {
                    steps: vec![ProjectedValueStep::Member { offset }],
                    resolved_type: projected.resolved_type,
                });
            }
            let presentation = projected_struct_presentation(layout.presentation);
            let output_type = TypeInfo::StructType {
                name: layout.type_name.to_string(),
                size: root_size,
                members,
            };
            return Ok(Some(ValueReadPlan::new(
                current.clone(),
                presentation,
                ValueCapturePlan::InlineView {
                    output_type,
                    fields: projected_fields,
                },
            )));
        }
        ValueLayout::CompositeStruct(layout) => {
            let mut members = Vec::with_capacity(layout.fields.len());
            let mut fields = Vec::with_capacity(layout.fields.len());
            let mut output_size = 0u64;
            for field in layout.fields {
                if members
                    .iter()
                    .any(|member: &StructMember| member.name == field.name)
                {
                    return Err(anyhow::anyhow!(
                        "duplicate semantic struct field '{}'",
                        field.name
                    ));
                }
                let value = context.project_value_path(
                    current,
                    &field.value_path,
                    type_module_path,
                    matches!(field.capture, CompositeStructFieldCapture::Address),
                )?;
                let Some(value) = value else {
                    return Ok(None);
                };
                let (member_type, capture) = match field.capture {
                    CompositeStructFieldCapture::Value(requirement) => {
                        if !projected_value_satisfies(requirement, &value) {
                            return Ok(None);
                        }
                        (
                            value.resolved_type.summary.clone(),
                            ProjectedViewFieldCapture::Value,
                        )
                    }
                    CompositeStructFieldCapture::Address => {
                        let Some(member_type) = projected_address_type(&value) else {
                            return Ok(None);
                        };
                        (member_type, ProjectedViewFieldCapture::Address)
                    }
                };
                let output_offset = output_size;
                output_size = output_size
                    .checked_add(member_type.size())
                    .ok_or_else(|| anyhow::anyhow!("semantic struct size overflow"))?;
                members.push(StructMember {
                    name: field.name.to_string(),
                    member_type,
                    offset: output_offset,
                    bit_offset: None,
                    bit_size: None,
                });
                fields.push(ProjectedViewField {
                    output_offset,
                    value,
                    capture,
                });
            }
            let output_type = TypeInfo::StructType {
                name: layout.type_name.to_string(),
                size: output_size,
                members,
            };
            return Ok(Some(ValueReadPlan::new(
                current.clone(),
                projected_struct_presentation(layout.presentation),
                ValueCapturePlan::ProjectedView {
                    output_type,
                    fields,
                },
            )));
        }
        ValueLayout::Extension(extension) => {
            return build_extension(context, current, type_module_path, extension);
        }
        ValueLayout::IndirectSequence(layout) => layout,
    };

    let data = context.project_member_path(current, &layout.data_path, type_module_path)?;
    let (presentation, element_stride, sequence_element) = match layout.kind {
        IndirectSequenceKind::Utf8String => (crate::ValuePresentation::Utf8String, None, None),
        IndirectSequenceKind::ByteString | IndirectSequenceKind::OpaqueByteString => {
            (crate::ValuePresentation::ByteString, None, None)
        }
        IndirectSequenceKind::PointerTarget => {
            let element = context.project_type(
                &data.resolved_type,
                &VariableAccessSegment::Dereference,
                type_module_path,
            )?;
            if matches!(
                strip_type_aliases(&element.resolved_type.summary),
                TypeInfo::UnknownType { .. } | TypeInfo::OptimizedOut { .. }
            ) {
                return Ok(None);
            }
            let element_type = element.resolved_type.summary.clone();
            let element_stride = element_type.size();
            (
                crate::ValuePresentation::Sequence {
                    element_type: Box::new(element_type),
                    element_stride,
                },
                Some(element_stride),
                Some(element.resolved_type),
            )
        }
        IndirectSequenceKind::TypeParameter { index } => {
            let Some(type_id) = current.identity.layout_dwarf_id() else {
                return Ok(None);
            };
            let Some(element) = context.template_type_parameter(type_id, index)? else {
                return Ok(None);
            };
            if matches!(
                strip_type_aliases(&element.summary),
                TypeInfo::UnknownType { .. } | TypeInfo::OptimizedOut { .. }
            ) {
                return Ok(None);
            }
            let element_stride = element.summary.size();
            (
                crate::ValuePresentation::Sequence {
                    element_type: Box::new(element.summary.clone()),
                    element_stride,
                },
                Some(element_stride),
                Some(element),
            )
        }
    };

    let capture = match layout.addressing {
        IndirectSequenceAddressing::Contiguous { length_path } => {
            let length = context.project_member_path(current, &length_path, type_module_path)?;
            match element_stride {
                Some(element_stride) => ValueCapturePlan::IndirectSequence {
                    data,
                    length,
                    element_stride,
                },
                None => ValueCapturePlan::IndirectBytes { data, length },
            }
        }
        IndirectSequenceAddressing::Ring {
            start_path,
            length_path,
            length_kind,
            capacity_path,
        } => {
            let Some(element_stride) = element_stride else {
                return Ok(None);
            };
            let length = context.project_member_path(current, &length_path, type_module_path)?;
            if element_stride == 0 && matches!(length_kind, RingSequenceLengthKind::Explicit) {
                // Physical order is unobservable for zero-sized elements.
                // Avoid depending on a producer-specific capacity encoding.
                ValueCapturePlan::IndirectSequence {
                    data,
                    length,
                    element_stride,
                }
            } else {
                let start = context.project_member_path(current, &start_path, type_module_path)?;
                let capacity =
                    context.project_member_path(current, &capacity_path, type_module_path)?;
                let length = Box::new(match length_kind {
                    RingSequenceLengthKind::Explicit => crate::RingSequenceLength::Explicit(length),
                    RingSequenceLengthKind::End => crate::RingSequenceLength::End(length),
                });
                ValueCapturePlan::IndirectRingSequence {
                    data,
                    start,
                    length,
                    capacity,
                    element_stride,
                }
            }
        }
    };

    let mut plan = ValueReadPlan::new(current.clone(), presentation, capture);
    plan.sequence_element = sequence_element;
    Ok(Some(plan))
}

fn projected_struct_presentation(
    presentation: ProjectedStructPresentation,
) -> crate::ValuePresentation {
    match presentation {
        ProjectedStructPresentation::SignedState {
            state_field,
            non_negative_label,
            negative_label,
        } => crate::ValuePresentation::SignedStateStruct {
            state_field: state_field.to_string(),
            non_negative_label: non_negative_label.to_string(),
            negative_label: negative_label.to_string(),
        },
        ProjectedStructPresentation::ReferenceCounted {
            strong_field,
            weak_field,
            implicit_weak,
        } => crate::ValuePresentation::ReferenceCountedStruct {
            strong_field: strong_field.to_string(),
            weak_field: weak_field.to_string(),
            implicit_weak,
        },
    }
}

fn projected_address_type(value: &ProjectedValueRead) -> Option<TypeInfo> {
    if matches!(
        strip_type_aliases(&value.resolved_type.summary),
        TypeInfo::UnknownType { .. } | TypeInfo::OptimizedOut { .. }
    ) {
        return None;
    }
    let pointer_size = value.steps.iter().rev().find_map(|step| match step {
        ProjectedValueStep::Dereference { pointer_size } => Some(*pointer_size),
        ProjectedValueStep::Member { .. } => None,
    })?;
    matches!(pointer_size, 4 | 8).then(|| TypeInfo::PointerType {
        target_type: Box::new(value.resolved_type.summary.clone()),
        size: pointer_size,
    })
}

fn projected_value_satisfies(
    requirement: ProjectedValueRequirement,
    value: &ProjectedValueRead,
) -> bool {
    let value_type = strip_type_aliases(&value.resolved_type.summary);
    match requirement {
        ProjectedValueRequirement::KnownSizedOrZst => match value_type {
            TypeInfo::UnknownType { .. }
            | TypeInfo::OptimizedOut { .. }
            | TypeInfo::ArrayType {
                total_size: None, ..
            } => false,
            TypeInfo::BaseType { name, size: 0, .. } => name == "()",
            TypeInfo::StructType { size: 0, .. }
            | TypeInfo::UnionType { size: 0, .. }
            | TypeInfo::ArrayType {
                total_size: Some(0),
                ..
            } => true,
            type_info => type_info.size() > 0,
        },
        ProjectedValueRequirement::SignedPointerSizedInteger => {
            let TypeInfo::BaseType { size, encoding, .. } = value_type else {
                return false;
            };
            let signed = *encoding == gimli::DW_ATE_signed.0 as u16
                || *encoding == gimli::DW_ATE_signed_char.0 as u16;
            signed && matches!(*size, 4 | 8) && projected_pointer_size(value) == Some(*size)
        }
        ProjectedValueRequirement::UnsignedPointerSizedInteger => {
            let TypeInfo::BaseType { size, encoding, .. } = value_type else {
                return false;
            };
            let unsigned = *encoding == gimli::DW_ATE_unsigned.0 as u16
                || *encoding == gimli::DW_ATE_unsigned_char.0 as u16;
            unsigned && matches!(*size, 4 | 8) && projected_pointer_size(value) == Some(*size)
        }
    }
}

fn projected_pointer_size(value: &ProjectedValueRead) -> Option<u64> {
    value.steps.iter().rev().find_map(|step| match step {
        ProjectedValueStep::Dereference { pointer_size } => Some(*pointer_size),
        ProjectedValueStep::Member { .. } => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TypeIdentity;

    fn projected_value(summary: TypeInfo, pointer_size: Option<u64>) -> ProjectedValueRead {
        let steps = pointer_size
            .map(|pointer_size| ProjectedValueStep::Dereference { pointer_size })
            .into_iter()
            .collect();
        ProjectedValueRead {
            steps,
            resolved_type: ResolvedType::new(summary, TypeIdentity::Unknown, None),
        }
    }

    #[test]
    fn known_sized_requirement_distinguishes_zst_from_unknown_layout() {
        let requirement = ProjectedValueRequirement::KnownSizedOrZst;
        let unit = projected_value(
            TypeInfo::BaseType {
                name: "()".to_string(),
                size: 0,
                encoding: gimli::DW_ATE_unsigned.0 as u16,
            },
            Some(8),
        );
        let unknown = projected_value(
            TypeInfo::UnknownType {
                name: "T".to_string(),
            },
            Some(8),
        );

        assert!(projected_value_satisfies(requirement, &unit));
        assert!(!projected_value_satisfies(requirement, &unknown));
    }

    #[test]
    fn projected_address_uses_the_dwarf_pointer_width() {
        let target = TypeInfo::ArrayType {
            element_type: Box::new(TypeInfo::BaseType {
                name: "u8".to_string(),
                size: 1,
                encoding: gimli::DW_ATE_unsigned.0 as u16,
            }),
            element_count: None,
            total_size: None,
        };
        let value = projected_value(target.clone(), Some(8));
        assert_eq!(
            projected_address_type(&value),
            Some(TypeInfo::PointerType {
                target_type: Box::new(target),
                size: 8,
            })
        );
        assert_eq!(
            projected_address_type(&projected_value(value.resolved_type.summary, None)),
            None
        );
    }

    #[test]
    fn signed_state_requirement_uses_dwarf_encoding_and_pointer_width() {
        let requirement = ProjectedValueRequirement::SignedPointerSizedInteger;
        let signed = |size, pointer_size| {
            projected_value(
                TypeInfo::BaseType {
                    name: "isize".to_string(),
                    size,
                    encoding: gimli::DW_ATE_signed.0 as u16,
                },
                pointer_size,
            )
        };
        assert!(projected_value_satisfies(requirement, &signed(8, Some(8))));
        assert!(!projected_value_satisfies(requirement, &signed(4, Some(8))));
        assert!(!projected_value_satisfies(requirement, &signed(8, None)));

        let unsigned = projected_value(
            TypeInfo::BaseType {
                name: "usize".to_string(),
                size: 8,
                encoding: gimli::DW_ATE_unsigned.0 as u16,
            },
            Some(8),
        );
        assert!(!projected_value_satisfies(requirement, &unsigned));
    }

    #[test]
    fn unsigned_counter_requirement_uses_dwarf_encoding_and_pointer_width() {
        let requirement = ProjectedValueRequirement::UnsignedPointerSizedInteger;
        let unsigned = |size, pointer_size| {
            projected_value(
                TypeInfo::BaseType {
                    name: "usize".to_string(),
                    size,
                    encoding: gimli::DW_ATE_unsigned.0 as u16,
                },
                pointer_size,
            )
        };
        assert!(projected_value_satisfies(
            requirement,
            &unsigned(8, Some(8))
        ));
        assert!(!projected_value_satisfies(
            requirement,
            &unsigned(4, Some(8))
        ));
        assert!(!projected_value_satisfies(requirement, &unsigned(8, None)));

        let signed = projected_value(
            TypeInfo::BaseType {
                name: "isize".to_string(),
                size: 8,
                encoding: gimli::DW_ATE_signed.0 as u16,
            },
            Some(8),
        );
        assert!(!projected_value_satisfies(requirement, &signed));
    }
}

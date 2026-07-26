use std::path::Path;

use crate::language::adapter::ValueAdapterContext;
use crate::{
    strip_type_aliases, ProjectedValueRead, ProjectedValueStep, ResolvedType, SourceLanguage,
    TypeInfo, TypeProjectionLayout, ValueCapturePlan, ValueNestedPlan, ValueNestedVariantCondition,
    ValueNestedVariantFieldPlan, ValuePresentation, ValueReadPlan, VariableAccessSegment,
    VariantSelector,
};

pub(super) fn build_aggregate_value_read_plan(
    context: &dyn ValueAdapterContext,
    current: &ResolvedType,
    type_module_path: Option<&Path>,
) -> Option<ValueReadPlan> {
    if current.origin.as_ref().map(|origin| origin.language) != Some(SourceLanguage::Rust) {
        return None;
    }
    let fields = match strip_type_aliases(&current.summary) {
        TypeInfo::StructType { members, .. } => {
            let mut fields = Vec::with_capacity(members.len());
            for member in members {
                let projection = match context.project_type(
                    current,
                    &VariableAccessSegment::Field(member.name.clone()),
                    type_module_path,
                ) {
                    Ok(projection) => projection,
                    Err(error) => {
                        tracing::debug!(
                            target: "ghostscope_dwarf::value_adapter",
                            type_name = current.summary.type_name(),
                            field = member.name,
                            %error,
                            "Rust aggregate could not form a nested field projection; using DWARF presentation"
                        );
                        return None;
                    }
                };
                let TypeProjectionLayout::Member { offset } = projection.layout else {
                    return None;
                };
                if offset != member.offset {
                    return None;
                }
                fields.push(ProjectedValueRead {
                    steps: vec![ProjectedValueStep::Member { offset }],
                    resolved_type: projection.resolved_type,
                });
            }
            fields
        }
        TypeInfo::VariantType { .. } => Vec::new(),
        _ => return None,
    };

    Some(ValueReadPlan::new(
        current.clone(),
        ValuePresentation::Dwarf,
        ValueCapturePlan::InlineView {
            output_type: strip_type_aliases(&current.summary).clone(),
            fields,
        },
    ))
}

pub(super) fn build_variant_nested_plan(
    context: &dyn ValueAdapterContext,
    current: &ResolvedType,
    type_module_path: Option<&Path>,
    resolve_nested: &mut dyn FnMut(&ResolvedType) -> Option<ValueReadPlan>,
) -> Option<ValueNestedPlan> {
    if current.origin.as_ref().map(|origin| origin.language) != Some(SourceLanguage::Rust) {
        return None;
    }
    let current_id = current.identity.layout_dwarf_id()?;
    let TypeInfo::VariantType { variant_parts, .. } = strip_type_aliases(&current.summary) else {
        return None;
    };
    let mut fields = Vec::new();

    for (part_index, part) in variant_parts.iter().enumerate() {
        for (variant_index, variant) in part.variants.iter().enumerate() {
            let Some(condition) = nested_variant_condition(part, variant_index) else {
                continue;
            };
            for (member_index, member) in variant.members.iter().enumerate() {
                let wrapper = match context.variant_member_resolved_type(
                    current_id,
                    part_index,
                    variant_index,
                    member_index,
                ) {
                    Ok(Some(wrapper)) => wrapper,
                    Ok(None) => continue,
                    Err(error) => {
                        tracing::debug!(
                            target: "ghostscope_dwarf::value_adapter",
                            type_name = current.summary.type_name(),
                            part_index,
                            variant_index,
                            member_index,
                            %error,
                            "Rust enum payload identity could not be resolved; using DWARF presentation"
                        );
                        continue;
                    }
                };
                if wrapper.summary != member.member_type {
                    tracing::debug!(
                        target: "ghostscope_dwarf::value_adapter",
                        type_name = current.summary.type_name(),
                        variant = member.name,
                        "Rust enum payload identity did not match its parsed member type; using DWARF presentation"
                    );
                    continue;
                }
                let TypeInfo::StructType {
                    members: payload_fields,
                    ..
                } = strip_type_aliases(&wrapper.summary)
                else {
                    continue;
                };

                for (payload_field_index, payload_field) in payload_fields.iter().enumerate() {
                    let projection = match context.project_type(
                        &wrapper,
                        &VariableAccessSegment::Field(payload_field.name.clone()),
                        type_module_path,
                    ) {
                        Ok(projection) => projection,
                        Err(error) => {
                            tracing::debug!(
                                target: "ghostscope_dwarf::value_adapter",
                                type_name = current.summary.type_name(),
                                variant = member.name,
                                field = payload_field.name,
                                %error,
                                "Rust enum payload field could not be projected; using DWARF presentation"
                            );
                            continue;
                        }
                    };
                    let TypeProjectionLayout::Member { offset } = projection.layout else {
                        continue;
                    };
                    if offset != payload_field.offset {
                        continue;
                    }
                    let Some(value) = resolve_nested(&projection.resolved_type) else {
                        continue;
                    };
                    fields.push(ValueNestedVariantFieldPlan {
                        part_index,
                        variant_index,
                        member_index,
                        payload_field_index,
                        steps: vec![
                            ProjectedValueStep::Member {
                                offset: member.offset,
                            },
                            ProjectedValueStep::Member { offset },
                        ],
                        condition: condition.clone(),
                        value: Box::new(value),
                    });
                }
            }
        }
    }

    (!fields.is_empty()).then_some(ValueNestedPlan::Variant { fields })
}

fn nested_variant_condition(
    part: &crate::VariantPart,
    variant_index: usize,
) -> Option<ValueNestedVariantCondition> {
    let variant = part.variants.get(variant_index)?;
    let Some(discriminant) = &part.discriminant else {
        let selected = part
            .variants
            .iter()
            .position(|variant| matches!(variant.selector, VariantSelector::Default))
            .unwrap_or(0);
        return (selected == variant_index).then_some(ValueNestedVariantCondition::Always);
    };

    match &variant.selector {
        VariantSelector::Ranges(ranges) if !ranges.is_empty() => {
            Some(ValueNestedVariantCondition::Discriminant {
                member: discriminant.clone(),
                ranges: ranges.clone(),
                inverted: false,
            })
        }
        VariantSelector::Ranges(_) => None,
        VariantSelector::Default => {
            let first_default = part
                .variants
                .iter()
                .position(|variant| matches!(variant.selector, VariantSelector::Default))?;
            if first_default != variant_index {
                return None;
            }
            let ranges = part
                .variants
                .iter()
                .filter_map(|variant| match &variant.selector {
                    VariantSelector::Ranges(ranges) => Some(ranges.as_slice()),
                    VariantSelector::Default => None,
                })
                .flatten()
                .cloned()
                .collect::<Vec<_>>();
            if ranges.is_empty() {
                Some(ValueNestedVariantCondition::Always)
            } else {
                Some(ValueNestedVariantCondition::Discriminant {
                    member: discriminant.clone(),
                    ranges,
                    inverted: true,
                })
            }
        }
    }
}

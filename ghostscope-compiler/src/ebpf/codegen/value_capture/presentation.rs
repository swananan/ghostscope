use super::*;

pub(in crate::ebpf::codegen) fn nested_value_presentation(
    value: &NestedValueSource,
) -> Result<ghostscope_dwarf::ValuePresentation> {
    let children = match &value.children {
        NestedValueChildrenSource::None => return Ok(value.presentation.clone()),
        NestedValueChildrenSource::ProjectedValue { slot_offset, child } => {
            ghostscope_protocol::NestedValueChildrenPresentation::ProjectedValue {
                child: Box::new(ghostscope_protocol::NestedValueChildPresentation {
                    slot_offset: u64::try_from(*slot_offset).map_err(|_| {
                        CodeGenError::DwarfError(
                            "nested child slot offset does not fit the protocol".to_string(),
                        )
                    })?,
                    value: Box::new(nested_child_presentation(child)?),
                }),
            }
        }
        NestedValueChildrenSource::ProjectedView { fields } => {
            ghostscope_protocol::NestedValueChildrenPresentation::ProjectedView {
                fields: fields
                    .iter()
                    .map(|field| {
                        Ok(ghostscope_protocol::NestedValueFieldPresentation {
                            field_index: u64::try_from(field.field_index).map_err(|_| {
                                CodeGenError::DwarfError(
                                    "nested field index does not fit the protocol".to_string(),
                                )
                            })?,
                            child: ghostscope_protocol::NestedValueChildPresentation {
                                slot_offset: u64::try_from(field.slot_offset).map_err(|_| {
                                    CodeGenError::DwarfError(
                                        "nested field slot offset does not fit the protocol"
                                            .to_string(),
                                    )
                                })?,
                                value: Box::new(nested_child_presentation(&field.child)?),
                            },
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            }
        }
        NestedValueChildrenSource::HashTable {
            first_slot_offset,
            bucket_slot_stride,
            bucket_count,
            fields,
            ..
        } => ghostscope_protocol::NestedValueChildrenPresentation::HashTable {
            first_slot_offset: u64::try_from(*first_slot_offset).map_err(|_| {
                CodeGenError::DwarfError(
                    "nested hash-table offset does not fit the protocol".to_string(),
                )
            })?,
            bucket_slot_stride: u64::try_from(*bucket_slot_stride).map_err(|_| {
                CodeGenError::DwarfError(
                    "nested hash-table stride does not fit the protocol".to_string(),
                )
            })?,
            bucket_count: u64::try_from(*bucket_count).map_err(|_| {
                CodeGenError::DwarfError(
                    "nested hash-table bucket count does not fit the protocol".to_string(),
                )
            })?,
            fields: fields
                .iter()
                .map(|field| {
                    Ok(ghostscope_protocol::NestedValueHashTableFieldPresentation {
                        field_index: u64::try_from(field.field_index).map_err(|_| {
                            CodeGenError::DwarfError(
                                "nested hash-table field index does not fit the protocol"
                                    .to_string(),
                            )
                        })?,
                        slot_offset: u64::try_from(field.slot_offset).map_err(|_| {
                            CodeGenError::DwarfError(
                                "nested hash-table field offset does not fit the protocol"
                                    .to_string(),
                            )
                        })?,
                        value: Box::new(nested_child_presentation(&field.child)?),
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        },
        NestedValueChildrenSource::Variant { fields } => {
            ghostscope_protocol::NestedValueChildrenPresentation::Variant {
                fields: fields
                    .iter()
                    .map(|field| {
                        let protocol_index = |index: usize, role: &str| {
                            u64::try_from(index).map_err(|_| {
                                CodeGenError::DwarfError(format!(
                                    "nested variant {role} index does not fit the protocol"
                                ))
                            })
                        };
                        Ok(ghostscope_protocol::NestedValueVariantFieldPresentation {
                            part_index: protocol_index(field.part_index, "part")?,
                            variant_index: protocol_index(field.variant_index, "branch")?,
                            member_index: protocol_index(field.member_index, "member")?,
                            payload_field_index: protocol_index(
                                field.payload_field_index,
                                "payload field",
                            )?,
                            child: ghostscope_protocol::NestedValueChildPresentation {
                                slot_offset: u64::try_from(field.field.slot_offset).map_err(
                                    |_| {
                                        CodeGenError::DwarfError(
                                            "nested variant slot offset does not fit the protocol"
                                                .to_string(),
                                        )
                                    },
                                )?,
                                value: Box::new(nested_child_presentation(&field.field.child)?),
                            },
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
            }
        }
        NestedValueChildrenSource::Sequence {
            first_slot_offset,
            slot_stride,
            slot_count,
            element,
            ..
        } => ghostscope_protocol::NestedValueChildrenPresentation::Sequence {
            first_slot_offset: u64::try_from(*first_slot_offset).map_err(|_| {
                CodeGenError::DwarfError(
                    "nested sequence offset does not fit the protocol".to_string(),
                )
            })?,
            slot_stride: u64::try_from(*slot_stride).map_err(|_| {
                CodeGenError::DwarfError(
                    "nested sequence stride does not fit the protocol".to_string(),
                )
            })?,
            slot_count: u64::try_from(*slot_count).map_err(|_| {
                CodeGenError::DwarfError(
                    "nested sequence count does not fit the protocol".to_string(),
                )
            })?,
            element: Box::new(nested_child_presentation(element)?),
        },
    };
    Ok(ghostscope_dwarf::ValuePresentation::Nested {
        root: Box::new(value.presentation.clone()),
        root_payload_len: u64::try_from(value.root_payload_len).map_err(|_| {
            CodeGenError::DwarfError(
                "nested root payload length does not fit the protocol".to_string(),
            )
        })?,
        children: Box::new(children),
    })
}

pub(in crate::ebpf::codegen) fn nested_child_presentation(
    value: &NestedValueSource,
) -> Result<ghostscope_protocol::NestedValuePresentation> {
    Ok(ghostscope_protocol::NestedValuePresentation {
        payload_len: u64::try_from(value.total_len).map_err(|_| {
            CodeGenError::DwarfError(
                "nested child payload length does not fit the protocol".to_string(),
            )
        })?,
        type_info: Box::new(value.output_type.clone()),
        presentation: Box::new(nested_value_presentation(value)?),
    })
}

use super::*;

pub(in crate::ebpf::codegen) fn metadata_access_size(
    projection: &ghostscope_dwarf::TypeProjection,
    role: &str,
) -> Result<ghostscope_dwarf::MemoryAccessSize> {
    let size = projection.resolved_type.summary.size();
    exact_memory_access_size(size, &format!("indirect value {role} member"))
}

pub(in crate::ebpf::codegen) fn exact_memory_access_size(
    size: u64,
    role: &str,
) -> Result<ghostscope_dwarf::MemoryAccessSize> {
    // Keep this exact; `from_size` falls back to U64 for unknown widths.
    match size {
        1 => Ok(ghostscope_dwarf::MemoryAccessSize::U8),
        2 => Ok(ghostscope_dwarf::MemoryAccessSize::U16),
        4 => Ok(ghostscope_dwarf::MemoryAccessSize::U32),
        8 => Ok(ghostscope_dwarf::MemoryAccessSize::U64),
        _ => Err(CodeGenError::DwarfError(format!(
            "{role} has unsupported DWARF size {size}"
        ))),
    }
}

pub(in crate::ebpf::codegen) fn projected_value_steps(
    value: &ghostscope_dwarf::ProjectedValueRead,
) -> Result<Vec<ProjectedViewStep>> {
    projected_steps(&value.steps)
}

pub(in crate::ebpf::codegen) fn projected_steps(
    steps: &[ghostscope_dwarf::ProjectedValueStep],
) -> Result<Vec<ProjectedViewStep>> {
    steps
        .iter()
        .map(|step| match step {
            ghostscope_dwarf::ProjectedValueStep::Member { offset } => {
                Ok(ProjectedViewStep::Member { offset: *offset })
            }
            ghostscope_dwarf::ProjectedValueStep::Dereference { pointer_size } => {
                Ok(ProjectedViewStep::Dereference {
                    pointer_size: exact_memory_access_size(
                        *pointer_size,
                        "projected semantic pointer",
                    )?,
                })
            }
        })
        .collect()
}

pub(in crate::ebpf::codegen) fn discriminant_is_signed(
    type_info: &ghostscope_dwarf::TypeInfo,
) -> Option<bool> {
    match type_info {
        ghostscope_dwarf::TypeInfo::BaseType { encoding, .. } => {
            if *encoding == ghostscope_dwarf::constants::DW_ATE_signed.0 as u16
                || *encoding == ghostscope_dwarf::constants::DW_ATE_signed_char.0 as u16
            {
                Some(true)
            } else if *encoding == ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16
                || *encoding == ghostscope_dwarf::constants::DW_ATE_unsigned_char.0 as u16
                || *encoding == ghostscope_dwarf::constants::DW_ATE_boolean.0 as u16
            {
                Some(false)
            } else {
                None
            }
        }
        ghostscope_dwarf::TypeInfo::EnumType { base_type, .. }
        | ghostscope_dwarf::TypeInfo::ScopedEnumType { base_type, .. }
        | ghostscope_dwarf::TypeInfo::TypedefType {
            underlying_type: base_type,
            ..
        }
        | ghostscope_dwarf::TypeInfo::QualifiedType {
            underlying_type: base_type,
            ..
        } => discriminant_is_signed(base_type),
        ghostscope_dwarf::TypeInfo::BitfieldType { .. } => None,
        _ => None,
    }
}

pub(in crate::ebpf::codegen) fn compile_nested_variant_condition(
    condition: &ghostscope_dwarf::ValueNestedVariantCondition,
) -> Option<NestedValueVariantConditionSource> {
    match condition {
        ghostscope_dwarf::ValueNestedVariantCondition::Always => {
            Some(NestedValueVariantConditionSource::Always)
        }
        ghostscope_dwarf::ValueNestedVariantCondition::Discriminant {
            member,
            ranges,
            inverted,
        } => {
            let signed = discriminant_is_signed(&member.member_type)?;
            let access_size =
                exact_memory_access_size(member.member_type.size(), "nested variant discriminant")
                    .ok()?;
            let ranges_match_type = ranges.iter().all(|range| {
                matches!(
                    (signed, range.start, range.end),
                    (
                        true,
                        ghostscope_dwarf::DiscriminantValue::Signed(_),
                        ghostscope_dwarf::DiscriminantValue::Signed(_)
                    ) | (
                        false,
                        ghostscope_dwarf::DiscriminantValue::Unsigned(_),
                        ghostscope_dwarf::DiscriminantValue::Unsigned(_)
                    )
                )
            });
            ranges_match_type.then(|| NestedValueVariantConditionSource::Discriminant {
                offset: member.offset,
                access_size,
                signed,
                ranges: ranges.clone(),
                inverted: *inverted,
            })
        }
    }
}

pub(in crate::ebpf::codegen) fn metadata_member(
    projection: &ghostscope_dwarf::TypeProjection,
    role: &str,
) -> Result<(u64, ghostscope_dwarf::MemoryAccessSize)> {
    let access_size = metadata_access_size(projection, role)?;
    let offset = projected_member_offset(projection, role)?;
    Ok((offset, access_size))
}

pub(in crate::ebpf::codegen) fn projected_member_offset(
    projection: &ghostscope_dwarf::TypeProjection,
    role: &str,
) -> Result<u64> {
    match &projection.layout {
        ghostscope_dwarf::TypeProjectionLayout::Member { offset } => Ok(*offset),
        layout => Err(CodeGenError::DwarfError(format!(
            "semantic value {role} projection must be a member, got {layout:?}"
        ))),
    }
}

pub(in crate::ebpf::codegen) fn is_known_zero_sized_type(
    type_info: &ghostscope_dwarf::TypeInfo,
) -> bool {
    match type_info {
        ghostscope_dwarf::TypeInfo::BaseType { name, size: 0, .. } if name == "()" => true,
        ghostscope_dwarf::TypeInfo::StructType { size: 0, .. }
        | ghostscope_dwarf::TypeInfo::UnionType { size: 0, .. }
        | ghostscope_dwarf::TypeInfo::VariantType { size: 0, .. }
        | ghostscope_dwarf::TypeInfo::ArrayType {
            total_size: Some(0),
            ..
        } => true,
        ghostscope_dwarf::TypeInfo::TypedefType {
            underlying_type, ..
        }
        | ghostscope_dwarf::TypeInfo::QualifiedType {
            underlying_type, ..
        } => is_known_zero_sized_type(underlying_type),
        _ => false,
    }
}

pub(in crate::ebpf::codegen) fn inline_view_data_len(
    physical_type: &ghostscope_dwarf::TypeInfo,
    output_type: &ghostscope_dwarf::TypeInfo,
) -> Result<usize> {
    let physical_size = usize::try_from(physical_type.size()).map_err(|_| {
        CodeGenError::DwarfError("inline semantic root size does not fit this host".to_string())
    })?;
    let output_size = usize::try_from(output_type.size()).map_err(|_| {
        CodeGenError::DwarfError("inline semantic view size does not fit this host".to_string())
    })?;
    if output_size != physical_size {
        return Err(CodeGenError::DwarfError(format!(
            "inline semantic view size {output_size} does not match DWARF root size {physical_size}"
        )));
    }
    if output_size == 0 && !is_known_zero_sized_type(output_type) {
        return Err(CodeGenError::DwarfError(
            "inline semantic view has an unknown zero-byte layout".to_string(),
        ));
    }
    Ok(output_size)
}

pub(in crate::ebpf::codegen) fn projected_view_source(
    output_type: &ghostscope_dwarf::TypeInfo,
    fields: &[ghostscope_dwarf::ProjectedViewField],
) -> Result<(usize, Vec<ProjectedViewFieldSource>)> {
    let ghostscope_dwarf::TypeInfo::StructType { size, members, .. } = output_type else {
        return Err(CodeGenError::DwarfError(
            "projected semantic view must be a struct".to_string(),
        ));
    };
    if members.len() != fields.len() {
        return Err(CodeGenError::DwarfError(
            "projected semantic fields do not match the output type".to_string(),
        ));
    }

    let data_len = usize::try_from(*size).map_err(|_| {
        CodeGenError::DwarfError("projected semantic view size does not fit this host".to_string())
    })?;
    if data_len > u16::MAX as usize {
        return Err(CodeGenError::DwarfError(format!(
            "projected semantic view size {data_len} exceeds the protocol limit"
        )));
    }
    let mut sources = Vec::with_capacity(fields.len());
    let mut ranges = Vec::with_capacity(fields.len());
    for (member, field) in members.iter().zip(fields) {
        let type_matches = match field.capture {
            ghostscope_dwarf::ProjectedViewFieldCapture::Value => {
                member.member_type == field.value.resolved_type.summary
            }
            ghostscope_dwarf::ProjectedViewFieldCapture::Address => {
                let pointer_size = field.value.steps.iter().rev().find_map(|step| match step {
                    ghostscope_dwarf::ProjectedValueStep::Dereference { pointer_size } => {
                        Some(*pointer_size)
                    }
                    ghostscope_dwarf::ProjectedValueStep::Member { .. } => None,
                });
                matches!(
                    &member.member_type,
                    ghostscope_dwarf::TypeInfo::PointerType { target_type, size }
                        if target_type.as_ref() == &field.value.resolved_type.summary
                            && pointer_size == Some(*size)
                )
            }
        };
        if member.offset != field.output_offset || !type_matches {
            return Err(CodeGenError::DwarfError(format!(
                "projected semantic field '{}' does not match its output member",
                member.name
            )));
        }
        let output_offset = usize::try_from(field.output_offset).map_err(|_| {
            CodeGenError::DwarfError(format!(
                "projected semantic field '{}' offset does not fit this host",
                member.name
            ))
        })?;
        let value_len = usize::try_from(member.member_type.size()).map_err(|_| {
            CodeGenError::DwarfError(format!(
                "projected semantic field '{}' size does not fit this host",
                member.name
            ))
        })?;
        let end = output_offset.checked_add(value_len).ok_or_else(|| {
            CodeGenError::DwarfError(format!(
                "projected semantic field '{}' end overflow",
                member.name
            ))
        })?;
        if end > data_len || (value_len == 0 && !is_known_zero_sized_type(&member.member_type)) {
            return Err(CodeGenError::DwarfError(format!(
                "projected semantic field '{}' exceeds its output layout",
                member.name
            )));
        }
        if value_len > 0
            && ranges
                .iter()
                .any(|(start, range_end)| output_offset < *range_end && *start < end)
        {
            return Err(CodeGenError::DwarfError(format!(
                "projected semantic field '{}' overlaps another output member",
                member.name
            )));
        }
        ranges.push((output_offset, end));

        sources.push(ProjectedViewFieldSource {
            output_offset,
            value_len,
            steps: projected_value_steps(&field.value)?,
            capture: field.capture,
        });
    }

    Ok((data_len, sources))
}

pub(in crate::ebpf::codegen) fn sequence_capture_limits(
    cap: usize,
    element_stride: u64,
) -> Result<(usize, usize, usize)> {
    let stride = usize::try_from(element_stride).map_err(|_| {
        CodeGenError::DwarfError(format!(
            "sequence element DWARF size {element_stride} does not fit this host"
        ))
    })?;
    let (max_elements, max_len) = if stride == 0 {
        // A byte cap cannot bound a ZST payload, so use the configured value
        // as its logical element-count cap.
        (cap, 0)
    } else {
        let max_elements = cap / stride;
        (max_elements, max_elements * stride)
    };
    let data_len = ghostscope_protocol::INDIRECT_SEQUENCE_HEADER_SIZE.saturating_add(max_len);
    Ok((max_elements, max_len, data_len))
}

pub(in crate::ebpf::codegen) fn hash_table_capture_limits(
    cap: usize,
    entry_stride: u64,
    occupancy: ghostscope_dwarf::HashTableOccupancy,
    bucket_limit: Option<usize>,
) -> Result<(usize, usize, usize)> {
    let stride = usize::try_from(entry_stride).map_err(|_| {
        CodeGenError::DwarfError(format!(
            "hash-table entry DWARF size {entry_stride} does not fit this host"
        ))
    })?;
    let occupancy_width = occupancy
        .byte_width()
        .and_then(|width| usize::try_from(width).ok())
        .ok_or_else(|| {
            CodeGenError::DwarfError("invalid hash-table occupancy width".to_string())
        })?;
    let bytes_per_bucket = stride.checked_add(occupancy_width).ok_or_else(|| {
        CodeGenError::DwarfError("hash-table bucket capture size overflow".to_string())
    })?;
    let max_buckets = (cap / bytes_per_bucket).min(bucket_limit.unwrap_or(usize::MAX));
    let max_len = max_buckets
        .checked_mul(bytes_per_bucket)
        .ok_or_else(|| CodeGenError::DwarfError("hash-table payload size overflow".to_string()))?;
    let data_len = ghostscope_protocol::HASH_TABLE_HEADER_SIZE.saturating_add(max_len);
    Ok((max_buckets, max_len, data_len))
}

pub(in crate::ebpf::codegen) fn btree_capture_limits(
    cap: usize,
    node_capacity: u64,
    key_stride: u64,
    value_stride: Option<u64>,
) -> Result<(usize, usize, usize)> {
    // Nodes are emitted as fixed control-flow blocks so kernels without
    // bounded-loop support can verify the program. Cap the unrolled code size.
    const MAX_CAPTURE_NODES: usize = 16;

    let capacity = usize::try_from(node_capacity).map_err(|_| {
        CodeGenError::DwarfError(format!(
            "B-Tree node capacity {node_capacity} does not fit this host"
        ))
    })?;
    let key_stride = usize::try_from(key_stride).map_err(|_| {
        CodeGenError::DwarfError("B-Tree key slot stride does not fit this host".to_string())
    })?;
    let value_stride = value_stride
        .map(|stride| {
            usize::try_from(stride).map_err(|_| {
                CodeGenError::DwarfError(
                    "B-Tree value slot stride does not fit this host".to_string(),
                )
            })
        })
        .transpose()?
        .unwrap_or(0);
    let slot_bytes = key_stride
        .checked_add(value_stride)
        .and_then(|stride| stride.checked_mul(capacity))
        .and_then(|bytes| bytes.checked_add(ghostscope_protocol::BTREE_NODE_HEADER_SIZE))
        .ok_or_else(|| CodeGenError::DwarfError("B-Tree node payload overflow".to_string()))?;
    if slot_bytes == 0 {
        return Err(CodeGenError::DwarfError(
            "B-Tree node payload has no metadata".to_string(),
        ));
    }
    let max_nodes = (cap / slot_bytes).min(MAX_CAPTURE_NODES);
    let max_len = max_nodes
        .checked_mul(slot_bytes)
        .ok_or_else(|| CodeGenError::DwarfError("B-Tree payload size overflow".to_string()))?;
    let data_len = ghostscope_protocol::BTREE_HEADER_SIZE
        .checked_add(max_len)
        .ok_or_else(|| CodeGenError::DwarfError("B-Tree payload size overflow".to_string()))?;
    Ok((max_nodes, max_len, data_len))
}

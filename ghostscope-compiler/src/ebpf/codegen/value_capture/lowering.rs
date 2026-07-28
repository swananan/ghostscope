use super::*;

pub(in crate::ebpf::codegen) fn compile_nested_value_source(
    plan: &ghostscope_dwarf::ValueReadPlan,
    budget: usize,
    max_sequence_elements: usize,
) -> Result<Option<NestedValueSource>> {
    let Some(nested) = &plan.nested else {
        let Some((output_type, root, root_payload_len)) =
            compile_nested_root_source(plan, budget, None, None)?
        else {
            return Ok(None);
        };
        return Ok(Some(NestedValueSource {
            output_type,
            presentation: plan.presentation.clone(),
            root_payload_len,
            total_len: root_payload_len,
            root,
            children: NestedValueChildrenSource::None,
        }));
    };

    match nested {
        ghostscope_dwarf::ValueNestedPlan::ProjectedValue { value } => {
            let Some((output_type, root, root_payload_len)) =
                compile_nested_root_source(plan, budget, None, None)?
            else {
                return Ok(None);
            };
            let child_budget = budget
                .saturating_sub(root_payload_len)
                .saturating_sub(ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE);
            let Some(child) =
                compile_nested_value_source(value, child_budget, max_sequence_elements)?
            else {
                return Ok(None);
            };
            let slot_offset = root_payload_len;
            let total_len = slot_offset
                .checked_add(ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE)
                .and_then(|len| len.checked_add(child.total_len))
                .ok_or_else(|| {
                    CodeGenError::DwarfError("nested value payload size overflow".to_string())
                })?;
            if total_len > budget {
                return Ok(None);
            }
            Ok(Some(NestedValueSource {
                output_type,
                presentation: plan.presentation.clone(),
                root_payload_len,
                total_len,
                root,
                children: NestedValueChildrenSource::ProjectedValue {
                    slot_offset,
                    child: Box::new(child),
                },
            }))
        }
        ghostscope_dwarf::ValueNestedPlan::ProjectedView { fields } => {
            let Some((output_type, root, root_payload_len)) =
                compile_nested_root_source(plan, budget, None, None)?
            else {
                return Ok(None);
            };
            let header_bytes = fields
                .len()
                .checked_mul(ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE)
                .ok_or_else(|| {
                    CodeGenError::DwarfError("nested field header size overflow".to_string())
                })?;
            let child_budget = budget
                .saturating_sub(root_payload_len)
                .saturating_sub(header_bytes)
                .checked_div(fields.len().max(1))
                .unwrap_or(0);
            let mut slot_offset = root_payload_len;
            let mut compiled_fields = Vec::with_capacity(fields.len());
            for field in fields {
                let Some(child) =
                    compile_nested_value_source(&field.value, child_budget, max_sequence_elements)?
                else {
                    continue;
                };
                let steps = nested_field_steps(&plan.capture, &root, field.field_index)?;
                compiled_fields.push(NestedValueFieldSource {
                    field_index: field.field_index,
                    slot_offset,
                    steps,
                    child: Box::new(child),
                });
                slot_offset = slot_offset
                    .checked_add(ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE)
                    .and_then(|offset| {
                        offset.checked_add(
                            compiled_fields
                                .last()
                                .expect("compiled nested field was just pushed")
                                .child
                                .total_len,
                        )
                    })
                    .ok_or_else(|| {
                        CodeGenError::DwarfError(
                            "nested projected-view payload size overflow".to_string(),
                        )
                    })?;
            }
            if compiled_fields.is_empty() || slot_offset > budget {
                return Ok(None);
            }
            Ok(Some(NestedValueSource {
                output_type,
                presentation: plan.presentation.clone(),
                root_payload_len,
                total_len: slot_offset,
                root,
                children: NestedValueChildrenSource::ProjectedView {
                    fields: compiled_fields,
                },
            }))
        }
        ghostscope_dwarf::ValueNestedPlan::Variant { fields } => {
            let Some((output_type, root, root_payload_len)) =
                compile_nested_root_source(plan, budget, None, None)?
            else {
                return Ok(None);
            };
            type VariantFieldCandidate<'a> = (
                &'a ghostscope_dwarf::ValueNestedVariantFieldPlan,
                NestedValueVariantConditionSource,
            );
            let mut parts = std::collections::BTreeMap::<
                usize,
                std::collections::BTreeMap<usize, Vec<VariantFieldCandidate<'_>>>,
            >::new();
            for field in fields {
                let Some(condition) = compile_nested_variant_condition(&field.condition) else {
                    continue;
                };
                parts
                    .entry(field.part_index)
                    .or_default()
                    .entry(field.variant_index)
                    .or_default()
                    .push((field, condition));
            }
            if parts.is_empty() {
                return Ok(None);
            }

            // Variant parts can be active at the same time, but branches in one
            // part are mutually exclusive and can reuse the same physical slots.
            let part_budget = budget
                .saturating_sub(root_payload_len)
                .checked_div(parts.len())
                .unwrap_or(0);
            let mut next_part_offset = root_payload_len;
            let mut compiled_fields = Vec::with_capacity(fields.len());
            for variants in parts.into_values() {
                let slot_count = variants.values().map(Vec::len).max().unwrap_or(0);
                if slot_count == 0 {
                    continue;
                }
                let header_bytes = slot_count
                    .checked_mul(ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE)
                    .ok_or_else(|| {
                        CodeGenError::DwarfError("nested variant header size overflow".to_string())
                    })?;
                let child_budget = part_budget
                    .saturating_sub(header_bytes)
                    .checked_div(slot_count)
                    .unwrap_or(0);
                let slot_stride = ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE
                    .checked_add(child_budget)
                    .ok_or_else(|| {
                        CodeGenError::DwarfError("nested variant slot stride overflow".to_string())
                    })?;
                let part_len = slot_stride.checked_mul(slot_count).ok_or_else(|| {
                    CodeGenError::DwarfError("nested variant part size overflow".to_string())
                })?;
                let mut compiled_part_fields = Vec::new();

                for variant_fields in variants.into_values() {
                    for (slot_index, (field, condition)) in variant_fields.into_iter().enumerate() {
                        let Some(child) = compile_nested_value_source(
                            &field.value,
                            child_budget,
                            max_sequence_elements,
                        )?
                        else {
                            continue;
                        };
                        if child.total_len > child_budget {
                            return Err(CodeGenError::DwarfError(
                                "nested variant child exceeds its slot budget".to_string(),
                            ));
                        }
                        let slot_offset = slot_index
                            .checked_mul(slot_stride)
                            .and_then(|offset| next_part_offset.checked_add(offset))
                            .ok_or_else(|| {
                                CodeGenError::DwarfError(
                                    "nested variant slot offset overflow".to_string(),
                                )
                            })?;
                        compiled_part_fields.push(NestedValueVariantFieldSource {
                            part_index: field.part_index,
                            variant_index: field.variant_index,
                            member_index: field.member_index,
                            payload_field_index: field.payload_field_index,
                            field: NestedValueFieldSource {
                                field_index: field.payload_field_index,
                                slot_offset,
                                steps: projected_steps(&field.steps)?,
                                child: Box::new(child),
                            },
                            condition,
                        });
                    }
                }
                if compiled_part_fields.is_empty() {
                    continue;
                }
                compiled_fields.extend(compiled_part_fields);
                next_part_offset = next_part_offset.checked_add(part_len).ok_or_else(|| {
                    CodeGenError::DwarfError("nested variant payload size overflow".to_string())
                })?;
            }
            if compiled_fields.is_empty() || next_part_offset > budget {
                return Ok(None);
            }
            Ok(Some(NestedValueSource {
                output_type,
                presentation: plan.presentation.clone(),
                root_payload_len,
                total_len: next_part_offset,
                root,
                children: NestedValueChildrenSource::Variant {
                    fields: compiled_fields,
                },
            }))
        }
        ghostscope_dwarf::ValueNestedPlan::HashTable { fields } => {
            if fields.is_empty() || max_sequence_elements == 0 {
                return Ok(None);
            }
            let Some((_, unconstrained_root, _)) =
                compile_nested_root_source(plan, budget, None, None)?
            else {
                return Ok(None);
            };
            let NestedValueRootSource::IndirectHashTable { max_buckets, .. } = unconstrained_root
            else {
                return Err(CodeGenError::DwarfError(
                    "nested hash-table children do not match their root capture".to_string(),
                ));
            };
            let max_buckets = max_buckets.min(max_sequence_elements);
            for bucket_count in (1..=max_buckets).rev() {
                let Some((output_type, root, root_payload_len)) =
                    compile_nested_root_source(plan, budget, None, Some(bucket_count))?
                else {
                    continue;
                };
                let header_bytes_per_bucket = fields
                    .len()
                    .checked_mul(ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE)
                    .ok_or_else(|| {
                        CodeGenError::DwarfError(
                            "nested hash-table field header size overflow".to_string(),
                        )
                    })?;
                let child_budget = budget
                    .saturating_sub(root_payload_len)
                    .checked_div(bucket_count)
                    .unwrap_or(0)
                    .saturating_sub(header_bytes_per_bucket)
                    .checked_div(fields.len())
                    .unwrap_or(0);
                let mut field_slot_offset = 0usize;
                let mut compiled_fields = Vec::with_capacity(fields.len());
                for field in fields {
                    let Some(child) = compile_nested_value_source(
                        &field.value,
                        child_budget,
                        max_sequence_elements,
                    )?
                    else {
                        break;
                    };
                    let entry_offset =
                        nested_hash_table_field_offset(&plan.presentation, field.field_index)?;
                    compiled_fields.push(NestedHashTableFieldSource {
                        field_index: field.field_index,
                        entry_offset,
                        slot_offset: field_slot_offset,
                        child: Box::new(child),
                    });
                    field_slot_offset = field_slot_offset
                        .checked_add(ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE)
                        .and_then(|offset| {
                            offset.checked_add(
                                compiled_fields
                                    .last()
                                    .expect("compiled hash-table field was just pushed")
                                    .child
                                    .total_len,
                            )
                        })
                        .ok_or_else(|| {
                            CodeGenError::DwarfError(
                                "nested hash-table field payload size overflow".to_string(),
                            )
                        })?;
                }
                if compiled_fields.len() != fields.len() {
                    continue;
                }
                let total_len = bucket_count
                    .checked_mul(field_slot_offset)
                    .and_then(|children_len| root_payload_len.checked_add(children_len))
                    .ok_or_else(|| {
                        CodeGenError::DwarfError(
                            "nested hash-table payload size overflow".to_string(),
                        )
                    })?;
                if total_len > budget {
                    continue;
                }
                let metadata = nested_hash_table_metadata(&plan.capture)?;
                return Ok(Some(NestedValueSource {
                    output_type,
                    presentation: plan.presentation.clone(),
                    root_payload_len,
                    total_len,
                    root,
                    children: NestedValueChildrenSource::HashTable {
                        first_slot_offset: root_payload_len,
                        bucket_slot_stride: field_slot_offset,
                        bucket_count,
                        fields: compiled_fields,
                        metadata,
                    },
                }));
            }
            Ok(None)
        }
        ghostscope_dwarf::ValueNestedPlan::Sequence { element } => {
            for slot_count in (1..=max_sequence_elements).rev() {
                let Some((output_type, root, root_payload_len)) =
                    compile_nested_root_source(plan, budget, Some(slot_count), None)?
                else {
                    continue;
                };
                let header_bytes = slot_count
                    .checked_mul(ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE)
                    .ok_or_else(|| {
                        CodeGenError::DwarfError("nested sequence header size overflow".to_string())
                    })?;
                let child_budget = budget
                    .saturating_sub(root_payload_len)
                    .saturating_sub(header_bytes)
                    / slot_count;
                let Some(child) =
                    compile_nested_value_source(element, child_budget, max_sequence_elements)?
                else {
                    continue;
                };
                let slot_stride = ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE
                    .checked_add(child.total_len)
                    .ok_or_else(|| {
                        CodeGenError::DwarfError("nested sequence slot size overflow".to_string())
                    })?;
                let total_len = root_payload_len
                    .checked_add(slot_count.checked_mul(slot_stride).ok_or_else(|| {
                        CodeGenError::DwarfError(
                            "nested sequence payload size overflow".to_string(),
                        )
                    })?)
                    .ok_or_else(|| {
                        CodeGenError::DwarfError(
                            "nested sequence payload size overflow".to_string(),
                        )
                    })?;
                if total_len > budget {
                    continue;
                }
                let metadata = nested_sequence_metadata(&plan.capture)?;
                return Ok(Some(NestedValueSource {
                    output_type,
                    presentation: plan.presentation.clone(),
                    root_payload_len,
                    total_len,
                    root,
                    children: NestedValueChildrenSource::Sequence {
                        first_slot_offset: root_payload_len,
                        slot_stride,
                        slot_count,
                        element: Box::new(child),
                        metadata,
                    },
                }));
            }
            Ok(None)
        }
    }
}

pub(in crate::ebpf::codegen) fn compile_nested_root_source(
    plan: &ghostscope_dwarf::ValueReadPlan,
    budget: usize,
    sequence_elements: Option<usize>,
    hash_buckets: Option<usize>,
) -> Result<Option<(ghostscope_dwarf::TypeInfo, NestedValueRootSource, usize)>> {
    let output = match &plan.capture {
        ghostscope_dwarf::ValueCapturePlan::ProjectedValue { value } => {
            let offset = projected_member_offset(value, "nested projected value")?;
            let output_type = value.resolved_type.summary.clone();
            let len = EbpfContext::compute_read_size_for_type(&output_type);
            if len == 0 && !is_known_zero_sized_type(&output_type) {
                return Ok(None);
            }
            (
                output_type,
                NestedValueRootSource::ProjectedValue { offset, len },
                len,
            )
        }
        ghostscope_dwarf::ValueCapturePlan::InlineView { output_type, .. } => {
            let len = usize::try_from(output_type.size()).map_err(|_| {
                CodeGenError::DwarfError(
                    "nested inline semantic view size does not fit this host".to_string(),
                )
            })?;
            if len == 0 && !is_known_zero_sized_type(output_type) {
                return Ok(None);
            }
            (
                output_type.clone(),
                NestedValueRootSource::InlineView { len },
                len,
            )
        }
        ghostscope_dwarf::ValueCapturePlan::ProjectedView {
            output_type,
            fields,
        } => {
            let (len, fields) = projected_view_source(output_type, fields)?;
            (
                output_type.clone(),
                NestedValueRootSource::ProjectedView { fields },
                len,
            )
        }
        ghostscope_dwarf::ValueCapturePlan::IndirectBytes {
            data,
            length,
            excluded_tail_bytes,
        } => {
            if budget < ghostscope_protocol::INDIRECT_BYTES_LENGTH_PREFIX_SIZE {
                return Ok(None);
            }
            let (data_offset, data_access_size) = metadata_member(data, "nested data")?;
            let (length_offset, length_access_size) = metadata_member(length, "nested length")?;
            let max_len = budget - ghostscope_protocol::INDIRECT_BYTES_LENGTH_PREFIX_SIZE;
            (
                plan.root_type.summary.clone(),
                NestedValueRootSource::IndirectBytes {
                    data_offset,
                    data_access_size,
                    length_offset,
                    length_access_size,
                    excluded_tail_bytes: *excluded_tail_bytes,
                    max_len,
                },
                ghostscope_protocol::INDIRECT_BYTES_LENGTH_PREFIX_SIZE + max_len,
            )
        }
        ghostscope_dwarf::ValueCapturePlan::IndirectSequence {
            data,
            length,
            element_stride,
        } => {
            if budget < ghostscope_protocol::INDIRECT_SEQUENCE_HEADER_SIZE {
                return Ok(None);
            }
            let (data_offset, data_access_size) = metadata_member(data, "nested sequence data")?;
            let (length_offset, length_access_size) =
                metadata_member(length, "nested sequence length")?;
            let (max_elements, max_len, data_len) =
                nested_sequence_capture_limits(budget, *element_stride, sequence_elements, false)?;
            (
                plan.root_type.summary.clone(),
                NestedValueRootSource::IndirectSequence {
                    data_offset,
                    data_access_size,
                    length_offset,
                    length_access_size,
                    element_stride: *element_stride,
                    max_elements,
                    max_len,
                },
                data_len,
            )
        }
        ghostscope_dwarf::ValueCapturePlan::IndirectRingSequence {
            data,
            start,
            length,
            capacity,
            element_stride,
        } => {
            if budget < ghostscope_protocol::INDIRECT_SEQUENCE_HEADER_SIZE {
                return Ok(None);
            }
            let (data_offset, data_access_size) =
                metadata_member(data, "nested ring sequence data")?;
            let (start_offset, start_access_size) =
                metadata_member(start, "nested ring sequence start")?;
            let length = match length.as_ref() {
                ghostscope_dwarf::RingSequenceLength::Explicit(length) => {
                    let (offset, access_size) =
                        metadata_member(length, "nested ring sequence length")?;
                    RingSequenceLengthSource::Explicit {
                        offset,
                        access_size,
                    }
                }
                ghostscope_dwarf::RingSequenceLength::End(end) => {
                    let (offset, access_size) = metadata_member(end, "nested ring sequence end")?;
                    RingSequenceLengthSource::End {
                        offset,
                        access_size,
                    }
                }
            };
            let (capacity_offset, capacity_access_size) =
                metadata_member(capacity, "nested ring sequence capacity")?;
            let (max_elements, max_len, data_len) =
                nested_sequence_capture_limits(budget, *element_stride, sequence_elements, true)?;
            (
                plan.root_type.summary.clone(),
                NestedValueRootSource::IndirectRingSequence {
                    data_offset,
                    data_access_size,
                    start_offset,
                    start_access_size,
                    length,
                    capacity_offset,
                    capacity_access_size,
                    element_stride: *element_stride,
                    max_elements,
                    max_len,
                },
                data_len,
            )
        }
        ghostscope_dwarf::ValueCapturePlan::IndirectHashTable {
            control,
            length,
            bucket_mask,
            entry_stride,
            occupancy,
            buckets,
            bucket_order,
        } => {
            if budget < ghostscope_protocol::HASH_TABLE_HEADER_SIZE {
                return Ok(None);
            }
            let (control_offset, control_access_size) =
                metadata_member(control, "nested hash-table control")?;
            let (length_offset, length_access_size) =
                metadata_member(length, "nested hash-table length")?;
            let (bucket_mask_offset, bucket_mask_access_size) =
                metadata_member(bucket_mask, "nested hash-table bucket mask")?;
            let buckets = match buckets {
                ghostscope_dwarf::HashTableBucketSource::Forward { data } => {
                    let (data_offset, data_access_size) =
                        metadata_member(data, "nested hash-table data")?;
                    HashTableBucketSource::Forward {
                        data_offset,
                        data_access_size,
                    }
                }
                ghostscope_dwarf::HashTableBucketSource::ReverseFromControl => {
                    HashTableBucketSource::ReverseFromControl
                }
                ghostscope_dwarf::HashTableBucketSource::LegacyAfterControl {
                    entry_alignment,
                    pointer_tag_mask,
                } => HashTableBucketSource::LegacyAfterControl {
                    entry_alignment: *entry_alignment,
                    pointer_tag_mask: *pointer_tag_mask,
                },
            };
            let (max_buckets, _, data_len) = hash_table_capture_limits(
                budget - ghostscope_protocol::HASH_TABLE_HEADER_SIZE,
                *entry_stride,
                *occupancy,
                hash_buckets,
            )?;
            (
                plan.root_type.summary.clone(),
                NestedValueRootSource::IndirectHashTable {
                    control_offset,
                    control_access_size,
                    length_offset,
                    length_access_size,
                    bucket_mask_offset,
                    bucket_mask_access_size,
                    entry_stride: *entry_stride,
                    occupancy: *occupancy,
                    buckets,
                    bucket_order: *bucket_order,
                    max_buckets,
                },
                data_len,
            )
        }
        ghostscope_dwarf::ValueCapturePlan::IndirectBTree {
            root_pointer,
            root_height,
            length,
            node_length,
            keys,
            values,
            edges,
            node_capacity,
        } => {
            if budget < ghostscope_protocol::BTREE_HEADER_SIZE {
                return Ok(None);
            }
            let (root_pointer_offset, root_pointer_access_size) =
                metadata_member(root_pointer, "nested B-Tree root pointer")?;
            let (root_height_offset, root_height_access_size) =
                metadata_member(root_height, "nested B-Tree root height")?;
            let (length_offset, length_access_size) =
                metadata_member(length, "nested B-Tree length")?;
            let (node_length_offset, node_length_access_size) =
                metadata_member(node_length, "nested B-Tree node length")?;
            let values_source = values.as_ref().map(|values| BTreeArraySource {
                offset: values.offset,
                slot_stride: values.slot_stride,
            });
            let (max_nodes, _, data_len) = btree_capture_limits(
                budget - ghostscope_protocol::BTREE_HEADER_SIZE,
                *node_capacity,
                keys.slot_stride,
                values_source.map(|values| values.slot_stride),
            )?;
            (
                plan.root_type.summary.clone(),
                NestedValueRootSource::IndirectBTree {
                    root_pointer_offset,
                    root_pointer_access_size,
                    root_height_offset,
                    root_height_access_size,
                    length_offset,
                    length_access_size,
                    node_length_offset,
                    node_length_access_size,
                    keys: BTreeArraySource {
                        offset: keys.offset,
                        slot_stride: keys.slot_stride,
                    },
                    values: values_source,
                    edges: BTreeEdgesSource {
                        offset_from_leaf: edges.offset_from_leaf,
                        slot_stride: edges.slot_stride,
                        pointer_offset: edges.pointer_offset,
                        pointer_access_size: exact_memory_access_size(
                            edges.pointer_size,
                            "nested B-Tree edge pointer",
                        )?,
                        edge_count: edges.edge_count,
                    },
                    node_capacity: *node_capacity,
                    max_nodes,
                },
                data_len,
            )
        }
    };
    Ok((output.2 <= budget).then_some(output))
}

pub(in crate::ebpf::codegen) fn nested_sequence_capture_limits(
    budget: usize,
    element_stride: u64,
    sequence_elements: Option<usize>,
    ring: bool,
) -> Result<(usize, usize, usize)> {
    let factor = if ring { 2 } else { 1 };
    let available = budget.saturating_sub(ghostscope_protocol::INDIRECT_SEQUENCE_HEADER_SIZE);
    let stride = usize::try_from(element_stride).map_err(|_| {
        CodeGenError::DwarfError(format!(
            "nested sequence element DWARF size {element_stride} does not fit this host"
        ))
    })?;
    let max_elements = match sequence_elements {
        Some(elements) => elements,
        None if stride == 0 => available,
        None => available / factor / stride,
    };
    let max_len = max_elements.checked_mul(stride).ok_or_else(|| {
        CodeGenError::DwarfError("nested sequence payload size overflow".to_string())
    })?;
    let data_len = ghostscope_protocol::INDIRECT_SEQUENCE_HEADER_SIZE
        .checked_add(max_len.checked_mul(factor).ok_or_else(|| {
            CodeGenError::DwarfError("nested ring payload size overflow".to_string())
        })?)
        .ok_or_else(|| {
            CodeGenError::DwarfError("nested sequence payload size overflow".to_string())
        })?;
    Ok((max_elements, max_len, data_len))
}

pub(in crate::ebpf::codegen) fn nested_field_steps(
    capture: &ghostscope_dwarf::ValueCapturePlan,
    root: &NestedValueRootSource,
    field_index: usize,
) -> Result<Vec<ProjectedViewStep>> {
    match (capture, root) {
        (
            ghostscope_dwarf::ValueCapturePlan::InlineView { fields, .. },
            NestedValueRootSource::InlineView { .. },
        ) => fields
            .get(field_index)
            .ok_or_else(|| {
                CodeGenError::DwarfError(
                    "nested inline-view field index is out of bounds".to_string(),
                )
            })
            .and_then(projected_value_steps),
        (
            ghostscope_dwarf::ValueCapturePlan::ProjectedView { .. },
            NestedValueRootSource::ProjectedView { fields },
        ) => fields
            .get(field_index)
            .map(|field| field.steps.clone())
            .ok_or_else(|| {
                CodeGenError::DwarfError(
                    "nested projected-view field index is out of bounds".to_string(),
                )
            }),
        _ => Err(CodeGenError::DwarfError(
            "nested projected-view metadata does not match its root capture".to_string(),
        )),
    }
}

pub(in crate::ebpf::codegen) fn nested_sequence_metadata(
    capture: &ghostscope_dwarf::ValueCapturePlan,
) -> Result<NestedSequenceMetadataSource> {
    match capture {
        ghostscope_dwarf::ValueCapturePlan::IndirectSequence {
            data,
            length,
            element_stride,
        } => {
            let (data_offset, data_access_size) =
                metadata_member(data, "nested sequence child data")?;
            let _ = length;
            Ok(NestedSequenceMetadataSource {
                data_offset,
                data_access_size,
                element_stride: *element_stride,
                ring: None,
            })
        }
        ghostscope_dwarf::ValueCapturePlan::IndirectRingSequence {
            data,
            start,
            length,
            capacity,
            element_stride,
        } => {
            let (data_offset, data_access_size) = metadata_member(data, "nested ring child data")?;
            let (start_offset, start_access_size) =
                metadata_member(start, "nested ring child start")?;
            let _ = length;
            let (capacity_offset, capacity_access_size) =
                metadata_member(capacity, "nested ring child capacity")?;
            Ok(NestedSequenceMetadataSource {
                data_offset,
                data_access_size,
                element_stride: *element_stride,
                ring: Some(NestedRingMetadataSource {
                    start_offset,
                    start_access_size,
                    capacity_offset,
                    capacity_access_size,
                }),
            })
        }
        _ => Err(CodeGenError::DwarfError(
            "nested sequence metadata does not match its root capture".to_string(),
        )),
    }
}

pub(in crate::ebpf::codegen) fn nested_hash_table_field_offset(
    presentation: &ghostscope_dwarf::ValuePresentation,
    field_index: usize,
) -> Result<u64> {
    let ghostscope_dwarf::ValuePresentation::HashTable { entry, .. } = presentation else {
        return Err(CodeGenError::DwarfError(
            "nested hash-table fields do not match their root presentation".to_string(),
        ));
    };
    match (entry, field_index) {
        (ghostscope_dwarf::HashTableEntryPresentation::Map { key, .. }, 0) => Ok(key.offset),
        (ghostscope_dwarf::HashTableEntryPresentation::Map { value, .. }, 1)
        | (ghostscope_dwarf::HashTableEntryPresentation::Set { value }, 0) => Ok(value.offset),
        _ => Err(CodeGenError::DwarfError(
            "nested hash-table field index is out of bounds".to_string(),
        )),
    }
}

pub(in crate::ebpf::codegen) fn nested_hash_table_metadata(
    capture: &ghostscope_dwarf::ValueCapturePlan,
) -> Result<NestedHashTableMetadataSource> {
    let ghostscope_dwarf::ValueCapturePlan::IndirectHashTable {
        control,
        entry_stride,
        occupancy,
        buckets,
        bucket_order,
        ..
    } = capture
    else {
        return Err(CodeGenError::DwarfError(
            "nested hash-table metadata does not match its root capture".to_string(),
        ));
    };
    let (control_offset, control_access_size) =
        metadata_member(control, "nested hash-table child control")?;
    let buckets = match (buckets, bucket_order) {
        (
            ghostscope_dwarf::HashTableBucketSource::Forward { data },
            ghostscope_dwarf::HashTableBucketOrder::Forward,
        ) => {
            let (data_offset, data_access_size) =
                metadata_member(data, "nested hash-table child data")?;
            HashTableBucketSource::Forward {
                data_offset,
                data_access_size,
            }
        }
        (
            ghostscope_dwarf::HashTableBucketSource::ReverseFromControl,
            ghostscope_dwarf::HashTableBucketOrder::Reverse,
        ) => HashTableBucketSource::ReverseFromControl,
        (
            ghostscope_dwarf::HashTableBucketSource::LegacyAfterControl {
                entry_alignment,
                pointer_tag_mask,
            },
            ghostscope_dwarf::HashTableBucketOrder::Forward,
        ) => HashTableBucketSource::LegacyAfterControl {
            entry_alignment: *entry_alignment,
            pointer_tag_mask: *pointer_tag_mask,
        },
        _ => {
            return Err(CodeGenError::DwarfError(
                "nested hash-table bucket source and order do not match".to_string(),
            ));
        }
    };
    Ok(NestedHashTableMetadataSource {
        control_offset,
        control_access_size,
        entry_stride: *entry_stride,
        occupancy: *occupancy,
        buckets,
    })
}

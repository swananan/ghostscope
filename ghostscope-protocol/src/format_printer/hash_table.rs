use super::{FormatPrinter, NestedHashTableContext};
use crate::{
    HashTableBucketOrder, HashTableEntryPresentation, HashTableFieldPresentation,
    HashTableOccupancy, HASH_TABLE_BUCKET_DATA_OFFSET, HASH_TABLE_CAPACITY_OFFSET,
    HASH_TABLE_CAPTURED_BUCKETS_OFFSET, HASH_TABLE_HEADER_SIZE,
};

pub(super) struct ParsedHashTablePayload<'a> {
    original_count: u64,
    captured_buckets: usize,
    occupancy: &'a [u8],
    pub(super) buckets: &'a [u8],
}

impl FormatPrinter {
    pub(super) fn parse_hash_table_payload(
        data: &[u8],
        entry_stride: u64,
        occupancy: HashTableOccupancy,
    ) -> Option<ParsedHashTablePayload<'_>> {
        let original_count = Self::payload_u64(data, 0)?;
        let capacity = Self::payload_u64(data, HASH_TABLE_CAPACITY_OFFSET)?;
        let captured_buckets = Self::payload_u64(data, HASH_TABLE_CAPTURED_BUCKETS_OFFSET)?;
        let bucket_offset = Self::payload_u64(data, HASH_TABLE_BUCKET_DATA_OFFSET)?;
        if original_count > capacity || captured_buckets > capacity {
            return None;
        }

        let captured_buckets = usize::try_from(captured_buckets).ok()?;
        let occupancy_width = usize::try_from(occupancy.byte_width()?).ok()?;
        let occupancy_len = captured_buckets.checked_mul(occupancy_width)?;
        let occupancy_end = HASH_TABLE_HEADER_SIZE.checked_add(occupancy_len)?;
        let bucket_offset = usize::try_from(bucket_offset).ok()?;
        // The eBPF layout fixes the bucket offset after the maximum reserved
        // occupancy region so the verifier sees constant destinations. A small
        // runtime table can therefore leave unused occupancy headroom here.
        if bucket_offset < occupancy_end {
            return None;
        }
        let stride = usize::try_from(entry_stride).ok()?;
        let bucket_len = captured_buckets.checked_mul(stride)?;
        let bucket_end = bucket_offset.checked_add(bucket_len)?;
        let occupancy_bytes = data.get(HASH_TABLE_HEADER_SIZE..occupancy_end)?;
        let buckets = data.get(bucket_offset..bucket_end)?;
        let mut occupied = 0_u64;
        for bucket_index in 0..captured_buckets {
            if Self::hash_table_bucket_occupied(occupancy_bytes, occupancy, bucket_index)? {
                occupied = occupied.checked_add(1)?;
            }
        }
        if occupied > original_count
            || (u64::try_from(captured_buckets).ok()? == capacity && occupied != original_count)
        {
            return None;
        }

        Some(ParsedHashTablePayload {
            original_count,
            captured_buckets,
            occupancy: occupancy_bytes,
            buckets,
        })
    }

    fn hash_table_bucket_occupied(
        occupancy_bytes: &[u8],
        occupancy: HashTableOccupancy,
        bucket_index: usize,
    ) -> Option<bool> {
        let width = usize::try_from(occupancy.byte_width()?).ok()?;
        let start = bucket_index.checked_mul(width)?;
        let end = start.checked_add(width)?;
        let bytes = occupancy_bytes.get(start..end)?;
        match occupancy {
            HashTableOccupancy::ControlByteHighBitClear => {
                Some(bytes.first().copied()? & 0x80 == 0)
            }
            HashTableOccupancy::NonZeroWord { .. } => Some(bytes.iter().any(|byte| *byte != 0)),
        }
    }

    fn hash_table_bucket<'a>(
        payload: &ParsedHashTablePayload<'a>,
        entry_stride: u64,
        bucket_order: HashTableBucketOrder,
        control_index: usize,
    ) -> Option<&'a [u8]> {
        let stride = usize::try_from(entry_stride).ok()?;
        let bucket_index = match bucket_order {
            HashTableBucketOrder::Forward => control_index,
            HashTableBucketOrder::Reverse => {
                payload.captured_buckets.checked_sub(control_index + 1)?
            }
        };
        let start = bucket_index.checked_mul(stride)?;
        let end = start.checked_add(stride)?;
        payload.buckets.get(start..end)
    }

    pub(super) fn hash_table_occupied_bucket_bytes(
        data: &[u8],
        entry_stride: u64,
        bucket_order: HashTableBucketOrder,
        occupancy: HashTableOccupancy,
    ) -> Option<Vec<u8>> {
        let payload = Self::parse_hash_table_payload(data, entry_stride, occupancy)?;
        let stride = usize::try_from(entry_stride).ok()?;
        let output_capacity = payload.captured_buckets.checked_mul(stride)?;
        let mut entries = Vec::with_capacity(output_capacity);
        for control_index in 0..payload.captured_buckets {
            if Self::hash_table_bucket_occupied(payload.occupancy, occupancy, control_index)? {
                entries.extend_from_slice(Self::hash_table_bucket(
                    &payload,
                    entry_stride,
                    bucket_order,
                    control_index,
                )?);
            }
        }
        Some(entries)
    }

    fn format_hash_table_field(
        entry_data: &[u8],
        entry_stride: u64,
        field: &HashTableFieldPresentation,
        field_index: usize,
        control_index: usize,
        nested: Option<&NestedHashTableContext<'_>>,
    ) -> Option<String> {
        if let Some(nested) = nested {
            if let Some(nested_field) = nested
                .fields
                .iter()
                .find(|candidate| candidate.field_index == field_index as u64)
            {
                let field_slot_offset = usize::try_from(nested_field.slot_offset).ok()?;
                let slot_offset = control_index
                    .checked_mul(nested.bucket_slot_stride)
                    .and_then(|offset| nested.first_slot_offset.checked_add(offset))
                    .and_then(|offset| offset.checked_add(field_slot_offset))?;
                return Some(Self::format_nested_value_at(
                    nested.full_data,
                    slot_offset,
                    &nested_field.value,
                ));
            }
        }
        let field_end = field.offset.checked_add(field.field_type.size())?;
        if field_end > entry_stride {
            return None;
        }
        let start = usize::try_from(field.offset).ok()?;
        let end = usize::try_from(field_end).ok()?;
        Some(Self::format_data_with_type_info_impl(
            entry_data.get(start..end)?,
            &field.field_type,
            1,
            32,
        ))
    }

    pub(super) fn format_hash_table_payload(
        data: &[u8],
        entry_stride: u64,
        bucket_order: HashTableBucketOrder,
        occupancy: HashTableOccupancy,
        entry: &HashTableEntryPresentation,
        nested: Option<&NestedHashTableContext<'_>>,
    ) -> String {
        let Some(payload) = Self::parse_hash_table_payload(data, entry_stride, occupancy) else {
            return "<INVALID_HASH_TABLE_PAYLOAD>".to_string();
        };
        if nested.is_some_and(|nested| payload.captured_buckets > nested.bucket_count) {
            return "<INVALID_NESTED_HASH_TABLE_PAYLOAD>".to_string();
        }
        let type_name = match entry {
            HashTableEntryPresentation::Map { .. } => "HashMap",
            HashTableEntryPresentation::Set { .. } => "HashSet",
        };
        let mut result = format!("{type_name}(size={}) {{", payload.original_count);
        let mut output_index = 0usize;
        for control_index in 0..payload.captured_buckets {
            let Some(occupied) =
                Self::hash_table_bucket_occupied(payload.occupancy, occupancy, control_index)
            else {
                return "<INVALID_HASH_TABLE_PAYLOAD>".to_string();
            };
            if !occupied {
                continue;
            }
            let Some(entry_data) =
                Self::hash_table_bucket(&payload, entry_stride, bucket_order, control_index)
            else {
                return "<INVALID_HASH_TABLE_PAYLOAD>".to_string();
            };
            if output_index > 0 {
                result.push_str(", ");
            }
            match entry {
                HashTableEntryPresentation::Map { key, value } => {
                    let Some(key) = Self::format_hash_table_field(
                        entry_data,
                        entry_stride,
                        key,
                        0,
                        control_index,
                        nested,
                    ) else {
                        return "<INVALID_HASH_TABLE_ENTRY_LAYOUT>".to_string();
                    };
                    let Some(value) = Self::format_hash_table_field(
                        entry_data,
                        entry_stride,
                        value,
                        1,
                        control_index,
                        nested,
                    ) else {
                        return "<INVALID_HASH_TABLE_ENTRY_LAYOUT>".to_string();
                    };
                    result.push_str(&key);
                    result.push_str(": ");
                    result.push_str(&value);
                }
                HashTableEntryPresentation::Set { value } => {
                    let Some(value) = Self::format_hash_table_field(
                        entry_data,
                        entry_stride,
                        value,
                        0,
                        control_index,
                        nested,
                    ) else {
                        return "<INVALID_HASH_TABLE_ENTRY_LAYOUT>".to_string();
                    };
                    result.push_str(&value);
                }
            }
            output_index += 1;
        }
        result.push('}');
        result
    }
}

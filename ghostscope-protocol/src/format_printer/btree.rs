use super::FormatPrinter;
use crate::{
    BTreeEntryPresentation, BTreeFieldPresentation, BTREE_CAPTURED_ITEM_COUNT_OFFSET,
    BTREE_HEADER_SIZE, BTREE_NODE_HEADER_SIZE, BTREE_NODE_HEIGHT_OFFSET, BTREE_NODE_LENGTH_OFFSET,
    BTREE_NODE_SLOT_COUNT_OFFSET,
};

struct ParsedBTreeNode<'a> {
    height: u64,
    length: usize,
    keys: &'a [u8],
    values: Option<&'a [u8]>,
}

pub(super) struct ParsedBTreePayload<'a> {
    original_count: u64,
    captured_count: u64,
    edge_count: usize,
    nodes: Vec<Option<ParsedBTreeNode<'a>>>,
}

type BTreeEntryBytes<'a> = (&'a [u8], Option<&'a [u8]>);

impl FormatPrinter {
    fn btree_fields(
        entry: &BTreeEntryPresentation,
    ) -> (&BTreeFieldPresentation, Option<&BTreeFieldPresentation>) {
        match entry {
            BTreeEntryPresentation::Map { key, value } => (key, Some(value)),
            BTreeEntryPresentation::Set { value } => (value, None),
        }
    }

    fn btree_record_layout(
        node_capacity: u64,
        entry: &BTreeEntryPresentation,
    ) -> Option<(usize, usize, usize)> {
        let capacity = usize::try_from(node_capacity).ok()?;
        if capacity == 0 {
            return None;
        }
        let (key, value) = Self::btree_fields(entry);
        let key_stride = usize::try_from(key.slot_stride).ok()?;
        let key_bytes = capacity.checked_mul(key_stride)?;
        let value_bytes = match value {
            Some(field) => usize::try_from(field.slot_stride)
                .ok()?
                .checked_mul(capacity)?,
            None => 0,
        };
        let values_offset = BTREE_NODE_HEADER_SIZE.checked_add(key_bytes)?;
        let record_size = values_offset.checked_add(value_bytes)?;
        Some((capacity, values_offset, record_size))
    }

    fn validate_btree_field(field: &BTreeFieldPresentation) -> bool {
        field
            .value_offset
            .checked_add(field.field_type.size())
            .is_some_and(|end| {
                end <= field.slot_stride
                    || (field.slot_stride == 0 && field.value_offset == 0 && end == 0)
            })
    }

    pub(super) fn parse_btree_payload<'a>(
        data: &'a [u8],
        node_capacity: u64,
        entry: &BTreeEntryPresentation,
    ) -> Option<ParsedBTreePayload<'a>> {
        let original_count = Self::payload_u64(data, 0)?;
        let node_slots = Self::payload_u64(data, BTREE_NODE_SLOT_COUNT_OFFSET)?;
        let captured_count = Self::payload_u64(data, BTREE_CAPTURED_ITEM_COUNT_OFFSET)?;
        if captured_count > original_count {
            return None;
        }
        let (key, value) = Self::btree_fields(entry);
        if !Self::validate_btree_field(key)
            || value.is_some_and(|field| !Self::validate_btree_field(field))
        {
            return None;
        }
        let (capacity, values_offset, record_size) =
            Self::btree_record_layout(node_capacity, entry)?;
        let node_slots = usize::try_from(node_slots).ok()?;
        let records_len = node_slots.checked_mul(record_size)?;
        let records_end = BTREE_HEADER_SIZE.checked_add(records_len)?;
        let records = data.get(BTREE_HEADER_SIZE..records_end)?;
        let key_bytes = values_offset.checked_sub(BTREE_NODE_HEADER_SIZE)?;
        let value_bytes = record_size.checked_sub(values_offset)?;

        let mut nodes = Vec::with_capacity(node_slots);
        let mut addresses = std::collections::HashSet::with_capacity(node_slots);
        let mut parsed_count = 0u64;
        for slot in 0..node_slots {
            let start = slot.checked_mul(record_size)?;
            let record = records.get(start..start.checked_add(record_size)?)?;
            let address = Self::payload_u64(record, 0)?;
            if address == 0 {
                nodes.push(None);
                continue;
            }
            if !addresses.insert(address) {
                return None;
            }
            let height = Self::payload_u64(record, BTREE_NODE_HEIGHT_OFFSET)?;
            let length = Self::payload_u64(record, BTREE_NODE_LENGTH_OFFSET)?;
            let length = usize::try_from(length).ok()?;
            if length > capacity {
                return None;
            }
            parsed_count = parsed_count.checked_add(u64::try_from(length).ok()?)?;
            let keys_end = BTREE_NODE_HEADER_SIZE.checked_add(key_bytes)?;
            let keys = record.get(BTREE_NODE_HEADER_SIZE..keys_end)?;
            let values = match value {
                Some(_) => {
                    Some(record.get(values_offset..values_offset.checked_add(value_bytes)?)?)
                }
                None => None,
            };
            nodes.push(Some(ParsedBTreeNode {
                height,
                length,
                keys,
                values,
            }));
        }
        let root_presence_valid = match (original_count, captured_count) {
            (0, _) => nodes.iter().all(Option::is_none),
            (_, 0) => nodes.iter().all(Option::is_none),
            (_, _) => nodes.first().is_some_and(Option::is_some),
        };
        if parsed_count != captured_count || !root_presence_valid {
            return None;
        }

        let edge_count = capacity.checked_add(1)?;
        for slot in 1..nodes.len() {
            let Some(node) = &nodes[slot] else {
                continue;
            };
            let parent_slot = (slot - 1) / edge_count;
            let parent_edge = (slot - 1) % edge_count;
            let Some(Some(parent)) = nodes.get(parent_slot) else {
                return None;
            };
            if parent.height == 0
                || parent_edge > parent.length
                || node.height.checked_add(1) != Some(parent.height)
            {
                return None;
            }
        }
        for (slot, node) in nodes.iter().enumerate() {
            let Some(node) = node else {
                continue;
            };
            if node.height == 0 {
                continue;
            }
            for edge in 0..=node.length {
                let child = slot
                    .checked_mul(edge_count)?
                    .checked_add(1)?
                    .checked_add(edge)?;
                if child < nodes.len() && nodes[child].is_none() {
                    return None;
                }
                if captured_count == original_count && child >= nodes.len() {
                    return None;
                }
            }
        }

        Some(ParsedBTreePayload {
            original_count,
            captured_count,
            edge_count,
            nodes,
        })
    }

    fn btree_field_bytes<'a>(
        slots: &'a [u8],
        index: usize,
        field: &BTreeFieldPresentation,
    ) -> Option<&'a [u8]> {
        let stride = usize::try_from(field.slot_stride).ok()?;
        let value_offset = usize::try_from(field.value_offset).ok()?;
        let value_size = usize::try_from(field.field_type.size()).ok()?;
        let start = index.checked_mul(stride)?.checked_add(value_offset)?;
        slots.get(start..start.checked_add(value_size)?)
    }

    fn collect_btree_entries<'a>(
        payload: &'a ParsedBTreePayload<'a>,
        entry: &'a BTreeEntryPresentation,
        node_index: usize,
        output: &mut Vec<BTreeEntryBytes<'a>>,
    ) -> Option<()> {
        let node = payload.nodes.get(node_index)?.as_ref()?;
        let (key, value) = Self::btree_fields(entry);
        for index in 0..node.length {
            if node.height > 0 {
                let child = node_index
                    .checked_mul(payload.edge_count)?
                    .checked_add(1)?
                    .checked_add(index)?;
                if payload.nodes.get(child).is_some_and(Option::is_some) {
                    Self::collect_btree_entries(payload, entry, child, output)?;
                }
            }
            let key_data = Self::btree_field_bytes(node.keys, index, key)?;
            let value_data = match (value, node.values) {
                (Some(field), Some(values)) => Some(Self::btree_field_bytes(values, index, field)?),
                (None, None) => None,
                _ => return None,
            };
            output.push((key_data, value_data));
        }
        if node.height > 0 {
            let child = node_index
                .checked_mul(payload.edge_count)?
                .checked_add(1)?
                .checked_add(node.length)?;
            if payload.nodes.get(child).is_some_and(Option::is_some) {
                Self::collect_btree_entries(payload, entry, child, output)?;
            }
        }
        Some(())
    }

    fn btree_entries<'a>(
        payload: &'a ParsedBTreePayload<'a>,
        entry: &'a BTreeEntryPresentation,
    ) -> Option<Vec<BTreeEntryBytes<'a>>> {
        let mut entries = Vec::with_capacity(usize::try_from(payload.captured_count).ok()?);
        if payload.captured_count > 0 {
            Self::collect_btree_entries(payload, entry, 0, &mut entries)?;
        }
        (u64::try_from(entries.len()).ok()? == payload.captured_count).then_some(entries)
    }

    pub(super) fn btree_value_bytes(
        data: &[u8],
        node_capacity: u64,
        entry: &BTreeEntryPresentation,
    ) -> Option<Vec<u8>> {
        let payload = Self::parse_btree_payload(data, node_capacity, entry)?;
        let entries = Self::btree_entries(&payload, entry)?;
        let mut values = Vec::new();
        for (key, value) in entries {
            values.extend_from_slice(key);
            if let Some(value) = value {
                values.extend_from_slice(value);
            }
        }
        Some(values)
    }

    pub(super) fn format_btree_payload(
        data: &[u8],
        node_capacity: u64,
        entry: &BTreeEntryPresentation,
    ) -> String {
        let Some(payload) = Self::parse_btree_payload(data, node_capacity, entry) else {
            return "<INVALID_BTREE_PAYLOAD>".to_string();
        };
        let Some(entries) = Self::btree_entries(&payload, entry) else {
            return "<INVALID_BTREE_PAYLOAD>".to_string();
        };
        let (key, value) = Self::btree_fields(entry);
        let type_name = match entry {
            BTreeEntryPresentation::Map { .. } => "BTreeMap",
            BTreeEntryPresentation::Set { .. } => "BTreeSet",
        };
        let mut result = format!("{type_name}(size={}) {{", payload.original_count);
        for (index, (key_data, value_data)) in entries.into_iter().enumerate() {
            if index > 0 {
                result.push_str(", ");
            }
            let formatted_key =
                Self::format_data_with_type_info_impl(key_data, &key.field_type, 1, 32);
            result.push_str(&formatted_key);
            if let (Some(field), Some(value_data)) = (value, value_data) {
                result.push_str(": ");
                result.push_str(&Self::format_data_with_type_info_impl(
                    value_data,
                    &field.field_type,
                    1,
                    32,
                ));
            }
        }
        result.push('}');
        result
    }
}

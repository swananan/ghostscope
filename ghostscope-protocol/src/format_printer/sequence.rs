use super::FormatPrinter;
use crate::{TypeInfo, INDIRECT_SEQUENCE_CAPTURED_COUNT_OFFSET, INDIRECT_SEQUENCE_HEADER_SIZE};

impl FormatPrinter {
    pub(super) fn parse_sequence_payload(
        data: &[u8],
        element_stride: u64,
    ) -> Option<(u64, u64, &[u8])> {
        let original_count = u64::from_le_bytes(data.get(..8)?.try_into().ok()?);
        let captured_count = u64::from_le_bytes(
            data.get(INDIRECT_SEQUENCE_CAPTURED_COUNT_OFFSET..INDIRECT_SEQUENCE_HEADER_SIZE)?
                .try_into()
                .ok()?,
        );
        if captured_count > original_count {
            return None;
        }
        let stride = usize::try_from(element_stride).ok()?;
        let captured = usize::try_from(captured_count).ok()?;
        let byte_len = captured.checked_mul(stride)?;
        let payload = data.get(INDIRECT_SEQUENCE_HEADER_SIZE..)?;
        Some((original_count, captured_count, payload.get(..byte_len)?))
    }

    pub(super) fn format_sequence_payload(
        data: &[u8],
        element_type: &TypeInfo,
        element_stride: u64,
    ) -> String {
        if element_type.size() != element_stride {
            return "<INVALID_SEQUENCE_ELEMENT_LAYOUT>".to_string();
        }
        let Some((_, captured_count, payload)) = Self::parse_sequence_payload(data, element_stride)
        else {
            return "<INVALID_SEQUENCE_PAYLOAD>".to_string();
        };
        let Ok(captured_count) = usize::try_from(captured_count) else {
            return "<INVALID_SEQUENCE_PAYLOAD>".to_string();
        };
        let Ok(stride) = usize::try_from(element_stride) else {
            return "<INVALID_SEQUENCE_ELEMENT_LAYOUT>".to_string();
        };

        let mut result = String::from("[");
        for index in 0..captured_count {
            if index > 0 {
                result.push_str(", ");
            }
            let start = index * stride;
            let element_data = &payload[start..start + stride];
            if stride == 0 && element_type.type_name() == "()" {
                result.push_str("()");
            } else {
                result.push_str(&Self::format_data_with_type_info_impl(
                    element_data,
                    element_type,
                    1,
                    32,
                ));
            }
        }
        result.push(']');
        result
    }
}

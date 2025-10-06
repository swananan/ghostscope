//! Format printer for complex print instructions
//!
//! Converts PrintComplexVariable/PrintComplexFormat payloads into formatted text in user space.

use crate::trace_context::TraceContext;
use crate::trace_event::VariableStatus;
use crate::type_info::TypeInfo;

// Removed legacy simple variable wrapper; use complex paths only.

/// A parsed complex variable from PrintComplexVariable instruction data
#[derive(Debug, Clone)]
pub struct ParsedComplexVariable {
    pub var_name_index: u16,
    pub type_index: u16,
    pub access_path: String,
    pub status: u8, // 0 OK; non-zero means error payload in data
    pub data: Vec<u8>,
}

/// Format printer for converting PrintComplexFormat data to formatted strings
pub struct FormatPrinter;

impl FormatPrinter {
    /// Format printer for converting PrintComplexFormat data to formatted strings
    pub fn format_complex_print_data(
        format_string_index: u16,
        complex_variables: &[ParsedComplexVariable],
        trace_context: &TraceContext,
    ) -> String {
        // Get the format string from the trace context
        let format_string = match trace_context.get_string(format_string_index) {
            Some(s) => s,
            None => {
                return format!("<INVALID_FORMAT_INDEX_{format_string_index}>");
            }
        };

        // Convert complex variables to formatted strings
        let formatted_vars: Vec<String> = complex_variables
            .iter()
            .map(|var| {
                Self::format_complex_variable_with_status(
                    var.var_name_index,
                    var.type_index,
                    &var.access_path,
                    &var.data,
                    var.status,
                    trace_context,
                )
                .split(" = ")
                .last() // Take just the value part, not "name = value"
                .unwrap_or("<FORMAT_ERROR>")
                .to_string()
            })
            .collect();

        // Apply formatting with the converted variables
        Self::apply_format_strings(format_string, &formatted_vars)
    }

    /// Apply formatting: replace {} placeholders with string values
    fn apply_format_strings(format_string: &str, formatted_values: &[String]) -> String {
        let mut result = String::new();
        let mut chars = format_string.chars().peekable();
        let mut var_index = 0;

        while let Some(ch) = chars.next() {
            match ch {
                '{' => {
                    if chars.peek() == Some(&'{') {
                        chars.next(); // Skip escaped '{{'
                        result.push('{');
                    } else {
                        // Found a placeholder, skip to '}' and replace with variable value
                        let mut found_closing = false;
                        for inner_ch in chars.by_ref() {
                            if inner_ch == '}' {
                                found_closing = true;
                                break;
                            }
                        }

                        if found_closing {
                            // Replace with string value
                            if var_index < formatted_values.len() {
                                result.push_str(&formatted_values[var_index]);
                                var_index += 1;
                            } else {
                                result.push_str("<MISSING_ARG>");
                            }
                        } else {
                            result.push_str("<MALFORMED_PLACEHOLDER>");
                        }
                    }
                }
                '}' => {
                    if chars.peek() == Some(&'}') {
                        chars.next(); // Skip escaped '}}'
                        result.push('}');
                    } else {
                        // Unmatched '}' - just output it (protocol doesn't validate)
                        result.push('}');
                    }
                }
                _ => result.push(ch),
            }
        }

        result
    }

    /// Format a complex variable with full DWARF type information
    pub fn format_complex_variable(
        var_name_index: u16,
        type_index: u16,
        access_path: &str,
        data: &[u8],
        trace_context: &TraceContext,
    ) -> String {
        let var_name = trace_context
            .get_variable_name(var_name_index)
            .unwrap_or("<INVALID_VAR_NAME>");

        let type_info = match trace_context.get_type(type_index) {
            Some(t) => t,
            None => return format!("<INVALID_TYPE_INDEX_{type_index}>: {var_name}"),
        };

        let formatted_data = Self::format_data_with_type_info(data, type_info);

        if access_path.is_empty() {
            format!("{var_name} = {formatted_data}")
        } else {
            format!("{var_name}.{access_path} = {formatted_data}")
        }
    }

    /// Status-aware complex variable formatting
    pub fn format_complex_variable_with_status(
        var_name_index: u16,
        type_index: u16,
        access_path: &str,
        data: &[u8],
        status: u8,
        trace_context: &TraceContext,
    ) -> String {
        let var_name = trace_context
            .get_variable_name(var_name_index)
            .unwrap_or("<INVALID_VAR_NAME>");
        let type_info = match trace_context.get_type(type_index) {
            Some(t) => t,
            None => return format!("<INVALID_TYPE_INDEX_{type_index}>: {var_name}"),
        };

        // OK path delegates to existing formatter
        if status == VariableStatus::Ok as u8 {
            return Self::format_complex_variable(
                var_name_index,
                type_index,
                access_path,
                data,
                trace_context,
            );
        }

        // Build error prefix based on status and optional payload (errno:i32 + addr:u64)
        let (errno, addr) = if data.len() >= 12 {
            let errno = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            let addr = u64::from_le_bytes([
                data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
            ]);
            (Some(errno), Some(addr))
        } else {
            (None, None)
        };

        let type_suffix = type_info.type_name();
        let err_text = match status {
            s if s == VariableStatus::NullDeref as u8 => {
                format!("<error: null pointer dereference> ({type_suffix}*)")
            }
            s if s == VariableStatus::ReadError as u8 => match (errno, addr) {
                (Some(e), Some(a)) => {
                    format!("<read_user failed errno={e} at 0x{a:x}> ({type_suffix}*)")
                }
                _ => format!("<read_user failed> ({type_suffix}*)"),
            },
            s if s == VariableStatus::AccessError as u8 => {
                format!("<address compute failed> ({type_suffix}*)")
            }
            s if s == VariableStatus::OffsetsUnavailable as u8 => {
                format!("<proc offsets unavailable> ({type_suffix}*)")
            }
            s if s == VariableStatus::Truncated as u8 => format!("<truncated> ({type_suffix}*)"),
            _ => format!("<error status={status}> ({type_suffix}*)"),
        };

        if access_path.is_empty() {
            format!("{var_name} = {err_text}")
        } else {
            format!("{var_name}.{access_path} = {err_text}")
        }
    }

    /// Format data using full DWARF type information
    pub fn format_data_with_type_info(data: &[u8], type_info: &TypeInfo) -> String {
        // Relax display limits: increase max depth to print more nested content.
        Self::format_data_with_type_info_impl(data, type_info, 0, 32)
    }

    /// Internal implementation with depth control for recursion
    fn format_data_with_type_info_impl(
        data: &[u8],
        type_info: &TypeInfo,
        current_depth: usize,
        max_depth: usize,
    ) -> String {
        if current_depth > max_depth {
            return "<MAX_DEPTH_EXCEEDED>".to_string();
        }

        match type_info {
            TypeInfo::BaseType { size, encoding, .. } => {
                Self::format_base_type_data(data, *size, *encoding)
            }
            TypeInfo::BitfieldType {
                underlying_type,
                bit_offset,
                bit_size,
            } => {
                let u_size = underlying_type.size() as usize;
                if data.len() < u_size || *bit_size == 0 {
                    return "<INVALID_BITFIELD>".to_string();
                }
                let val =
                    Self::extract_bits_le(&data[..u_size], *bit_offset as u32, *bit_size as u32);
                Self::format_bitfield_value(val, underlying_type, *bit_size as u32)
            }
            TypeInfo::PointerType { target_type, .. } => {
                if data.len() < 8 {
                    "<INVALID_POINTER>".to_string()
                } else {
                    let addr = u64::from_le_bytes([
                        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                    ]);
                    let ty = format!("{}*", target_type.type_name());
                    if addr == 0 {
                        format!("NULL ({ty})")
                    } else {
                        format!("0x{addr:x} ({ty})")
                    }
                }
            }
            TypeInfo::ArrayType {
                element_type,
                element_count,
                ..
            } => {
                // Special-case: char arrays -> print as string
                if Self::is_char_byte_type(element_type) {
                    return Self::format_char_array_as_string(data, element_count);
                }
                let elem_size = element_type.size() as usize;
                if elem_size == 0 {
                    return "<ZERO_SIZE_ELEMENT>".to_string();
                }

                let count = element_count.unwrap_or(data.len() as u64 / elem_size as u64);
                let actual_count = std::cmp::min(count, data.len() as u64 / elem_size as u64);

                if actual_count == 0 {
                    return "[]".to_string();
                }

                let mut result = String::from("[");
                for i in 0..actual_count {
                    if i > 0 {
                        result.push_str(", ");
                    }

                    let start = i as usize * elem_size;
                    let end = std::cmp::min(start + elem_size, data.len());
                    let elem_data = &data[start..end];

                    let formatted_elem = Self::format_data_with_type_info_impl(
                        elem_data,
                        element_type,
                        current_depth + 1,
                        max_depth,
                    );
                    result.push_str(&formatted_elem);
                }
                result.push(']');
                result
            }
            TypeInfo::StructType { name, members, .. } => {
                // Allow deeper nested structures now; cutoff managed by max_depth param
                if current_depth > max_depth {
                    return format!("<STRUCT_{name}>");
                }

                let mut result = format!("{name} {{ ");
                let mut first = true;

                for member in members.iter() {
                    if !first {
                        result.push_str(", ");
                    }
                    first = false;

                    let offset = member.offset as usize;
                    // Prefer explicit BitfieldType on member_type, else use legacy member.bit_* fields
                    if let TypeInfo::BitfieldType {
                        underlying_type,
                        bit_offset,
                        bit_size,
                    } = &member.member_type
                    {
                        let u_size = underlying_type.size() as usize;
                        if offset + u_size <= data.len() && *bit_size > 0 && *bit_size <= 64 {
                            let raw = &data[offset..offset + u_size];
                            let val_u64 =
                                Self::extract_bits_le(raw, *bit_offset as u32, *bit_size as u32);
                            let formatted_value = Self::format_bitfield_value(
                                val_u64,
                                underlying_type,
                                *bit_size as u32,
                            );
                            result.push_str(&format!("{}: {}", member.name, formatted_value));
                        } else {
                            result.push_str(&format!("{}: <OUT_OF_BOUNDS>", member.name));
                        }
                    } else if let (Some(bit_size), maybe_bit_offset) =
                        (member.bit_size, member.bit_offset)
                    {
                        // Handle bitfield member formatting (up to 64 bits)
                        let bit_size = bit_size as u32;
                        let bit_offset = maybe_bit_offset.unwrap_or(0) as u32;
                        let bytes_needed = (bit_offset + bit_size).div_ceil(8) as usize;
                        if offset + bytes_needed <= data.len() && bit_size > 0 && bit_size <= 64 {
                            let raw = &data[offset..offset + bytes_needed];
                            let val_u64 = Self::extract_bits_le(raw, bit_offset, bit_size);
                            let formatted_value =
                                Self::format_bitfield_value(val_u64, &member.member_type, bit_size);
                            result.push_str(&format!("{}: {}", member.name, formatted_value));
                        } else {
                            result.push_str(&format!("{}: <OUT_OF_BOUNDS>", member.name));
                        }
                    } else {
                        let member_size = member.member_type.size() as usize;
                        if offset + member_size <= data.len() {
                            let member_data = &data[offset..offset + member_size];
                            let formatted_value = Self::format_data_with_type_info_impl(
                                member_data,
                                &member.member_type,
                                current_depth + 1,
                                max_depth,
                            );
                            result.push_str(&format!("{}: {}", member.name, formatted_value));
                        } else {
                            result.push_str(&format!("{}: <OUT_OF_BOUNDS>", member.name));
                        }
                    }
                }

                // No explicit elision; show all available members
                result.push_str(" }");
                result
            }
            TypeInfo::UnionType { name, members, .. } => {
                if members.is_empty() {
                    format!("union {name} {{}}")
                } else {
                    // For unions, show the first member interpretation
                    let first_member = &members[0];
                    let member_size = first_member.member_type.size() as usize;
                    let member_data = if member_size <= data.len() {
                        &data[..member_size]
                    } else {
                        data
                    };

                    let formatted_value = Self::format_data_with_type_info_impl(
                        member_data,
                        &first_member.member_type,
                        current_depth + 1,
                        max_depth,
                    );
                    format!(
                        "union {} {{ {} = {} }}",
                        name, first_member.name, formatted_value
                    )
                }
            }
            TypeInfo::EnumType {
                name,
                base_type,
                variants,
                ..
            } => {
                let base_value = Self::format_data_with_type_info_impl(
                    data,
                    base_type,
                    current_depth + 1,
                    max_depth,
                );

                // Try to find matching enum variant and print both type::variant and numeric value
                if let Ok(int_val) = base_value.parse::<i64>() {
                    for variant in variants {
                        if variant.value == int_val {
                            return format!("{}::{}({})", name, variant.name, base_value);
                        }
                    }
                }

                // No variant matched; still print type name with raw value
                format!("{name}({base_value})")
            }
            TypeInfo::TypedefType {
                name,
                underlying_type,
                ..
            } => {
                // Reuse aggregate formatters by substituting display name
                match &**underlying_type {
                    TypeInfo::StructType { size, members, .. } => {
                        let alias_struct = TypeInfo::StructType {
                            name: name.clone(),
                            size: *size,
                            members: members.clone(),
                        };
                        Self::format_data_with_type_info_impl(
                            data,
                            &alias_struct,
                            current_depth,
                            max_depth,
                        )
                    }
                    TypeInfo::UnionType { size, members, .. } => {
                        let alias_union = TypeInfo::UnionType {
                            name: name.clone(),
                            size: *size,
                            members: members.clone(),
                        };
                        Self::format_data_with_type_info_impl(
                            data,
                            &alias_union,
                            current_depth,
                            max_depth,
                        )
                    }
                    _ => {
                        let underlying_formatted = Self::format_data_with_type_info_impl(
                            data,
                            underlying_type,
                            current_depth,
                            max_depth,
                        );
                        format!("{name}({underlying_formatted})")
                    }
                }
            }
            TypeInfo::QualifiedType {
                underlying_type, ..
            } => Self::format_data_with_type_info_impl(
                data,
                underlying_type,
                current_depth,
                max_depth,
            ),
            TypeInfo::FunctionType { .. } => {
                if data.len() >= 8 {
                    let addr = u64::from_le_bytes([
                        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                    ]);
                    format!("<FUNCTION@0x{addr:x}>")
                } else {
                    "<INVALID_FUNCTION_POINTER>".to_string()
                }
            }
            TypeInfo::UnknownType { name } => {
                format!("<UNKNOWN_TYPE_{name}_{}_BYTES>", data.len())
            }
            TypeInfo::OptimizedOut { name } => {
                format!("<OPTIMIZED_OUT_{name}>")
            }
        }
    }

    /// Format base type data using DWARF encoding information
    fn format_base_type_data(data: &[u8], size: u64, encoding: u16) -> String {
        if encoding == gimli::constants::DW_ATE_boolean.0 as u16 {
            if data.is_empty() {
                "<EMPTY_BOOL>".to_string()
            } else {
                (data[0] != 0).to_string()
            }
        } else if encoding == gimli::constants::DW_ATE_float.0 as u16 {
            match size {
                4 => {
                    if data.len() >= 4 {
                        let bytes: [u8; 4] = [data[0], data[1], data[2], data[3]];
                        f32::from_le_bytes(bytes).to_string()
                    } else {
                        "<INVALID_F32>".to_string()
                    }
                }
                8 => {
                    if data.len() >= 8 {
                        let bytes: [u8; 8] = [
                            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                        ];
                        f64::from_le_bytes(bytes).to_string()
                    } else {
                        "<INVALID_F64>".to_string()
                    }
                }
                _ => format!("<UNSUPPORTED_FLOAT_SIZE_{size}>"),
            }
        } else if encoding == gimli::constants::DW_ATE_signed.0 as u16
            || encoding == gimli::constants::DW_ATE_signed_char.0 as u16
        {
            match size {
                1 => {
                    if !data.is_empty() {
                        (data[0] as i8).to_string()
                    } else {
                        "<EMPTY_I8>".to_string()
                    }
                }
                2 => {
                    if data.len() >= 2 {
                        let bytes: [u8; 2] = [data[0], data[1]];
                        i16::from_le_bytes(bytes).to_string()
                    } else {
                        "<INVALID_I16>".to_string()
                    }
                }
                4 => {
                    if data.len() >= 4 {
                        let bytes: [u8; 4] = [data[0], data[1], data[2], data[3]];
                        i32::from_le_bytes(bytes).to_string()
                    } else {
                        "<INVALID_I32>".to_string()
                    }
                }
                8 => {
                    if data.len() >= 8 {
                        let bytes: [u8; 8] = [
                            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                        ];
                        i64::from_le_bytes(bytes).to_string()
                    } else {
                        "<INVALID_I64>".to_string()
                    }
                }
                _ => format!("<UNSUPPORTED_SIGNED_SIZE_{size}>"),
            }
        } else if encoding == gimli::constants::DW_ATE_unsigned.0 as u16
            || encoding == gimli::constants::DW_ATE_unsigned_char.0 as u16
        {
            match size {
                1 => {
                    if !data.is_empty() {
                        data[0].to_string()
                    } else {
                        "<EMPTY_U8>".to_string()
                    }
                }
                2 => {
                    if data.len() >= 2 {
                        let bytes: [u8; 2] = [data[0], data[1]];
                        u16::from_le_bytes(bytes).to_string()
                    } else {
                        "<INVALID_U16>".to_string()
                    }
                }
                4 => {
                    if data.len() >= 4 {
                        let bytes: [u8; 4] = [data[0], data[1], data[2], data[3]];
                        u32::from_le_bytes(bytes).to_string()
                    } else {
                        "<INVALID_U32>".to_string()
                    }
                }
                8 => {
                    if data.len() >= 8 {
                        let bytes: [u8; 8] = [
                            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                        ];
                        u64::from_le_bytes(bytes).to_string()
                    } else {
                        "<INVALID_U64>".to_string()
                    }
                }
                _ => format!("<UNSUPPORTED_UNSIGNED_SIZE_{size}>"),
            }
        } else {
            // Handle char-like 1-byte integers as characters (signed or unsigned)
            if (encoding == gimli::constants::DW_ATE_signed_char.0 as u16
                || encoding == gimli::constants::DW_ATE_unsigned_char.0 as u16)
                && size == 1
            {
                if !data.is_empty() {
                    if data[0] >= 32 && data[0] <= 126 {
                        format!("'{}'", data[0] as char)
                    } else {
                        format!("'\\x{:02x}'", data[0])
                    }
                } else {
                    "<EMPTY_CHAR>".to_string()
                }
            } else {
                // Fallback for unknown encodings
                format!("<UNKNOWN_ENCODING_{encoding}_SIZE_{size}_BYTES>")
            }
        }
    }

    /// Determine if a type is a single-byte character type (signed/unsigned char)
    fn is_char_byte_type(t: &TypeInfo) -> bool {
        match t {
            TypeInfo::BaseType { size, encoding, .. } => {
                *size == 1
                    && (*encoding == gimli::constants::DW_ATE_signed_char.0 as u16
                        || *encoding == gimli::constants::DW_ATE_unsigned_char.0 as u16
                        || *encoding == gimli::constants::DW_ATE_unsigned.0 as u16
                        || *encoding == gimli::constants::DW_ATE_signed.0 as u16)
            }
            TypeInfo::TypedefType {
                underlying_type, ..
            }
            | TypeInfo::QualifiedType {
                underlying_type, ..
            } => Self::is_char_byte_type(underlying_type),
            _ => false,
        }
    }

    /// Format a char array as a UTF-8-ish escaped string (best-effort)
    fn format_char_array_as_string(data: &[u8], element_count: &Option<u64>) -> String {
        let max_len = element_count.map(|c| c as usize).unwrap_or(data.len());
        let mut s = String::new();
        s.push('"');
        let mut i = 0usize;
        while i < data.len() && i < max_len {
            let b = data[i];
            if b == 0 {
                break; // C-string termination
            }
            match b {
                b'"' => s.push_str("\\\""),
                b'\\' => s.push_str("\\\\"),
                0x20..=0x7E => s.push(b as char),
                _ => s.push_str(&format!("\\x{b:02x}")),
            }
            i += 1;
        }
        s.push('"');
        s
    }

    /// Extract bits from a little-endian byte slice, starting at bit_offset, with length bit_size (<=64)
    fn extract_bits_le(raw: &[u8], bit_offset: u32, bit_size: u32) -> u64 {
        // Assemble up to 8 bytes into a u64 (little-endian)
        let mut word: u64 = 0;
        let take = std::cmp::min(8, raw.len());
        for (i, byte) in raw.iter().take(take).enumerate() {
            word |= (*byte as u64) << (8 * i);
        }
        let shifted = word >> bit_offset;
        let mask: u64 = if bit_size == 64 {
            u64::MAX
        } else {
            (1u64 << bit_size) - 1
        };
        shifted & mask
    }

    /// Format bitfield value according to the member's TypeInfo (basic support)
    fn format_bitfield_value(val: u64, ty: &TypeInfo, bit_size: u32) -> String {
        // Bool by encoding
        if let TypeInfo::BaseType { encoding, .. } = ty {
            if *encoding == gimli::constants::DW_ATE_boolean.0 as u16 {
                return if val != 0 {
                    "true".to_string()
                } else {
                    "false".to_string()
                };
            }
        }

        // Enum mapping
        if let TypeInfo::EnumType { variants, .. } = ty {
            let sval = val as i64; // interpret as non-negative; signed variants must match exact value
            for v in variants {
                if v.value == sval {
                    return v.name.clone();
                }
            }
        }

        // Signed extension if base type is signed
        let is_signed = ty.is_signed_int();
        if is_signed && bit_size > 0 && bit_size <= 64 {
            let sign_bit = 1u64 << (bit_size - 1);
            let signed_val: i64 = if (val & sign_bit) != 0 {
                // negative value, sign-extend
                let ext_mask = (!0u64) << bit_size;
                (val | ext_mask) as i64
            } else {
                val as i64
            };
            return signed_val.to_string();
        }

        // Default: unsigned decimal
        val.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_format_basic() {
        let fmt = "pid: {}, name: {}";
        let rendered: Vec<String> = vec!["42".to_string(), "hello".to_string()];
        let result = FormatPrinter::apply_format_strings(fmt, &rendered);
        assert_eq!(result, "pid: 42, name: hello");
    }

    #[test]
    fn test_apply_format_escape_sequences() {
        let rendered: Vec<String> = vec!["123".to_string()];
        let result =
            FormatPrinter::apply_format_strings("use {{}} for braces, value: {}", &rendered);
        assert_eq!(result, "use {} for braces, value: 123");
    }

    #[test]
    fn test_missing_arguments() {
        let result = FormatPrinter::apply_format_strings("need arg: {}", &[]);
        assert_eq!(result, "need arg: <MISSING_ARG>");
    }

    #[test]
    fn test_format_print_data_with_trace_context() {
        let mut trace_context = TraceContext::new();
        let format_index = trace_context.add_string("Hello {}, you are {} years old!".to_string());
        let rendered: Vec<String> = vec!["Alice".to_string(), "25".to_string()];
        let fmt = trace_context.get_string(format_index).unwrap();
        let result = FormatPrinter::apply_format_strings(fmt, &rendered);
        assert_eq!(result, "Hello Alice, you are 25 years old!");
    }

    #[test]
    fn test_format_complex_variable_struct() {
        use crate::type_info::{StructMember, TypeInfo};

        let mut trace_context = TraceContext::new();
        let var_name_idx = trace_context.add_variable_name("person".to_string());

        let person_type = TypeInfo::StructType {
            name: "Person".to_string(),
            size: 36,
            members: vec![
                StructMember {
                    name: "age".to_string(),
                    member_type: TypeInfo::BaseType {
                        name: "int".to_string(),
                        size: 4,
                        encoding: gimli::constants::DW_ATE_signed.0 as u16,
                    },
                    offset: 0,
                    bit_offset: None,
                    bit_size: None,
                },
                StructMember {
                    name: "id".to_string(),
                    member_type: TypeInfo::BaseType {
                        name: "long".to_string(),
                        size: 8,
                        encoding: gimli::constants::DW_ATE_signed.0 as u16,
                    },
                    offset: 4,
                    bit_offset: None,
                    bit_size: None,
                },
            ],
        };

        let type_idx = trace_context.add_type(person_type);

        // Data: age=25 (4 bytes) + id=12345 (8 bytes)
        let data = vec![
            25, 0, 0, 0, // age = 25
            57, 48, 0, 0, 0, 0, 0, 0, // id = 12345
        ];

        let result = FormatPrinter::format_complex_variable(
            var_name_idx,
            type_idx,
            "",
            &data,
            &trace_context,
        );

        assert!(result.contains("person = Person"));
        assert!(result.contains("age: 25"));
        assert!(result.contains("id: 12345"));
    }

    #[test]
    fn test_complex_format_char_array() {
        use crate::type_info::TypeInfo;

        let mut trace_context = TraceContext::new();
        let var_name_idx = trace_context.add_variable_name("name".to_string());
        // Define char array type: char name[16]
        let char_type = TypeInfo::BaseType {
            name: "char".to_string(),
            size: 1,
            encoding: gimli::constants::DW_ATE_unsigned_char.0 as u16,
        };
        let arr_type = TypeInfo::ArrayType {
            element_type: Box::new(char_type),
            element_count: Some(16),
            total_size: Some(16),
        };
        let type_idx = trace_context.add_type(arr_type);

        // Data buffer with "Alice\0" and padding
        let mut data = b"Alice\0".to_vec();
        data.resize(16, 0u8);

        let fmt_idx = trace_context.add_string("{}".to_string());
        let complex_vars = vec![ParsedComplexVariable {
            var_name_index: var_name_idx,
            type_index: type_idx,
            access_path: String::new(),
            status: 0,
            data,
        }];

        let result =
            FormatPrinter::format_complex_print_data(fmt_idx, &complex_vars, &trace_context);
        assert_eq!(result, "\"Alice\"");
    }

    #[test]
    fn test_format_data_with_type_info_array() {
        let array_type = TypeInfo::ArrayType {
            element_type: Box::new(TypeInfo::BaseType {
                name: "int".to_string(),
                size: 4,
                encoding: gimli::constants::DW_ATE_signed.0 as u16,
            }),
            element_count: Some(3),
            total_size: Some(12),
        };

        let data = vec![
            1, 0, 0, 0, // 1
            2, 0, 0, 0, // 2
            3, 0, 0, 0, // 3
        ];

        let result = FormatPrinter::format_data_with_type_info(&data, &array_type);
        assert_eq!(result, "[1, 2, 3]");
    }

    #[test]
    fn test_bitfield_value_signed_and_unsigned() {
        use crate::type_info::TypeInfo;

        // Unsigned 3-bit at bit 0 from a u32 container
        let u32_type = TypeInfo::BaseType {
            name: "unsigned int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_unsigned.0 as u16,
        };
        let bf_unsigned = TypeInfo::BitfieldType {
            underlying_type: Box::new(u32_type.clone()),
            bit_offset: 0,
            bit_size: 3,
        };
        let data = [0b0000_0101u8, 0, 0, 0]; // value = 5
        let res = FormatPrinter::format_data_with_type_info(&data, &bf_unsigned);
        assert_eq!(res, "5");

        // Signed 3-bit at bit 0 from an i32 container (0b111 -> -1)
        let i32_type = TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let bf_signed = TypeInfo::BitfieldType {
            underlying_type: Box::new(i32_type),
            bit_offset: 0,
            bit_size: 3,
        };
        let data_neg1 = [0b0000_0111u8, 0, 0, 0];
        let res2 = FormatPrinter::format_data_with_type_info(&data_neg1, &bf_signed);
        assert_eq!(res2, "-1");

        // Boolean 1-bit at bit 0 from a bool underlying type
        let bool_type = TypeInfo::BaseType {
            name: "bool".to_string(),
            size: 1,
            encoding: gimli::constants::DW_ATE_boolean.0 as u16,
        };
        let bf_bool = TypeInfo::BitfieldType {
            underlying_type: Box::new(bool_type),
            bit_offset: 0,
            bit_size: 1,
        };
        let data_true = [0x01u8];
        let res3 = FormatPrinter::format_data_with_type_info(&data_true, &bf_bool);
        assert_eq!(res3, "true");
    }

    #[test]
    fn test_struct_with_bitfields() {
        use crate::type_info::{StructMember, TypeInfo};

        // Define a struct S with two bitfields in a 32-bit storage at offset 0
        let u32_type = TypeInfo::BaseType {
            name: "unsigned int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_unsigned.0 as u16,
        };

        let s_type = TypeInfo::StructType {
            name: "S".to_string(),
            size: 4,
            members: vec![
                StructMember {
                    name: "active".to_string(),
                    member_type: TypeInfo::BitfieldType {
                        underlying_type: Box::new(u32_type.clone()),
                        bit_offset: 0,
                        bit_size: 1,
                    },
                    offset: 0,
                    bit_offset: Some(0),
                    bit_size: Some(1),
                },
                StructMember {
                    name: "flags".to_string(),
                    member_type: TypeInfo::BitfieldType {
                        underlying_type: Box::new(u32_type.clone()),
                        bit_offset: 1,
                        bit_size: 3,
                    },
                    offset: 0,
                    bit_offset: Some(1),
                    bit_size: Some(3),
                },
            ],
        };

        // Value layout: bit0=1 (active), bits1..3=0b011 (flags=3)
        let data = [0b0000_0111u8, 0, 0, 0];
        let res = FormatPrinter::format_data_with_type_info(&data, &s_type);
        assert!(res.contains("S {"));
        assert!(res.contains("active: 1"));
        assert!(res.contains("flags: 3"));
    }
}

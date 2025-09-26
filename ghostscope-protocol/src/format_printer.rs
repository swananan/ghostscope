//! Format printer for PrintFormat instructions
//!
//! This module handles the parsing and formatting of PrintFormat instructions
//! in the user space, converting raw variable data into formatted strings.

use crate::trace_context::TraceContext;
use crate::type_info::TypeInfo;
use crate::TypeKind;

/// A parsed variable from PrintFormat instruction data
#[derive(Debug, Clone)]
pub struct ParsedVariable {
    pub var_name_index: u16,
    pub type_encoding: TypeKind,
    pub type_index: Option<u16>, // Optional index into type table for perfect formatting
    pub data: Vec<u8>,
}

/// A parsed complex variable from PrintComplexVariable instruction data
#[derive(Debug, Clone)]
pub struct ParsedComplexVariable {
    pub var_name_index: u16,
    pub type_index: u16,
    pub access_path: String,
    pub data: Vec<u8>,
}

/// Format printer for converting PrintFormat data to formatted strings
pub struct FormatPrinter;

impl FormatPrinter {
    /// Convert PrintFormat instruction data into a formatted string
    /// This is the main entry point for format printing
    pub fn format_print_data(
        format_string_index: u16,
        variables: &[ParsedVariable],
        trace_context: &TraceContext,
    ) -> String {
        // Get the format string from the trace context
        let format_string = match trace_context.get_string(format_string_index) {
            Some(s) => s,
            None => {
                return format!("<INVALID_FORMAT_INDEX_{format_string_index}>");
            }
        };

        // Parse the format string and replace placeholders with variable values
        Self::apply_format(format_string, variables)
    }

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
                Self::format_complex_variable(
                    var.var_name_index,
                    var.type_index,
                    &var.access_path,
                    &var.data,
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

    /// Apply formatting: replace {} placeholders with variable values
    fn apply_format(format_string: &str, variables: &[ParsedVariable]) -> String {
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
                            // Replace with variable value
                            if var_index < variables.len() {
                                let formatted_value =
                                    Self::format_variable_value(&variables[var_index]);
                                result.push_str(&formatted_value);
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

    /// Format data using full DWARF type information
    pub fn format_data_with_type_info(data: &[u8], type_info: &TypeInfo) -> String {
        // Debug: Log the TypeInfo we received
        tracing::debug!(
            "format_data_with_type_info called with TypeInfo: {:#?}",
            type_info
        );
        tracing::debug!("Data bytes: {:?}", data);

        let result = Self::format_data_with_type_info_impl(data, type_info, 0, 8); // max depth 8
        tracing::debug!("Format result: '{}'", result);
        result
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
            TypeInfo::PointerType { target_type, .. } => {
                if data.len() < 8 {
                    "<INVALID_POINTER>".to_string()
                } else {
                    let addr = u64::from_le_bytes([
                        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                    ]);
                    if addr == 0 {
                        "NULL".to_string()
                    } else {
                        format!("0x{:x} -> <POINTER_TO_{}>", addr, target_type.type_name())
                    }
                }
            }
            TypeInfo::ArrayType {
                element_type,
                element_count,
                ..
            } => {
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
                    if i >= 16 {
                        result.push_str("...");
                        break;
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
                if current_depth > 3 {
                    return format!("<STRUCT_{name}>");
                }

                let mut result = format!("{name} {{ ");
                let mut first = true;

                for member in members.iter().take(8) {
                    if !first {
                        result.push_str(", ");
                    }
                    first = false;

                    let offset = member.offset as usize;
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

                if members.len() > 8 {
                    result.push_str(", ...");
                }
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

                // Try to find matching enum variant
                if let Ok(int_val) = base_value.parse::<i64>() {
                    for variant in variants {
                        if variant.value == int_val {
                            return format!("{}::{}", name, variant.name);
                        }
                    }
                }

                format!("{name}({base_value})")
            }
            TypeInfo::TypedefType {
                name,
                underlying_type,
                ..
            } => {
                let underlying_formatted = Self::format_data_with_type_info_impl(
                    data,
                    underlying_type,
                    current_depth,
                    max_depth,
                );
                format!("{name}({underlying_formatted})")
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
            // Handle char strings
            if encoding == gimli::constants::DW_ATE_signed_char.0 as u16 && size == 1 {
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

    /// Format multiple instructions with context (main entry point for enhanced formatting)
    pub fn format_with_context(
        instructions: &[crate::streaming_parser::ParsedInstruction],
        trace_context: &TraceContext,
    ) -> String {
        let mut output = String::new();

        for instruction in instructions {
            match instruction {
                crate::streaming_parser::ParsedInstruction::PrintVariable {
                    name,
                    type_encoding: _,
                    formatted_value,
                    raw_data,
                } => {
                    // Use existing formatted value or reformat with context if available
                    if formatted_value.is_empty() && !raw_data.is_empty() {
                        // Try to reformat with better type information
                        let var_data = ParsedVariable {
                            var_name_index: 0,           // dummy value
                            type_encoding: TypeKind::U8, // fallback
                            type_index: None,
                            data: raw_data.clone(),
                        };
                        let reformatted =
                            Self::format_variable_with_context(&var_data, trace_context);
                        output.push_str(&format!("{name} = {reformatted}"));
                    } else {
                        output.push_str(&format!("{name} = {formatted_value}"));
                    }
                }
                crate::streaming_parser::ParsedInstruction::PrintComplexVariable {
                    name,
                    access_path,
                    type_index,
                    formatted_value,
                    raw_data,
                } => {
                    // Use existing formatted value or reformat with context
                    if formatted_value.is_empty() && !raw_data.is_empty() {
                        let reformatted = Self::format_complex_variable(
                            0, // dummy var_name_index
                            *type_index,
                            access_path,
                            raw_data,
                            trace_context,
                        );
                        output.push_str(&reformatted);
                    } else if access_path.is_empty() {
                        output.push_str(&format!("{name} = {formatted_value}"));
                    } else {
                        output.push_str(&format!("{name}.{access_path} = {formatted_value}"));
                    }
                }
                crate::streaming_parser::ParsedInstruction::PrintString { content } => {
                    output.push_str(content);
                }
                crate::streaming_parser::ParsedInstruction::PrintFormat { formatted_output } => {
                    output.push_str(formatted_output);
                }
                crate::streaming_parser::ParsedInstruction::PrintComplexFormat {
                    formatted_output,
                } => {
                    output.push_str(formatted_output);
                }
                // Add other instruction types as needed
                _ => {
                    output.push_str("<UNSUPPORTED_INSTRUCTION_TYPE>");
                }
            }
            output.push('\n');
        }

        output
    }

    /// Format a variable with context-aware perfect formatting
    /// NOTE: This method should not be used in normal operations.
    /// Direct formatting is handled in streaming_parser.rs for better performance.
    fn format_variable_with_context(
        variable: &ParsedVariable,
        trace_context: &TraceContext,
    ) -> String {
        // If we have type_index, use perfect formatting
        if let Some(type_index) = variable.type_index {
            match trace_context.get_type(type_index) {
                Some(type_info) => {
                    return Self::format_data_with_type_info(&variable.data, type_info);
                }
                None => {
                    return format!(
                        "<COMPILER_ERROR: type_index {type_index} not found in TraceContext>"
                    );
                }
            }
        }

        // No type_index available - this should not happen in normal operations
        format!(
            "<COMPILER_ERROR: no type_index for variable with TypeKind::{:?}>",
            variable.type_encoding
        )
    }

    /// Format a single variable value as a string based on its type
    pub(crate) fn format_variable_value(variable: &ParsedVariable) -> String {
        match variable.type_encoding {
            TypeKind::U8 => {
                if variable.data.is_empty() {
                    "<EMPTY_U8>".to_string()
                } else {
                    variable.data[0].to_string()
                }
            }
            TypeKind::U16 => {
                if variable.data.len() < 2 {
                    "<INVALID_U16>".to_string()
                } else {
                    let bytes: [u8; 2] = [variable.data[0], variable.data[1]];
                    u16::from_le_bytes(bytes).to_string()
                }
            }
            TypeKind::U32 => {
                if variable.data.len() < 4 {
                    "<INVALID_U32>".to_string()
                } else {
                    let bytes: [u8; 4] = [
                        variable.data[0],
                        variable.data[1],
                        variable.data[2],
                        variable.data[3],
                    ];
                    u32::from_le_bytes(bytes).to_string()
                }
            }
            TypeKind::U64 => {
                if variable.data.len() < 8 {
                    "<INVALID_U64>".to_string()
                } else {
                    let bytes: [u8; 8] = [
                        variable.data[0],
                        variable.data[1],
                        variable.data[2],
                        variable.data[3],
                        variable.data[4],
                        variable.data[5],
                        variable.data[6],
                        variable.data[7],
                    ];
                    u64::from_le_bytes(bytes).to_string()
                }
            }
            TypeKind::I8 => {
                if variable.data.is_empty() {
                    "<EMPTY_I8>".to_string()
                } else {
                    (variable.data[0] as i8).to_string()
                }
            }
            TypeKind::I16 => {
                if variable.data.len() < 2 {
                    "<INVALID_I16>".to_string()
                } else {
                    let bytes: [u8; 2] = [variable.data[0], variable.data[1]];
                    i16::from_le_bytes(bytes).to_string()
                }
            }
            TypeKind::I32 => {
                if variable.data.len() < 4 {
                    "<INVALID_I32>".to_string()
                } else {
                    let bytes: [u8; 4] = [
                        variable.data[0],
                        variable.data[1],
                        variable.data[2],
                        variable.data[3],
                    ];
                    i32::from_le_bytes(bytes).to_string()
                }
            }
            TypeKind::I64 => {
                if variable.data.len() < 8 {
                    "<INVALID_I64>".to_string()
                } else {
                    let bytes: [u8; 8] = [
                        variable.data[0],
                        variable.data[1],
                        variable.data[2],
                        variable.data[3],
                        variable.data[4],
                        variable.data[5],
                        variable.data[6],
                        variable.data[7],
                    ];
                    i64::from_le_bytes(bytes).to_string()
                }
            }
            TypeKind::F32 => {
                if variable.data.len() < 4 {
                    "<INVALID_F32>".to_string()
                } else {
                    let bytes: [u8; 4] = [
                        variable.data[0],
                        variable.data[1],
                        variable.data[2],
                        variable.data[3],
                    ];
                    f32::from_le_bytes(bytes).to_string()
                }
            }
            TypeKind::F64 => {
                if variable.data.len() < 8 {
                    "<INVALID_F64>".to_string()
                } else {
                    let bytes: [u8; 8] = [
                        variable.data[0],
                        variable.data[1],
                        variable.data[2],
                        variable.data[3],
                        variable.data[4],
                        variable.data[5],
                        variable.data[6],
                        variable.data[7],
                    ];
                    f64::from_le_bytes(bytes).to_string()
                }
            }
            TypeKind::Bool => {
                if variable.data.is_empty() {
                    "<EMPTY_BOOL>".to_string()
                } else {
                    (variable.data[0] != 0).to_string()
                }
            }
            TypeKind::Char => {
                if variable.data.is_empty() {
                    "<EMPTY_CHAR>".to_string()
                } else {
                    char::from(variable.data[0]).to_string()
                }
            }
            TypeKind::Pointer => {
                if variable.data.len() < 8 {
                    "<INVALID_POINTER>".to_string()
                } else {
                    let bytes: [u8; 8] = [
                        variable.data[0],
                        variable.data[1],
                        variable.data[2],
                        variable.data[3],
                        variable.data[4],
                        variable.data[5],
                        variable.data[6],
                        variable.data[7],
                    ];
                    let addr = u64::from_le_bytes(bytes);
                    format!("0x{addr:x}")
                }
            }
            TypeKind::NullPointer => "null".to_string(),
            TypeKind::CString | TypeKind::String => {
                match String::from_utf8(variable.data.clone()) {
                    Ok(s) => s.trim_end_matches('\0').to_string(), // Remove null terminator
                    Err(_) => "<INVALID_UTF8>".to_string(),
                }
            }
            TypeKind::Unknown => format!("<UNKNOWN_TYPE_{}_BYTES>", variable.data.len()),
            TypeKind::OptimizedOut => "<OPTIMIZED_OUT>".to_string(),
            TypeKind::Error => "<ERROR>".to_string(),
            _ => format!("<UNSUPPORTED_TYPE_{:?}>", variable.type_encoding),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apply_format_basic() {
        let variables = vec![
            ParsedVariable {
                var_name_index: 0,
                type_encoding: TypeKind::I32,
                type_index: None,
                data: vec![42, 0, 0, 0], // 42 in little-endian
            },
            ParsedVariable {
                var_name_index: 1,
                type_encoding: TypeKind::CString,
                type_index: None,
                data: b"hello\0".to_vec(),
            },
        ];

        let result = FormatPrinter::apply_format("pid: {}, name: {}", &variables);
        assert_eq!(result, "pid: 42, name: hello");
    }

    #[test]
    fn test_apply_format_escape_sequences() {
        let variables = vec![ParsedVariable {
            var_name_index: 0,
            type_encoding: TypeKind::I32,
            type_index: None,
            data: vec![123, 0, 0, 0], // 123 in little-endian
        }];

        let result = FormatPrinter::apply_format("use {{}} for braces, value: {}", &variables);
        assert_eq!(result, "use {} for braces, value: 123");
    }

    #[test]
    fn test_format_different_types() {
        // Test U64
        let var_u64 = ParsedVariable {
            var_name_index: 0,
            type_encoding: TypeKind::U64,
            type_index: None,
            data: vec![255, 255, 255, 255, 255, 255, 255, 255], // u64::MAX
        };
        assert_eq!(
            FormatPrinter::format_variable_value(&var_u64),
            "18446744073709551615"
        );

        // Test Pointer
        let var_ptr = ParsedVariable {
            var_name_index: 0,
            type_encoding: TypeKind::Pointer,
            type_index: None,
            data: vec![0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0], // 0xdeadbeef in little-endian
        };
        assert_eq!(FormatPrinter::format_variable_value(&var_ptr), "0xdeadbeef");

        // Test Bool
        let var_bool_true = ParsedVariable {
            var_name_index: 0,
            type_encoding: TypeKind::Bool,
            type_index: None,
            data: vec![1],
        };
        assert_eq!(FormatPrinter::format_variable_value(&var_bool_true), "true");

        let var_bool_false = ParsedVariable {
            var_name_index: 0,
            type_encoding: TypeKind::Bool,
            type_index: None,
            data: vec![0],
        };
        assert_eq!(
            FormatPrinter::format_variable_value(&var_bool_false),
            "false"
        );
    }

    #[test]
    fn test_missing_arguments() {
        let variables = vec![]; // No variables

        let result = FormatPrinter::apply_format("need arg: {}", &variables);
        assert_eq!(result, "need arg: <MISSING_ARG>");
    }

    #[test]
    fn test_format_print_data_with_trace_context() {
        let mut trace_context = TraceContext::new();
        let format_index = trace_context.add_string("Hello {}, you are {} years old!".to_string());

        let variables = vec![
            ParsedVariable {
                var_name_index: 0,
                type_encoding: TypeKind::CString,
                type_index: None,
                data: b"Alice\0".to_vec(),
            },
            ParsedVariable {
                var_name_index: 1,
                type_encoding: TypeKind::U32,
                type_index: None,
                data: vec![25, 0, 0, 0], // 25 in little-endian
            },
        ];

        let result = FormatPrinter::format_print_data(format_index, &variables, &trace_context);
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
}

//! Format printer for complex print instructions
//!
//! Converts PrintComplexVariable/PrintComplexFormat payloads into formatted text in user space.

use std::borrow::Cow;

use crate::trace_context::TraceContext;
use crate::trace_event::{
    VariableStatus, VARIABLE_READ_ERROR_PAYLOAD_ADDR_OFFSET,
    VARIABLE_READ_ERROR_PAYLOAD_ERRNO_OFFSET, VARIABLE_READ_ERROR_PAYLOAD_LEN,
};
use crate::type_info::TypeInfo;
use crate::{
    BTreeEntryPresentation, BTreeFieldPresentation, HashTableBucketOrder,
    HashTableEntryPresentation, HashTableFieldPresentation, ValuePresentation,
    BTREE_CAPTURED_ITEM_COUNT_OFFSET, BTREE_HEADER_SIZE, BTREE_NODE_HEADER_SIZE,
    BTREE_NODE_HEIGHT_OFFSET, BTREE_NODE_LENGTH_OFFSET, BTREE_NODE_SLOT_COUNT_OFFSET,
    HASH_TABLE_BUCKET_DATA_OFFSET, HASH_TABLE_CAPACITY_OFFSET, HASH_TABLE_CAPTURED_BUCKETS_OFFSET,
    HASH_TABLE_HEADER_SIZE, INDIRECT_BYTES_LENGTH_PREFIX_SIZE,
    INDIRECT_SEQUENCE_CAPTURED_COUNT_OFFSET, INDIRECT_SEQUENCE_HEADER_SIZE,
};

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

struct ParsedHashTablePayload<'a> {
    original_count: u64,
    controls: &'a [u8],
    buckets: &'a [u8],
}

struct ParsedBTreeNode<'a> {
    height: u64,
    length: usize,
    keys: &'a [u8],
    values: Option<&'a [u8]>,
}

struct ParsedBTreePayload<'a> {
    original_count: u64,
    captured_count: u64,
    edge_count: usize,
    nodes: Vec<Option<ParsedBTreeNode<'a>>>,
}

type BTreeEntryBytes<'a> = (&'a [u8], Option<&'a [u8]>);

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

        // Apply formatting using raw variables to support extended specifiers
        Self::apply_format_with_specs(format_string, complex_variables, trace_context)
    }

    /// Simple placeholder applier for tests that don't use complex variables
    #[cfg(test)]
    fn apply_format_strings(format_string: &str, formatted_values: &[String]) -> String {
        let mut result = String::new();
        let mut chars = format_string.chars().peekable();
        let mut var_index = 0;

        while let Some(ch) = chars.next() {
            match ch {
                '{' => {
                    if chars.peek() == Some(&'{') {
                        chars.next();
                        result.push('{');
                    } else {
                        // Skip to closing '}' and substitute
                        let mut found = false;
                        for c in chars.by_ref() {
                            if c == '}' {
                                found = true;
                                break;
                            }
                        }
                        if found {
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
                        chars.next();
                        result.push('}');
                    } else {
                        result.push('}');
                    }
                }
                _ => result.push(ch),
            }
        }
        result
    }

    /// Apply formatting with extended specifiers {:x}/{:X}/{:p}/{:s}, and optional
    /// length suffix .N / .* / .name$.
    fn apply_format_with_specs(
        format_string: &str,
        vars: &[ParsedComplexVariable],
        trace_context: &TraceContext,
    ) -> String {
        let mut result = String::new();
        let mut chars = format_string.chars().peekable();
        let mut var_index: usize = 0;

        while let Some(ch) = chars.next() {
            match ch {
                '{' => {
                    if chars.peek() == Some(&'{') {
                        chars.next();
                        result.push('{');
                    } else {
                        let mut found = false;
                        let mut content = String::new();
                        for c in chars.by_ref() {
                            if c == '}' {
                                found = true;
                                break;
                            }
                            content.push(c);
                        }
                        if !found {
                            result.push_str("<MALFORMED_PLACEHOLDER>");
                            continue;
                        }

                        if content.is_empty() {
                            // default {}
                            if var_index < vars.len() {
                                let v = &vars[var_index];
                                let s = Self::format_complex_variable_with_status(
                                    v.var_name_index,
                                    v.type_index,
                                    &v.access_path,
                                    &v.data,
                                    v.status,
                                    trace_context,
                                );
                                let value_part = Self::formatted_value_part(&s);
                                result.push_str(value_part);
                                var_index += 1;
                            } else {
                                result.push_str("<MISSING_ARG>");
                            }
                            continue;
                        }

                        if !content.starts_with(':') {
                            result.push_str("<INVALID_SPEC>");
                            continue;
                        }
                        let tail = &content[1..];
                        let mut it = tail.chars();
                        let conv = it.next().unwrap_or(' ');
                        let rest: String = it.collect();

                        // (removed) helper to get bytes of current arg; we now surface errors explicitly

                        enum Len {
                            None,
                            Static(usize),
                            Star,
                            Capture,
                        }
                        // helper: parse static length supporting decimal/0x.. /0o.. /0b..
                        fn parse_static_len(spec: &str) -> Option<usize> {
                            if spec.chars().all(|c| c.is_ascii_digit()) {
                                return spec.parse::<usize>().ok();
                            }
                            if let Some(hex) = spec.strip_prefix("0x") {
                                if !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                                    return usize::from_str_radix(hex, 16).ok();
                                }
                            }
                            if let Some(oct) = spec.strip_prefix("0o") {
                                if !oct.is_empty() && oct.chars().all(|c| matches!(c, '0'..='7')) {
                                    return usize::from_str_radix(oct, 8).ok();
                                }
                            }
                            if let Some(bin) = spec.strip_prefix("0b") {
                                if !bin.is_empty() && bin.chars().all(|c| matches!(c, '0' | '1')) {
                                    return usize::from_str_radix(bin, 2).ok();
                                }
                            }
                            None
                        }

                        let lenspec = if rest.is_empty() {
                            Len::None
                        } else if let Some(r) = rest.strip_prefix('.') {
                            if r == "*" {
                                Len::Star
                            } else if r.ends_with('$') {
                                Len::Capture
                            } else if let Some(n) = parse_static_len(r) {
                                Len::Static(n)
                            } else {
                                Len::None
                            }
                        } else {
                            Len::None
                        };

                        // helper: parse signed length from 8-byte little endian, clamp to >=0
                        fn parse_len_usize(lenb: &[u8]) -> usize {
                            if lenb.len() >= 8 {
                                let arr = [
                                    lenb[0], lenb[1], lenb[2], lenb[3], lenb[4], lenb[5], lenb[6],
                                    lenb[7],
                                ];
                                let v = i64::from_le_bytes(arr);
                                if v <= 0 {
                                    0
                                } else {
                                    v as usize
                                }
                            } else {
                                0
                            }
                        }

                        // Format statuses that cannot be consumed by a conversion.
                        let err_value_part = |idx: usize| -> Option<String> {
                            if idx >= vars.len() {
                                return None;
                            }
                            let v = &vars[idx];
                            if v.status == VariableStatus::Ok as u8
                                || v.status == VariableStatus::ZeroLength as u8
                            {
                                None
                            } else {
                                let s = Self::format_complex_variable_with_status(
                                    v.var_name_index,
                                    v.type_index,
                                    &v.access_path,
                                    &v.data,
                                    v.status,
                                    trace_context,
                                );
                                Some(Self::formatted_value_part(&s).to_string())
                            }
                        };
                        let raw_err_value_part = |idx: usize| -> Option<String> {
                            if vars.get(idx).is_some_and(|variable| {
                                Self::is_semantic_truncation(variable, trace_context)
                            }) {
                                None
                            } else {
                                err_value_part(idx)
                            }
                        };

                        match conv {
                            'x' | 'X' => {
                                match lenspec {
                                    Len::Star => {
                                        if var_index + 1 >= vars.len() {
                                            result.push_str("<MISSING_ARG>");
                                        } else if let Some(err) = err_value_part(var_index) {
                                            // surface error from length argument
                                            result.push_str(&err);
                                            var_index += 2;
                                            continue;
                                        } else if let Some(err) = err_value_part(var_index + 1) {
                                            // surface error from value argument
                                            result.push_str(&err);
                                            var_index += 2;
                                            continue;
                                        } else {
                                            // both Ok or ZeroLength
                                            let lenb = vars[var_index].data.as_slice();
                                            let n = parse_len_usize(lenb);
                                            let v = &vars[var_index + 1];
                                            let full = v.data.as_slice();
                                            let take =
                                                if v.status == VariableStatus::ZeroLength as u8 {
                                                    0
                                                } else {
                                                    std::cmp::min(n, full.len())
                                                };
                                            let b = &full[..take];
                                            let s = b
                                                .iter()
                                                .map(|vv| {
                                                    if conv == 'x' {
                                                        format!("{vv:02x}")
                                                    } else {
                                                        format!("{vv:02X}")
                                                    }
                                                })
                                                .collect::<Vec<_>>()
                                                .join(" ");
                                            result.push_str(&s);
                                            var_index += 2;
                                            continue;
                                        }
                                        // when missing one of the args, don't advance to avoid misalignment
                                    }
                                    Len::Static(n) => {
                                        if var_index >= vars.len() {
                                            result.push_str("<MISSING_ARG>");
                                        } else if let Some(err) = err_value_part(var_index) {
                                            result.push_str(&err);
                                            var_index += 1;
                                            continue;
                                        } else {
                                            let v = &vars[var_index];
                                            let full = v.data.as_slice();
                                            let take =
                                                if v.status == VariableStatus::ZeroLength as u8 {
                                                    0
                                                } else {
                                                    std::cmp::min(n, full.len())
                                                };
                                            let b = &full[..take];
                                            let s = b
                                                .iter()
                                                .map(|vv| {
                                                    if conv == 'x' {
                                                        format!("{vv:02x}")
                                                    } else {
                                                        format!("{vv:02X}")
                                                    }
                                                })
                                                .collect::<Vec<_>>()
                                                .join(" ");
                                            result.push_str(&s);
                                            var_index += 1;
                                            continue;
                                        }
                                    }
                                    Len::Capture => {
                                        if var_index + 1 >= vars.len() {
                                            result.push_str("<MISSING_ARG>");
                                        } else if let Some(err) = err_value_part(var_index) {
                                            result.push_str(&err);
                                            var_index += 2;
                                            continue;
                                        } else if let Some(err) = err_value_part(var_index + 1) {
                                            result.push_str(&err);
                                            var_index += 2;
                                            continue;
                                        } else {
                                            let lenb = vars[var_index].data.as_slice();
                                            let n = parse_len_usize(lenb);
                                            let v = &vars[var_index + 1];
                                            let full = v.data.as_slice();
                                            let take =
                                                if v.status == VariableStatus::ZeroLength as u8 {
                                                    0
                                                } else {
                                                    std::cmp::min(n, full.len())
                                                };
                                            let b = &full[..take];
                                            let s = b
                                                .iter()
                                                .map(|vv| {
                                                    if conv == 'x' {
                                                        format!("{vv:02x}")
                                                    } else {
                                                        format!("{vv:02X}")
                                                    }
                                                })
                                                .collect::<Vec<_>>()
                                                .join(" ");
                                            result.push_str(&s);
                                            var_index += 2;
                                            continue;
                                        }
                                        // when missing one of the args, don't advance
                                    }
                                    Len::None => {
                                        if var_index >= vars.len() {
                                            result.push_str("<MISSING_ARG>");
                                        } else if let Some(err) = raw_err_value_part(var_index) {
                                            result.push_str(&err);
                                            var_index += 1;
                                            continue;
                                        } else {
                                            let v = &vars[var_index];
                                            match Self::format_spec_payload_bytes(v, trace_context)
                                            {
                                                Ok(bytes) => {
                                                    let formatted = bytes
                                                        .iter()
                                                        .map(|byte| {
                                                            if conv == 'x' {
                                                                format!("{byte:02x}")
                                                            } else {
                                                                format!("{byte:02X}")
                                                            }
                                                        })
                                                        .collect::<Vec<_>>()
                                                        .join(" ");
                                                    result.push_str(&formatted);
                                                }
                                                Err(error) => result.push_str(error),
                                            }
                                            Self::append_semantic_truncation_marker(
                                                &mut result,
                                                v,
                                                trace_context,
                                            );
                                            var_index += 1;
                                            continue;
                                        }
                                    }
                                }
                            }
                            's' => {
                                let render_bytes = |b: &[u8]| {
                                    let mut out = String::new();
                                    for &c in b.iter() {
                                        if c == 0 {
                                            break;
                                        }
                                        if (0x20..=0x7e).contains(&c) {
                                            out.push(c as char);
                                        } else {
                                            out.push_str(&format!("\\x{c:02x}"));
                                        }
                                    }
                                    out
                                };

                                match lenspec {
                                    Len::Star => {
                                        if var_index + 1 >= vars.len() {
                                            result.push_str("<MISSING_ARG>");
                                        } else if let Some(err) = err_value_part(var_index) {
                                            result.push_str(&err);
                                            var_index += 2;
                                            continue;
                                        } else if let Some(err) = err_value_part(var_index + 1) {
                                            result.push_str(&err);
                                            var_index += 2;
                                            continue;
                                        } else {
                                            let lenb = vars[var_index].data.as_slice();
                                            let n = parse_len_usize(lenb);
                                            let v = &vars[var_index + 1];
                                            let full = v.data.as_slice();
                                            let take =
                                                if v.status == VariableStatus::ZeroLength as u8 {
                                                    0
                                                } else {
                                                    std::cmp::min(n, full.len())
                                                };
                                            result.push_str(&render_bytes(&full[..take]));
                                            var_index += 2;
                                            continue;
                                        }
                                    }
                                    Len::Static(n) => {
                                        if var_index >= vars.len() {
                                            result.push_str("<MISSING_ARG>");
                                        } else if let Some(err) = err_value_part(var_index) {
                                            result.push_str(&err);
                                            var_index += 1;
                                            continue;
                                        } else {
                                            let v = &vars[var_index];
                                            let full = v.data.as_slice();
                                            let take =
                                                if v.status == VariableStatus::ZeroLength as u8 {
                                                    0
                                                } else {
                                                    std::cmp::min(n, full.len())
                                                };
                                            result.push_str(&render_bytes(&full[..take]));
                                            var_index += 1;
                                            continue;
                                        }
                                    }
                                    Len::Capture => {
                                        if var_index + 1 >= vars.len() {
                                            result.push_str("<MISSING_ARG>");
                                        } else if let Some(err) = err_value_part(var_index) {
                                            result.push_str(&err);
                                            var_index += 2;
                                            continue;
                                        } else if let Some(err) = err_value_part(var_index + 1) {
                                            result.push_str(&err);
                                            var_index += 2;
                                            continue;
                                        } else {
                                            let lenb = vars[var_index].data.as_slice();
                                            let n = parse_len_usize(lenb);
                                            let v = &vars[var_index + 1];
                                            let full = v.data.as_slice();
                                            let take =
                                                if v.status == VariableStatus::ZeroLength as u8 {
                                                    0
                                                } else {
                                                    std::cmp::min(n, full.len())
                                                };
                                            result.push_str(&render_bytes(&full[..take]));
                                            var_index += 2;
                                            continue;
                                        }
                                    }
                                    Len::None => {
                                        if var_index >= vars.len() {
                                            result.push_str("<MISSING_ARG>");
                                        } else if let Some(err) = raw_err_value_part(var_index) {
                                            result.push_str(&err);
                                            var_index += 1;
                                            continue;
                                        } else {
                                            let v = &vars[var_index];
                                            match Self::format_spec_payload_bytes(v, trace_context)
                                            {
                                                Ok(bytes) => {
                                                    result.push_str(&render_bytes(bytes.as_ref()));
                                                }
                                                Err(error) => result.push_str(error),
                                            }
                                            Self::append_semantic_truncation_marker(
                                                &mut result,
                                                v,
                                                trace_context,
                                            );
                                            var_index += 1;
                                            continue;
                                        }
                                    }
                                }
                            }
                            'p' => {
                                if var_index >= vars.len() {
                                    result.push_str("<MISSING_ARG>");
                                } else if let Some(err) = err_value_part(var_index) {
                                    result.push_str(&err);
                                    var_index += 1;
                                    continue;
                                } else {
                                    let b = vars[var_index].data.as_slice();
                                    if b.len() >= 8 {
                                        let addr = u64::from_le_bytes([
                                            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
                                        ]);
                                        result.push_str(&format!("0x{addr:x}"));
                                    } else {
                                        result.push_str("<INVALID_POINTER>");
                                    }
                                    var_index += 1;
                                    continue;
                                }
                            }
                            _ => {
                                // fallback to default formatting
                                if var_index < vars.len() {
                                    let v = &vars[var_index];
                                    let s = Self::format_complex_variable_with_status(
                                        v.var_name_index,
                                        v.type_index,
                                        &v.access_path,
                                        &v.data,
                                        v.status,
                                        trace_context,
                                    );
                                    let value_part = Self::formatted_value_part(&s);
                                    result.push_str(value_part);
                                    var_index += 1;
                                } else {
                                    result.push_str("<MISSING_ARG>");
                                }
                            }
                        }
                    }
                }
                '}' => {
                    if chars.peek() == Some(&'}') {
                        chars.next();
                        result.push('}');
                    } else {
                        result.push('}');
                    }
                }
                _ => result.push(ch),
            }
        }
        result
    }

    fn formatted_value_part(formatted: &str) -> &str {
        formatted
            .split_once(" = ")
            .map_or(formatted, |(_, value)| value)
    }

    fn is_semantic_truncation(
        variable: &ParsedComplexVariable,
        trace_context: &TraceContext,
    ) -> bool {
        variable.status == VariableStatus::Truncated as u8
            && trace_context.get_value_presentation(variable.type_index)
                != &ValuePresentation::Dwarf
    }

    fn append_semantic_truncation_marker(
        output: &mut String,
        variable: &ParsedComplexVariable,
        trace_context: &TraceContext,
    ) {
        if Self::is_semantic_truncation(variable, trace_context) {
            if !output.is_empty() {
                output.push(' ');
            }
            output.push_str("<truncated>");
        }
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

        let presentation = trace_context.get_value_presentation(type_index);
        let formatted_data = Self::format_data_with_presentation(data, type_info, presentation);

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
        let presentation = trace_context.get_value_presentation(type_index);

        if presentation != &ValuePresentation::Dwarf
            && matches!(
                status,
                s if s == VariableStatus::Ok as u8
                    || s == VariableStatus::ZeroLength as u8
                    || s == VariableStatus::Truncated as u8
            )
        {
            let payload_omitted = status == VariableStatus::Truncated as u8
                && Self::presentation_payload_bytes(data, presentation).is_none();
            let mut formatted_data = if payload_omitted {
                "<truncated>".to_string()
            } else {
                Self::format_data_with_presentation(data, type_info, presentation)
            };
            if status == VariableStatus::Truncated as u8 && !payload_omitted {
                formatted_data.push_str(" <truncated>");
            }
            return if access_path.is_empty() {
                format!("{var_name} = {formatted_data}")
            } else {
                format!("{var_name}.{access_path} = {formatted_data}")
            };
        }

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
        let (errno, addr) = if data.len() >= VARIABLE_READ_ERROR_PAYLOAD_LEN {
            let errno_start = VARIABLE_READ_ERROR_PAYLOAD_ERRNO_OFFSET;
            let errno_end = errno_start + std::mem::size_of::<i32>();
            let addr_start = VARIABLE_READ_ERROR_PAYLOAD_ADDR_OFFSET;
            let addr_end = addr_start + std::mem::size_of::<u64>();
            let errno = i32::from_le_bytes(
                data[errno_start..errno_end]
                    .try_into()
                    .expect("read-error errno payload length checked"),
            );
            let addr = u64::from_le_bytes(
                data[addr_start..addr_end]
                    .try_into()
                    .expect("read-error addr payload length checked"),
            );
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
            s if s == VariableStatus::ZeroLength as u8 => format!("<len<=0> ({type_suffix})"),
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

    /// Format captured data using its semantic presentation when one is
    /// registered, otherwise preserve physical DWARF formatting.
    pub fn format_data_with_presentation(
        data: &[u8],
        type_info: &TypeInfo,
        presentation: &ValuePresentation,
    ) -> String {
        match presentation {
            ValuePresentation::Dwarf => Self::format_data_with_type_info(data, type_info),
            ValuePresentation::Utf8String => Self::format_utf8_string_payload(data),
            ValuePresentation::Sequence {
                element_type,
                element_stride,
            } => Self::format_sequence_payload(data, element_type, *element_stride),
            ValuePresentation::ByteString => Self::format_byte_string_payload(data),
            ValuePresentation::SingleField {
                type_name,
                field_name,
            } => {
                let value = Self::format_data_with_type_info(data, type_info);
                format!("{type_name} {{ {field_name}: {value} }}")
            }
            ValuePresentation::SignedStateStruct {
                state_field,
                non_negative_label,
                negative_label,
            } => Self::format_signed_state_struct(
                data,
                type_info,
                state_field,
                non_negative_label,
                negative_label,
            ),
            ValuePresentation::ReferenceCountedStruct {
                strong_field,
                weak_field,
                implicit_weak,
            } => Self::format_reference_counted_struct(
                data,
                type_info,
                strong_field,
                weak_field,
                *implicit_weak,
            ),
            ValuePresentation::HashTable {
                entry_stride,
                bucket_order,
                entry,
            } => Self::format_hash_table_payload(data, *entry_stride, *bucket_order, entry),
            ValuePresentation::BTree {
                node_capacity,
                entry,
            } => Self::format_btree_payload(data, *node_capacity, entry),
        }
    }

    fn format_signed_state_struct(
        data: &[u8],
        type_info: &TypeInfo,
        state_field: &str,
        non_negative_label: &str,
        negative_label: &str,
    ) -> String {
        let TypeInfo::StructType { name, members, .. } = type_info else {
            return "<INVALID_SIGNED_STATE_STRUCT>".to_string();
        };
        let Some(member) = members.iter().find(|member| member.name == state_field) else {
            return "<INVALID_SIGNED_STATE_STRUCT>".to_string();
        };
        let state = usize::try_from(member.offset)
            .ok()
            .and_then(|offset| data.get(offset..))
            .and_then(|data| Self::decode_signed_integer(data, &member.member_type));
        let summary = match state {
            Some(state) if state >= 0 => {
                format!("{name}({non_negative_label}={state})")
            }
            Some(state) => {
                format!("{name}({negative_label}={})", state.unsigned_abs())
            }
            None => format!("{name}({state_field}=<unavailable>)"),
        };
        let fields = Self::format_data_with_type_info(data, type_info);
        let Some(fields) = fields.strip_prefix(name) else {
            return "<INVALID_SIGNED_STATE_STRUCT>".to_string();
        };
        format!("{summary}{fields}")
    }

    fn format_reference_counted_struct(
        data: &[u8],
        type_info: &TypeInfo,
        strong_field: &str,
        weak_field: &str,
        implicit_weak: u64,
    ) -> String {
        let TypeInfo::StructType { name, members, .. } = type_info else {
            return "<INVALID_REFERENCE_COUNTED_STRUCT>".to_string();
        };
        let Some(strong_member) = members.iter().find(|member| member.name == strong_field) else {
            return "<INVALID_REFERENCE_COUNTED_STRUCT>".to_string();
        };
        let Some(weak_member) = members.iter().find(|member| member.name == weak_field) else {
            return "<INVALID_REFERENCE_COUNTED_STRUCT>".to_string();
        };

        let strong = Self::decode_unsigned_member(data, strong_member);
        let weak = Self::decode_unsigned_member(data, weak_member)
            .and_then(|weak| weak.checked_sub(u128::from(implicit_weak)));

        // Keep the protocol payload raw. Adjust a user-space copy so the
        // existing DWARF struct formatter shows the public weak count too.
        let mut adjusted_data = data.to_vec();
        if let Some(weak) = weak {
            let offset = usize::try_from(weak_member.offset).ok();
            if let Some(field_data) = offset.and_then(|offset| adjusted_data.get_mut(offset..)) {
                let _ = Self::encode_unsigned_integer(field_data, &weak_member.member_type, weak);
            }
        }

        let strong = strong
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<unavailable>".to_string());
        let weak = weak
            .map(|value| value.to_string())
            .unwrap_or_else(|| "<unavailable>".to_string());
        let summary = format!("{name}({strong_field}={strong}, {weak_field}={weak})");
        let fields = Self::format_data_with_type_info(&adjusted_data, type_info);
        let Some(fields) = fields.strip_prefix(name) else {
            return "<INVALID_REFERENCE_COUNTED_STRUCT>".to_string();
        };
        format!("{summary}{fields}")
    }

    fn decode_unsigned_member(data: &[u8], member: &crate::StructMember) -> Option<u128> {
        let offset = usize::try_from(member.offset).ok()?;
        Self::decode_unsigned_integer(data.get(offset..)?, &member.member_type)
    }

    fn decode_unsigned_integer(data: &[u8], type_info: &TypeInfo) -> Option<u128> {
        let type_info = match type_info {
            TypeInfo::TypedefType {
                underlying_type, ..
            }
            | TypeInfo::QualifiedType {
                underlying_type, ..
            } => return Self::decode_unsigned_integer(data, underlying_type),
            type_info => type_info,
        };
        let TypeInfo::BaseType { size, encoding, .. } = type_info else {
            return None;
        };
        if *encoding != gimli::constants::DW_ATE_unsigned.0 as u16
            && *encoding != gimli::constants::DW_ATE_unsigned_char.0 as u16
        {
            return None;
        }

        match *size {
            1 => Some(u8::from_le_bytes(data.get(..1)?.try_into().ok()?) as u128),
            2 => Some(u16::from_le_bytes(data.get(..2)?.try_into().ok()?) as u128),
            4 => Some(u32::from_le_bytes(data.get(..4)?.try_into().ok()?) as u128),
            8 => Some(u64::from_le_bytes(data.get(..8)?.try_into().ok()?) as u128),
            16 => Some(u128::from_le_bytes(data.get(..16)?.try_into().ok()?)),
            _ => None,
        }
    }

    fn encode_unsigned_integer(data: &mut [u8], type_info: &TypeInfo, value: u128) -> bool {
        let type_info = match type_info {
            TypeInfo::TypedefType {
                underlying_type, ..
            }
            | TypeInfo::QualifiedType {
                underlying_type, ..
            } => return Self::encode_unsigned_integer(data, underlying_type, value),
            type_info => type_info,
        };
        let TypeInfo::BaseType { size, encoding, .. } = type_info else {
            return false;
        };
        if *encoding != gimli::constants::DW_ATE_unsigned.0 as u16
            && *encoding != gimli::constants::DW_ATE_unsigned_char.0 as u16
        {
            return false;
        }

        let bytes = value.to_le_bytes();
        let Ok(size) = usize::try_from(*size) else {
            return false;
        };
        let Some(target) = data.get_mut(..size) else {
            return false;
        };
        let Some(source) = bytes.get(..size) else {
            return false;
        };
        target.copy_from_slice(source);
        true
    }

    fn decode_signed_integer(data: &[u8], type_info: &TypeInfo) -> Option<i128> {
        let type_info = match type_info {
            TypeInfo::TypedefType {
                underlying_type, ..
            }
            | TypeInfo::QualifiedType {
                underlying_type, ..
            } => return Self::decode_signed_integer(data, underlying_type),
            type_info => type_info,
        };
        let TypeInfo::BaseType { size, encoding, .. } = type_info else {
            return None;
        };
        if *encoding != gimli::constants::DW_ATE_signed.0 as u16
            && *encoding != gimli::constants::DW_ATE_signed_char.0 as u16
        {
            return None;
        }

        match *size {
            1 => Some(i8::from_le_bytes(data.get(..1)?.try_into().ok()?) as i128),
            2 => Some(i16::from_le_bytes(data.get(..2)?.try_into().ok()?) as i128),
            4 => Some(i32::from_le_bytes(data.get(..4)?.try_into().ok()?) as i128),
            8 => Some(i64::from_le_bytes(data.get(..8)?.try_into().ok()?) as i128),
            16 => Some(i128::from_le_bytes(data.get(..16)?.try_into().ok()?)),
            _ => None,
        }
    }

    fn format_spec_payload_bytes<'a>(
        variable: &'a ParsedComplexVariable,
        trace_context: &TraceContext,
    ) -> Result<Cow<'a, [u8]>, &'static str> {
        if variable.status == VariableStatus::ZeroLength as u8 {
            return Ok(Cow::Borrowed(&[]));
        }

        let presentation = trace_context.get_value_presentation(variable.type_index);
        if let ValuePresentation::HashTable {
            entry_stride,
            bucket_order,
            ..
        } = presentation
        {
            return Self::hash_table_occupied_bucket_bytes(
                &variable.data,
                *entry_stride,
                *bucket_order,
            )
            .map(Cow::Owned)
            .ok_or("<INVALID_SEMANTIC_PAYLOAD>");
        }
        if let ValuePresentation::BTree {
            node_capacity,
            entry,
        } = presentation
        {
            return match Self::btree_value_bytes(&variable.data, *node_capacity, entry) {
                Some(bytes) => Ok(Cow::Owned(bytes)),
                None if Self::is_semantic_truncation(variable, trace_context) => {
                    Ok(Cow::Borrowed(&[]))
                }
                None => Err("<INVALID_SEMANTIC_PAYLOAD>"),
            };
        }
        match Self::presentation_payload_bytes(&variable.data, presentation) {
            Some(payload) => Ok(Cow::Borrowed(payload)),
            None if Self::is_semantic_truncation(variable, trace_context) => Ok(Cow::Borrowed(&[])),
            None => Err("<INVALID_SEMANTIC_PAYLOAD>"),
        }
    }

    fn presentation_payload_bytes<'a>(
        data: &'a [u8],
        presentation: &ValuePresentation,
    ) -> Option<&'a [u8]> {
        match presentation {
            ValuePresentation::Dwarf => Some(data),
            ValuePresentation::Utf8String | ValuePresentation::ByteString => {
                let prefix = data.get(..INDIRECT_BYTES_LENGTH_PREFIX_SIZE)?;
                let original_len = u64::from_le_bytes(prefix.try_into().ok()?);
                let payload = &data[INDIRECT_BYTES_LENGTH_PREFIX_SIZE..];
                let captured_len = usize::try_from(original_len)
                    .unwrap_or(usize::MAX)
                    .min(payload.len());
                Some(&payload[..captured_len])
            }
            ValuePresentation::Sequence { element_stride, .. } => {
                let (_, _, payload) = Self::parse_sequence_payload(data, *element_stride)?;
                Some(payload)
            }
            ValuePresentation::HashTable { entry_stride, .. } => {
                Some(Self::parse_hash_table_payload(data, *entry_stride)?.buckets)
            }
            ValuePresentation::BTree {
                node_capacity,
                entry,
            } => {
                Self::parse_btree_payload(data, *node_capacity, entry)?;
                Some(data)
            }
            ValuePresentation::SingleField { .. }
            | ValuePresentation::SignedStateStruct { .. }
            | ValuePresentation::ReferenceCountedStruct { .. } => Some(data),
        }
    }

    fn format_utf8_string_payload(data: &[u8]) -> String {
        let Some(captured) = Self::presentation_payload_bytes(data, &ValuePresentation::Utf8String)
        else {
            return "<INVALID_UTF8_STRING_PAYLOAD>".to_string();
        };

        match std::str::from_utf8(captured) {
            Ok(value) => format!("{value:?}"),
            Err(error) if error.error_len().is_none() => {
                let valid = &captured[..error.valid_up_to()];
                let valid = std::str::from_utf8(valid)
                    .expect("UTF-8 error valid_up_to always identifies valid bytes");
                format!("{valid:?}")
            }
            Err(_) => {
                let escaped = captured
                    .iter()
                    .map(|byte| format!("\\x{byte:02x}"))
                    .collect::<String>();
                format!("<INVALID_UTF8:{escaped}>")
            }
        }
    }

    fn format_byte_string_payload(data: &[u8]) -> String {
        let Some(captured) = Self::presentation_payload_bytes(data, &ValuePresentation::ByteString)
        else {
            return "<INVALID_BYTE_STRING_PAYLOAD>".to_string();
        };

        let mut output = String::from("\"");
        let mut remaining = captured;
        while !remaining.is_empty() {
            match std::str::from_utf8(remaining) {
                Ok(valid) => {
                    for character in valid.chars() {
                        output.extend(character.escape_debug());
                    }
                    break;
                }
                Err(error) => {
                    let valid_len = error.valid_up_to();
                    let valid = std::str::from_utf8(&remaining[..valid_len])
                        .expect("UTF-8 error valid_up_to identifies valid bytes");
                    for character in valid.chars() {
                        output.extend(character.escape_debug());
                    }

                    let invalid_len = error
                        .error_len()
                        .unwrap_or_else(|| remaining.len().saturating_sub(valid_len));
                    for byte in &remaining[valid_len..valid_len + invalid_len] {
                        output.push_str(&format!("\\x{byte:02x}"));
                    }
                    remaining = &remaining[valid_len + invalid_len..];
                }
            }
        }
        output.push('"');
        output
    }

    fn payload_u64(data: &[u8], offset: usize) -> Option<u64> {
        let end = offset.checked_add(std::mem::size_of::<u64>())?;
        Some(u64::from_le_bytes(data.get(offset..end)?.try_into().ok()?))
    }

    fn parse_hash_table_payload(
        data: &[u8],
        entry_stride: u64,
    ) -> Option<ParsedHashTablePayload<'_>> {
        let original_count = Self::payload_u64(data, 0)?;
        let capacity = Self::payload_u64(data, HASH_TABLE_CAPACITY_OFFSET)?;
        let captured_buckets = Self::payload_u64(data, HASH_TABLE_CAPTURED_BUCKETS_OFFSET)?;
        let bucket_offset = Self::payload_u64(data, HASH_TABLE_BUCKET_DATA_OFFSET)?;
        if original_count > capacity || captured_buckets > capacity {
            return None;
        }

        let captured_buckets = usize::try_from(captured_buckets).ok()?;
        let control_end = HASH_TABLE_HEADER_SIZE.checked_add(captured_buckets)?;
        let bucket_offset = usize::try_from(bucket_offset).ok()?;
        // The eBPF layout fixes the bucket offset after the maximum reserved
        // control region so the verifier sees constant destinations. A small
        // runtime table can therefore leave unused control headroom here.
        if bucket_offset < control_end {
            return None;
        }
        let stride = usize::try_from(entry_stride).ok()?;
        let bucket_len = captured_buckets.checked_mul(stride)?;
        let bucket_end = bucket_offset.checked_add(bucket_len)?;
        let controls = data.get(HASH_TABLE_HEADER_SIZE..control_end)?;
        let buckets = data.get(bucket_offset..bucket_end)?;
        let occupied = controls
            .iter()
            .filter(|control| (**control & 0x80) == 0)
            .count();
        let occupied = u64::try_from(occupied).ok()?;
        if occupied > original_count
            || (u64::try_from(captured_buckets).ok()? == capacity && occupied != original_count)
        {
            return None;
        }

        Some(ParsedHashTablePayload {
            original_count,
            controls,
            buckets,
        })
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
                payload.controls.len().checked_sub(control_index + 1)?
            }
        };
        let start = bucket_index.checked_mul(stride)?;
        let end = start.checked_add(stride)?;
        payload.buckets.get(start..end)
    }

    fn hash_table_occupied_bucket_bytes(
        data: &[u8],
        entry_stride: u64,
        bucket_order: HashTableBucketOrder,
    ) -> Option<Vec<u8>> {
        let payload = Self::parse_hash_table_payload(data, entry_stride)?;
        let stride = usize::try_from(entry_stride).ok()?;
        let output_capacity = payload.controls.len().checked_mul(stride)?;
        let mut entries = Vec::with_capacity(output_capacity);
        for (control_index, control) in payload.controls.iter().enumerate() {
            if (*control & 0x80) == 0 {
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
    ) -> Option<String> {
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

    fn format_hash_table_payload(
        data: &[u8],
        entry_stride: u64,
        bucket_order: HashTableBucketOrder,
        entry: &HashTableEntryPresentation,
    ) -> String {
        let Some(payload) = Self::parse_hash_table_payload(data, entry_stride) else {
            return "<INVALID_HASH_TABLE_PAYLOAD>".to_string();
        };
        let type_name = match entry {
            HashTableEntryPresentation::Map { .. } => "HashMap",
            HashTableEntryPresentation::Set { .. } => "HashSet",
        };
        let mut result = format!("{type_name}(size={}) {{", payload.original_count);
        let mut output_index = 0usize;
        for (control_index, control) in payload.controls.iter().enumerate() {
            if (*control & 0x80) != 0 {
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
                    let Some(key) = Self::format_hash_table_field(entry_data, entry_stride, key)
                    else {
                        return "<INVALID_HASH_TABLE_ENTRY_LAYOUT>".to_string();
                    };
                    let Some(value) =
                        Self::format_hash_table_field(entry_data, entry_stride, value)
                    else {
                        return "<INVALID_HASH_TABLE_ENTRY_LAYOUT>".to_string();
                    };
                    result.push_str(&key);
                    result.push_str(": ");
                    result.push_str(&value);
                }
                HashTableEntryPresentation::Set { value } => {
                    let Some(value) =
                        Self::format_hash_table_field(entry_data, entry_stride, value)
                    else {
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

    fn parse_btree_payload<'a>(
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

    fn btree_value_bytes(
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

    fn format_btree_payload(
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

    fn parse_sequence_payload(data: &[u8], element_stride: u64) -> Option<(u64, u64, &[u8])> {
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

    fn format_sequence_payload(
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
            TypeInfo::BaseType { name, size: 0, .. } if name == "()" => "()".to_string(),
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
            TypeInfo::PointerType { target_type, size } => {
                let Ok(pointer_size) = usize::try_from(*size) else {
                    return "<INVALID_POINTER>".to_string();
                };
                if pointer_size == 0 || pointer_size > 8 || data.len() < pointer_size {
                    "<INVALID_POINTER>".to_string()
                } else {
                    let mut address_bytes = [0u8; 8];
                    address_bytes[..pointer_size].copy_from_slice(&data[..pointer_size]);
                    let addr = u64::from_le_bytes(address_bytes);
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
                if members.is_empty() && type_info.size() == 0 && name == "()" {
                    return "()".to_string();
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
            TypeInfo::OptimizedOut { .. } => "<optimized out>".to_string(),
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
                16 => match data.get(..16).and_then(|bytes| bytes.try_into().ok()) {
                    Some(bytes) => i128::from_le_bytes(bytes).to_string(),
                    None => "<INVALID_I128>".to_string(),
                },
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
                16 => match data.get(..16).and_then(|bytes| bytes.try_into().ok()) {
                    Some(bytes) => u128::from_le_bytes(bytes).to_string(),
                    None => "<INVALID_U128>".to_string(),
                },
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

    type BTreeMapNode<'a> = (usize, u64, u64, &'a [i32], &'a [u16]);

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
        let format_index = trace_context
            .add_string("Hello {}, you are {} years old!".to_string())
            .expect("add format string");
        let rendered: Vec<String> = vec!["Alice".to_string(), "25".to_string()];
        let fmt = trace_context.get_string(format_index).unwrap();
        let result = FormatPrinter::apply_format_strings(fmt, &rendered);
        assert_eq!(result, "Hello Alice, you are 25 years old!");
    }

    #[test]
    fn test_format_complex_variable_struct() {
        use crate::type_info::{StructMember, TypeInfo};

        let mut trace_context = TraceContext::new();
        let var_name_idx = trace_context
            .add_variable_name("person".to_string())
            .expect("add variable name");

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

        let type_idx = trace_context
            .add_type(person_type)
            .expect("add person type");

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
        let var_name_idx = trace_context
            .add_variable_name("name".to_string())
            .expect("add variable name");
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
        let type_idx = trace_context.add_type(arr_type).expect("add array type");

        // Data buffer with "Alice\0" and padding
        let mut data = b"Alice\0".to_vec();
        data.resize(16, 0u8);

        let fmt_idx = trace_context
            .add_string("{}".to_string())
            .expect("add format string");
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

    fn rust_str_type() -> TypeInfo {
        TypeInfo::StructType {
            name: "&str".to_string(),
            size: 16,
            members: Vec::new(),
        }
    }

    fn indirect_bytes_payload(original_len: u64, captured: &[u8]) -> Vec<u8> {
        let mut data = original_len.to_le_bytes().to_vec();
        data.extend_from_slice(captured);
        data
    }

    fn indirect_sequence_payload(
        original_count: u64,
        captured_count: u64,
        captured: &[u8],
    ) -> Vec<u8> {
        let mut data = original_count.to_le_bytes().to_vec();
        data.extend_from_slice(&captured_count.to_le_bytes());
        data.extend_from_slice(captured);
        data
    }

    fn hash_table_payload(
        original_count: u64,
        capacity: u64,
        controls: &[u8],
        buckets: &[u8],
    ) -> Vec<u8> {
        hash_table_payload_with_control_headroom(original_count, capacity, controls, buckets, 0)
    }

    fn hash_table_payload_with_control_headroom(
        original_count: u64,
        capacity: u64,
        controls: &[u8],
        buckets: &[u8],
        unused_control_bytes: usize,
    ) -> Vec<u8> {
        let bucket_offset = HASH_TABLE_HEADER_SIZE + controls.len() + unused_control_bytes;
        let mut data = original_count.to_le_bytes().to_vec();
        data.extend_from_slice(&capacity.to_le_bytes());
        data.extend_from_slice(&(controls.len() as u64).to_le_bytes());
        data.extend_from_slice(&(bucket_offset as u64).to_le_bytes());
        data.extend_from_slice(controls);
        data.resize(bucket_offset, 0);
        data.extend_from_slice(buckets);
        data
    }

    fn btree_map_presentation(node_capacity: u64) -> ValuePresentation {
        ValuePresentation::BTree {
            node_capacity,
            entry: BTreeEntryPresentation::Map {
                key: BTreeFieldPresentation {
                    slot_stride: 4,
                    value_offset: 0,
                    field_type: Box::new(signed_i32_type()),
                },
                value: BTreeFieldPresentation {
                    slot_stride: 2,
                    value_offset: 0,
                    field_type: Box::new(unsigned_u16_type()),
                },
            },
        }
    }

    fn btree_set_presentation(node_capacity: u64) -> ValuePresentation {
        ValuePresentation::BTree {
            node_capacity,
            entry: BTreeEntryPresentation::Set {
                value: BTreeFieldPresentation {
                    slot_stride: 4,
                    value_offset: 0,
                    field_type: Box::new(signed_i32_type()),
                },
            },
        }
    }

    fn btree_map_payload(
        original_count: u64,
        captured_count: u64,
        node_capacity: usize,
        node_slots: usize,
        nodes: &[BTreeMapNode<'_>],
    ) -> Vec<u8> {
        let keys_size = node_capacity * 4;
        let values_offset = BTREE_NODE_HEADER_SIZE + keys_size;
        let record_size = values_offset + node_capacity * 2;
        let mut data = original_count.to_le_bytes().to_vec();
        data.extend_from_slice(&(node_slots as u64).to_le_bytes());
        data.extend_from_slice(&captured_count.to_le_bytes());
        data.resize(BTREE_HEADER_SIZE + node_slots * record_size, 0);
        for (slot, address, height, keys, values) in nodes {
            assert_eq!(keys.len(), values.len());
            assert!(keys.len() <= node_capacity);
            let start = BTREE_HEADER_SIZE + slot * record_size;
            data[start..start + 8].copy_from_slice(&address.to_le_bytes());
            data[start + 8..start + 16].copy_from_slice(&height.to_le_bytes());
            data[start + 16..start + 24].copy_from_slice(&(keys.len() as u64).to_le_bytes());
            for (index, key) in keys.iter().enumerate() {
                let offset = start + BTREE_NODE_HEADER_SIZE + index * 4;
                data[offset..offset + 4].copy_from_slice(&key.to_le_bytes());
            }
            for (index, value) in values.iter().enumerate() {
                let offset = start + values_offset + index * 2;
                data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            }
        }
        data
    }

    fn btree_set_payload(
        original_count: u64,
        captured_count: u64,
        node_capacity: usize,
        node_slots: usize,
        nodes: &[(usize, u64, u64, &[i32])],
    ) -> Vec<u8> {
        let record_size = BTREE_NODE_HEADER_SIZE + node_capacity * 4;
        let mut data = original_count.to_le_bytes().to_vec();
        data.extend_from_slice(&(node_slots as u64).to_le_bytes());
        data.extend_from_slice(&captured_count.to_le_bytes());
        data.resize(BTREE_HEADER_SIZE + node_slots * record_size, 0);
        for (slot, address, height, values) in nodes {
            assert!(values.len() <= node_capacity);
            let start = BTREE_HEADER_SIZE + slot * record_size;
            data[start..start + 8].copy_from_slice(&address.to_le_bytes());
            data[start + 8..start + 16].copy_from_slice(&height.to_le_bytes());
            data[start + 16..start + 24].copy_from_slice(&(values.len() as u64).to_le_bytes());
            for (index, value) in values.iter().enumerate() {
                let offset = start + BTREE_NODE_HEADER_SIZE + index * 4;
                data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
        }
        data
    }

    fn signed_i32_type() -> TypeInfo {
        TypeInfo::BaseType {
            name: "i32".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        }
    }

    fn unsigned_u16_type() -> TypeInfo {
        TypeInfo::BaseType {
            name: "u16".to_string(),
            size: 2,
            encoding: gimli::constants::DW_ATE_unsigned.0 as u16,
        }
    }

    #[test]
    fn test_hash_table_presentation_filters_controls_and_projects_fields() {
        let controls = [0xff, 0x12, 0x80, 0x01];
        let mut buckets = vec![0u8; 4 * 8];
        buckets[8..12].copy_from_slice(&(-7_i32).to_le_bytes());
        buckets[12..14].copy_from_slice(&13_u16.to_le_bytes());
        buckets[24..28].copy_from_slice(&29_i32.to_le_bytes());
        buckets[28..30].copy_from_slice(&17_u16.to_le_bytes());
        let data = hash_table_payload(2, 4, &controls, &buckets);
        let presentation = ValuePresentation::HashTable {
            entry_stride: 8,
            bucket_order: HashTableBucketOrder::Forward,
            entry: HashTableEntryPresentation::Map {
                key: HashTableFieldPresentation {
                    offset: 0,
                    field_type: Box::new(signed_i32_type()),
                },
                value: HashTableFieldPresentation {
                    offset: 4,
                    field_type: Box::new(unsigned_u16_type()),
                },
            },
        };

        assert_eq!(
            FormatPrinter::format_data_with_presentation(
                &data,
                &TypeInfo::UnknownType {
                    name: "HashMap".to_string(),
                },
                &presentation,
            ),
            "HashMap(size=2) {-7: 13, 29: 17}"
        );
    }

    #[test]
    fn test_hash_table_presentation_handles_reverse_and_zst_buckets() {
        let controls = [0x01, 0xff, 0x02, 0x80];
        let mut reverse_buckets = vec![0u8; 4 * 4];
        reverse_buckets[12..16].copy_from_slice(&5_i32.to_le_bytes());
        reverse_buckets[4..8].copy_from_slice(&(-9_i32).to_le_bytes());
        let reverse = hash_table_payload(2, 4, &controls, &reverse_buckets);
        let set = ValuePresentation::HashTable {
            entry_stride: 4,
            bucket_order: HashTableBucketOrder::Reverse,
            entry: HashTableEntryPresentation::Set {
                value: HashTableFieldPresentation {
                    offset: 0,
                    field_type: Box::new(signed_i32_type()),
                },
            },
        };
        assert_eq!(
            FormatPrinter::format_data_with_presentation(
                &reverse,
                &TypeInfo::UnknownType {
                    name: "HashSet".to_string(),
                },
                &set,
            ),
            "HashSet(size=2) {5, -9}"
        );

        let zst = hash_table_payload(1, 1, &[0x00], &[]);
        let unit_set = ValuePresentation::HashTable {
            entry_stride: 0,
            bucket_order: HashTableBucketOrder::Reverse,
            entry: HashTableEntryPresentation::Set {
                value: HashTableFieldPresentation {
                    offset: 0,
                    field_type: Box::new(TypeInfo::BaseType {
                        name: "()".to_string(),
                        size: 0,
                        encoding: 0,
                    }),
                },
            },
        };
        assert_eq!(
            FormatPrinter::format_data_with_presentation(
                &zst,
                &TypeInfo::UnknownType {
                    name: "HashSet".to_string(),
                },
                &unit_set,
            ),
            "HashSet(size=1) {()}"
        );
    }

    #[test]
    fn test_hash_table_raw_specs_skip_unoccupied_buckets() {
        let controls = [0x01, 0xff, 0x02, 0x80];
        let buckets = vec![0xde, 0xad, 0x42, 0x00, 0xbe, 0xef, 0x41, 0x00];
        let data = hash_table_payload(2, 4, &controls, &buckets);

        let presentation = ValuePresentation::HashTable {
            entry_stride: 2,
            bucket_order: HashTableBucketOrder::Reverse,
            entry: HashTableEntryPresentation::Set {
                value: HashTableFieldPresentation {
                    offset: 0,
                    field_type: Box::new(unsigned_u16_type()),
                },
            },
        };
        let mut trace_context = TraceContext::new();
        let format_index = trace_context.add_string("{:x}|{:s}".to_string()).unwrap();
        let type_index = trace_context
            .add_type_with_presentation(
                TypeInfo::UnknownType {
                    name: "HashSet".to_string(),
                },
                presentation,
            )
            .unwrap();
        let name_index = trace_context.add_variable_name("set".to_string()).unwrap();
        let variable = ParsedComplexVariable {
            var_name_index: name_index,
            type_index,
            access_path: String::new(),
            status: VariableStatus::Ok as u8,
            data,
        };

        assert_eq!(
            FormatPrinter::format_complex_print_data(
                format_index,
                &[variable.clone(), variable],
                &trace_context,
            ),
            "41 00 42 00|A"
        );

        let huge_count_format = trace_context.add_string("{:x}".to_string()).unwrap();
        let huge_count = ParsedComplexVariable {
            var_name_index: name_index,
            type_index,
            access_path: String::new(),
            status: VariableStatus::Truncated as u8,
            data: hash_table_payload(u64::MAX, u64::MAX, &[0x01], &[0x34, 0x12]),
        };
        assert_eq!(
            FormatPrinter::format_complex_print_data(
                huge_count_format,
                &[huge_count],
                &trace_context,
            ),
            "34 12 <truncated>"
        );
    }

    #[test]
    fn test_hash_table_payload_validates_complete_occupancy_and_keeps_partial_capture() {
        let presentation = ValuePresentation::HashTable {
            entry_stride: 4,
            bucket_order: HashTableBucketOrder::Forward,
            entry: HashTableEntryPresentation::Set {
                value: HashTableFieldPresentation {
                    offset: 0,
                    field_type: Box::new(signed_i32_type()),
                },
            },
        };
        let mut buckets = vec![0_u8; 8];
        buckets[..4].copy_from_slice(&5_i32.to_le_bytes());

        let invalid_complete = hash_table_payload(2, 2, &[0x01, 0xff], &buckets);
        assert_eq!(
            FormatPrinter::format_data_with_presentation(
                &invalid_complete,
                &TypeInfo::UnknownType {
                    name: "HashSet".to_string(),
                },
                &presentation,
            ),
            "<INVALID_HASH_TABLE_PAYLOAD>"
        );

        let partial = hash_table_payload_with_control_headroom(2, 4, &[0x01, 0xff], &buckets, 6);
        let mut trace_context = TraceContext::new();
        let type_index = trace_context
            .add_type_with_presentation(
                TypeInfo::UnknownType {
                    name: "HashSet".to_string(),
                },
                presentation,
            )
            .unwrap();
        let name_index = trace_context.add_variable_name("set".to_string()).unwrap();
        assert_eq!(
            FormatPrinter::format_complex_variable_with_status(
                name_index,
                type_index,
                "",
                &partial,
                VariableStatus::Truncated as u8,
                &trace_context,
            ),
            "set = HashSet(size=2) {5} <truncated>"
        );
    }

    #[test]
    fn test_btree_map_presentation_formats_leaf_and_raw_entry_bytes() {
        let presentation = btree_map_presentation(2);
        let data = btree_map_payload(2, 2, 2, 1, &[(0, 0x1000, 0, &[-7, 29], &[13, 17])]);
        assert_eq!(
            FormatPrinter::format_data_with_presentation(
                &data,
                &TypeInfo::UnknownType {
                    name: "BTreeMap".to_string(),
                },
                &presentation,
            ),
            "BTreeMap(size=2) {-7: 13, 29: 17}"
        );

        let mut trace_context = TraceContext::new();
        let format_index = trace_context.add_string("{:x}".to_string()).unwrap();
        let type_index = trace_context
            .add_type_with_presentation(
                TypeInfo::UnknownType {
                    name: "BTreeMap".to_string(),
                },
                presentation,
            )
            .unwrap();
        let name_index = trace_context.add_variable_name("map".to_string()).unwrap();
        let variable = ParsedComplexVariable {
            var_name_index: name_index,
            type_index,
            access_path: String::new(),
            status: VariableStatus::Ok as u8,
            data,
        };
        assert_eq!(
            FormatPrinter::format_complex_print_data(format_index, &[variable], &trace_context,),
            "f9 ff ff ff 0d 00 1d 00 00 00 11 00"
        );
    }

    #[test]
    fn test_btree_set_presentation_reconstructs_internal_nodes_in_order() {
        let presentation = btree_set_presentation(2);
        let data = btree_set_payload(
            5,
            5,
            2,
            3,
            &[
                (0, 0x1000, 1, &[10]),
                (1, 0x2000, 0, &[-5, 4]),
                (2, 0x3000, 0, &[12, 20]),
            ],
        );
        assert_eq!(
            FormatPrinter::format_data_with_presentation(
                &data,
                &TypeInfo::UnknownType {
                    name: "BTreeSet".to_string(),
                },
                &presentation,
            ),
            "BTreeSet(size=5) {-5, 4, 10, 12, 20}"
        );
    }

    #[test]
    fn test_btree_payload_preserves_valid_prefix_when_truncated() {
        let presentation = btree_set_presentation(2);
        let data = btree_set_payload(3, 2, 2, 2, &[(0, 0x1000, 1, &[10]), (1, 0x2000, 0, &[1])]);
        let mut trace_context = TraceContext::new();
        let type_index = trace_context
            .add_type_with_presentation(
                TypeInfo::UnknownType {
                    name: "BTreeSet".to_string(),
                },
                presentation,
            )
            .unwrap();
        let name_index = trace_context.add_variable_name("set".to_string()).unwrap();
        assert_eq!(
            FormatPrinter::format_complex_variable_with_status(
                name_index,
                type_index,
                "",
                &data,
                VariableStatus::Truncated as u8,
                &trace_context,
            ),
            "set = BTreeSet(size=3) {1, 10} <truncated>"
        );

        let empty_prefix = btree_set_payload(3, 0, 2, 0, &[]);
        assert_eq!(
            FormatPrinter::format_complex_variable_with_status(
                name_index,
                type_index,
                "",
                &empty_prefix,
                VariableStatus::Truncated as u8,
                &trace_context,
            ),
            "set = BTreeSet(size=3) {} <truncated>"
        );
        assert_eq!(
            FormatPrinter::format_complex_variable_with_status(
                name_index,
                type_index,
                "",
                &[0; 12],
                VariableStatus::Truncated as u8,
                &trace_context,
            ),
            "set = <truncated>"
        );
        let raw_format = trace_context.add_string("{:x}".to_string()).unwrap();
        let variable = ParsedComplexVariable {
            var_name_index: name_index,
            type_index,
            access_path: String::new(),
            status: VariableStatus::Truncated as u8,
            data: data.clone(),
        };
        assert_eq!(
            FormatPrinter::format_complex_print_data(raw_format, &[variable], &trace_context,),
            "01 00 00 00 0a 00 00 00 <truncated>"
        );
        let omitted_raw = ParsedComplexVariable {
            var_name_index: name_index,
            type_index,
            access_path: String::new(),
            status: VariableStatus::Truncated as u8,
            data: vec![0; 12],
        };
        assert_eq!(
            FormatPrinter::format_complex_print_data(raw_format, &[omitted_raw], &trace_context,),
            "<truncated>"
        );

        let mut malformed = data;
        malformed[BTREE_CAPTURED_ITEM_COUNT_OFFSET..BTREE_HEADER_SIZE]
            .copy_from_slice(&3_u64.to_le_bytes());
        assert_eq!(
            FormatPrinter::format_data_with_presentation(
                &malformed,
                &TypeInfo::UnknownType {
                    name: "BTreeSet".to_string(),
                },
                &btree_set_presentation(2),
            ),
            "<INVALID_BTREE_PAYLOAD>"
        );
    }

    #[test]
    fn test_utf8_string_presentation_uses_length_not_nul_termination() {
        let mut trace_context = TraceContext::new();
        let format_idx = trace_context.add_string("{}".to_string()).unwrap();
        let type_idx = trace_context
            .add_type_with_presentation(rust_str_type(), ValuePresentation::Utf8String)
            .unwrap();
        let name_idx = trace_context
            .add_variable_name("message".to_string())
            .unwrap();
        let data = indirect_bytes_payload(3, b"a\0b");
        let vars = vec![ParsedComplexVariable {
            var_name_index: name_idx,
            type_index: type_idx,
            access_path: String::new(),
            status: VariableStatus::Ok as u8,
            data,
        }];

        assert_eq!(
            FormatPrinter::format_complex_print_data(format_idx, &vars, &trace_context),
            "\"a\\0b\""
        );
    }

    #[test]
    fn test_byte_string_presentation_preserves_utf8_and_escapes_invalid_bytes() {
        let valid = indirect_bytes_payload(4, "aé\0".as_bytes());
        let invalid = indirect_bytes_payload(3, b"a\xffb");

        assert_eq!(
            FormatPrinter::format_data_with_presentation(
                &valid,
                &rust_str_type(),
                &ValuePresentation::ByteString,
            ),
            "\"aé\\0\""
        );
        assert_eq!(
            FormatPrinter::format_data_with_presentation(
                &invalid,
                &rust_str_type(),
                &ValuePresentation::ByteString,
            ),
            "\"a\\xffb\""
        );
    }

    #[test]
    fn test_single_field_presentation_wraps_dwarf_value() {
        let value_type = TypeInfo::BaseType {
            name: "u32".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_unsigned.0 as u16,
        };
        let presentation = ValuePresentation::SingleField {
            type_name: "Cell".to_string(),
            field_name: "value".to_string(),
        };
        let data = 42_u32.to_le_bytes();

        assert_eq!(
            FormatPrinter::format_data_with_presentation(&data, &value_type, &presentation),
            "Cell { value: 42 }"
        );
        assert_eq!(
            FormatPrinter::presentation_payload_bytes(&data, &presentation),
            Some(data.as_slice())
        );

        let unit_type = TypeInfo::BaseType {
            name: "()".to_string(),
            size: 0,
            encoding: gimli::constants::DW_ATE_unsigned.0 as u16,
        };
        assert_eq!(
            FormatPrinter::format_data_with_presentation(&[], &unit_type, &presentation),
            "Cell { value: () }"
        );
    }

    #[test]
    fn test_signed_state_struct_presentation_formats_borrow_states() {
        let type_info = TypeInfo::StructType {
            name: "RefCell".to_string(),
            size: 16,
            members: vec![
                crate::StructMember {
                    name: "value".to_string(),
                    member_type: TypeInfo::BaseType {
                        name: "i32".to_string(),
                        size: 4,
                        encoding: gimli::constants::DW_ATE_signed.0 as u16,
                    },
                    offset: 0,
                    bit_offset: None,
                    bit_size: None,
                },
                crate::StructMember {
                    name: "borrow".to_string(),
                    member_type: TypeInfo::BaseType {
                        name: "isize".to_string(),
                        size: 8,
                        encoding: gimli::constants::DW_ATE_signed.0 as u16,
                    },
                    offset: 8,
                    bit_offset: None,
                    bit_size: None,
                },
            ],
        };
        let presentation = ValuePresentation::SignedStateStruct {
            state_field: "borrow".to_string(),
            non_negative_label: "borrow".to_string(),
            negative_label: "borrow_mut".to_string(),
        };
        let mut shared = [0_u8; 16];
        shared[..4].copy_from_slice(&17_i32.to_le_bytes());
        shared[8..].copy_from_slice(&2_i64.to_le_bytes());
        assert_eq!(
            FormatPrinter::format_data_with_presentation(&shared, &type_info, &presentation),
            "RefCell(borrow=2) { value: 17, borrow: 2 }"
        );

        let mut mutable = shared;
        mutable[8..].copy_from_slice(&(-1_i64).to_le_bytes());
        assert_eq!(
            FormatPrinter::format_data_with_presentation(&mutable, &type_info, &presentation),
            "RefCell(borrow_mut=1) { value: 17, borrow: -1 }"
        );

        mutable[8..].copy_from_slice(&i64::MIN.to_le_bytes());
        assert!(
            FormatPrinter::format_data_with_presentation(&mutable, &type_info, &presentation)
                .starts_with("RefCell(borrow_mut=9223372036854775808)")
        );
        assert_eq!(
            FormatPrinter::presentation_payload_bytes(&shared, &presentation),
            Some(shared.as_slice())
        );
    }

    #[test]
    fn test_reference_counted_presentation_removes_implicit_weak_count() {
        let usize_type = TypeInfo::BaseType {
            name: "usize".to_string(),
            size: 8,
            encoding: gimli::constants::DW_ATE_unsigned.0 as u16,
        };
        let type_info = TypeInfo::StructType {
            name: "Rc".to_string(),
            size: 20,
            members: vec![
                crate::StructMember {
                    name: "value".to_string(),
                    member_type: TypeInfo::BaseType {
                        name: "i32".to_string(),
                        size: 4,
                        encoding: gimli::constants::DW_ATE_signed.0 as u16,
                    },
                    offset: 0,
                    bit_offset: None,
                    bit_size: None,
                },
                crate::StructMember {
                    name: "strong".to_string(),
                    member_type: usize_type.clone(),
                    offset: 4,
                    bit_offset: None,
                    bit_size: None,
                },
                crate::StructMember {
                    name: "weak".to_string(),
                    member_type: usize_type,
                    offset: 12,
                    bit_offset: None,
                    bit_size: None,
                },
            ],
        };
        let presentation = ValuePresentation::ReferenceCountedStruct {
            strong_field: "strong".to_string(),
            weak_field: "weak".to_string(),
            implicit_weak: 1,
        };
        let mut data = [0_u8; 20];
        data[..4].copy_from_slice(&(-7_i32).to_le_bytes());
        data[4..12].copy_from_slice(&3_u64.to_le_bytes());
        data[12..].copy_from_slice(&2_u64.to_le_bytes());

        assert_eq!(
            FormatPrinter::format_data_with_presentation(&data, &type_info, &presentation),
            "Rc(strong=3, weak=1) { value: -7, strong: 3, weak: 1 }"
        );
        assert_eq!(u64::from_le_bytes(data[12..].try_into().unwrap()), 2);
        assert_eq!(
            FormatPrinter::presentation_payload_bytes(&data, &presentation),
            Some(data.as_slice())
        );
    }

    #[test]
    fn test_signed_state_struct_presentation_handles_truncated_state() {
        let type_info = TypeInfo::StructType {
            name: "RefCell".to_string(),
            size: 16,
            members: vec![
                crate::StructMember {
                    name: "value".to_string(),
                    member_type: TypeInfo::BaseType {
                        name: "i32".to_string(),
                        size: 4,
                        encoding: gimli::constants::DW_ATE_signed.0 as u16,
                    },
                    offset: 0,
                    bit_offset: None,
                    bit_size: None,
                },
                crate::StructMember {
                    name: "borrow".to_string(),
                    member_type: TypeInfo::BaseType {
                        name: "isize".to_string(),
                        size: 8,
                        encoding: gimli::constants::DW_ATE_signed.0 as u16,
                    },
                    offset: 8,
                    bit_offset: None,
                    bit_size: None,
                },
            ],
        };
        let presentation = ValuePresentation::SignedStateStruct {
            state_field: "borrow".to_string(),
            non_negative_label: "borrow".to_string(),
            negative_label: "borrow_mut".to_string(),
        };
        let mut trace_context = TraceContext::new();
        let type_index = trace_context
            .add_type_with_presentation(type_info, presentation)
            .unwrap();
        let name_index = trace_context.add_variable_name("cell".to_string()).unwrap();
        let value = 17_i32.to_le_bytes();

        assert_eq!(
            FormatPrinter::format_complex_variable_with_status(
                name_index,
                type_index,
                "",
                &value,
                VariableStatus::Truncated as u8,
                &trace_context,
            ),
            "cell = RefCell(borrow=<unavailable>) { value: 17, borrow: <OUT_OF_BOUNDS> } \
             <truncated>"
        );
    }

    #[test]
    fn test_byte_string_presentation_retains_truncation_status() {
        let mut trace_context = TraceContext::new();
        let type_idx = trace_context
            .add_type_with_presentation(rust_str_type(), ValuePresentation::ByteString)
            .unwrap();
        let name_idx = trace_context.add_variable_name("path".to_string()).unwrap();

        assert_eq!(
            FormatPrinter::format_complex_variable_with_status(
                name_idx,
                type_idx,
                "",
                &indirect_bytes_payload(4, b"a\xff"),
                VariableStatus::Truncated as u8,
                &trace_context,
            ),
            "path = \"a\\xff\" <truncated>"
        );
    }

    #[test]
    fn test_utf8_string_presentation_preserves_embedded_wrapper_separator() {
        let mut trace_context = TraceContext::new();
        let format_idx = trace_context.add_string("{}".to_string()).unwrap();
        let type_idx = trace_context
            .add_type_with_presentation(rust_str_type(), ValuePresentation::Utf8String)
            .unwrap();
        let name_idx = trace_context
            .add_variable_name("message".to_string())
            .unwrap();
        let vars = vec![ParsedComplexVariable {
            var_name_index: name_idx,
            type_index: type_idx,
            access_path: String::new(),
            status: VariableStatus::Ok as u8,
            data: indirect_bytes_payload(5, b"a = b"),
        }];

        assert_eq!(
            FormatPrinter::format_complex_print_data(format_idx, &vars, &trace_context),
            r#""a = b""#
        );
    }

    #[test]
    fn test_raw_specs_decode_utf8_string_payload() {
        let mut trace_context = TraceContext::new();
        let format_idx = trace_context.add_string("{:s}|{:x}".to_string()).unwrap();
        let type_idx = trace_context
            .add_type_with_presentation(rust_str_type(), ValuePresentation::Utf8String)
            .unwrap();
        let name_idx = trace_context
            .add_variable_name("message".to_string())
            .unwrap();
        let variable = ParsedComplexVariable {
            var_name_index: name_idx,
            type_index: type_idx,
            access_path: String::new(),
            status: VariableStatus::Ok as u8,
            data: indirect_bytes_payload(3, b"abc"),
        };

        assert_eq!(
            FormatPrinter::format_complex_print_data(
                format_idx,
                &[variable.clone(), variable],
                &trace_context,
            ),
            "abc|61 62 63"
        );
    }

    #[test]
    fn test_raw_specs_decode_byte_string_payload() {
        let mut trace_context = TraceContext::new();
        let format_idx = trace_context.add_string("{:s}|{:x}".to_string()).unwrap();
        let type_idx = trace_context
            .add_type_with_presentation(rust_str_type(), ValuePresentation::ByteString)
            .unwrap();
        let name_idx = trace_context.add_variable_name("path".to_string()).unwrap();
        let variable = ParsedComplexVariable {
            var_name_index: name_idx,
            type_index: type_idx,
            access_path: String::new(),
            status: VariableStatus::Ok as u8,
            data: indirect_bytes_payload(3, b"a\xffb"),
        };

        assert_eq!(
            FormatPrinter::format_complex_print_data(
                format_idx,
                &[variable.clone(), variable],
                &trace_context,
            ),
            "a\\xffb|61 ff 62"
        );
    }

    #[test]
    fn test_raw_specs_decode_truncated_utf8_string_payload() {
        let mut trace_context = TraceContext::new();
        let format_idx = trace_context.add_string("{:s}|{:x}".to_string()).unwrap();
        let type_idx = trace_context
            .add_type_with_presentation(rust_str_type(), ValuePresentation::Utf8String)
            .unwrap();
        let name_idx = trace_context
            .add_variable_name("message".to_string())
            .unwrap();
        let variable = ParsedComplexVariable {
            var_name_index: name_idx,
            type_index: type_idx,
            access_path: String::new(),
            status: VariableStatus::Truncated as u8,
            data: indirect_bytes_payload(6, b"abc"),
        };

        assert_eq!(
            FormatPrinter::format_complex_print_data(
                format_idx,
                &[variable.clone(), variable],
                &trace_context,
            ),
            "abc <truncated>|61 62 63 <truncated>"
        );
    }

    #[test]
    fn test_utf8_string_presentation_renders_empty_and_truncated_values() {
        let mut trace_context = TraceContext::new();
        let type_idx = trace_context
            .add_type_with_presentation(rust_str_type(), ValuePresentation::Utf8String)
            .unwrap();
        let name_idx = trace_context
            .add_variable_name("message".to_string())
            .unwrap();

        let empty = FormatPrinter::format_complex_variable_with_status(
            name_idx,
            type_idx,
            "",
            &indirect_bytes_payload(0, &[]),
            VariableStatus::ZeroLength as u8,
            &trace_context,
        );
        let truncated = FormatPrinter::format_complex_variable_with_status(
            name_idx,
            type_idx,
            "",
            &indirect_bytes_payload(6, b"abc"),
            VariableStatus::Truncated as u8,
            &trace_context,
        );

        assert_eq!(empty, "message = \"\"");
        assert_eq!(truncated, "message = \"abc\" <truncated>");
    }

    #[test]
    fn test_utf8_string_read_error_uses_standard_error_payload() {
        let mut trace_context = TraceContext::new();
        let type_idx = trace_context
            .add_type_with_presentation(rust_str_type(), ValuePresentation::Utf8String)
            .unwrap();
        let name_idx = trace_context
            .add_variable_name("message".to_string())
            .unwrap();
        let mut payload = vec![0; VARIABLE_READ_ERROR_PAYLOAD_LEN];
        let errno_end = VARIABLE_READ_ERROR_PAYLOAD_ERRNO_OFFSET + std::mem::size_of::<i32>();
        let addr_end = VARIABLE_READ_ERROR_PAYLOAD_ADDR_OFFSET + std::mem::size_of::<u64>();
        payload[VARIABLE_READ_ERROR_PAYLOAD_ERRNO_OFFSET..errno_end]
            .copy_from_slice(&(-14i32).to_le_bytes());
        payload[VARIABLE_READ_ERROR_PAYLOAD_ADDR_OFFSET..addr_end]
            .copy_from_slice(&0x1234u64.to_le_bytes());

        assert_eq!(
            FormatPrinter::format_complex_variable_with_status(
                name_idx,
                type_idx,
                "",
                &payload,
                VariableStatus::ReadError as u8,
                &trace_context,
            ),
            "message = <read_user failed errno=-14 at 0x1234> (struct &str*)"
        );
    }

    #[test]
    fn test_sequence_presentation_formats_dwarf_elements() {
        let mut trace_context = TraceContext::new();
        let format_idx = trace_context.add_string("{}".to_string()).unwrap();
        let element_type = TypeInfo::BaseType {
            name: "i32".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let type_idx = trace_context
            .add_type_with_presentation(
                TypeInfo::StructType {
                    name: "Vec<i32>".to_string(),
                    size: 24,
                    members: Vec::new(),
                },
                ValuePresentation::Sequence {
                    element_type: Box::new(element_type),
                    element_stride: 4,
                },
            )
            .unwrap();
        let name_idx = trace_context
            .add_variable_name("values".to_string())
            .unwrap();
        let mut elements = Vec::new();
        elements.extend_from_slice(&1i32.to_le_bytes());
        elements.extend_from_slice(&(-2i32).to_le_bytes());
        elements.extend_from_slice(&3i32.to_le_bytes());
        let vars = vec![ParsedComplexVariable {
            var_name_index: name_idx,
            type_index: type_idx,
            access_path: String::new(),
            status: VariableStatus::Ok as u8,
            data: indirect_sequence_payload(3, 3, &elements),
        }];

        assert_eq!(
            FormatPrinter::format_complex_print_data(format_idx, &vars, &trace_context),
            "[1, -2, 3]"
        );
    }

    #[test]
    fn test_sequence_presentation_formats_empty_truncated_and_zst_values() {
        let mut trace_context = TraceContext::new();
        let i32_type = TypeInfo::BaseType {
            name: "i32".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let vec_type = TypeInfo::StructType {
            name: "Vec<i32>".to_string(),
            size: 24,
            members: Vec::new(),
        };
        let vec_idx = trace_context
            .add_type_with_presentation(
                vec_type.clone(),
                ValuePresentation::Sequence {
                    element_type: Box::new(i32_type),
                    element_stride: 4,
                },
            )
            .unwrap();
        let zst_idx = trace_context
            .add_type_with_presentation(
                vec_type,
                ValuePresentation::Sequence {
                    element_type: Box::new(TypeInfo::BaseType {
                        name: "()".to_string(),
                        size: 0,
                        encoding: gimli::constants::DW_ATE_unsigned.0 as u16,
                    }),
                    element_stride: 0,
                },
            )
            .unwrap();
        let name_idx = trace_context
            .add_variable_name("values".to_string())
            .unwrap();
        let mut two_elements = Vec::new();
        two_elements.extend_from_slice(&10i32.to_le_bytes());
        two_elements.extend_from_slice(&20i32.to_le_bytes());

        let empty = FormatPrinter::format_complex_variable_with_status(
            name_idx,
            vec_idx,
            "",
            &indirect_sequence_payload(0, 0, &[]),
            VariableStatus::ZeroLength as u8,
            &trace_context,
        );
        let truncated = FormatPrinter::format_complex_variable_with_status(
            name_idx,
            vec_idx,
            "",
            &indirect_sequence_payload(4, 2, &two_elements),
            VariableStatus::Truncated as u8,
            &trace_context,
        );
        let zst = FormatPrinter::format_complex_variable_with_status(
            name_idx,
            zst_idx,
            "",
            &indirect_sequence_payload(3, 3, &[]),
            VariableStatus::Ok as u8,
            &trace_context,
        );

        assert_eq!(empty, "values = []");
        assert_eq!(truncated, "values = [10, 20] <truncated>");
        assert_eq!(zst, "values = [(), (), ()]");
    }

    #[test]
    fn test_sequence_presentation_uses_dwarf_pointer_size() {
        let element_type = TypeInfo::PointerType {
            target_type: Box::new(TypeInfo::BaseType {
                name: "u8".to_string(),
                size: 1,
                encoding: gimli::constants::DW_ATE_unsigned_char.0 as u16,
            }),
            size: 4,
        };
        let presentation = ValuePresentation::Sequence {
            element_type: Box::new(element_type),
            element_stride: 4,
        };
        let payload = indirect_sequence_payload(1, 1, &0x1234_5678u32.to_le_bytes());

        assert_eq!(
            FormatPrinter::format_data_with_presentation(
                &payload,
                &TypeInfo::UnknownType {
                    name: "Vec<*const u8>".to_string(),
                },
                &presentation,
            ),
            "[0x12345678 (u8*)]"
        );
    }

    #[test]
    fn test_truncated_sequence_without_complete_header_is_not_invalid() {
        let mut trace_context = TraceContext::new();
        let type_idx = trace_context
            .add_type_with_presentation(
                TypeInfo::UnknownType {
                    name: "Vec<i32>".to_string(),
                },
                ValuePresentation::Sequence {
                    element_type: Box::new(TypeInfo::BaseType {
                        name: "i32".to_string(),
                        size: 4,
                        encoding: gimli::constants::DW_ATE_signed.0 as u16,
                    }),
                    element_stride: 4,
                },
            )
            .unwrap();
        let name_idx = trace_context
            .add_variable_name("values".to_string())
            .unwrap();

        assert_eq!(
            FormatPrinter::format_complex_variable_with_status(
                name_idx,
                type_idx,
                "",
                &[0; VARIABLE_READ_ERROR_PAYLOAD_LEN],
                VariableStatus::Truncated as u8,
                &trace_context,
            ),
            "values = <truncated>"
        );
    }

    #[test]
    fn formats_128_bit_dwarf_integers() {
        let signed = TypeInfo::BaseType {
            name: "i128".to_string(),
            size: 16,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let unsigned = TypeInfo::BaseType {
            name: "u128".to_string(),
            size: 16,
            encoding: gimli::constants::DW_ATE_unsigned.0 as u16,
        };
        let signed_value = -170_141_183_460_469_231_731_687_303_715_884_105_727_i128;
        let unsigned_value = 340_282_366_920_938_463_463_374_607_431_768_211_454_u128;

        assert_eq!(
            FormatPrinter::format_data_with_type_info(&signed_value.to_le_bytes(), &signed),
            signed_value.to_string()
        );
        assert_eq!(
            FormatPrinter::format_data_with_type_info(&unsigned_value.to_le_bytes(), &unsigned),
            unsigned_value.to_string()
        );
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

    #[test]
    fn test_ext_hex_preserves_null_deref_error() {
        let mut trace_context = TraceContext::new();
        let fmt_idx = trace_context
            .add_string("{:x.16}".to_string())
            .expect("add format string");

        // Array<u8,16> as the value type
        let arr_type = TypeInfo::ArrayType {
            element_type: Box::new(TypeInfo::BaseType {
                name: "u8".to_string(),
                size: 1,
                encoding: gimli::constants::DW_ATE_unsigned_char.0 as u16,
            }),
            element_count: Some(16),
            total_size: Some(16),
        };
        let type_idx = trace_context.add_type(arr_type).expect("add array type");
        let var_name_idx = trace_context
            .add_variable_name("buf".to_string())
            .expect("add variable name");

        let vars = vec![ParsedComplexVariable {
            var_name_index: var_name_idx,
            type_index: type_idx,
            access_path: String::new(),
            status: VariableStatus::NullDeref as u8,
            data: vec![],
        }];

        let out = FormatPrinter::format_complex_print_data(fmt_idx, &vars, &trace_context);
        assert!(
            out.contains("null pointer dereference"),
            "unexpected output: {out}"
        );
        assert!(
            !out.contains("<MISSING_ARG>"),
            "should not hide error: {out}"
        );
    }

    #[test]
    fn test_ext_s_preserves_read_error_errno_addr() {
        let mut trace_context = TraceContext::new();
        let fmt_idx = trace_context
            .add_string("{:s.16}".to_string())
            .expect("add format string");

        // Array<u8,16>
        let arr_type = TypeInfo::ArrayType {
            element_type: Box::new(TypeInfo::BaseType {
                name: "u8".to_string(),
                size: 1,
                encoding: gimli::constants::DW_ATE_unsigned_char.0 as u16,
            }),
            element_count: Some(16),
            total_size: Some(16),
        };
        let type_idx = trace_context.add_type(arr_type).expect("add array type");
        let var_name_idx = trace_context
            .add_variable_name("buf".to_string())
            .expect("add variable name");

        // Encode errno:i32 + addr:u64 into data
        let errno: i32 = -14; // EFAULT-like
        let addr: u64 = 0x1234_5678_9abc_def0;
        let mut data = Vec::new();
        data.extend_from_slice(&errno.to_le_bytes());
        data.extend_from_slice(&addr.to_le_bytes());

        let vars = vec![ParsedComplexVariable {
            var_name_index: var_name_idx,
            type_index: type_idx,
            access_path: String::new(),
            status: VariableStatus::ReadError as u8,
            data,
        }];

        let out = FormatPrinter::format_complex_print_data(fmt_idx, &vars, &trace_context);
        assert!(
            out.contains("read_user failed errno=-14"),
            "unexpected: {out}"
        );
        assert!(out.contains("0x123456789abcdef0"), "missing addr: {out}");
    }

    #[test]
    fn test_ext_p_preserves_offsets_unavailable() {
        let mut trace_context = TraceContext::new();
        let fmt_idx = trace_context
            .add_string("P={:p}".to_string())
            .expect("add format string");

        let ptr_type = TypeInfo::PointerType {
            target_type: Box::new(TypeInfo::BaseType {
                name: "u8".to_string(),
                size: 1,
                encoding: gimli::constants::DW_ATE_unsigned_char.0 as u16,
            }),
            size: 8,
        };
        let type_idx = trace_context.add_type(ptr_type).expect("add pointer type");
        let var_name_idx = trace_context
            .add_variable_name("ptr".to_string())
            .expect("add variable name");

        let vars = vec![ParsedComplexVariable {
            var_name_index: var_name_idx,
            type_index: type_idx,
            access_path: String::new(),
            status: VariableStatus::OffsetsUnavailable as u8,
            data: vec![],
        }];

        let out = FormatPrinter::format_complex_print_data(fmt_idx, &vars, &trace_context);
        assert!(out.starts_with("P="), "prefix lost: {out}");
        assert!(
            out.contains("proc offsets unavailable"),
            "unexpected: {out}"
        );
    }

    #[test]
    fn test_ext_star_len_error_precedence() {
        let mut trace_context = TraceContext::new();
        let fmt_idx = trace_context
            .add_string("S={:x.*}".to_string())
            .expect("add format string");

        // length argument (will surface its error), use base type for simplicity
        let len_type = TypeInfo::BaseType {
            name: "i64".to_string(),
            size: 8,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let len_ty_idx = trace_context.add_type(len_type).expect("add length type");
        let len_name_idx = trace_context
            .add_variable_name("len".to_string())
            .expect("add length variable");

        // value argument (OK)
        let arr_type = TypeInfo::ArrayType {
            element_type: Box::new(TypeInfo::BaseType {
                name: "u8".to_string(),
                size: 1,
                encoding: gimli::constants::DW_ATE_unsigned_char.0 as u16,
            }),
            element_count: Some(16),
            total_size: Some(16),
        };
        let val_ty_idx = trace_context.add_type(arr_type).expect("add array type");
        let val_name_idx = trace_context
            .add_variable_name("buf".to_string())
            .expect("add variable name");
        let val_data: Vec<u8> = (0u8..16).collect();

        let vars = vec![
            ParsedComplexVariable {
                var_name_index: len_name_idx,
                type_index: len_ty_idx,
                access_path: String::new(),
                status: VariableStatus::NullDeref as u8,
                data: vec![],
            },
            ParsedComplexVariable {
                var_name_index: val_name_idx,
                type_index: val_ty_idx,
                access_path: String::new(),
                status: VariableStatus::Ok as u8,
                data: val_data,
            },
        ];

        let out = FormatPrinter::format_complex_print_data(fmt_idx, &vars, &trace_context);
        assert!(out.starts_with("S="), "prefix lost: {out}");
        assert!(
            out.contains("null pointer"),
            "should surface len arg error: {out}"
        );
        // should not print hex bytes when length errored out
        assert!(
            !out.contains("00 01 02 03"),
            "should not render bytes: {out}"
        );
    }
}

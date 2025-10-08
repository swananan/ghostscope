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

        // Apply formatting using raw variables to support extended specifiers
        Self::apply_format_with_specs(format_string, complex_variables, trace_context)
    }

    #[allow(dead_code)]
    /// Simple placeholder applier for tests that don't use complex variables
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
                                let value_part = s.split(" = ").last().unwrap_or(&s);
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

                        // helper: format error value for a var when status != Ok/ZeroLength
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
                                Some(s.split(" = ").last().unwrap_or(&s).to_string())
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
                                        } else if let Some(err) = err_value_part(var_index) {
                                            result.push_str(&err);
                                            var_index += 1;
                                            continue;
                                        } else {
                                            let v = &vars[var_index];
                                            let b = if v.status == VariableStatus::ZeroLength as u8
                                            {
                                                &[][..]
                                            } else {
                                                v.data.as_slice()
                                            };
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
                                }
                            }
                            's' => {
                                let mut render_bytes = |b: &[u8]| {
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
                                    result.push_str(&out);
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
                                            render_bytes(&full[..take]);
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
                                            render_bytes(&full[..take]);
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
                                            render_bytes(&full[..take]);
                                            var_index += 2;
                                            continue;
                                        }
                                    }
                                    Len::None => {
                                        if var_index >= vars.len() {
                                            result.push_str("<MISSING_ARG>");
                                        } else if let Some(err) = err_value_part(var_index) {
                                            result.push_str(&err);
                                            var_index += 1;
                                            continue;
                                        } else {
                                            let v = &vars[var_index];
                                            let b = if v.status == VariableStatus::ZeroLength as u8
                                            {
                                                &[][..]
                                            } else {
                                                v.data.as_slice()
                                            };
                                            render_bytes(b);
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
                                    let value_part = s.split(" = ").last().unwrap_or(&s);
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

    #[test]
    fn test_ext_hex_preserves_null_deref_error() {
        let mut trace_context = TraceContext::new();
        let fmt_idx = trace_context.add_string("{:x.16}".to_string());

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
        let type_idx = trace_context.add_type(arr_type);
        let var_name_idx = trace_context.add_variable_name("buf".to_string());

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
        let fmt_idx = trace_context.add_string("{:s.16}".to_string());

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
        let type_idx = trace_context.add_type(arr_type);
        let var_name_idx = trace_context.add_variable_name("buf".to_string());

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
        let fmt_idx = trace_context.add_string("P={:p}".to_string());

        let ptr_type = TypeInfo::PointerType {
            target_type: Box::new(TypeInfo::BaseType {
                name: "u8".to_string(),
                size: 1,
                encoding: gimli::constants::DW_ATE_unsigned_char.0 as u16,
            }),
            size: 8,
        };
        let type_idx = trace_context.add_type(ptr_type);
        let var_name_idx = trace_context.add_variable_name("ptr".to_string());

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
        let fmt_idx = trace_context.add_string("S={:x.*}".to_string());

        // length argument (will surface its error), use base type for simplicity
        let len_type = TypeInfo::BaseType {
            name: "i64".to_string(),
            size: 8,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };
        let len_ty_idx = trace_context.add_type(len_type);
        let len_name_idx = trace_context.add_variable_name("len".to_string());

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
        let val_ty_idx = trace_context.add_type(arr_type);
        let val_name_idx = trace_context.add_variable_name("buf".to_string());
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

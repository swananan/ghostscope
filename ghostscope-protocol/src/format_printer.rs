//! Format printer for PrintFormat instructions
//!
//! This module handles the parsing and formatting of PrintFormat instructions
//! in the user space, converting raw variable data into formatted strings.

use crate::string_table::StringTable;
use crate::TypeEncoding;

/// A parsed variable from PrintFormat instruction data
#[derive(Debug, Clone)]
pub struct ParsedVariable {
    pub var_name_index: u16,
    pub type_encoding: TypeEncoding,
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
        string_table: &StringTable,
    ) -> String {
        // Get the format string from the string table
        let format_string = match string_table.get_string(format_string_index) {
            Some(s) => s,
            None => {
                return format!("<INVALID_FORMAT_INDEX_{format_string_index}>");
            }
        };

        // Parse the format string and replace placeholders with variable values
        Self::apply_format(format_string, variables)
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

    /// Format a single variable value as a string based on its type
    fn format_variable_value(variable: &ParsedVariable) -> String {
        match variable.type_encoding {
            TypeEncoding::U8 => {
                if variable.data.is_empty() {
                    "<EMPTY_U8>".to_string()
                } else {
                    variable.data[0].to_string()
                }
            }
            TypeEncoding::U16 => {
                if variable.data.len() < 2 {
                    "<INVALID_U16>".to_string()
                } else {
                    let bytes: [u8; 2] = [variable.data[0], variable.data[1]];
                    u16::from_le_bytes(bytes).to_string()
                }
            }
            TypeEncoding::U32 => {
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
            TypeEncoding::U64 => {
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
            TypeEncoding::I8 => {
                if variable.data.is_empty() {
                    "<EMPTY_I8>".to_string()
                } else {
                    (variable.data[0] as i8).to_string()
                }
            }
            TypeEncoding::I16 => {
                if variable.data.len() < 2 {
                    "<INVALID_I16>".to_string()
                } else {
                    let bytes: [u8; 2] = [variable.data[0], variable.data[1]];
                    i16::from_le_bytes(bytes).to_string()
                }
            }
            TypeEncoding::I32 => {
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
            TypeEncoding::I64 => {
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
            TypeEncoding::F32 => {
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
            TypeEncoding::F64 => {
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
            TypeEncoding::Bool => {
                if variable.data.is_empty() {
                    "<EMPTY_BOOL>".to_string()
                } else {
                    (variable.data[0] != 0).to_string()
                }
            }
            TypeEncoding::Char => {
                if variable.data.is_empty() {
                    "<EMPTY_CHAR>".to_string()
                } else {
                    char::from(variable.data[0]).to_string()
                }
            }
            TypeEncoding::Pointer => {
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
            TypeEncoding::NullPointer => "null".to_string(),
            TypeEncoding::CString | TypeEncoding::String => {
                match String::from_utf8(variable.data.clone()) {
                    Ok(s) => s.trim_end_matches('\0').to_string(), // Remove null terminator
                    Err(_) => "<INVALID_UTF8>".to_string(),
                }
            }
            TypeEncoding::Unknown => format!("<UNKNOWN_TYPE_{}_BYTES>", variable.data.len()),
            TypeEncoding::OptimizedOut => "<OPTIMIZED_OUT>".to_string(),
            TypeEncoding::Error => "<ERROR>".to_string(),
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
                type_encoding: TypeEncoding::I32,
                data: vec![42, 0, 0, 0], // 42 in little-endian
            },
            ParsedVariable {
                var_name_index: 1,
                type_encoding: TypeEncoding::CString,
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
            type_encoding: TypeEncoding::I32,
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
            type_encoding: TypeEncoding::U64,
            data: vec![255, 255, 255, 255, 255, 255, 255, 255], // u64::MAX
        };
        assert_eq!(
            FormatPrinter::format_variable_value(&var_u64),
            "18446744073709551615"
        );

        // Test Pointer
        let var_ptr = ParsedVariable {
            var_name_index: 0,
            type_encoding: TypeEncoding::Pointer,
            data: vec![0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0], // 0xdeadbeef in little-endian
        };
        assert_eq!(FormatPrinter::format_variable_value(&var_ptr), "0xdeadbeef");

        // Test Bool
        let var_bool_true = ParsedVariable {
            var_name_index: 0,
            type_encoding: TypeEncoding::Bool,
            data: vec![1],
        };
        assert_eq!(FormatPrinter::format_variable_value(&var_bool_true), "true");

        let var_bool_false = ParsedVariable {
            var_name_index: 0,
            type_encoding: TypeEncoding::Bool,
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
    fn test_format_print_data_with_string_table() {
        let mut string_table = StringTable::new();
        let format_index = string_table.add_string("Hello {}, you are {} years old!");

        let variables = vec![
            ParsedVariable {
                var_name_index: 0,
                type_encoding: TypeEncoding::CString,
                data: b"Alice\0".to_vec(),
            },
            ParsedVariable {
                var_name_index: 1,
                type_encoding: TypeEncoding::U32,
                data: vec![25, 0, 0, 0], // 25 in little-endian
            },
        ];

        let result = FormatPrinter::format_print_data(format_index, &variables, &string_table);
        assert_eq!(result, "Hello Alice, you are 25 years old!");
    }
}

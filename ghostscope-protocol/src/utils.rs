//! Utility functions for message parsing

use crate::TypeEncoding;

/// Utility functions for variable value formatting - used by streaming_parser
pub(crate) struct MessageParser;

impl MessageParser {
    pub(crate) fn format_variable_value(
        type_encoding: TypeEncoding,
        data: &[u8],
    ) -> Result<String, String> {
        match type_encoding {
            TypeEncoding::U8 => {
                if data.len() != 1 {
                    return Err("Invalid u8 data length".to_string());
                }
                Ok(format!("{}", data[0]))
            }
            TypeEncoding::U16 => {
                if data.len() != 2 {
                    return Err("Invalid u16 data length".to_string());
                }
                let value = u16::from_le_bytes([data[0], data[1]]);
                Ok(format!("{value}"))
            }
            TypeEncoding::U32 => {
                if data.len() != 4 {
                    return Err("Invalid u32 data length".to_string());
                }
                let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                Ok(format!("{value}"))
            }
            TypeEncoding::U64 => {
                if data.len() != 8 {
                    return Err("Invalid u64 data length".to_string());
                }
                let value = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                Ok(format!("{value}"))
            }
            TypeEncoding::I8 => {
                if data.len() != 1 {
                    return Err("Invalid i8 data length".to_string());
                }
                Ok(format!("{}", data[0] as i8))
            }
            TypeEncoding::I16 => {
                if data.len() != 2 {
                    return Err("Invalid i16 data length".to_string());
                }
                let value = i16::from_le_bytes([data[0], data[1]]);
                Ok(format!("{value}"))
            }
            TypeEncoding::I32 => {
                if data.len() != 4 {
                    return Err("Invalid i32 data length".to_string());
                }
                let value = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                Ok(format!("{value}"))
            }
            TypeEncoding::I64 => {
                if data.len() != 8 {
                    return Err("Invalid i64 data length".to_string());
                }
                let value = i64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                Ok(format!("{value}"))
            }
            TypeEncoding::F32 => {
                if data.len() != 4 {
                    return Err("Invalid f32 data length".to_string());
                }
                let value = f32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                Ok(format!("{value}"))
            }
            TypeEncoding::F64 => {
                if data.len() != 8 {
                    return Err("Invalid f64 data length".to_string());
                }
                let value = f64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                Ok(format!("{value}"))
            }
            TypeEncoding::Pointer => {
                if data.len() != 8 {
                    return Err("Invalid pointer data length".to_string());
                }
                let value = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                Ok(format!("0x{value:016x}"))
            }
            TypeEncoding::Bool => {
                if data.len() != 1 {
                    return Err("Invalid bool data length".to_string());
                }
                Ok(format!("{}", data[0] != 0))
            }
            TypeEncoding::OptimizedOut => Ok("<optimized out>".to_string()),
            TypeEncoding::Unknown => Ok(format!("<unknown: {} bytes>", data.len())),
            _ => Ok(format!("<unsupported type: {:02x}>", type_encoding as u8)),
        }
    }
}

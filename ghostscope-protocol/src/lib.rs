use serde::{Deserialize, Serialize};

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct MessageHeader {
    pub magic: u32,
    pub msg_type: u8,
    pub flags: u8,
    pub length: u16,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageType {
    VariableData = 0x01,
    Error = 0x02,
    Heartbeat = 0x03,
    BatchVariables = 0x04,
    Log = 0x05,
    ExecutionFailure = 0x06,
    Reserved = 0xFF,
}

pub mod flags {
    pub const COMPRESSED: u8 = 0x01;
    pub const ENCRYPTED: u8 = 0x02;
    pub const PARTIAL: u8 = 0x04;
    pub const LAST_FRAGMENT: u8 = 0x08;
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TypeEncoding {
    U8 = 0x01,
    U16 = 0x02,
    U32 = 0x03,
    U64 = 0x04,
    I8 = 0x05,
    I16 = 0x06,
    I32 = 0x07,
    I64 = 0x08,
    F32 = 0x09,
    F64 = 0x0A,
    Bool = 0x0B,
    Char = 0x0C,

    Pointer = 0x20,
    NullPointer = 0x21,

    Struct = 0x40,
    Array = 0x41,
    Union = 0x42,
    Enum = 0x43,

    CString = 0x50,
    String = 0x51,

    Unknown = 0x80,
    OptimizedOut = 0x81,
    Error = 0x82,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct VariableDataMessage {
    pub trace_id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub var_count: u16,
    pub reserved: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct VariableEntry {
    pub name_len: u8,
    pub type_encoding: u8,
    pub data_len: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ErrorMessage {
    pub error_code: u32,
    pub trace_id: u64,
    pub message_len: u16,
    pub reserved: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct LogMessage {
    pub trace_id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub log_level: u8,
    pub reserved: [u8; 3],
    pub message_len: u16,
    pub reserved2: u16,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct ExecutionFailureMessage {
    pub trace_id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub function_id: u32,
    pub error_code: i32,
    pub message_len: u16,
    pub reserved: u16,
}

pub mod consts {
    pub const MAGIC: u32 = 0x47534350; // "GSCP"
    pub const VERSION: u8 = 1;
    pub const MAX_MESSAGE_SIZE: u16 = 4096;
    pub const MAX_VARIABLE_NAME_LEN: u8 = 255;
    pub const MAX_VARIABLES_PER_MESSAGE: u16 = 64;

    // Struct sizes
    pub const MESSAGE_HEADER_SIZE: usize = std::mem::size_of::<crate::MessageHeader>();
    pub const LOG_MESSAGE_SIZE: usize = std::mem::size_of::<crate::LogMessage>();
    pub const EXECUTION_FAILURE_MESSAGE_SIZE: usize =
        std::mem::size_of::<crate::ExecutionFailureMessage>();
    pub const VARIABLE_DATA_MESSAGE_SIZE: usize = std::mem::size_of::<crate::VariableDataMessage>();

    // Default values
    pub const DEFAULT_TRACE_ID: u64 = 1;
    pub const MAX_STRING_LENGTH: usize = 256;
}

pub mod log_levels {
    pub const DEBUG: u8 = 0;
    pub const INFO: u8 = 1;
    pub const WARN: u8 = 2;
    pub const ERROR: u8 = 3;
}

pub struct MessageBuilder {
    buffer: Vec<u8>,
}

impl MessageBuilder {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(1024),
        }
    }

    pub fn build_variable_message(
        &mut self,
        trace_id: u64,
        pid: u32,
        tid: u32,
        variables: &[(String, TypeEncoding, Vec<u8>)],
    ) -> Result<Vec<u8>, String> {
        self.buffer.clear();

        if variables.len() > consts::MAX_VARIABLES_PER_MESSAGE as usize {
            return Err("Too many variables".to_string());
        }

        let mut total_len =
            std::mem::size_of::<MessageHeader>() + std::mem::size_of::<VariableDataMessage>();

        for (name, _type_enc, data) in variables {
            if name.len() > consts::MAX_VARIABLE_NAME_LEN as usize {
                return Err(format!("Variable name too long: {}", name));
            }
            total_len += std::mem::size_of::<VariableEntry>() + name.len() + data.len();
        }

        if total_len > consts::MAX_MESSAGE_SIZE as usize {
            return Err("Message too large".to_string());
        }

        let header = MessageHeader {
            magic: consts::MAGIC,
            msg_type: MessageType::VariableData as u8,
            flags: 0,
            length: total_len as u16,
        };
        self.write_header(&header);

        let msg_body = VariableDataMessage {
            trace_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            pid,
            tid,
            var_count: variables.len() as u16,
            reserved: 0,
        };
        self.write_struct(&msg_body);

        for (name, type_encoding, data) in variables {
            let entry = VariableEntry {
                name_len: name.len() as u8,
                type_encoding: *type_encoding as u8,
                data_len: data.len() as u16,
            };
            self.write_struct(&entry);
            self.buffer.extend_from_slice(name.as_bytes());
            self.buffer.extend_from_slice(data);
        }

        Ok(self.buffer.clone())
    }

    pub fn build_error_message(
        &mut self,
        error_code: u32,
        trace_id: u64,
        message: &str,
    ) -> Result<Vec<u8>, String> {
        self.buffer.clear();

        let total_len = std::mem::size_of::<MessageHeader>()
            + std::mem::size_of::<ErrorMessage>()
            + message.len();

        if total_len > consts::MAX_MESSAGE_SIZE as usize {
            return Err("Error message too large".to_string());
        }

        let header = MessageHeader {
            magic: consts::MAGIC,
            msg_type: MessageType::Error as u8,
            flags: 0,
            length: total_len as u16,
        };
        self.write_header(&header);

        let error_msg = ErrorMessage {
            error_code,
            trace_id,
            message_len: message.len() as u16,
            reserved: 0,
        };
        self.write_struct(&error_msg);
        self.buffer.extend_from_slice(message.as_bytes());

        Ok(self.buffer.clone())
    }

    pub fn build_log_message(
        &mut self,
        trace_id: u64,
        pid: u32,
        tid: u32,
        log_level: u8,
        message: &str,
    ) -> Result<Vec<u8>, String> {
        self.buffer.clear();

        let total_len = std::mem::size_of::<MessageHeader>()
            + std::mem::size_of::<LogMessage>()
            + message.len();

        if total_len > consts::MAX_MESSAGE_SIZE as usize {
            return Err("Log message too large".to_string());
        }

        let header = MessageHeader {
            magic: consts::MAGIC,
            msg_type: MessageType::Log as u8,
            flags: 0,
            length: total_len as u16,
        };
        self.write_header(&header);

        let log_msg = LogMessage {
            trace_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            pid,
            tid,
            log_level,
            reserved: [0; 3],
            message_len: message.len() as u16,
            reserved2: 0,
        };
        self.write_struct(&log_msg);
        self.buffer.extend_from_slice(message.as_bytes());

        Ok(self.buffer.clone())
    }

    pub fn build_execution_failure_message(
        &mut self,
        trace_id: u64,
        pid: u32,
        tid: u32,
        function_id: u32,
        error_code: i32,
        message: &str,
    ) -> Result<Vec<u8>, String> {
        self.buffer.clear();

        let total_len = std::mem::size_of::<MessageHeader>()
            + std::mem::size_of::<ExecutionFailureMessage>()
            + message.len();

        if total_len > consts::MAX_MESSAGE_SIZE as usize {
            return Err("Execution failure message too large".to_string());
        }

        let header = MessageHeader {
            magic: consts::MAGIC,
            msg_type: MessageType::ExecutionFailure as u8,
            flags: 0,
            length: total_len as u16,
        };
        self.write_header(&header);

        let failure_msg = ExecutionFailureMessage {
            trace_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            pid,
            tid,
            function_id,
            error_code,
            message_len: message.len() as u16,
            reserved: 0,
        };
        self.write_struct(&failure_msg);
        self.buffer.extend_from_slice(message.as_bytes());

        Ok(self.buffer.clone())
    }

    fn write_header(&mut self, header: &MessageHeader) {
        self.write_struct(header);
    }

    fn write_struct<T>(&mut self, s: &T) {
        let bytes = unsafe {
            std::slice::from_raw_parts(s as *const T as *const u8, std::mem::size_of::<T>())
        };
        self.buffer.extend_from_slice(bytes);
    }
}

pub struct MessageParser;

impl MessageParser {
    pub fn parse_header(data: &[u8]) -> Result<MessageHeader, String> {
        if data.len() < std::mem::size_of::<MessageHeader>() {
            return Err("Data too short for header".to_string());
        }

        let header = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const MessageHeader) };

        let magic = header.magic; // Copy field to avoid packed reference
        if magic != consts::MAGIC {
            return Err(format!("Invalid magic: 0x{:08x}", magic));
        }

        Ok(header)
    }

    pub fn parse_variable_message(
        data: &[u8],
    ) -> Result<(VariableDataMessage, Vec<(String, TypeEncoding, Vec<u8>)>), String> {
        use tracing::debug;
        debug!(
            "Raw data ({} bytes): {:02x?}",
            data.len(),
            &data[..std::cmp::min(data.len(), 64)]
        );
        if data.len()
            < std::mem::size_of::<MessageHeader>() + std::mem::size_of::<VariableDataMessage>()
        {
            return Err("Data too short for variable message".to_string());
        }

        let mut offset = std::mem::size_of::<MessageHeader>();

        let msg_body = unsafe {
            std::ptr::read_unaligned(data[offset..].as_ptr() as *const VariableDataMessage)
        };
        let trace_id = msg_body.trace_id;
        let var_count = msg_body.var_count;
        debug!(
            "Message body - trace_id: {}, var_count: {}, offset after header: {}",
            trace_id, var_count, offset
        );
        offset += std::mem::size_of::<VariableDataMessage>();

        let mut variables = Vec::new();

        for i in 0..var_count {
            if offset + std::mem::size_of::<VariableEntry>() > data.len() {
                return Err("Invalid variable entry".to_string());
            }

            let entry = unsafe {
                std::ptr::read_unaligned(data[offset..].as_ptr() as *const VariableEntry)
            };
            let name_len = entry.name_len;
            let type_encoding = entry.type_encoding;
            let data_len = entry.data_len;
            debug!("Variable {} - name_len: {}, type_encoding: {}, data_len: {}, offset: {}, total_len: {}", 
                   i, name_len, type_encoding, data_len, offset, data.len());
            offset += std::mem::size_of::<VariableEntry>();

            if offset + name_len as usize > data.len() {
                debug!(
                    "name_len check failed - offset: {}, name_len: {}, total_len: {}",
                    offset,
                    name_len,
                    data.len()
                );
                return Err("Invalid variable name".to_string());
            }
            let name = String::from_utf8(data[offset..offset + name_len as usize].to_vec())
                .map_err(|e| format!("Invalid UTF-8 in variable name: {}", e))?;
            offset += name_len as usize;

            if offset + data_len as usize > data.len() {
                return Err("Invalid variable data".to_string());
            }
            let var_data = data[offset..offset + data_len as usize].to_vec();
            offset += data_len as usize;

            let type_encoding_val = match type_encoding {
                0x01 => TypeEncoding::U8,
                0x02 => TypeEncoding::U16,
                0x03 => TypeEncoding::U32,
                0x04 => TypeEncoding::U64,
                0x05 => TypeEncoding::I8,
                0x06 => TypeEncoding::I16,
                0x07 => TypeEncoding::I32,
                0x08 => TypeEncoding::I64,
                0x09 => TypeEncoding::F32,
                0x0A => TypeEncoding::F64,
                _ => TypeEncoding::Unknown,
            };

            variables.push((name, type_encoding_val, var_data));
        }

        Ok((msg_body, variables))
    }

    pub fn parse_log_message(data: &[u8]) -> Result<(LogMessage, String), String> {
        use tracing::debug;
        let header_size = std::mem::size_of::<MessageHeader>();
        let log_msg_size = std::mem::size_of::<LogMessage>();
        let min_expected = header_size + log_msg_size;

        debug!(
            "parse_log_message: data.len()={}, header_size={}, log_msg_size={}, min_expected={}",
            data.len(),
            header_size,
            log_msg_size,
            min_expected
        );

        if data.len() < min_expected {
            return Err(format!(
                "Data too short for log message: got {}, need {}",
                data.len(),
                min_expected
            ));
        }

        let mut offset = header_size;

        let log_msg =
            unsafe { std::ptr::read_unaligned(data[offset..].as_ptr() as *const LogMessage) };
        offset += log_msg_size;

        let message_len = log_msg.message_len as usize;
        debug!(
            "parse_log_message: offset={}, message_len={}, total_available={}",
            offset,
            message_len,
            data.len()
        );
        debug!(
            "LogMessage bytes at offset {}: {:02x?}",
            header_size,
            &data[header_size..header_size + 32]
        );

        if offset + message_len > data.len() {
            return Err(format!(
                "Invalid log message length: offset {} + message_len {} = {} > data.len() {}",
                offset,
                message_len,
                offset + message_len,
                data.len()
            ));
        }

        let message = String::from_utf8(data[offset..offset + message_len].to_vec())
            .map_err(|e| format!("Invalid UTF-8 in log message: {}", e))?;

        Ok((log_msg, message))
    }

    pub fn parse_execution_failure_message(
        data: &[u8],
    ) -> Result<(ExecutionFailureMessage, String), String> {
        use tracing::debug;
        let header_size = std::mem::size_of::<MessageHeader>();
        let failure_msg_size = std::mem::size_of::<ExecutionFailureMessage>();
        let min_expected = header_size + failure_msg_size;

        debug!("parse_execution_failure_message: data.len()={}, header_size={}, failure_msg_size={}, min_expected={}", 
               data.len(), header_size, failure_msg_size, min_expected);

        if data.len() < min_expected {
            return Err(format!(
                "Data too short for execution failure message: got {}, need {}",
                data.len(),
                min_expected
            ));
        }

        let mut offset = header_size;

        let failure_msg = unsafe {
            std::ptr::read_unaligned(data[offset..].as_ptr() as *const ExecutionFailureMessage)
        };
        offset += failure_msg_size;

        let message_len = failure_msg.message_len as usize;
        debug!(
            "parse_execution_failure_message: offset={}, message_len={}, total_available={}",
            offset,
            message_len,
            data.len()
        );
        debug!(
            "ExecutionFailureMessage bytes at offset {}: {:02x?}",
            header_size,
            &data[header_size..header_size + 36]
        );

        if offset + message_len > data.len() {
            return Err(format!("Invalid execution failure message length: offset {} + message_len {} = {} > data.len() {}", 
                      offset, message_len, offset + message_len, data.len()));
        }

        let message = String::from_utf8(data[offset..offset + message_len].to_vec())
            .map_err(|e| format!("Invalid UTF-8 in execution failure message: {}", e))?;

        Ok((failure_msg, message))
    }

    pub fn format_variable_value(
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
                Ok(format!("{}", value))
            }
            TypeEncoding::U32 => {
                if data.len() != 4 {
                    return Err("Invalid u32 data length".to_string());
                }
                let value = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                Ok(format!("{}", value))
            }
            TypeEncoding::U64 => {
                if data.len() != 8 {
                    return Err("Invalid u64 data length".to_string());
                }
                let value = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                Ok(format!("{}", value))
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
                Ok(format!("{}", value))
            }
            TypeEncoding::I32 => {
                if data.len() != 4 {
                    return Err("Invalid i32 data length".to_string());
                }
                let value = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                Ok(format!("{}", value))
            }
            TypeEncoding::I64 => {
                if data.len() != 8 {
                    return Err("Invalid i64 data length".to_string());
                }
                let value = i64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                Ok(format!("{}", value))
            }
            TypeEncoding::F32 => {
                if data.len() != 4 {
                    return Err("Invalid f32 data length".to_string());
                }
                let value = f32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                Ok(format!("{}", value))
            }
            TypeEncoding::F64 => {
                if data.len() != 8 {
                    return Err("Invalid f64 data length".to_string());
                }
                let value = f64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                Ok(format!("{}", value))
            }
            TypeEncoding::Pointer => {
                if data.len() != 8 {
                    return Err("Invalid pointer data length".to_string());
                }
                let value = u64::from_le_bytes([
                    data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                ]);
                Ok(format!("0x{:016x}", value))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_builder_and_parser() {
        let mut builder = MessageBuilder::new();

        let variables = vec![
            (
                "result".to_string(),
                TypeEncoding::I32,
                vec![0x2A, 0x00, 0x00, 0x00],
            ),
            (
                "counter".to_string(),
                TypeEncoding::U64,
                vec![0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            ),
        ];

        let message = builder
            .build_variable_message(
                123,  // trace_id
                1000, // pid
                2000, // tid
                &variables,
            )
            .unwrap();

        let header = MessageParser::parse_header(&message).unwrap();
        assert_eq!(header.magic, consts::MAGIC);
        assert_eq!(header.msg_type, MessageType::VariableData as u8);

        let (msg_body, parsed_vars) = MessageParser::parse_variable_message(&message).unwrap();
        assert_eq!(msg_body.trace_id, 123);
        assert_eq!(msg_body.pid, 1000);
        assert_eq!(msg_body.tid, 2000);
        assert_eq!(parsed_vars.len(), 2);

        assert_eq!(parsed_vars[0].0, "result");
        assert_eq!(parsed_vars[0].1, TypeEncoding::I32);

        let formatted_value =
            MessageParser::format_variable_value(TypeEncoding::I32, &parsed_vars[0].2).unwrap();
        assert_eq!(formatted_value, "42");
    }
}

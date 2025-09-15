use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

pub mod dwarf_types;
pub use dwarf_types::*;

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
    pub error_code: i64,
    pub message_len: u16,
    pub reserved: u16,
}

pub mod consts {
    pub const MAGIC: u32 = 0x43484C53; // "CHLS" (Chelsea)
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

    // MessageHeader field offsets
    pub const MESSAGE_HEADER_MAGIC_OFFSET: usize =
        core::mem::offset_of!(crate::MessageHeader, magic);
    pub const MESSAGE_HEADER_MSG_TYPE_OFFSET: usize =
        core::mem::offset_of!(crate::MessageHeader, msg_type);
    pub const MESSAGE_HEADER_FLAGS_OFFSET: usize =
        core::mem::offset_of!(crate::MessageHeader, flags);
    pub const MESSAGE_HEADER_LENGTH_OFFSET: usize =
        core::mem::offset_of!(crate::MessageHeader, length);

    // VariableDataMessage field offsets (relative to start of VariableDataMessage)
    pub const VARIABLE_DATA_TRACE_ID_OFFSET: usize =
        core::mem::offset_of!(crate::VariableDataMessage, trace_id);
    pub const VARIABLE_DATA_TIMESTAMP_OFFSET: usize =
        core::mem::offset_of!(crate::VariableDataMessage, timestamp);
    pub const VARIABLE_DATA_PID_OFFSET: usize =
        core::mem::offset_of!(crate::VariableDataMessage, pid);
    pub const VARIABLE_DATA_TID_OFFSET: usize =
        core::mem::offset_of!(crate::VariableDataMessage, tid);
    pub const VARIABLE_DATA_VAR_COUNT_OFFSET: usize =
        core::mem::offset_of!(crate::VariableDataMessage, var_count);
    pub const VARIABLE_DATA_RESERVED_OFFSET: usize =
        core::mem::offset_of!(crate::VariableDataMessage, reserved);

    // Default values
    pub const DEFAULT_TRACE_ID: u64 = 1;
    pub const MAX_STRING_LENGTH: usize = 256;

    // Type sizes (bytes) for 64-bit architecture
    pub const CHAR_SIZE: u64 = 1;
    pub const SHORT_SIZE: u64 = 2;
    pub const INT_SIZE: u64 = 4;
    pub const LONG_SIZE: u64 = 8; // 64-bit architecture
    pub const LONG_LONG_SIZE: u64 = 8;
    pub const FLOAT_SIZE: u64 = 4;
    pub const DOUBLE_SIZE: u64 = 8;
    pub const LONG_DOUBLE_SIZE: u64 = 16; // x86-64 extended precision
    pub const BOOL_SIZE: u64 = 1;
    pub const POINTER_SIZE: u64 = 8; // 64-bit pointers
    pub const SIZE_T_SIZE: u64 = 8; // 64-bit architecture
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
        error_code: i64,
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

/// High-level event parser that converts raw protocol data into structured events
pub struct EventParser;

impl EventParser {
    /// Parse event data using GhostScope Protocol format
    pub fn parse_event(data: &[u8]) -> Option<EventData> {
        debug!("Processing protocol message: {} bytes", data.len());

        // Check minimum message size
        if data.len() < 8 {
            debug!("Message too short for header: {} bytes", data.len());
            return None;
        }

        // Parse message header
        let header = match MessageParser::parse_header(data) {
            Ok(header) => header,
            Err(e) => {
                debug!("Failed to parse header: {}", e);
                return None;
            }
        };

        // Verify magic number
        if header.magic != consts::MAGIC {
            let magic = header.magic; // Copy field to avoid packed reference
            debug!(
                "Invalid magic number: 0x{:08x}, expected 0x{:08x}",
                magic,
                consts::MAGIC
            );
            return None;
        }

        // Handle different message types
        match header.msg_type {
            t if t == MessageType::VariableData as u8 => Self::parse_variable_data_message(data),
            t if t == MessageType::Error as u8 => {
                warn!("Received error message from eBPF");
                None
            }
            t if t == MessageType::Heartbeat as u8 => {
                debug!("Received heartbeat message");
                None
            }
            t if t == MessageType::Log as u8 => Self::handle_log_message(data),
            t if t == MessageType::ExecutionFailure as u8 => {
                Self::handle_execution_failure_message(data)
            }
            _ => {
                debug!("Unknown message type: {}", header.msg_type);
                None
            }
        }
    }

    /// Parse variable data message
    fn parse_variable_data_message(data: &[u8]) -> Option<EventData> {
        match MessageParser::parse_variable_message(data) {
            Ok((msg_body, variables)) => {
                let trace_id = msg_body.trace_id; // Copy field to avoid packed reference
                info!(
                    "Parsed variable message: {} variables from trace_id {}",
                    variables.len(),
                    trace_id
                );

                let mut variable_infos = Vec::new();
                for (name, type_encoding, raw_data) in variables {
                    let formatted_value =
                        MessageParser::format_variable_value(type_encoding, &raw_data)
                            .unwrap_or_else(|e| format!("<format error: {}>", e));

                    info!(
                        "Variable: {} ({:?}) = {}",
                        name, type_encoding, formatted_value
                    );

                    variable_infos.push(VariableInfo {
                        name,
                        type_encoding,
                        raw_data,
                        formatted_value,
                    });
                }

                Some(EventData {
                    message_number: 0, // Will be assigned by UI
                    trace_id: msg_body.trace_id,
                    timestamp: msg_body.timestamp,
                    pid: msg_body.pid,
                    tid: msg_body.tid,
                    variables: variable_infos,
                    readable_timestamp: Self::format_timestamp_ns(msg_body.timestamp),
                    message_type: EventMessageType::VariableData,
                    log_level: None,
                    error_code: None,
                    log_message: None,
                    failure_message: None,
                })
            }
            Err(e) => {
                error!("Failed to parse variable data message: {}", e);
                None
            }
        }
    }

    /// Handle log message from eBPF
    fn handle_log_message(data: &[u8]) -> Option<EventData> {
        match MessageParser::parse_log_message(data) {
            Ok((log_msg, message)) => {
                // Copy fields from packed struct to avoid packed reference issues
                let trace_id = log_msg.trace_id;
                let timestamp = log_msg.timestamp;
                let pid = log_msg.pid;
                let tid = log_msg.tid;
                let log_level = log_msg.log_level;

                let level_str = match log_level {
                    0 => "DEBUG",
                    1 => "INFO",
                    2 => "WARN",
                    3 => "ERROR",
                    _ => "UNKNOWN",
                };

                // Convert nanosecond timestamp to readable format
                let readable_ts = Self::format_timestamp_ns(timestamp);

                info!(
                    "[eBPF-{}] trace_id:{} pid:{} tid:{} {} - {}",
                    level_str, trace_id, pid, tid, readable_ts, message
                );

                Some(EventData {
                    message_number: 0, // Will be assigned by UI
                    trace_id,
                    timestamp,
                    pid,
                    tid,
                    variables: Vec::new(), // Log messages don't have variables
                    readable_timestamp: readable_ts,
                    message_type: EventMessageType::Log,
                    log_level: Some(log_level),
                    error_code: None,
                    log_message: Some(message.clone()),
                    failure_message: None,
                })
            }
            Err(e) => {
                warn!("Failed to parse log message: {}", e);
                None
            }
        }
    }

    /// Handle execution failure message from eBPF
    fn handle_execution_failure_message(data: &[u8]) -> Option<EventData> {
        match MessageParser::parse_execution_failure_message(data) {
            Ok((failure_msg, message)) => {
                // Copy fields from packed struct to avoid packed reference issues
                let trace_id = failure_msg.trace_id;
                let timestamp = failure_msg.timestamp;
                let pid = failure_msg.pid;
                let tid = failure_msg.tid;
                let error_code = failure_msg.error_code;

                // Convert nanosecond timestamp to readable format
                let readable_ts = Self::format_timestamp_ns(timestamp);

                error!(
                    "[eBPF-ExecutionFailure] trace_id:{} pid:{} tid:{} error_code:{} {} - {}",
                    trace_id, pid, tid, error_code, readable_ts, message
                );

                Some(EventData {
                    message_number: 0, // Will be assigned by UI
                    trace_id,
                    timestamp,
                    pid,
                    tid,
                    variables: Vec::new(), // Execution failure messages don't have variables
                    readable_timestamp: readable_ts,
                    message_type: EventMessageType::ExecutionFailure,
                    log_level: None,
                    error_code: Some(error_code),
                    log_message: None,
                    failure_message: Some(message.clone()),
                })
            }
            Err(e) => {
                warn!("Failed to parse execution failure message: {}", e);
                None
            }
        }
    }

    /// Format eBPF timestamp (nanoseconds since boot) to human-readable format
    /// eBPF uses bpf_ktime_get_ns() which returns nanoseconds since system boot
    pub fn format_timestamp_ns(ns_timestamp: u64) -> String {
        // Get current system time and boot time
        let now = SystemTime::now();
        let uptime = Self::get_system_uptime_ns();

        if let (Ok(now_since_epoch), Some(boot_ns)) = (now.duration_since(UNIX_EPOCH), uptime) {
            // Calculate when the system booted
            let boot_time_ns = now_since_epoch.as_nanos() as u64 - boot_ns;

            // Add eBPF timestamp to boot time to get actual time
            let actual_time_ns = boot_time_ns + ns_timestamp;
            let actual_time_secs = actual_time_ns / 1_000_000_000;
            let actual_time_nanos = actual_time_ns % 1_000_000_000;

            // Convert to chrono DateTime with local timezone
            if let Some(utc_datetime) =
                chrono::DateTime::from_timestamp(actual_time_secs as i64, actual_time_nanos as u32)
            {
                let local_datetime: chrono::DateTime<chrono::Local> = utc_datetime.into();
                return format!(
                    "{}.{:03}",
                    local_datetime.format("%Y-%m-%d %H:%M:%S"),
                    actual_time_nanos / 1_000_000
                );
            }
        }

        // Fallback to boot time offset if conversion fails
        let ms = ns_timestamp / 1_000_000;
        let seconds = ms / 1000;
        let ms_remainder = ms % 1000;
        format!("boot+{}.{:03}s", seconds, ms_remainder)
    }

    /// Get system uptime in nanoseconds
    fn get_system_uptime_ns() -> Option<u64> {
        std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|content| {
                let uptime_secs: f64 = content.split_whitespace().next()?.parse().ok()?;
                Some((uptime_secs * 1_000_000_000.0) as u64)
            })
    }
}

/// Structured event data from eBPF program using GhostScope Protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventData {
    pub message_number: u64, // Unique message number assigned by UI
    pub trace_id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub variables: Vec<VariableInfo>,
    pub readable_timestamp: String,      // Human-readable timestamp
    pub message_type: EventMessageType,  // Type of the event message
    pub log_level: Option<u8>,           // For log messages
    pub error_code: Option<i64>,         // For execution failure messages
    pub log_message: Option<String>,     // For log messages
    pub failure_message: Option<String>, // For execution failure messages
}

/// Type of event message from eBPF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventMessageType {
    VariableData,     // Variable data message
    Log,              // Log message
    ExecutionFailure, // Execution failure message
    Unknown,          // Unknown message type
}

/// Variable information extracted from protocol message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableInfo {
    pub name: String,
    pub type_encoding: TypeEncoding,
    pub raw_data: Vec<u8>,
    pub formatted_value: String,
}

impl std::fmt::Display for EventData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let readable_ts = EventParser::format_timestamp_ns(self.timestamp);
        writeln!(
            f,
            "Event [no: {}, trace_id: {}, pid: {}, tid: {}, timestamp: {}]:",
            self.message_number, self.trace_id, self.pid, self.tid, readable_ts
        )?;
        for var in &self.variables {
            writeln!(
                f,
                "  {} ({}): {}",
                var.name,
                format!("{:?}", var.type_encoding),
                var.formatted_value
            )?;
        }
        Ok(())
    }
}

impl std::fmt::Display for VariableInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} = {}", self.name, self.formatted_value)
    }
}

/// Platform-specific register mappings and utilities for eBPF code generation
///
/// This module handles the mapping between DWARF register numbers and platform-specific
/// register layouts (like pt_regs) for different architectures.
pub mod platform {
    use tracing::warn;

    /// pt_regs indices for x86_64 architecture
    ///
    /// These indices are used to access pt_regs structure fields as a u64 array.
    /// The indices are calculated by dividing the field offset by the size of u64,
    /// which gives us the array index for accessing pt_regs as a u64 array.
    pub mod pt_regs_indices {
        use aya_ebpf_bindings::bindings::pt_regs;

        // Size of u64 in bytes for array index calculation
        const U64_SIZE: usize = core::mem::size_of::<u64>();

        // Core registers - calculated from pt_regs structure layout
        pub const R15: usize = core::mem::offset_of!(pt_regs, r15) / U64_SIZE;
        pub const R14: usize = core::mem::offset_of!(pt_regs, r14) / U64_SIZE;
        pub const R13: usize = core::mem::offset_of!(pt_regs, r13) / U64_SIZE;
        pub const R12: usize = core::mem::offset_of!(pt_regs, r12) / U64_SIZE;
        pub const RBP: usize = core::mem::offset_of!(pt_regs, rbp) / U64_SIZE; // Frame pointer
        pub const RBX: usize = core::mem::offset_of!(pt_regs, rbx) / U64_SIZE;
        pub const R11: usize = core::mem::offset_of!(pt_regs, r11) / U64_SIZE;
        pub const R10: usize = core::mem::offset_of!(pt_regs, r10) / U64_SIZE;
        pub const R9: usize = core::mem::offset_of!(pt_regs, r9) / U64_SIZE;
        pub const R8: usize = core::mem::offset_of!(pt_regs, r8) / U64_SIZE;
        pub const RAX: usize = core::mem::offset_of!(pt_regs, rax) / U64_SIZE; // Return value
        pub const RCX: usize = core::mem::offset_of!(pt_regs, rcx) / U64_SIZE; // 4th argument
        pub const RDX: usize = core::mem::offset_of!(pt_regs, rdx) / U64_SIZE; // 3rd argument
        pub const RSI: usize = core::mem::offset_of!(pt_regs, rsi) / U64_SIZE; // 2nd argument
        pub const RDI: usize = core::mem::offset_of!(pt_regs, rdi) / U64_SIZE; // 1st argument

        // Special registers
        pub const ORIG_RAX: usize = core::mem::offset_of!(pt_regs, orig_rax) / U64_SIZE; // Original syscall number
        pub const RIP: usize = core::mem::offset_of!(pt_regs, rip) / U64_SIZE; // Instruction pointer
        pub const CS: usize = core::mem::offset_of!(pt_regs, cs) / U64_SIZE; // Code segment
        pub const EFLAGS: usize = core::mem::offset_of!(pt_regs, eflags) / U64_SIZE; // Flags register
        pub const RSP: usize = core::mem::offset_of!(pt_regs, rsp) / U64_SIZE; // Stack pointer
        pub const SS: usize = core::mem::offset_of!(pt_regs, ss) / U64_SIZE; // Stack segment
    }

    /// Convert DWARF register number to pt_regs byte offset for x86_64
    ///
    /// This function maps DWARF register numbers to the correct byte offset
    /// within the pt_regs structure for x86_64 architecture.
    ///
    /// Reference: https://github.com/torvalds/linux/blob/master/arch/x86/include/asm/ptrace.h
    /// pt_regs structure layout on x86_64:
    /// ```c
    /// struct pt_regs {
    ///     unsigned long r15;    // offset 0
    ///     unsigned long r14;    // offset 8  
    ///     unsigned long r13;    // offset 16
    ///     unsigned long r12;    // offset 24
    ///     unsigned long bp;     // offset 32  (RBP)
    ///     unsigned long bx;     // offset 40  (RBX)
    ///     unsigned long r11;    // offset 48
    ///     unsigned long r10;    // offset 56
    ///     unsigned long r9;     // offset 64
    ///     unsigned long r8;     // offset 72
    ///     unsigned long ax;     // offset 80  (RAX)
    ///     unsigned long cx;     // offset 88  (RCX)  
    ///     unsigned long dx;     // offset 96  (RDX)
    ///     unsigned long si;     // offset 104 (RSI)
    ///     unsigned long di;     // offset 112 (RDI)
    ///     unsigned long orig_ax;// offset 120
    ///     unsigned long ip;     // offset 128 (RIP)
    ///     unsigned long cs;     // offset 136
    ///     unsigned long flags;  // offset 144
    ///     unsigned long sp;     // offset 152 (RSP)
    ///     unsigned long ss;     // offset 160
    /// };
    /// ```
    pub fn dwarf_reg_to_pt_regs_byte_offset_x86_64(dwarf_reg: u16) -> Option<usize> {
        const U64_SIZE: usize = core::mem::size_of::<u64>();
        match dwarf_reg {
            // x86_64 DWARF register mappings to pt_regs indices (converted to byte offsets)
            0 => Some(pt_regs_indices::RAX * U64_SIZE), // DWARF 0 = RAX
            1 => Some(pt_regs_indices::RDX * U64_SIZE), // DWARF 1 = RDX
            2 => Some(pt_regs_indices::RCX * U64_SIZE), // DWARF 2 = RCX
            3 => Some(pt_regs_indices::RBX * U64_SIZE), // DWARF 3 = RBX
            4 => Some(pt_regs_indices::RSI * U64_SIZE), // DWARF 4 = RSI
            5 => Some(pt_regs_indices::RDI * U64_SIZE), // DWARF 5 = RDI
            6 => Some(pt_regs_indices::RBP * U64_SIZE), // DWARF 6 = RBP
            7 => Some(pt_regs_indices::RSP * U64_SIZE), // DWARF 7 = RSP
            8 => Some(pt_regs_indices::R8 * U64_SIZE),  // DWARF 8 = R8
            9 => Some(pt_regs_indices::R9 * U64_SIZE),  // DWARF 9 = R9
            10 => Some(pt_regs_indices::R10 * U64_SIZE), // DWARF 10 = R10
            11 => Some(pt_regs_indices::R11 * U64_SIZE), // DWARF 11 = R11
            12 => Some(pt_regs_indices::R12 * U64_SIZE), // DWARF 12 = R12
            13 => Some(pt_regs_indices::R13 * U64_SIZE), // DWARF 13 = R13
            14 => Some(pt_regs_indices::R14 * U64_SIZE), // DWARF 14 = R14
            15 => Some(pt_regs_indices::R15 * U64_SIZE), // DWARF 15 = R15
            16 => Some(pt_regs_indices::RIP * U64_SIZE), // DWARF 16 = RIP
            _ => {
                warn!("Unknown DWARF register {} for x86_64", dwarf_reg);
                None
            }
        }
    }

    /// Convert DWARF register number to register name for x86_64
    ///
    /// Maps DWARF register numbers to human-readable register names
    /// for debugging and display purposes.
    pub fn dwarf_reg_to_name_x86_64(dwarf_reg: u16) -> Option<&'static str> {
        match dwarf_reg {
            0 => Some("RAX"),  // DWARF 0 = RAX
            1 => Some("RDX"),  // DWARF 1 = RDX
            2 => Some("RCX"),  // DWARF 2 = RCX
            3 => Some("RBX"),  // DWARF 3 = RBX
            4 => Some("RSI"),  // DWARF 4 = RSI
            5 => Some("RDI"),  // DWARF 5 = RDI
            6 => Some("RBP"),  // DWARF 6 = RBP
            7 => Some("RSP"),  // DWARF 7 = RSP
            8 => Some("R8"),   // DWARF 8 = R8
            9 => Some("R9"),   // DWARF 9 = R9
            10 => Some("R10"), // DWARF 10 = R10
            11 => Some("R11"), // DWARF 11 = R11
            12 => Some("R12"), // DWARF 12 = R12
            13 => Some("R13"), // DWARF 13 = R13
            14 => Some("R14"), // DWARF 14 = R14
            15 => Some("R15"), // DWARF 15 = R15
            16 => Some("RIP"), // DWARF 16 = RIP
            _ => None,
        }
    }

    /// Convert DWARF register number to register name
    ///
    /// Currently only supports x86_64. This function can be extended
    /// to support other architectures in the future.
    pub fn dwarf_reg_to_name(dwarf_reg: u16) -> Option<&'static str> {
        // For now, we only support x86_64
        // TODO: Add support for other architectures (ARM64, RISC-V, etc.)
        dwarf_reg_to_name_x86_64(dwarf_reg)
    }

    /// Convert DWARF register number to pt_regs byte offset
    ///
    /// Currently only supports x86_64. This function can be extended
    /// to support other architectures in the future.
    pub fn dwarf_reg_to_pt_regs_byte_offset(dwarf_reg: u16) -> Option<usize> {
        // For now, we only support x86_64
        // TODO: Add support for other architectures (ARM64, RISC-V, etc.)
        dwarf_reg_to_pt_regs_byte_offset_x86_64(dwarf_reg)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_x86_64_dwarf_to_pt_regs_mapping() {
            // Test key registers
            assert_eq!(dwarf_reg_to_pt_regs_byte_offset_x86_64(0), Some(80)); // RAX
            assert_eq!(dwarf_reg_to_pt_regs_byte_offset_x86_64(6), Some(32)); // RBP
            assert_eq!(dwarf_reg_to_pt_regs_byte_offset_x86_64(7), Some(152)); // RSP
            assert_eq!(dwarf_reg_to_pt_regs_byte_offset_x86_64(16), Some(128)); // RIP

            // Test invalid register
            assert_eq!(dwarf_reg_to_pt_regs_byte_offset_x86_64(99), None);
        }

        #[test]
        fn test_x86_64_dwarf_to_name_mapping() {
            // Test core registers
            assert_eq!(dwarf_reg_to_name_x86_64(0), Some("RAX"));
            assert_eq!(dwarf_reg_to_name_x86_64(1), Some("RDX"));
            assert_eq!(dwarf_reg_to_name_x86_64(4), Some("RSI"));
            assert_eq!(dwarf_reg_to_name_x86_64(5), Some("RDI"));
            assert_eq!(dwarf_reg_to_name_x86_64(6), Some("RBP"));
            assert_eq!(dwarf_reg_to_name_x86_64(7), Some("RSP"));

            // Test extended registers
            assert_eq!(dwarf_reg_to_name_x86_64(8), Some("R8"));
            assert_eq!(dwarf_reg_to_name_x86_64(13), Some("R13"));
            assert_eq!(dwarf_reg_to_name_x86_64(15), Some("R15"));

            // Test special registers
            assert_eq!(dwarf_reg_to_name_x86_64(16), Some("RIP"));

            // Test invalid register
            assert_eq!(dwarf_reg_to_name_x86_64(99), None);
        }

        #[test]
        fn test_dwarf_reg_to_name_generic() {
            // Test the generic function (currently just calls x86_64)
            assert_eq!(dwarf_reg_to_name(0), Some("RAX"));
            assert_eq!(dwarf_reg_to_name(5), Some("RDI"));
            assert_eq!(dwarf_reg_to_name(13), Some("R13"));
            assert_eq!(dwarf_reg_to_name(99), None);
        }

        #[test]
        fn test_dwarf_reg_to_pt_regs_byte_offset_generic() {
            // Test the generic function (currently just calls x86_64)
            assert_eq!(dwarf_reg_to_pt_regs_byte_offset(0), Some(80)); // RAX
            assert_eq!(dwarf_reg_to_pt_regs_byte_offset(5), Some(112)); // RDI
            assert_eq!(dwarf_reg_to_pt_regs_byte_offset(99), None);
        }
    }
}

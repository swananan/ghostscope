use crate::string_table::StringTable;
use crate::trace_event::*;
use crate::TypeEncoding;
use tracing::{debug, warn};

/// Parsed instruction from trace event
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ParsedInstruction {
    PrintString {
        content: String,
    },
    PrintVariable {
        name: String,
        type_encoding: TypeEncoding,
        formatted_value: String,
        raw_data: Vec<u8>,
    },
    PrintVariableError {
        name: String,
        error_code: u8,
        error_message: String,
    },
    Backtrace {
        depth: u8,
    },
    EndInstruction {
        total_instructions: u16,
        execution_status: u8,
    },
}

/// Parsed trace event containing header, message, and instructions
#[derive(Debug, Clone)]
pub struct ParsedTraceEvent {
    pub trace_id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub instructions: Vec<ParsedInstruction>,
}

/// State of ongoing trace event parsing
#[derive(Debug, Clone)]
pub enum ParseState {
    WaitingForHeader,
    WaitingForMessage {
        header: TraceEventHeader,
    },
    WaitingForInstructions {
        header: TraceEventHeader,
        message: TraceEventMessage,
        instructions: Vec<ParsedInstruction>,
    },
    Complete,
}

/// Streaming parser for trace events received in segments
/// StringTable is externally managed by the loader
pub struct StreamingTraceParser {
    parse_state: ParseState,
    buffer: Vec<u8>,
}

impl Default for StreamingTraceParser {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingTraceParser {
    /// Create a new streaming parser
    /// Note: StringTable is provided by loader during parsing
    pub fn new() -> Self {
        Self {
            parse_state: ParseState::WaitingForHeader,
            buffer: Vec::with_capacity(1024),
        }
    }

    /// Process incoming data segment and return complete trace events
    /// StringTable is provided by the loader (uprobe config after compilation)
    pub fn process_segment(
        &mut self,
        data: &[u8],
        string_table: &StringTable,
    ) -> Result<Option<ParsedTraceEvent>, String> {
        debug!(
            "Processing segment of {} bytes, current state: {:?}",
            data.len(),
            self.parse_state
        );

        match &self.parse_state {
            ParseState::WaitingForHeader => {
                if data.len() < std::mem::size_of::<TraceEventHeader>() {
                    return Err("Invalid header segment size".to_string());
                }

                let header =
                    unsafe { std::ptr::read_unaligned(data.as_ptr() as *const TraceEventHeader) };

                if header.magic != crate::consts::MAGIC {
                    return Err("Invalid magic number in header".to_string());
                }

                // No msg_type check needed - TraceEventHeader is specifically for TraceEvent

                let magic = header.magic;
                debug!("Received valid header: magic=0x{:x}", magic);
                self.parse_state = ParseState::WaitingForMessage { header };
                Ok(None)
            }

            ParseState::WaitingForMessage { header } => {
                if data.len() < std::mem::size_of::<TraceEventMessage>() {
                    return Err("Invalid message segment size".to_string());
                }

                let message =
                    unsafe { std::ptr::read_unaligned(data.as_ptr() as *const TraceEventMessage) };

                let trace_id = message.trace_id;
                let pid = message.pid;
                let tid = message.tid;
                debug!(
                    "Received message: trace_id={}, pid={}, tid={}",
                    trace_id, pid, tid
                );

                self.parse_state = ParseState::WaitingForInstructions {
                    header: *header,
                    message,
                    instructions: Vec::new(),
                };
                Ok(None)
            }

            ParseState::WaitingForInstructions {
                header,
                message,
                instructions,
            } => {
                // Parse instruction from segment
                let parsed_instruction = self.parse_instruction_segment(data, string_table)?;

                let mut new_instructions = instructions.clone();

                // Check if this is EndInstruction
                if matches!(parsed_instruction, ParsedInstruction::EndInstruction { .. }) {
                    new_instructions.push(parsed_instruction);

                    // Complete trace event
                    let complete_event = ParsedTraceEvent {
                        trace_id: message.trace_id,
                        timestamp: message.timestamp,
                        pid: message.pid,
                        tid: message.tid,
                        instructions: new_instructions,
                    };

                    debug!(
                        "Completed trace event with {} instructions",
                        complete_event.instructions.len()
                    );

                    // Reset state for next event
                    self.parse_state = ParseState::WaitingForHeader;
                    return Ok(Some(complete_event));
                } else {
                    // Add instruction and continue waiting
                    new_instructions.push(parsed_instruction);

                    self.parse_state = ParseState::WaitingForInstructions {
                        header: *header,
                        message: *message,
                        instructions: new_instructions,
                    };
                }

                Ok(None)
            }

            ParseState::Complete => {
                warn!("Received data while in Complete state, resetting");
                self.parse_state = ParseState::WaitingForHeader;
                self.process_segment(data, string_table)
            }
        }
    }

    /// Parse a single instruction from segment data
    fn parse_instruction_segment(
        &self,
        data: &[u8],
        string_table: &StringTable,
    ) -> Result<ParsedInstruction, String> {
        if data.len() < std::mem::size_of::<InstructionHeader>() {
            return Err("Instruction segment too small for header".to_string());
        }

        let inst_header =
            unsafe { std::ptr::read_unaligned(data.as_ptr() as *const InstructionHeader) };

        let expected_total_size =
            std::mem::size_of::<InstructionHeader>() + inst_header.data_length as usize;
        if data.len() < expected_total_size {
            return Err(format!(
                "Instruction segment size {} < expected {}",
                data.len(),
                expected_total_size
            ));
        }

        let inst_data = &data[std::mem::size_of::<InstructionHeader>()..expected_total_size];

        match inst_header.inst_type {
            t if t == InstructionType::PrintStringIndex as u8 => {
                if inst_data.len() < std::mem::size_of::<PrintStringIndexData>() {
                    return Err("Invalid PrintStringIndex data".to_string());
                }

                let data_struct = unsafe {
                    std::ptr::read_unaligned(inst_data.as_ptr() as *const PrintStringIndexData)
                };

                let string_index = data_struct.string_index;
                let string_content = string_table
                    .get_string(string_index)
                    .ok_or_else(|| format!("Invalid string index: {string_index}"))?;

                Ok(ParsedInstruction::PrintString {
                    content: string_content.to_string(),
                })
            }

            t if t == InstructionType::PrintVariableIndex as u8 => {
                if inst_data.len() < std::mem::size_of::<PrintVariableIndexData>() {
                    return Err("Invalid PrintVariableIndex data".to_string());
                }

                let data_struct = unsafe {
                    std::ptr::read_unaligned(inst_data.as_ptr() as *const PrintVariableIndexData)
                };

                let var_name_index = data_struct.var_name_index;
                let var_name = string_table
                    .get_variable_name(var_name_index)
                    .ok_or_else(|| format!("Invalid variable index: {var_name_index}"))?;

                let var_data_offset = std::mem::size_of::<PrintVariableIndexData>();
                if inst_data.len() < var_data_offset + data_struct.data_len as usize {
                    return Err("Invalid variable data length".to_string());
                }

                let var_data =
                    &inst_data[var_data_offset..var_data_offset + data_struct.data_len as usize];

                let type_encoding = match data_struct.type_encoding {
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
                    0x0B => TypeEncoding::Bool,
                    0x0C => TypeEncoding::Char,
                    0x20 => TypeEncoding::Pointer,
                    0x50 => TypeEncoding::CString,
                    0x51 => TypeEncoding::String,
                    _ => TypeEncoding::Unknown,
                };

                let formatted_value =
                    crate::utils::MessageParser::format_variable_value(type_encoding, var_data)
                        .unwrap_or_else(|e| format!("<format error: {e}>"));

                Ok(ParsedInstruction::PrintVariable {
                    name: var_name.to_string(),
                    type_encoding,
                    formatted_value,
                    raw_data: var_data.to_vec(),
                })
            }

            t if t == InstructionType::PrintVariableError as u8 => {
                if inst_data.len() < std::mem::size_of::<PrintVariableErrorData>() {
                    return Err("Invalid PrintVariableError data".to_string());
                }

                let data_struct = unsafe {
                    std::ptr::read_unaligned(inst_data.as_ptr() as *const PrintVariableErrorData)
                };

                let var_name_index = data_struct.var_name_index;
                let var_name = string_table
                    .get_variable_name(var_name_index)
                    .ok_or_else(|| format!("Invalid variable index: {var_name_index}"))?;

                let error_message = match data_struct.error_code {
                    1 => "failed to read user memory",
                    2 => "variable not found",
                    3 => "invalid memory address",
                    _ => "unknown error",
                };

                Ok(ParsedInstruction::PrintVariableError {
                    name: var_name.to_string(),
                    error_code: data_struct.error_code,
                    error_message: error_message.to_string(),
                })
            }

            t if t == InstructionType::Backtrace as u8 => {
                if inst_data.is_empty() {
                    return Err("Invalid Backtrace data".to_string());
                }

                let depth = inst_data[0];
                Ok(ParsedInstruction::Backtrace { depth })
            }

            t if t == InstructionType::EndInstruction as u8 => {
                if inst_data.len() < std::mem::size_of::<EndInstructionData>() {
                    return Err("Invalid EndInstruction data".to_string());
                }

                let data_struct = unsafe {
                    std::ptr::read_unaligned(inst_data.as_ptr() as *const EndInstructionData)
                };

                Ok(ParsedInstruction::EndInstruction {
                    total_instructions: data_struct.total_instructions,
                    execution_status: data_struct.execution_status,
                })
            }

            _ => Err(format!(
                "Unknown instruction type: {}",
                inst_header.inst_type
            )),
        }
    }

    /// Reset parser state (useful for error recovery)
    pub fn reset(&mut self) {
        self.parse_state = ParseState::WaitingForHeader;
        self.buffer.clear();
    }

    /// Get current parse state for debugging
    pub fn get_state(&self) -> &ParseState {
        &self.parse_state
    }
}

impl ParsedInstruction {
    /// Return a display string for this instruction
    pub fn to_display_string(&self) -> String {
        match self {
            ParsedInstruction::PrintString { content } => {
                format!("print \"{content}\"")
            }
            ParsedInstruction::PrintVariable {
                name,
                type_encoding,
                formatted_value,
                raw_data: _,
            } => {
                format!("{name} ({type_encoding:?}): {formatted_value}")
            }
            ParsedInstruction::PrintVariableError {
                name,
                error_code: _,
                error_message,
            } => {
                format!("{name} (error: {error_message})")
            }
            ParsedInstruction::Backtrace { depth } => {
                format!("backtrace({depth})")
            }
            ParsedInstruction::EndInstruction {
                total_instructions,
                execution_status,
            } => {
                let status_str = match *execution_status {
                    0 => "success",
                    1 => "partial_failure",
                    2 => "complete_failure",
                    _ => "unknown",
                };
                format!("end({total_instructions} instructions, {status_str})")
            }
        }
    }

    /// Return the instruction type as a string
    pub fn instruction_type(&self) -> String {
        match self {
            ParsedInstruction::PrintString { .. } => "PrintString".to_string(),
            ParsedInstruction::PrintVariable { .. } => "PrintVariable".to_string(),
            ParsedInstruction::PrintVariableError { .. } => "PrintVariableError".to_string(),
            ParsedInstruction::Backtrace { .. } => "Backtrace".to_string(),
            ParsedInstruction::EndInstruction { .. } => "EndInstruction".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_streaming_parser() {
        let mut string_table = StringTable::new();
        let _str_idx = string_table.add_string("hello world");

        let mut parser = StreamingTraceParser::new();

        // Create test segments
        let header = TraceEventHeader {
            magic: crate::consts::MAGIC,
        };

        let message = TraceEventMessage {
            trace_id: 12345,
            timestamp: 1000,
            pid: 1001,
            tid: 2002,
        };

        // Test header segment
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &header as *const _ as *const u8,
                std::mem::size_of::<TraceEventHeader>(),
            )
        };
        let result = parser.process_segment(header_bytes, &string_table).unwrap();
        assert!(result.is_none()); // Not complete yet

        // Test message segment
        let message_bytes = unsafe {
            std::slice::from_raw_parts(
                &message as *const _ as *const u8,
                std::mem::size_of::<TraceEventMessage>(),
            )
        };
        let result = parser
            .process_segment(message_bytes, &string_table)
            .unwrap();
        assert!(result.is_none()); // Not complete yet

        // TODO: Add instruction segments and EndInstruction test
        // This demonstrates the pattern: StringTable is managed externally by loader,
        // not by the parser itself
    }
}

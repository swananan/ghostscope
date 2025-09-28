use crate::format_printer::FormatPrinter;
use crate::trace_context::TraceContext;
use crate::trace_event::*;
use crate::TypeKind;
use tracing::{debug, warn};

/// Parsed instruction from trace event
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ParsedInstruction {
    PrintString {
        content: String,
    },
    PrintVariable {
        name: String,
        type_encoding: TypeKind,
        formatted_value: String,
        raw_data: Vec<u8>,
    },
    PrintFormat {
        formatted_output: String,
    },
    PrintComplexFormat {
        formatted_output: String,
    },
    PrintComplexVariable {
        name: String,
        access_path: String,
        type_index: u16,
        formatted_value: String,
        raw_data: Vec<u8>,
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

impl ParsedTraceEvent {
    /// Generate a formatted display output by combining format strings with variables
    /// This handles the pattern: PrintString + PrintVariable sequence
    pub fn to_formatted_output(&self) -> Vec<String> {
        let mut output = Vec::new();
        let mut i = 0;

        while i < self.instructions.len() {
            match &self.instructions[i] {
                ParsedInstruction::PrintString { content } => {
                    // Check if this looks like a format string (contains {})
                    if content.contains("{}") {
                        // Try to find corresponding variables
                        let (formatted, consumed) =
                            self.format_string_with_variables(content, i + 1);
                        output.push(formatted);
                        i += consumed; // Skip the variables we consumed
                    } else {
                        // Regular string, just add it
                        output.push(content.clone());
                        i += 1;
                    }
                }
                ParsedInstruction::PrintFormat { formatted_output } => {
                    // Already formatted, just add it
                    output.push(formatted_output.clone());
                    i += 1;
                }
                ParsedInstruction::EndInstruction { .. } => {
                    // Skip EndInstruction - it's for protocol control, not user output
                    i += 1;
                }
                instruction => {
                    // Other instructions (variables without format string, etc.)
                    output.push(instruction.to_display_string());
                    i += 1;
                }
            }
        }

        output
    }

    /// Format a format string with following variable instructions
    fn format_string_with_variables(
        &self,
        format_string: &str,
        start_index: usize,
    ) -> (String, usize) {
        // Count placeholders in format string
        let placeholder_count = format_string.matches("{}").count();

        // Collect variable values
        let mut variables = Vec::new();
        let mut consumed = 1; // At least consume the format string itself

        for i in start_index..(start_index + placeholder_count).min(self.instructions.len()) {
            if let ParsedInstruction::PrintVariable {
                formatted_value, ..
            } = &self.instructions[i]
            {
                variables.push(formatted_value.clone());
                consumed += 1;
            } else {
                break; // Not a variable, stop collecting
            }
        }

        // Apply formatting
        let mut result = format_string.to_string();
        for value in variables {
            if let Some(pos) = result.find("{}") {
                result.replace_range(pos..pos + 2, &value);
            }
        }

        (result, consumed)
    }
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
/// TraceContext is externally managed by the loader
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
    /// Note: TraceContext is provided by loader during parsing
    pub fn new() -> Self {
        Self {
            parse_state: ParseState::WaitingForHeader,
            buffer: Vec::with_capacity(1024),
        }
    }

    /// Process incoming data segment and return complete trace events
    /// TraceContext is provided by the loader (uprobe config after compilation)
    pub fn process_segment(
        &mut self,
        data: &[u8],
        trace_context: &TraceContext,
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
                let parsed_instruction = self.parse_instruction_segment(data, trace_context)?;

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
                self.process_segment(data, trace_context)
            }
        }
    }

    /// Parse a single instruction from segment data
    fn parse_instruction_segment(
        &self,
        data: &[u8],
        trace_context: &TraceContext,
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
                let string_content = trace_context
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
                let var_name = trace_context
                    .get_variable_name(var_name_index)
                    .ok_or_else(|| format!("Invalid variable index: {var_name_index}"))?;

                let var_data_offset = std::mem::size_of::<PrintVariableIndexData>();
                if inst_data.len() < var_data_offset + data_struct.data_len as usize {
                    return Err("Invalid variable data length".to_string());
                }

                let var_data =
                    &inst_data[var_data_offset..var_data_offset + data_struct.data_len as usize];

                let type_encoding =
                    TypeKind::from_u8(data_struct.type_encoding).unwrap_or(TypeKind::Unknown);

                // Use FormatPrinter with type context for enhanced formatting
                let type_index = data_struct.type_index; // Copy to avoid packed field alignment issues
                tracing::debug!("streaming_parser - type_index = {}", type_index);
                tracing::debug!(
                    "streaming_parser - TraceContext has {} types",
                    trace_context.types.len()
                );

                let formatted_value = match trace_context.get_type(type_index) {
                    Some(type_info) => {
                        tracing::debug!(
                            "streaming_parser - Found type_info for index {}",
                            type_index
                        );
                        // Use advanced formatting with full type information
                        crate::format_printer::FormatPrinter::format_data_with_type_info(
                            var_data, type_info,
                        )
                    }
                    None => {
                        tracing::debug!(
                            "streaming_parser - No type_info found for index {}",
                            type_index
                        );
                        // Type information missing - this indicates a serious compiler bug
                        format!(
                            "<COMPILER_ERROR: type_index {type_index} not found in TraceContext>"
                        )
                    }
                };

                Ok(ParsedInstruction::PrintVariable {
                    name: var_name.to_string(),
                    type_encoding,
                    formatted_value,
                    raw_data: var_data.to_vec(),
                })
            }

            t if t == InstructionType::PrintFormat as u8 => {
                if inst_data.len() < std::mem::size_of::<PrintFormatData>() {
                    return Err("Invalid PrintFormat data".to_string());
                }

                let format_data = unsafe {
                    std::ptr::read_unaligned(inst_data.as_ptr() as *const PrintFormatData)
                };

                // Parse variable data
                let mut variables = Vec::new();
                let mut offset = std::mem::size_of::<PrintFormatData>();

                for _ in 0..format_data.arg_count {
                    // Header: var_name_index:u16 (2), type_encoding:u8 (1), data_len:u16 (2), type_index:u16 (2), status:u8 (1)
                    if offset + 8 > inst_data.len() {
                        return Err("Invalid PrintFormat variable header".to_string());
                    }

                    // Read variable header fields in struct order
                    let var_name_index =
                        u16::from_le_bytes([inst_data[offset], inst_data[offset + 1]]);
                    let type_encoding_byte = inst_data[offset + 2];
                    let data_len =
                        u16::from_le_bytes([inst_data[offset + 3], inst_data[offset + 4]]);
                    let type_index =
                        u16::from_le_bytes([inst_data[offset + 5], inst_data[offset + 6]]);
                    let status = inst_data[offset + 7];

                    offset += 8;

                    if offset + data_len as usize > inst_data.len() {
                        return Err("Invalid PrintFormat variable data".to_string());
                    }

                    let var_data = inst_data[offset..offset + data_len as usize].to_vec();
                    offset += data_len as usize;

                    // Convert type encoding byte to enum
                    let type_encoding =
                        TypeKind::from_u8(type_encoding_byte).unwrap_or(TypeKind::Unknown);

                    variables.push(crate::format_printer::ParsedVariable {
                        var_name_index,
                        type_encoding,
                        // Preserve zero-based indices; 0 is a valid type_index
                        type_index: Some(type_index),
                        status,
                        data: var_data,
                    });
                }

                // Use FormatPrinter to generate formatted output
                let formatted_output = crate::format_printer::FormatPrinter::format_print_data(
                    format_data.format_string_index,
                    &variables,
                    trace_context,
                );

                Ok(ParsedInstruction::PrintFormat { formatted_output })
            }

            t if t == InstructionType::PrintComplexFormat as u8 => {
                if inst_data.len() < std::mem::size_of::<PrintComplexFormatData>() {
                    return Err("Invalid PrintComplexFormat data".to_string());
                }

                let format_data = unsafe {
                    std::ptr::read_unaligned(inst_data.as_ptr() as *const PrintComplexFormatData)
                };

                // Parse complex variable data
                let mut complex_variables = Vec::new();
                let mut data_offset = std::mem::size_of::<PrintComplexFormatData>();

                for _ in 0..format_data.arg_count {
                    if data_offset + 7 > inst_data.len() {
                        return Err("Invalid PrintComplexFormat argument data".to_string());
                    }

                    // Read complex variable header: var_name_index, type_index, status, access_path_len
                    let var_name_index =
                        u16::from_le_bytes([inst_data[data_offset], inst_data[data_offset + 1]]);
                    let type_index = u16::from_le_bytes([
                        inst_data[data_offset + 2],
                        inst_data[data_offset + 3],
                    ]);
                    let status = inst_data[data_offset + 4];
                    let access_path_len = inst_data[data_offset + 5] as usize;
                    data_offset += 6; // 2+2+1(status)+1(ap_len)

                    // Read access path
                    if data_offset + access_path_len > inst_data.len() {
                        return Err("Invalid PrintComplexFormat access path".to_string());
                    }
                    let access_path_bytes = &inst_data[data_offset..data_offset + access_path_len];
                    let access_path = String::from_utf8_lossy(access_path_bytes).to_string();
                    data_offset += access_path_len;

                    // Read data length
                    if data_offset + 2 > inst_data.len() {
                        return Err("Invalid PrintComplexFormat data length".to_string());
                    }
                    let data_len =
                        u16::from_le_bytes([inst_data[data_offset], inst_data[data_offset + 1]]);
                    data_offset += 2;

                    // Read variable data
                    if data_offset + data_len as usize > inst_data.len() {
                        return Err("Invalid PrintComplexFormat variable data".to_string());
                    }
                    let var_data = inst_data[data_offset..data_offset + data_len as usize].to_vec();
                    data_offset += data_len as usize;

                    complex_variables.push(crate::format_printer::ParsedComplexVariable {
                        var_name_index,
                        type_index,
                        access_path,
                        status,
                        data: var_data,
                    });
                }

                // Use FormatPrinter to generate formatted output
                let formatted_output =
                    crate::format_printer::FormatPrinter::format_complex_print_data(
                        format_data.format_string_index,
                        &complex_variables,
                        trace_context,
                    );

                Ok(ParsedInstruction::PrintComplexFormat { formatted_output })
            }

            t if t == InstructionType::Backtrace as u8 => {
                if inst_data.is_empty() {
                    return Err("Invalid Backtrace data".to_string());
                }

                let depth = inst_data[0];
                Ok(ParsedInstruction::Backtrace { depth })
            }

            t if t == InstructionType::PrintComplexVariable as u8 => {
                if inst_data.len() < std::mem::size_of::<PrintComplexVariableData>() {
                    return Err("Invalid PrintComplexVariable data".to_string());
                }

                let data_struct = unsafe {
                    std::ptr::read_unaligned(inst_data.as_ptr() as *const PrintComplexVariableData)
                };

                // Extract variable name
                let var_name_index = data_struct.var_name_index;
                let var_name = trace_context
                    .get_variable_name(var_name_index)
                    .ok_or_else(|| format!("Invalid variable index: {var_name_index}"))?;

                // Extract access path
                let access_path_len = data_struct.access_path_len as usize;
                let struct_size = std::mem::size_of::<PrintComplexVariableData>();

                if inst_data.len() < struct_size + access_path_len {
                    return Err("Invalid PrintComplexVariable access path length".to_string());
                }

                let access_path_bytes = &inst_data[struct_size..struct_size + access_path_len];
                let access_path = String::from_utf8_lossy(access_path_bytes);

                // Extract variable data (either value or error payload)
                let var_data_offset = struct_size + access_path_len;
                if inst_data.len() < var_data_offset + data_struct.data_len as usize {
                    return Err("Invalid PrintComplexVariable data length".to_string());
                }

                let var_data =
                    &inst_data[var_data_offset..var_data_offset + data_struct.data_len as usize];

                // Get type information and format with status-aware printer
                let formatted_value = FormatPrinter::format_complex_variable_with_status(
                    var_name_index,
                    data_struct.type_index,
                    &access_path,
                    var_data,
                    data_struct.status,
                    trace_context,
                );

                Ok(ParsedInstruction::PrintComplexVariable {
                    name: var_name.to_string(),
                    access_path: access_path.to_string(),
                    type_index: data_struct.type_index,
                    formatted_value,
                    raw_data: var_data.to_vec(),
                })
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
            ParsedInstruction::PrintFormat { formatted_output } => formatted_output.clone(),
            ParsedInstruction::PrintComplexFormat { formatted_output } => formatted_output.clone(),
            ParsedInstruction::PrintComplexVariable {
                name: _,
                access_path: _,
                type_index: _,
                formatted_value,
                raw_data: _,
            } => {
                // formatted_value already contains "name = ..." or "name.access = ..."
                formatted_value.clone()
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
            ParsedInstruction::PrintFormat { .. } => "PrintFormat".to_string(),
            ParsedInstruction::PrintComplexFormat { .. } => "PrintComplexFormat".to_string(),
            ParsedInstruction::PrintComplexVariable { .. } => "PrintComplexVariable".to_string(),
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
        let mut trace_context = TraceContext::new();
        let _str_idx = trace_context.add_string("hello world".to_string());

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
        let result = parser
            .process_segment(header_bytes, &trace_context)
            .unwrap();
        assert!(result.is_none()); // Not complete yet

        // Test message segment
        let message_bytes = unsafe {
            std::slice::from_raw_parts(
                &message as *const _ as *const u8,
                std::mem::size_of::<TraceEventMessage>(),
            )
        };
        let result = parser
            .process_segment(message_bytes, &trace_context)
            .unwrap();
        assert!(result.is_none()); // Not complete yet

        // TODO: Add instruction segments and EndInstruction test
        // This demonstrates the pattern: TraceContext is managed externally by loader,
        // not by the parser itself
    }
}

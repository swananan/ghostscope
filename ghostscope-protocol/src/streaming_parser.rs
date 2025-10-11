use crate::format_printer::FormatPrinter;
use crate::trace_context::TraceContext;
use crate::trace_event::*;
use crate::TypeKind;
use tracing::{debug, warn};
use zerocopy::FromBytes;

/// Event source type for parser buffer management
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventSource {
    /// Continuous byte stream from RingBuf - may span multiple reads
    /// Parser preserves residual bytes across events
    #[default]
    RingBuf,
    /// Independent events from PerfEventArray - each event is complete
    /// Parser clears buffer after each event to prevent pollution
    PerfEventArray,
}

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
    /// Structured runtime expression error/warning
    ExprError {
        expr: String,
        error_code: u8,
        flags: u8,
        failing_addr: u64,
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
    event_source: EventSource,
}

impl Default for StreamingTraceParser {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingTraceParser {
    /// Create a new streaming parser with RingBuf mode (default)
    /// Note: TraceContext is provided by loader during parsing
    pub fn new() -> Self {
        Self::with_event_source(EventSource::RingBuf)
    }

    /// Create a new streaming parser with specified event source
    pub fn with_event_source(event_source: EventSource) -> Self {
        Self {
            parse_state: ParseState::WaitingForHeader,
            buffer: Vec::with_capacity(1024),
            event_source,
        }
    }

    /// Process incoming data segment and return complete trace events
    /// TraceContext is provided by the loader (uprobe config after compilation)
    pub fn process_segment(
        &mut self,
        data: &[u8],
        trace_context: &TraceContext,
    ) -> Result<Option<ParsedTraceEvent>, String> {
        // Append incoming data to buffer
        self.buffer.extend_from_slice(data);

        debug!(
            "Processing segment of {} bytes, buffer now has {} bytes, state: {:?}",
            data.len(),
            self.buffer.len(),
            self.parse_state
        );

        // Process buffer in a loop until we can't make progress
        loop {
            let consumed = match &self.parse_state {
                ParseState::WaitingForHeader => {
                    // Try to read header
                    let (header, _rest) = match TraceEventHeader::read_from_prefix(&self.buffer) {
                        Ok((h, r)) => (h, r),
                        Err(_) => {
                            debug!(
                                "Waiting for more data for header (have {} bytes, need {})",
                                self.buffer.len(),
                                std::mem::size_of::<TraceEventHeader>()
                            );
                            return Ok(None);
                        }
                    };

                    // Copy packed fields to avoid unaligned reference
                    let magic = header.magic;
                    if magic != crate::consts::MAGIC {
                        return Err(format!("Invalid magic number: 0x{magic:x}"));
                    }

                    debug!("Received valid header: magic=0x{magic:x}");
                    self.parse_state = ParseState::WaitingForMessage { header };
                    std::mem::size_of::<TraceEventHeader>()
                }

                ParseState::WaitingForMessage { header } => {
                    // Try to read message
                    let (message, _rest) = match TraceEventMessage::read_from_prefix(&self.buffer) {
                        Ok((m, r)) => (m, r),
                        Err(_) => {
                            debug!(
                                "Waiting for more data for message (have {} bytes, need {})",
                                self.buffer.len(),
                                std::mem::size_of::<TraceEventMessage>()
                            );
                            return Ok(None);
                        }
                    };

                    // Copy packed fields to avoid unaligned reference
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
                    std::mem::size_of::<TraceEventMessage>()
                }

                ParseState::WaitingForInstructions {
                    header,
                    message,
                    instructions,
                } => {
                    // Try to parse instruction from buffer
                    match self.try_parse_instruction(&self.buffer, trace_context)? {
                        Some((parsed_instruction, consumed_bytes)) => {
                            let mut new_instructions = instructions.clone();

                            // Check if this is EndInstruction
                            if matches!(
                                parsed_instruction,
                                ParsedInstruction::EndInstruction { .. }
                            ) {
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

                                // Handle buffer cleanup based on event source
                                match self.event_source {
                                    EventSource::RingBuf => {
                                        // RingBuf: continuous stream, preserve residual bytes
                                        self.buffer.drain(..consumed_bytes);
                                        debug!(
                                            "RingBuf mode: consumed {} bytes, {} bytes remain in buffer",
                                            consumed_bytes,
                                            self.buffer.len()
                                        );
                                    }
                                    EventSource::PerfEventArray => {
                                        // PerfEventArray: independent events, clear all to prevent pollution
                                        let residual = self.buffer.len() - consumed_bytes;
                                        if residual > 0 {
                                            warn!(
                                                "PerfEventArray mode: discarding {} residual bytes after event",
                                                residual
                                            );
                                        }
                                        self.buffer.clear();
                                        debug!("PerfEventArray mode: cleared buffer after complete event");
                                    }
                                }

                                return Ok(Some(complete_event));
                            } else {
                                // Add instruction and continue waiting
                                new_instructions.push(parsed_instruction);

                                self.parse_state = ParseState::WaitingForInstructions {
                                    header: *header,
                                    message: *message,
                                    instructions: new_instructions,
                                };
                                consumed_bytes
                            }
                        }
                        None => {
                            debug!("Waiting for more data for instruction");
                            return Ok(None);
                        }
                    }
                }

                ParseState::Complete => {
                    warn!("Received data while in Complete state, resetting");
                    self.parse_state = ParseState::WaitingForHeader;
                    continue;
                }
            };

            // Consume processed bytes from buffer
            if consumed > 0 {
                self.buffer.drain(..consumed);
                debug!(
                    "Consumed {} bytes, buffer now has {} bytes",
                    consumed,
                    self.buffer.len()
                );
            }
        }
    }

    /// Try to parse a single instruction from buffer
    /// Returns Some((instruction, consumed_bytes)) if successful, None if need more data
    fn try_parse_instruction(
        &self,
        data: &[u8],
        trace_context: &TraceContext,
    ) -> Result<Option<(ParsedInstruction, usize)>, String> {
        // Try to read instruction header
        let (inst_header, _rest) = match InstructionHeader::read_from_prefix(data) {
            Ok((h, r)) => (h, r),
            Err(_) => return Ok(None),
        };

        let expected_total_size =
            std::mem::size_of::<InstructionHeader>() + inst_header.data_length as usize;
        if data.len() < expected_total_size {
            debug!(
                "Waiting for complete instruction: have {} bytes, need {} bytes",
                data.len(),
                expected_total_size
            );
            return Ok(None);
        }

        let inst_data = &data[std::mem::size_of::<InstructionHeader>()..expected_total_size];

        let instruction = match inst_header.inst_type {
            t if t == InstructionType::PrintStringIndex as u8 => {
                let (data_struct, _) = PrintStringIndexData::read_from_prefix(inst_data)
                    .map_err(|_| "Invalid PrintStringIndex data".to_string())?;

                let string_index = data_struct.string_index;
                let string_content = trace_context
                    .get_string(string_index)
                    .ok_or_else(|| format!("Invalid string index: {string_index}"))?;

                ParsedInstruction::PrintString {
                    content: string_content.to_string(),
                }
            }

            t if t == InstructionType::PrintVariableIndex as u8 => {
                let (data_struct, _) = PrintVariableIndexData::read_from_prefix(inst_data)
                    .map_err(|_| "Invalid PrintVariableIndex data".to_string())?;

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

                ParsedInstruction::PrintVariable {
                    name: var_name.to_string(),
                    type_encoding,
                    formatted_value,
                    raw_data: var_data.to_vec(),
                }
            }

            t if t == InstructionType::ExprError as u8 => {
                let (data_struct, _) =
                    crate::trace_event::ExprErrorData::read_from_prefix(inst_data)
                        .map_err(|_| "Invalid ExprError data".to_string())?;
                let si = data_struct.string_index;
                let expr = match trace_context.get_string(si) {
                    Some(s) => s.to_string(),
                    None => format!("<INVALID_EXPR_INDEX_{si}>"),
                };
                ParsedInstruction::ExprError {
                    expr,
                    error_code: data_struct.error_code,
                    flags: data_struct.flags,
                    failing_addr: data_struct.failing_addr,
                }
            }

            t if t == InstructionType::PrintComplexFormat as u8 => {
                let (format_data, _) = PrintComplexFormatData::read_from_prefix(inst_data)
                    .map_err(|_| "Invalid PrintComplexFormat data".to_string())?;

                // Parse complex variable data
                let mut complex_variables = Vec::new();
                let mut data_offset = std::mem::size_of::<PrintComplexFormatData>();

                for _ in 0..format_data.arg_count {
                    if data_offset + 7 > inst_data.len() {
                        return Err("Invalid PrintComplexFormat argument data".to_string());
                    }

                    // Read complex variable header: var_name_index, type_index, access_path_len, status
                    let var_name_index =
                        u16::from_le_bytes([inst_data[data_offset], inst_data[data_offset + 1]]);
                    let type_index = u16::from_le_bytes([
                        inst_data[data_offset + 2],
                        inst_data[data_offset + 3],
                    ]);
                    let access_path_len = inst_data[data_offset + 4] as usize;
                    let status = inst_data[data_offset + 5];
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

                ParsedInstruction::PrintComplexFormat { formatted_output }
            }

            t if t == InstructionType::Backtrace as u8 => {
                if inst_data.is_empty() {
                    return Err("Invalid Backtrace data".to_string());
                }

                let depth = inst_data[0];
                ParsedInstruction::Backtrace { depth }
            }

            t if t == InstructionType::PrintComplexVariable as u8 => {
                let (data_struct, _) = PrintComplexVariableData::read_from_prefix(inst_data)
                    .map_err(|_| "Invalid PrintComplexVariable data".to_string())?;

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

                ParsedInstruction::PrintComplexVariable {
                    name: var_name.to_string(),
                    access_path: access_path.to_string(),
                    type_index: data_struct.type_index,
                    formatted_value,
                    raw_data: var_data.to_vec(),
                }
            }

            t if t == InstructionType::EndInstruction as u8 => {
                let (data_struct, _) = EndInstructionData::read_from_prefix(inst_data)
                    .map_err(|_| "Invalid EndInstruction data".to_string())?;

                ParsedInstruction::EndInstruction {
                    total_instructions: data_struct.total_instructions,
                    execution_status: data_struct.execution_status,
                }
            }

            _ => {
                return Err(format!(
                    "Unknown instruction type: {}",
                    inst_header.inst_type
                ))
            }
        };

        Ok(Some((instruction, expected_total_size)))
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
            ParsedInstruction::ExprError {
                expr,
                error_code,
                flags,
                failing_addr,
            } => {
                // Map code to brief reason aligned with VariableStatus
                // 1: NullDeref, 2: ReadError, 3: AccessError, 4: Truncated, 5: OffsetsUnavailable, 6: ZeroLength
                let reason = match *error_code {
                    1 => "null deref",
                    2 => "read error",
                    3 => "access error",
                    4 => "truncated",
                    5 => "offsets unavailable",
                    6 => "zero length",
                    _ => "error",
                };

                // Human-friendly flags (best-effort based on expr content)
                fn readable_flags(expr: &str, flags: u8) -> Option<String> {
                    if flags == 0 {
                        return None;
                    }
                    let mut tags: Vec<&'static str> = Vec::new();
                    let is_memcmp = expr.contains("memcmp(");
                    let is_strncmp = expr.contains("strncmp(") || expr.contains("starts_with(");
                    if is_memcmp {
                        if (flags & 0x01) != 0 {
                            tags.push("first-arg read-fail");
                        }
                        if (flags & 0x02) != 0 {
                            tags.push("second-arg read-fail");
                        }
                        if (flags & 0x04) != 0 {
                            tags.push("len-clamped");
                        }
                        if (flags & 0x08) != 0 {
                            tags.push("len=0");
                        }
                    } else if is_strncmp {
                        if (flags & 0x01) != 0 {
                            tags.push("read-fail");
                        }
                        if (flags & 0x04) != 0 {
                            tags.push("len-clamped");
                        }
                        if (flags & 0x08) != 0 {
                            tags.push("len=0");
                        }
                    } else {
                        // Unknown producer; fall back to hex for transparency
                        return Some(format!("0x{flags:02x}"));
                    }
                    if tags.is_empty() {
                        None
                    } else {
                        Some(tags.join(","))
                    }
                }

                let flags_text = readable_flags(expr, *flags);
                let addr_text = if *failing_addr != 0 {
                    format!("at 0x{failing_addr:016x}")
                } else {
                    "at NULL".to_string()
                };
                let base = format!("ExprError: {expr} ({reason} {addr_text}");
                match flags_text {
                    Some(f) => format!("{base}, flags: {f})"),
                    None => format!("{base})"),
                }
            }

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
            ParsedInstruction::ExprError { .. } => "ExprError".to_string(),

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

        // Test header segment (using zerocopy to convert struct to bytes)
        let header_bytes = zerocopy::IntoBytes::as_bytes(&header);
        let result = parser
            .process_segment(header_bytes, &trace_context)
            .unwrap();
        assert!(result.is_none()); // Not complete yet

        // Test message segment (using zerocopy to convert struct to bytes)
        let message_bytes = zerocopy::IntoBytes::as_bytes(&message);
        let result = parser
            .process_segment(message_bytes, &trace_context)
            .unwrap();
        assert!(result.is_none()); // Not complete yet

        // TODO: Add instruction segments and EndInstruction test
        // This demonstrates the pattern: TraceContext is managed externally by loader,
        // not by the parser itself
    }

    #[test]
    fn test_parse_exprerror_instruction() {
        let mut trace_context = TraceContext::new();
        let expr_idx = trace_context.add_string("memcmp(buf, hex(\"504f\"), 2)".to_string());

        let mut parser = StreamingTraceParser::new();

        // Header
        let header = TraceEventHeader {
            magic: crate::consts::MAGIC,
        };
        let header_bytes = zerocopy::IntoBytes::as_bytes(&header);
        assert!(parser
            .process_segment(header_bytes, &trace_context)
            .unwrap()
            .is_none());

        // Message
        let message = TraceEventMessage {
            trace_id: 1,
            timestamp: 0,
            pid: 123,
            tid: 456,
        };
        let message_bytes = zerocopy::IntoBytes::as_bytes(&message);
        assert!(parser
            .process_segment(message_bytes, &trace_context)
            .unwrap()
            .is_none());

        // ExprError instruction: header(4) + payload(12)
        let mut inst = Vec::new();
        // InstructionHeader
        inst.push(InstructionType::ExprError as u8); // inst_type
        inst.extend_from_slice(
            &(std::mem::size_of::<crate::trace_event::ExprErrorData>() as u16).to_le_bytes(),
        ); // data_length
        inst.push(0u8); // reserved
                        // ExprErrorData payload
        inst.extend_from_slice(&expr_idx.to_le_bytes()); // string_index
        inst.push(1u8); // error_code
        inst.push(0u8); // flags
        inst.extend_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes()); // failing_addr

        // EndInstruction
        inst.push(InstructionType::EndInstruction as u8);
        inst.extend_from_slice(&(std::mem::size_of::<EndInstructionData>() as u16).to_le_bytes());
        inst.push(0u8); // reserved
                        // EndInstructionData
                        // EndInstructionData: total_instructions:u16, execution_status:u8, reserved:u8
        inst.extend_from_slice(&1u16.to_le_bytes()); // total_instructions
        inst.push(1u8); // execution_status
        inst.push(0u8); // reserved

        let event = parser
            .process_segment(&inst, &trace_context)
            .unwrap()
            .expect("complete event");
        assert_eq!(event.trace_id, 1);
        assert_eq!(event.pid, 123);
        assert_eq!(event.tid, 456);
        assert_eq!(event.instructions.len(), 2);
        match &event.instructions[0] {
            ParsedInstruction::ExprError {
                expr,
                error_code,
                flags,
                failing_addr,
            } => {
                assert_eq!(expr, "memcmp(buf, hex(\"504f\"), 2)");
                assert_eq!(*error_code, 1);
                assert_eq!(*flags, 0);
                assert_eq!(*failing_addr, 0x1234_5678_9abc_def0u64);
            }
            other => panic!("unexpected first instruction: {other:?}"),
        }
        match &event.instructions[1] {
            ParsedInstruction::EndInstruction {
                total_instructions,
                execution_status,
            } => {
                assert_eq!(*total_instructions, 1);
                assert_eq!(*execution_status, 1); // partial_failure
            }
            other => panic!("unexpected last instruction: {other:?}"),
        }
    }
}

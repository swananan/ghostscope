use crate::TypeEncoding;
use serde::{Deserialize, Serialize};

/// Each trace event contains multiple instructions followed by EndInstruction
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TraceEventHeader {
    pub magic: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct TraceEventMessage {
    pub trace_id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    // Followed by variable-length instruction sequence ending with EndInstruction
}

/// Instruction types for trace events
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum InstructionType {
    PrintStringIndex = 0x01,   // print "string" (using string table index)
    PrintVariableIndex = 0x02, // print variable (using variable name index)
    PrintVariable = 0x03,      // print variable (full name, for compatibility)
    PrintVariableError = 0x12, // variable read error (using variable name index)
    Backtrace = 0x10,          // backtrace instruction

    // Control instructions
    EndInstruction = 0xFF, // marks end of instruction sequence
}

/// Common instruction header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct InstructionHeader {
    pub inst_type: u8,    // InstructionType
    pub data_length: u16, // Length of instruction data following this header
    pub reserved: u8,
}

/// Print string instruction data (most optimized)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PrintStringIndexData {
    pub string_index: u16, // Index into string table
}

/// Print variable instruction data (optimized with name index)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PrintVariableIndexData {
    pub var_name_index: u16, // Index into variable name table
    pub type_encoding: u8,   // TypeEncoding
    pub data_len: u16,       // Length of variable data that follows
    pub reserved: u8,
    // Followed by variable data
}

/// Print variable instruction data (full name for compatibility)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct PrintVariableData {
    pub var_name_len: u8,  // Length of variable name
    pub type_encoding: u8, // TypeEncoding
    pub data_len: u16,     // Length of variable data
                           // Followed by: variable name + variable data
}

/// Variable read error instruction data
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PrintVariableErrorData {
    pub var_name_index: u16, // Index into variable name table
    pub error_code: u8,      // Error type: 1=read_user failed, 2=other
    pub reserved: u8,
}

/// Backtrace instruction data
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct BacktraceData {
    pub depth: u8, // Maximum backtrace depth to capture
    pub flags: u8, // Backtrace options (0 = default)
    pub reserved: u16, // Padding for alignment
                   // Followed by backtrace frame data in the instruction payload
}

/// End instruction data - marks the end of instruction sequence
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct EndInstructionData {
    pub total_instructions: u16, // Total number of instructions before this EndInstruction
    pub execution_status: u8,    // 0=success, 1=partial_failure, 2=complete_failure
    pub reserved: u8,            // Padding for alignment
}

/// High-level instruction representation for compilation and parsing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Instruction {
    PrintStringIndex {
        string_index: u16,
    },
    PrintVariableIndex {
        var_name_index: u16,
        type_encoding: TypeEncoding,
        data: Vec<u8>,
    },
    PrintVariable {
        var_name: String,
        type_encoding: TypeEncoding,
        data: Vec<u8>,
    },
    PrintVariableError {
        var_name_index: u16,
        error_code: u8,
    },
    Backtrace {
        depth: u8,
        flags: u8,
        frames: Vec<u64>, // Stack frame addresses
    },
    EndInstruction {
        total_instructions: u16,
        execution_status: u8, // 0=success, 1=partial_failure, 2=complete_failure
    },
}

impl Instruction {
    /// Calculate the encoded size of this instruction (header + data)
    pub fn encoded_size(&self) -> usize {
        let header_size = std::mem::size_of::<InstructionHeader>();
        let data_size = match self {
            Instruction::PrintStringIndex { .. } => std::mem::size_of::<PrintStringIndexData>(),
            Instruction::PrintVariableIndex { data, .. } => {
                std::mem::size_of::<PrintVariableIndexData>() + data.len()
            }
            Instruction::PrintVariable { var_name, data, .. } => {
                std::mem::size_of::<PrintVariableData>() + var_name.len() + data.len()
            }
            Instruction::PrintVariableError { .. } => std::mem::size_of::<PrintVariableErrorData>(),
            Instruction::Backtrace { frames, .. } => {
                std::mem::size_of::<BacktraceData>() + frames.len() * 8
            }
            Instruction::EndInstruction { .. } => std::mem::size_of::<EndInstructionData>(),
        };
        header_size + data_size
    }

    /// Get the instruction type
    pub fn instruction_type(&self) -> InstructionType {
        match self {
            Instruction::PrintStringIndex { .. } => InstructionType::PrintStringIndex,
            Instruction::PrintVariableIndex { .. } => InstructionType::PrintVariableIndex,
            Instruction::PrintVariable { .. } => InstructionType::PrintVariable,
            Instruction::PrintVariableError { .. } => InstructionType::PrintVariableError,
            Instruction::Backtrace { .. } => InstructionType::Backtrace,
            Instruction::EndInstruction { .. } => InstructionType::EndInstruction,
        }
    }
}

/// Builder for trace event messages
#[allow(dead_code)]
pub(crate) struct TraceEventBuilder {
    buffer: Vec<u8>,
}

impl TraceEventBuilder {
    #[allow(dead_code)]
    pub(crate) fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(1024),
        }
    }

    /// Build a complete trace event message with EndInstruction design
    #[allow(dead_code)]
    pub(crate) fn build_trace_event(
        &mut self,
        trace_id: u64,
        pid: u32,
        tid: u32,
        instructions: &[Instruction],
    ) -> Result<Vec<u8>, String> {
        self.buffer.clear();

        if instructions.len() > u16::MAX as usize {
            return Err("Too many instructions in trace event".to_string());
        }

        // Reserve space for header (will be filled at the end)
        let header_size = std::mem::size_of::<TraceEventHeader>();
        self.buffer.resize(header_size, 0);

        // Write message body
        let msg_body = TraceEventMessage {
            trace_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64,
            pid,
            tid,
        };
        self.write_struct(&msg_body);

        // Write instructions
        for instruction in instructions {
            self.write_instruction(instruction)?;
        }

        // Automatically add EndInstruction
        let end_instruction = Instruction::EndInstruction {
            total_instructions: instructions.len() as u16,
            execution_status: 0, // 0 = success
        };
        self.write_instruction(&end_instruction)?;

        // Calculate and write final header
        let total_size = self.buffer.len();
        if total_size > u16::MAX as usize {
            return Err("Trace event too large".to_string());
        }

        let header = TraceEventHeader {
            magic: crate::consts::MAGIC,
        };

        // Write header at the beginning
        let header_bytes =
            unsafe { std::slice::from_raw_parts(&header as *const _ as *const u8, header_size) };
        self.buffer[0..header_size].copy_from_slice(header_bytes);

        Ok(self.buffer.clone())
    }

    /// Write a single instruction to the buffer
    #[allow(dead_code)]
    fn write_instruction(&mut self, instruction: &Instruction) -> Result<(), String> {
        let inst_type = instruction.instruction_type();

        match instruction {
            Instruction::PrintStringIndex { string_index } => {
                let header = InstructionHeader {
                    inst_type: inst_type as u8,
                    data_length: std::mem::size_of::<PrintStringIndexData>() as u16,
                    reserved: 0,
                };
                self.write_struct(&header);

                let data = PrintStringIndexData {
                    string_index: *string_index,
                };
                self.write_struct(&data);
            }

            Instruction::PrintVariableIndex {
                var_name_index,
                type_encoding,
                data,
            } => {
                let header = InstructionHeader {
                    inst_type: inst_type as u8,
                    data_length: (std::mem::size_of::<PrintVariableIndexData>() + data.len())
                        as u16,
                    reserved: 0,
                };
                self.write_struct(&header);

                let var_data = PrintVariableIndexData {
                    var_name_index: *var_name_index,
                    type_encoding: *type_encoding as u8,
                    data_len: data.len() as u16,
                    reserved: 0,
                };
                self.write_struct(&var_data);
                self.buffer.extend_from_slice(data);
            }

            Instruction::PrintVariable {
                var_name,
                type_encoding,
                data,
            } => {
                let header = InstructionHeader {
                    inst_type: inst_type as u8,
                    data_length: (std::mem::size_of::<PrintVariableData>()
                        + var_name.len()
                        + data.len()) as u16,
                    reserved: 0,
                };
                self.write_struct(&header);

                let var_data = PrintVariableData {
                    var_name_len: var_name.len() as u8,
                    type_encoding: *type_encoding as u8,
                    data_len: data.len() as u16,
                };
                self.write_struct(&var_data);
                self.buffer.extend_from_slice(var_name.as_bytes());
                self.buffer.extend_from_slice(data);
            }

            Instruction::PrintVariableError {
                var_name_index,
                error_code,
            } => {
                let header = InstructionHeader {
                    inst_type: inst_type as u8,
                    data_length: std::mem::size_of::<PrintVariableErrorData>() as u16,
                    reserved: 0,
                };
                self.write_struct(&header);

                let data = PrintVariableErrorData {
                    var_name_index: *var_name_index,
                    error_code: *error_code,
                    reserved: 0,
                };
                self.write_struct(&data);
            }

            Instruction::Backtrace {
                depth,
                flags,
                frames,
            } => {
                let header = InstructionHeader {
                    inst_type: inst_type as u8,
                    data_length: (std::mem::size_of::<BacktraceData>() + frames.len() * 8) as u16,
                    reserved: 0,
                };
                self.write_struct(&header);

                let data = BacktraceData {
                    depth: *depth,
                    flags: *flags,
                    reserved: 0,
                };
                self.write_struct(&data);

                // Write frame addresses
                for frame in frames {
                    self.buffer.extend_from_slice(&frame.to_le_bytes());
                }
            }

            Instruction::EndInstruction {
                total_instructions,
                execution_status,
            } => {
                let header = InstructionHeader {
                    inst_type: inst_type as u8,
                    data_length: std::mem::size_of::<EndInstructionData>() as u16,
                    reserved: 0,
                };
                self.write_struct(&header);

                let data = EndInstructionData {
                    total_instructions: *total_instructions,
                    execution_status: *execution_status,
                    reserved: 0,
                };
                self.write_struct(&data);
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    fn write_struct<T>(&mut self, s: &T) {
        let bytes = unsafe {
            std::slice::from_raw_parts(s as *const T as *const u8, std::mem::size_of::<T>())
        };
        self.buffer.extend_from_slice(bytes);
    }
}

impl Default for TraceEventBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TypeEncoding;

    #[test]
    fn test_instruction_sizes() {
        let inst1 = Instruction::PrintStringIndex { string_index: 0 };
        assert_eq!(inst1.encoded_size(), 4 + 2); // header + u16

        let inst2 = Instruction::PrintVariableIndex {
            var_name_index: 0,
            type_encoding: TypeEncoding::U32,
            data: vec![1, 2, 3, 4],
        };
        assert_eq!(inst2.encoded_size(), 4 + 6 + 4); // header + data struct + payload
    }

    #[test]
    fn test_trace_event_builder() {
        let mut builder = TraceEventBuilder::new();

        let instructions = vec![
            Instruction::PrintStringIndex { string_index: 0 },
            Instruction::PrintVariableIndex {
                var_name_index: 0,
                type_encoding: TypeEncoding::U32,
                data: vec![0x34, 0x12, 0x00, 0x00],
            },
        ];

        let result = builder.build_trace_event(12345, 1001, 2002, &instructions);
        assert!(result.is_ok());

        let data = result.unwrap();
        assert!(!data.is_empty());

        // Check header magic
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        assert_eq!(magic, crate::consts::MAGIC);
    }
}

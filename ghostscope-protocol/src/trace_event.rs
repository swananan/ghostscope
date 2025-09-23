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
    fn test_instruction_types() {
        let inst = Instruction::PrintStringIndex { string_index: 0 };
        assert_eq!(inst.instruction_type(), InstructionType::PrintStringIndex);

        let inst = Instruction::EndInstruction {
            total_instructions: 5,
            execution_status: 0,
        };
        assert_eq!(inst.instruction_type(), InstructionType::EndInstruction);
    }
}

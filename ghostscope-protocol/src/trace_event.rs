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
    PrintFormat = 0x04,        // print "format {} {}", var1, var2 (formatted print)
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

/// Format print instruction data
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct PrintFormatData {
    pub format_string_index: u16, // Index into string table for format string
    pub arg_count: u8,            // Number of arguments
    pub reserved: u8,             // Padding for alignment
                                  // Followed by argument data: [var_name_index:u16, type_encoding:u8, data_len:u16, data:bytes] * arg_count
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
    PrintFormat {
        format_string_index: u16,
        variables: Vec<VariableData>,
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

/// Variable data for PrintFormat instruction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableData {
    pub var_name_index: u16,
    pub type_encoding: TypeEncoding,
    pub data: Vec<u8>,
}

impl Instruction {
    /// Get the instruction type
    pub fn instruction_type(&self) -> InstructionType {
        match self {
            Instruction::PrintStringIndex { .. } => InstructionType::PrintStringIndex,
            Instruction::PrintVariableIndex { .. } => InstructionType::PrintVariableIndex,
            Instruction::PrintFormat { .. } => InstructionType::PrintFormat,
            Instruction::PrintVariableError { .. } => InstructionType::PrintVariableError,
            Instruction::Backtrace { .. } => InstructionType::Backtrace,
            Instruction::EndInstruction { .. } => InstructionType::EndInstruction,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_types() {
        let inst1 = Instruction::PrintStringIndex { string_index: 0 };
        assert_eq!(inst1.instruction_type(), InstructionType::PrintStringIndex);

        let inst2 = Instruction::PrintFormat {
            format_string_index: 0,
            variables: vec![],
        };
        assert_eq!(inst2.instruction_type(), InstructionType::PrintFormat);
    }

    #[test]
    fn test_instruction_types_basic() {
        let inst = Instruction::EndInstruction {
            total_instructions: 5,
            execution_status: 0,
        };
        assert_eq!(inst.instruction_type(), InstructionType::EndInstruction);
    }
}

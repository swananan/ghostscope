use crate::TypeKind;
use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Each trace event contains multiple instructions followed by EndInstruction
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct TraceEventHeader {
    pub magic: u32,
}

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
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
    PrintStringIndex = 0x01,     // print "string" (using string table index)
    PrintVariableIndex = 0x02,   // print variable (using variable name index)
    PrintComplexVariable = 0x03, // print complex variable (with full type info)
    PrintComplexFormat = 0x05,   // print with complex variables in format args
    Backtrace = 0x10,            // backtrace instruction
    /// Structured runtime expression error/warning (control-flow or print context)
    ExprError = 0x20,

    // Control instructions
    EndInstruction = 0xFF, // marks end of instruction sequence
}

/// Common instruction header
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct InstructionHeader {
    pub inst_type: u8,    // InstructionType
    pub data_length: u16, // Length of instruction data following this header
    pub reserved: u8,
}

/// Per-variable runtime status for data acquisition
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VariableStatus {
    Ok = 0,
    NullDeref = 1,
    ReadError = 2,
    AccessError = 3,
    Truncated = 4,
    /// Required runtime offsets/proc mapping not available at eBPF time
    /// (e.g., no (pid,module) offsets to compute address)
    OffsetsUnavailable = 5,
    /// Requested dynamic length is <= 0; no bytes were read
    ZeroLength = 6,
}

/// Print string instruction data (most optimized)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct PrintStringIndexData {
    pub string_index: u16, // Index into string table
}

/// Print variable instruction data (optimized with name index)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct PrintVariableIndexData {
    pub var_name_index: u16, // Index into variable name table
    pub type_encoding: u8,   // TypeKind
    pub data_len: u16,       // Length of variable data that follows
    pub type_index: u16,     // Index into type table (new field)
    pub status: u8, // Variable read status: see VariableStatus. For script variables this is 0.
                    // Followed by variable data
}

/// Print complex variable instruction data (enhanced with full type info)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct PrintComplexVariableData {
    pub var_name_index: u16, // Index into variable name table
    pub type_index: u16,     // Index into type table for complete type information
    pub access_path_len: u8, // Length of access path description (e.g., "person.name.first")
    pub status: u8,          // Variable read status: see VariableStatus
    pub data_len: u16,       // Length of variable data that follows
                             // Followed by access_path (UTF-8 string) then variable data
}

/// Complex format print instruction data (with full type info)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct PrintComplexFormatData {
    pub format_string_index: u16, // Index into string table for format string
    pub arg_count: u8,            // Number of arguments
    pub reserved: u8,             // Padding for alignment
                                  // Followed by complex argument data:
                                  // [var_name_index:u16, type_index:u16, access_path_len:u8, status:u8,
                                  //  access_path:bytes, data_len:u16, data:bytes] * arg_count
}

// Note: historical PrintVariableError has been removed; per-variable errors
// are carried via status in PrintVariableIndex/ComplexFormat.

/// Backtrace instruction data
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct BacktraceData {
    pub depth: u8, // Maximum backtrace depth to capture
    pub flags: u8, // Backtrace options (0 = default)
    pub reserved: u16, // Padding for alignment
                   // Followed by backtrace frame data in the instruction payload
}
/// ExprError instruction data - structured warning for runtime expression failure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct ExprErrorData {
    pub string_index: u16, // Index into string table for pretty expression text
    pub error_code: u8,    // Error code (semantic defined by compiler)
    pub flags: u8,         // Optional flags bitfield (e.g., which side failed)
    pub failing_addr: u64, // Optional: address involved in failure (0 if unknown)
}

/// End instruction data - marks the end of instruction sequence
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
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
        type_encoding: TypeKind,
        type_index: u16, // Index into type table (new field)
        data: Vec<u8>,
    },
    /// Structured runtime expression error/warning
    ExprError {
        string_index: u16,
        error_code: u8,
        flags: u8,
        failing_addr: u64,
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
    /// Get the instruction type
    pub fn instruction_type(&self) -> InstructionType {
        match self {
            Instruction::PrintStringIndex { .. } => InstructionType::PrintStringIndex,
            Instruction::PrintVariableIndex { .. } => InstructionType::PrintVariableIndex,
            Instruction::ExprError { .. } => InstructionType::ExprError,
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

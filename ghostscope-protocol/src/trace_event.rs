use crate::TypeKind;
use serde::{Deserialize, Serialize};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Each trace event contains multiple instructions followed by EndInstruction
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct TraceEventHeader {
    pub magic: u32,
}

pub const TRACE_EVENT_HEADER_SIZE: usize = std::mem::size_of::<TraceEventHeader>();
pub const TRACE_EVENT_HEADER_MAGIC_OFFSET: usize = std::mem::offset_of!(TraceEventHeader, magic);

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct TraceEventMessage {
    pub trace_id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    // Followed by variable-length instruction sequence ending with EndInstruction
}

pub const TRACE_EVENT_MESSAGE_SIZE: usize = std::mem::size_of::<TraceEventMessage>();
pub const TRACE_EVENT_MESSAGE_TRACE_ID_OFFSET: usize =
    std::mem::offset_of!(TraceEventMessage, trace_id);
pub const TRACE_EVENT_MESSAGE_TIMESTAMP_OFFSET: usize =
    std::mem::offset_of!(TraceEventMessage, timestamp);
pub const TRACE_EVENT_MESSAGE_PID_OFFSET: usize = std::mem::offset_of!(TraceEventMessage, pid);
pub const TRACE_EVENT_MESSAGE_TID_OFFSET: usize = std::mem::offset_of!(TraceEventMessage, tid);

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

pub const INSTRUCTION_HEADER_SIZE: usize = std::mem::size_of::<InstructionHeader>();
pub const INSTRUCTION_HEADER_INST_TYPE_OFFSET: usize =
    std::mem::offset_of!(InstructionHeader, inst_type);
pub const INSTRUCTION_HEADER_DATA_LENGTH_OFFSET: usize =
    std::mem::offset_of!(InstructionHeader, data_length);
pub const INSTRUCTION_HEADER_RESERVED_OFFSET: usize =
    std::mem::offset_of!(InstructionHeader, reserved);

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

/// Payload carried by ReadError variable statuses.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable, Unaligned)]
pub struct VariableReadErrorPayload {
    pub errno: i32,
    pub addr: u64,
}

pub const VARIABLE_READ_ERROR_PAYLOAD_LEN: usize = std::mem::size_of::<VariableReadErrorPayload>();
pub const VARIABLE_READ_ERROR_PAYLOAD_ERRNO_OFFSET: usize =
    std::mem::offset_of!(VariableReadErrorPayload, errno);
pub const VARIABLE_READ_ERROR_PAYLOAD_ADDR_OFFSET: usize =
    std::mem::offset_of!(VariableReadErrorPayload, addr);

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

/// Fixed prefix for each PrintComplexFormat argument.
///
/// The full argument is variable-length:
/// `PrintComplexFormatArgPrefix`, then `access_path`, then `data_len:u16`,
/// then `data`.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct PrintComplexFormatArgPrefix {
    pub var_name_index: u16,
    pub type_index: u16,
    pub access_path_len: u8,
    pub status: u8,
}

pub const PRINT_COMPLEX_FORMAT_DATA_ARG_COUNT_OFFSET: usize =
    std::mem::offset_of!(PrintComplexFormatData, arg_count);

pub const PRINT_COMPLEX_FORMAT_ARG_VAR_NAME_INDEX_OFFSET: usize =
    std::mem::offset_of!(PrintComplexFormatArgPrefix, var_name_index);
pub const PRINT_COMPLEX_FORMAT_ARG_TYPE_INDEX_OFFSET: usize =
    std::mem::offset_of!(PrintComplexFormatArgPrefix, type_index);
pub const PRINT_COMPLEX_FORMAT_ARG_ACCESS_PATH_LEN_OFFSET: usize =
    std::mem::offset_of!(PrintComplexFormatArgPrefix, access_path_len);
pub const PRINT_COMPLEX_FORMAT_ARG_STATUS_OFFSET: usize =
    std::mem::offset_of!(PrintComplexFormatArgPrefix, status);
pub const PRINT_COMPLEX_FORMAT_ARG_ACCESS_PATH_OFFSET: usize =
    std::mem::size_of::<PrintComplexFormatArgPrefix>();
pub const PRINT_COMPLEX_FORMAT_ARG_DATA_LEN_SIZE: usize = std::mem::size_of::<u16>();
pub const PRINT_COMPLEX_FORMAT_ARG_FIXED_HEADER_LEN: usize =
    PRINT_COMPLEX_FORMAT_ARG_ACCESS_PATH_OFFSET + PRINT_COMPLEX_FORMAT_ARG_DATA_LEN_SIZE;

// Note: historical PrintVariableError has been removed; per-variable errors
// are carried via status in PrintVariableIndex/ComplexFormat.

/// Backtrace instruction data
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct BacktraceData {
    pub requested_depth: u8,
    pub frame_count: u8,
    pub flags: u8,
    pub status: u8,
    pub error_code: u16,
    pub reserved: u16,
    // Followed by BacktraceFrameData[requested_depth].
}

pub const BACKTRACE_DATA_SIZE: usize = std::mem::size_of::<BacktraceData>();
pub const BACKTRACE_DATA_REQUESTED_DEPTH_OFFSET: usize =
    std::mem::offset_of!(BacktraceData, requested_depth);
pub const BACKTRACE_DATA_FRAME_COUNT_OFFSET: usize =
    std::mem::offset_of!(BacktraceData, frame_count);
pub const BACKTRACE_DATA_FLAGS_OFFSET: usize = std::mem::offset_of!(BacktraceData, flags);
pub const BACKTRACE_DATA_STATUS_OFFSET: usize = std::mem::offset_of!(BacktraceData, status);
pub const BACKTRACE_DATA_ERROR_CODE_OFFSET: usize = std::mem::offset_of!(BacktraceData, error_code);

#[repr(C, packed)]
#[derive(
    Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned, Serialize, Deserialize,
)]
pub struct BacktraceFrameData {
    pub module_cookie: u64,
    /// Module-normalized DWARF PC / ELF virtual address.
    pub pc: u64,
    /// Runtime instruction pointer as observed in the target process.
    pub raw_ip: u64,
    pub flags: u16,
    pub reserved: u16,
    pub reserved2: u32,
}

pub const BACKTRACE_FRAME_DATA_SIZE: usize = std::mem::size_of::<BacktraceFrameData>();
pub const BACKTRACE_FRAME_MODULE_COOKIE_OFFSET: usize =
    std::mem::offset_of!(BacktraceFrameData, module_cookie);
pub const BACKTRACE_FRAME_PC_OFFSET: usize = std::mem::offset_of!(BacktraceFrameData, pc);
pub const BACKTRACE_FRAME_RAW_IP_OFFSET: usize = std::mem::offset_of!(BacktraceFrameData, raw_ip);
pub const BACKTRACE_FRAME_FLAGS_OFFSET: usize = std::mem::offset_of!(BacktraceFrameData, flags);

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BacktraceStatus {
    Complete = 0,
    Truncated = 1,
    DwarfUnavailable = 2,
    UnsupportedCfi = 3,
    OffsetsUnavailable = 4,
    ReadError = 5,
    InternalError = 6,
    InvalidFrame = 7,
    NoUnwindRowsForPc = 8,
}

impl BacktraceStatus {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Complete,
            1 => Self::Truncated,
            2 => Self::DwarfUnavailable,
            3 => Self::UnsupportedCfi,
            4 => Self::OffsetsUnavailable,
            5 => Self::ReadError,
            6 => Self::InternalError,
            7 => Self::InvalidFrame,
            8 => Self::NoUnwindRowsForPc,
            _ => Self::InternalError,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Truncated => "truncated",
            Self::DwarfUnavailable => "dwarf unavailable",
            Self::UnsupportedCfi => "unsupported CFI",
            Self::OffsetsUnavailable => "offsets unavailable",
            Self::ReadError => "read error",
            Self::InternalError => "internal error",
            Self::InvalidFrame => "invalid frame",
            Self::NoUnwindRowsForPc => "no unwind rows for PC",
        }
    }
}

pub const BACKTRACE_ERROR_NONE: u16 = 0;
pub const BACKTRACE_ERROR_RETURN_ADDRESS_READ: u16 = 1;
pub const BACKTRACE_ERROR_FRAME_POINTER_READ: u16 = 2;
pub const BACKTRACE_ERROR_NEXT_IP_BELOW_USER: u16 = 3;
pub const BACKTRACE_ERROR_NEXT_IP_KERNEL_LIKE: u16 = 4;
pub const BACKTRACE_ERROR_NEXT_CFA_ZERO: u16 = 5;
pub const BACKTRACE_ERROR_NEXT_CFA_NOT_ADVANCING: u16 = 6;

pub fn backtrace_error_label(error_code: u16) -> Option<&'static str> {
    match error_code {
        BACKTRACE_ERROR_NONE => None,
        BACKTRACE_ERROR_RETURN_ADDRESS_READ => Some("return-address-read-failed"),
        BACKTRACE_ERROR_FRAME_POINTER_READ => Some("frame-pointer-read-failed"),
        BACKTRACE_ERROR_NEXT_IP_BELOW_USER => Some("next-ip-below-user-range"),
        BACKTRACE_ERROR_NEXT_IP_KERNEL_LIKE => Some("next-ip-kernel-like"),
        BACKTRACE_ERROR_NEXT_CFA_ZERO => Some("next-cfa-zero"),
        BACKTRACE_ERROR_NEXT_CFA_NOT_ADVANCING => Some("next-cfa-not-advancing"),
        _ => Some("unknown"),
    }
}

pub const BACKTRACE_FLAG_RAW: u8 = 0x01;
pub const BACKTRACE_FLAG_FULL: u8 = 0x02;
pub const BACKTRACE_FLAG_INLINE: u8 = 0x04;
/// ExprError instruction data - structured warning for runtime expression failure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct ExprErrorData {
    pub string_index: u16, // Index into string table for pretty expression text
    pub error_code: u8,    // Error code (semantic defined by compiler)
    pub flags: u8,         // Optional flags bitfield (e.g., which side failed)
    pub failing_addr: u64, // Optional: address involved in failure (0 if unknown)
}

pub const EXPR_ERROR_DATA_SIZE: usize = std::mem::size_of::<ExprErrorData>();
pub const EXPR_ERROR_DATA_STRING_INDEX_OFFSET: usize =
    std::mem::offset_of!(ExprErrorData, string_index);
pub const EXPR_ERROR_DATA_ERROR_CODE_OFFSET: usize =
    std::mem::offset_of!(ExprErrorData, error_code);
pub const EXPR_ERROR_DATA_FLAGS_OFFSET: usize = std::mem::offset_of!(ExprErrorData, flags);
pub const EXPR_ERROR_DATA_FAILING_ADDR_OFFSET: usize =
    std::mem::offset_of!(ExprErrorData, failing_addr);

/// End instruction data - marks the end of instruction sequence
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable, Unaligned)]
pub struct EndInstructionData {
    pub total_instructions: u16, // Total number of instructions before this EndInstruction
    pub execution_status: u8,    // 0=success, 1=partial_failure, 2=complete_failure
    pub reserved: u8,            // Padding for alignment
}

pub const END_INSTRUCTION_DATA_OFFSET: usize = INSTRUCTION_HEADER_SIZE;
pub const END_INSTRUCTION_TOTAL_INSTRUCTIONS_OFFSET: usize =
    std::mem::offset_of!(EndInstructionData, total_instructions);
pub const END_INSTRUCTION_EXECUTION_STATUS_OFFSET: usize =
    std::mem::offset_of!(EndInstructionData, execution_status);

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
        requested_depth: u8,
        frame_count: u8,
        flags: u8,
        status: BacktraceStatus,
        error_code: u16,
        frames: Vec<BacktraceFrameData>,
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

    #[test]
    fn backtrace_status_wire_values_and_labels_are_stable() {
        assert_eq!(BacktraceStatus::UnsupportedCfi as u8, 3);
        assert_eq!(BacktraceStatus::NoUnwindRowsForPc as u8, 8);
        assert_eq!(
            BacktraceStatus::from_u8(8),
            BacktraceStatus::NoUnwindRowsForPc
        );
        assert_eq!(
            BacktraceStatus::NoUnwindRowsForPc.label(),
            "no unwind rows for PC"
        );
        assert_eq!(
            BacktraceStatus::from_u8(255),
            BacktraceStatus::InternalError
        );
    }

    #[test]
    fn protocol_layout_constants_match_wire_format() {
        assert_eq!(TRACE_EVENT_HEADER_SIZE, 4);
        assert_eq!(TRACE_EVENT_HEADER_MAGIC_OFFSET, 0);
        assert_eq!(TRACE_EVENT_MESSAGE_SIZE, 24);
        assert_eq!(TRACE_EVENT_MESSAGE_TRACE_ID_OFFSET, 0);
        assert_eq!(TRACE_EVENT_MESSAGE_TIMESTAMP_OFFSET, 8);
        assert_eq!(TRACE_EVENT_MESSAGE_PID_OFFSET, 16);
        assert_eq!(TRACE_EVENT_MESSAGE_TID_OFFSET, 20);
        assert_eq!(INSTRUCTION_HEADER_SIZE, 4);
        assert_eq!(INSTRUCTION_HEADER_INST_TYPE_OFFSET, 0);
        assert_eq!(INSTRUCTION_HEADER_DATA_LENGTH_OFFSET, 1);
        assert_eq!(INSTRUCTION_HEADER_RESERVED_OFFSET, 3);
        assert_eq!(END_INSTRUCTION_DATA_OFFSET, 4);
        assert_eq!(END_INSTRUCTION_TOTAL_INSTRUCTIONS_OFFSET, 0);
        assert_eq!(END_INSTRUCTION_EXECUTION_STATUS_OFFSET, 2);
        assert_eq!(VARIABLE_READ_ERROR_PAYLOAD_LEN, 12);
        assert_eq!(VARIABLE_READ_ERROR_PAYLOAD_ERRNO_OFFSET, 0);
        assert_eq!(VARIABLE_READ_ERROR_PAYLOAD_ADDR_OFFSET, 4);
        assert_eq!(EXPR_ERROR_DATA_SIZE, 12);
        assert_eq!(EXPR_ERROR_DATA_STRING_INDEX_OFFSET, 0);
        assert_eq!(EXPR_ERROR_DATA_ERROR_CODE_OFFSET, 2);
        assert_eq!(EXPR_ERROR_DATA_FLAGS_OFFSET, 3);
        assert_eq!(EXPR_ERROR_DATA_FAILING_ADDR_OFFSET, 4);
        assert_eq!(BACKTRACE_DATA_SIZE, 8);
        assert_eq!(BACKTRACE_DATA_REQUESTED_DEPTH_OFFSET, 0);
        assert_eq!(BACKTRACE_DATA_FRAME_COUNT_OFFSET, 1);
        assert_eq!(BACKTRACE_DATA_FLAGS_OFFSET, 2);
        assert_eq!(BACKTRACE_DATA_STATUS_OFFSET, 3);
        assert_eq!(BACKTRACE_DATA_ERROR_CODE_OFFSET, 4);
        assert_eq!(BACKTRACE_FRAME_DATA_SIZE, 32);
        assert_eq!(BACKTRACE_FRAME_MODULE_COOKIE_OFFSET, 0);
        assert_eq!(BACKTRACE_FRAME_PC_OFFSET, 8);
        assert_eq!(BACKTRACE_FRAME_RAW_IP_OFFSET, 16);
        assert_eq!(BACKTRACE_FRAME_FLAGS_OFFSET, 24);
        assert_eq!(PRINT_COMPLEX_FORMAT_DATA_ARG_COUNT_OFFSET, 2);
        assert_eq!(PRINT_COMPLEX_FORMAT_ARG_VAR_NAME_INDEX_OFFSET, 0);
        assert_eq!(PRINT_COMPLEX_FORMAT_ARG_TYPE_INDEX_OFFSET, 2);
        assert_eq!(PRINT_COMPLEX_FORMAT_ARG_ACCESS_PATH_LEN_OFFSET, 4);
        assert_eq!(PRINT_COMPLEX_FORMAT_ARG_STATUS_OFFSET, 5);
        assert_eq!(PRINT_COMPLEX_FORMAT_ARG_ACCESS_PATH_OFFSET, 6);
        assert_eq!(PRINT_COMPLEX_FORMAT_ARG_DATA_LEN_SIZE, 2);
        assert_eq!(PRINT_COMPLEX_FORMAT_ARG_FIXED_HEADER_LEN, 8);
    }
}

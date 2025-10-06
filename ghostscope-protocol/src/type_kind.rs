//! TypeKind enumeration and protocol constants

use crate::type_info::TypeInfo;
use serde::{Deserialize, Serialize};

/// Variable type kind - used by compiler and streaming parser for runtime classification
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TypeKind {
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
}

impl TypeKind {
    /// Convert a u8 value to TypeKind enum
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            x if x == (Self::U8 as u8) => Some(Self::U8),
            x if x == (Self::U16 as u8) => Some(Self::U16),
            x if x == (Self::U32 as u8) => Some(Self::U32),
            x if x == (Self::U64 as u8) => Some(Self::U64),
            x if x == (Self::I8 as u8) => Some(Self::I8),
            x if x == (Self::I16 as u8) => Some(Self::I16),
            x if x == (Self::I32 as u8) => Some(Self::I32),
            x if x == (Self::I64 as u8) => Some(Self::I64),
            x if x == (Self::F32 as u8) => Some(Self::F32),
            x if x == (Self::F64 as u8) => Some(Self::F64),
            x if x == (Self::Bool as u8) => Some(Self::Bool),
            x if x == (Self::Char as u8) => Some(Self::Char),
            x if x == (Self::Pointer as u8) => Some(Self::Pointer),
            x if x == (Self::NullPointer as u8) => Some(Self::NullPointer),
            x if x == (Self::Struct as u8) => Some(Self::Struct),
            x if x == (Self::Array as u8) => Some(Self::Array),
            x if x == (Self::Union as u8) => Some(Self::Union),
            x if x == (Self::Enum as u8) => Some(Self::Enum),
            x if x == (Self::CString as u8) => Some(Self::CString),
            x if x == (Self::String as u8) => Some(Self::String),
            x if x == (Self::Unknown as u8) => Some(Self::Unknown),
            x if x == (Self::OptimizedOut as u8) => Some(Self::OptimizedOut),
            _ => None,
        }
    }
}

impl From<&TypeInfo> for TypeKind {
    /// Convert TypeInfo to TypeKind for runtime classification
    fn from(type_info: &TypeInfo) -> Self {
        match type_info {
            TypeInfo::BaseType { size, encoding, .. } => {
                // Use DWARF encoding constants for proper type mapping
                match *encoding {
                    1 => TypeKind::Pointer, // DW_ATE_address
                    2 => TypeKind::Bool,    // DW_ATE_boolean
                    4 => match size {
                        // DW_ATE_float
                        4 => TypeKind::F32,
                        8 => TypeKind::F64,
                        _ => TypeKind::F64, // Default to F64
                    },
                    5 => match size {
                        // DW_ATE_signed
                        1 => TypeKind::I8,
                        2 => TypeKind::I16,
                        4 => TypeKind::I32,
                        8 => TypeKind::I64,
                        _ => TypeKind::I64, // Default to I64
                    },
                    7 => match size {
                        // DW_ATE_unsigned
                        1 => TypeKind::U8,
                        2 => TypeKind::U16,
                        4 => TypeKind::U32,
                        8 => TypeKind::U64,
                        _ => TypeKind::U64, // Default to U64
                    },
                    6 => TypeKind::I8, // DW_ATE_signed_char
                    8 => TypeKind::U8, // DW_ATE_unsigned_char
                    _ => TypeKind::U8, // Default to byte for unknown encoding
                }
            }
            TypeInfo::BitfieldType {
                underlying_type, ..
            } => TypeKind::from(underlying_type.as_ref()),
            TypeInfo::PointerType { .. } => TypeKind::Pointer,
            TypeInfo::ArrayType { .. } => TypeKind::Array,
            TypeInfo::StructType { .. } => TypeKind::Struct,
            TypeInfo::UnionType { .. } => TypeKind::Union,
            TypeInfo::EnumType { .. } => TypeKind::I32, // Treat enum as integer
            TypeInfo::TypedefType {
                underlying_type, ..
            } => TypeKind::from(underlying_type.as_ref()),
            TypeInfo::QualifiedType {
                underlying_type, ..
            } => TypeKind::from(underlying_type.as_ref()),
            TypeInfo::FunctionType { .. } => TypeKind::Pointer,
            TypeInfo::UnknownType { .. } => TypeKind::U8, // Default to byte for unknown types
            TypeInfo::OptimizedOut { .. } => TypeKind::OptimizedOut,
        }
    }
}

/// Protocol constants
pub mod consts {
    pub const MAGIC: u32 = 0x43484C53; // "CHLS" (Chelsea)

    // Default values
    pub const DEFAULT_TRACE_ID: u64 = 0;

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

    // Trace event limits and sizes
    /// Maximum number of instructions per trace event
    pub const MAX_INSTRUCTIONS_PER_EVENT: u16 = 256;

    /// Maximum size of a single trace event
    pub const MAX_TRACE_EVENT_SIZE: u16 = 8192;

    /// Trace event message size
    pub const TRACE_EVENT_MESSAGE_SIZE: usize =
        std::mem::size_of::<crate::trace_event::TraceEventMessage>();

    /// Trace event header size
    pub const TRACE_EVENT_HEADER_SIZE: usize =
        std::mem::size_of::<crate::trace_event::TraceEventHeader>();

    /// Instruction header size
    pub const INSTRUCTION_HEADER_SIZE: usize =
        std::mem::size_of::<crate::trace_event::InstructionHeader>();

    /// Print variable index data size (extended with type_index)
    pub const PRINT_VARIABLE_INDEX_DATA_SIZE: usize =
        std::mem::size_of::<crate::trace_event::PrintVariableIndexData>();

    // TraceEventMessage field offsets
    pub const TRACE_EVENT_MESSAGE_TRACE_ID_OFFSET: usize = 0;
    pub const TRACE_EVENT_MESSAGE_TIMESTAMP_OFFSET: usize = 8;
    pub const TRACE_EVENT_MESSAGE_PID_OFFSET: usize = 16;
    pub const TRACE_EVENT_MESSAGE_TID_OFFSET: usize = 20;

    // InstructionHeader field offsets
    pub const INSTRUCTION_HEADER_INST_TYPE_OFFSET: usize = 0;
    pub const INSTRUCTION_HEADER_DATA_LENGTH_OFFSET: usize = 1;
    pub const INSTRUCTION_HEADER_RESERVED_OFFSET: usize = 3;

    // EndInstructionData relative offset from InstructionHeader start
    pub const END_INSTRUCTION_DATA_OFFSET: usize = 4;
    pub const END_INSTRUCTION_TOTAL_INSTRUCTIONS_OFFSET: usize = 0; // Within EndInstructionData
    pub const END_INSTRUCTION_EXECUTION_STATUS_OFFSET: usize = 2; // Within EndInstructionData
}

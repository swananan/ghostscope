//! Core protocol types and constants

use serde::{Deserialize, Serialize};

/// Variable type encoding - used by compiler and streaming parser
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
}

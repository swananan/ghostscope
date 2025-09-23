//! GhostScope Protocol Library
//!
//! Provides types and functionality for the GhostScope tracing protocol.

// Core modules
mod event;
mod types;
pub(crate) mod utils;

pub mod streaming_parser;
pub mod string_table;
pub mod trace_event;

pub use types::{consts, TypeEncoding};

pub use event::{EventMessageType, TraceEventData, VariableInfo};

pub use trace_event::{
    EndInstructionData, InstructionHeader, InstructionType, PrintStringIndexData,
    PrintVariableErrorData, PrintVariableIndexData, TraceEventHeader, TraceEventMessage,
};

pub use string_table::StringTable;

pub use streaming_parser::{ParseState, ParsedInstruction, ParsedTraceEvent, StreamingTraceParser};

pub use ghostscope_platform as platform;

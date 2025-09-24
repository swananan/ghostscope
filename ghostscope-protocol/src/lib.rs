//! GhostScope Protocol Library
//!
//! Provides types and functionality for the GhostScope tracing protocol.

// Core modules
mod types;
pub(crate) mod utils;

pub mod format_printer;
pub mod streaming_parser;
pub mod string_table;
pub mod trace_event;

pub use types::{consts, TypeEncoding};

pub use trace_event::{
    EndInstructionData, InstructionHeader, InstructionType, PrintFormatData, PrintStringIndexData,
    PrintVariableErrorData, PrintVariableIndexData, TraceEventHeader, TraceEventMessage,
    VariableData,
};

pub use string_table::StringTable;

pub use format_printer::{FormatPrinter, ParsedVariable};

pub use streaming_parser::{ParseState, ParsedInstruction, ParsedTraceEvent, StreamingTraceParser};

pub use ghostscope_platform as platform;

//! GhostScope Protocol Library
//!
//! Provides types and functionality for the GhostScope tracing protocol.

// Core modules
mod type_kind;

pub mod format_printer;
pub mod streaming_parser;
pub mod trace_context;
pub mod trace_event;
pub mod type_info;

pub use type_kind::{consts, TypeKind};

pub use trace_event::{
    EndInstructionData, InstructionHeader, InstructionType, PrintStringIndexData,
    PrintVariableIndexData, TraceEventHeader, TraceEventMessage, VariableStatus,
};

pub use trace_context::TraceContext;

pub use format_printer::FormatPrinter;

pub use streaming_parser::{
    EventSource, ParseState, ParsedInstruction, ParsedTraceEvent, StreamingTraceParser,
};

pub use type_info::{EnumVariant, StructMember, TypeCache, TypeInfo, TypeQualifier};

pub use ghostscope_platform as platform;

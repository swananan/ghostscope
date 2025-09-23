//! Event data structures for the protocol

use crate::streaming_parser::ParsedInstruction;
use crate::TypeEncoding;
use serde::{Deserialize, Serialize};

/// Type of event message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventMessageType {
    VariableData,     // Variable data message
    Log,              // Log message
    ExecutionFailure, // Execution failure message
    TraceEvent,       // New trace event with instructions
    Unknown,          // Unknown message type
}

/// Processed trace event data structure - used for communication between loader and UI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEventData {
    pub message_number: u64, // Unique message number assigned by UI
    pub trace_id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub variables: Vec<VariableInfo>,
    pub readable_timestamp: String,      // Human-readable timestamp
    pub message_type: EventMessageType,  // Type of the event message
    pub trace_instructions: Option<Vec<ParsedInstruction>>, // For new trace events
}

/// Variable information extracted from protocol message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VariableInfo {
    pub name: String,
    pub type_encoding: TypeEncoding,
    pub raw_data: Vec<u8>,
    pub formatted_value: String,
}

impl std::fmt::Display for TraceEventData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Event [no: {}, trace_id: {}, pid: {}, tid: {}, timestamp: {}]:",
            self.message_number, self.trace_id, self.pid, self.tid, self.readable_timestamp
        )?;
        for var in &self.variables {
            writeln!(
                f,
                "  {} ({:?}): {}",
                var.name, var.type_encoding, var.formatted_value
            )?;
        }
        Ok(())
    }
}

impl std::fmt::Display for VariableInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} = {}", self.name, self.formatted_value)
    }
}

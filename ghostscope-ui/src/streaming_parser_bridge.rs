//! Bridge between StreamingTraceParser and UI TraceEventData
//!
//! This module handles the integration of StreamingTraceParser with the UI crate,
//! converting parsed trace events into TraceEventData for the UI to display.

use ghostscope_protocol::{
    TraceEventData, EventMessageType, ParsedTraceEvent, StreamingTraceParser, StringTable,
};
use std::time::SystemTime;
use tracing::debug;

/// Bridge for streaming trace event parsing in UI context
pub struct StreamingParserBridge {
    parser: StreamingTraceParser,
    next_message_number: u64,
}

impl StreamingParserBridge {
    /// Create a new streaming parser bridge
    pub fn new() -> Self {
        Self {
            parser: StreamingTraceParser::new(),
            next_message_number: 1,
        }
    }

    /// Process incoming ringbuf segment and return complete TraceEventData if ready
    ///
    /// This method integrates with the existing UI architecture by:
    /// 1. Using StreamingTraceParser to reconstruct complete trace events
    /// 2. Converting ParsedTraceEvent to TraceEventData format expected by UI
    /// 3. Assigning message numbers for UI display
    pub fn process_ringbuf_segment(
        &mut self,
        segment_data: &[u8],
        string_table: &StringTable,
    ) -> Result<Option<TraceEventData>, String> {
        // Use StreamingTraceParser to process the segment
        let parsed_event = self.parser.process_segment(segment_data, string_table)?;

        if let Some(trace_event) = parsed_event {
            debug!(
                "Completed trace event: trace_id={}, {} instructions",
                trace_event.trace_id,
                trace_event.instructions.len()
            );

            // Convert ParsedTraceEvent to TraceEventData for UI
            let event_data = self.convert_to_event_data(trace_event);
            Ok(Some(event_data))
        } else {
            // Segment processed but event not yet complete
            Ok(None)
        }
    }

    /// Convert ParsedTraceEvent to TraceEventData format expected by UI
    fn convert_to_event_data(&mut self, trace_event: ParsedTraceEvent) -> TraceEventData {
        // Generate human-readable timestamp
        let readable_timestamp = self.format_timestamp(trace_event.timestamp);

        // Create TraceEventData with new instruction-based format
        let mut event_data = TraceEventData {
            message_number: self.next_message_number,
            trace_id: trace_event.trace_id,
            timestamp: trace_event.timestamp,
            pid: trace_event.pid,
            tid: trace_event.tid,
            variables: Vec::new(), // Empty for instruction-based events
            readable_timestamp,
            message_type: EventMessageType::TraceEvent, // New trace event type
            trace_instructions: Some(trace_event.instructions), // New field for instructions
        };

        self.next_message_number += 1;

        // Check execution status from EndInstruction
        if let Some(last_instruction) = event_data
            .trace_instructions
            .as_ref()
            .and_then(|insts| insts.last())
        {
            if let ghostscope_protocol::ParsedInstruction::EndInstruction {
                execution_status, ..
            } = last_instruction
            {
                match execution_status {
                    1 | 2 => {
                        // Mark as execution failure, UI can detect this from message_type
                        event_data.message_type = EventMessageType::ExecutionFailure;
                    }
                    _ => {} // Success, keep as TraceEvent
                }
            }
        }

        event_data
    }

    /// Format timestamp for human readability
    fn format_timestamp(&self, timestamp_ns: u64) -> String {
        let timestamp_secs = timestamp_ns / 1_000_000_000;
        let nanosecs = timestamp_ns % 1_000_000_000;

        match SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(timestamp_secs)) {
            Some(system_time) => {
                let datetime: chrono::DateTime<chrono::Utc> = system_time.into();
                format!("{}.{:09}", datetime.format("%Y-%m-%d %H:%M:%S"), nanosecs)
            }
            None => format!("{}ns", timestamp_ns),
        }
    }

    /// Reset parser state (useful for error recovery)
    pub fn reset(&mut self) {
        self.parser.reset();
    }

    /// Get current parse state for debugging
    pub fn get_parse_state(&self) -> &ghostscope_protocol::ParseState {
        self.parser.get_state()
    }

    /// Get statistics
    pub fn get_stats(&self) -> (u64, &ghostscope_protocol::ParseState) {
        (self.next_message_number - 1, self.parser.get_state())
    }
}

impl Default for StreamingParserBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghostscope_protocol::{ParsedInstruction, StringTable};

    #[test]
    fn test_streaming_parser_bridge() {
        let mut bridge = StreamingParserBridge::new();
        let string_table = StringTable::new();

        // Create test segment data (this would come from ringbuf in real usage)
        let test_segment = vec![0u8; 32]; // Placeholder

        // Process segment
        let result = bridge.process_ringbuf_segment(&test_segment, &string_table);

        // Should not fail even with placeholder data
        assert!(result.is_ok());
    }

    #[test]
    fn test_timestamp_formatting() {
        let bridge = StreamingParserBridge::new();

        // Test with a known timestamp
        let timestamp_ns = 1694700000_000_000_000; // September 14, 2023
        let formatted = bridge.format_timestamp(timestamp_ns);

        assert!(formatted.contains("2023"));
        assert!(formatted.contains(":"));
    }
}

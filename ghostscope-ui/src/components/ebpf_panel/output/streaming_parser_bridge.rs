//! Simplified bridge for streaming trace event parsing
//!
//! This module handles the integration of StreamingTraceParser with the UI crate,
//! returning ParsedTraceEvent directly for UI processing.

use ghostscope_protocol::{ParsedTraceEvent, StreamingTraceParser, StringTable};
use tracing::debug;

/// Bridge for streaming trace event parsing in UI context
pub struct StreamingParserBridge {
    parser: StreamingTraceParser,
}

impl StreamingParserBridge {
    /// Create a new streaming parser bridge
    pub fn new() -> Self {
        Self {
            parser: StreamingTraceParser::new(),
        }
    }

    /// Process incoming ringbuf segment and return complete ParsedTraceEvent if ready
    ///
    /// This method uses StreamingTraceParser to reconstruct complete trace events
    /// and returns them directly for UI processing.
    pub fn process_ringbuf_segment(
        &mut self,
        segment_data: &[u8],
        string_table: &StringTable,
    ) -> Result<Option<ParsedTraceEvent>, String> {
        // Use StreamingTraceParser to process the segment
        let parsed_event = self.parser.process_segment(segment_data, string_table)?;

        if let Some(trace_event) = parsed_event {
            debug!(
                "Completed trace event: trace_id={}, {} instructions",
                trace_event.trace_id,
                trace_event.instructions.len()
            );

            Ok(Some(trace_event))
        } else {
            // Segment processed but event not yet complete
            Ok(None)
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
}

impl Default for StreamingParserBridge {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghostscope_protocol::StringTable;

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
}

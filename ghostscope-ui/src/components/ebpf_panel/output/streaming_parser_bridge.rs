//! Simplified bridge for streaming trace event parsing
//!
//! This module handles the integration of StreamingTraceParser with the UI crate,
//! returning ParsedTraceEvent directly for UI processing.

use ghostscope_protocol::{ParsedTraceEvent, StreamingTraceParser, TraceContext};
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
        trace_context: &TraceContext,
    ) -> Result<Option<ParsedTraceEvent>, String> {
        // Use StreamingTraceParser to process the segment
        let parsed_event = self.parser.process_segment(segment_data, trace_context)?;

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
    use ghostscope_protocol::TraceContext;

    #[test]
    fn test_streaming_parser_bridge() {
        let mut bridge = StreamingParserBridge::new();
        let trace_context = TraceContext::new();

        // Create test segment data with valid TraceEventHeader
        use ghostscope_protocol::{consts, TraceEventHeader};
        let test_header = TraceEventHeader {
            magic: consts::MAGIC,
        };

        // Convert header to bytes
        let header_bytes = unsafe {
            std::slice::from_raw_parts(
                &test_header as *const _ as *const u8,
                std::mem::size_of::<TraceEventHeader>(),
            )
        };

        // Process valid header segment
        let result = bridge.process_ringbuf_segment(header_bytes, &trace_context);

        // Should succeed with valid header but return None (incomplete event)
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
    }
}

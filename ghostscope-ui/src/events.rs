mod channels;
mod debug_info;
mod runtime;
mod source_path;
mod trace_display;
mod tui_event;

pub use channels::{EventRegistry, RuntimeChannels, DEFAULT_TRACE_CHANNEL_CAPACITY};
pub use debug_info::{
    AddressMapping, ModuleDebugInfo, SectionInfo, SharedLibraryInfo, SourceCodeInfo,
    SourceFileGroup, SourceFileInfo, TargetDebugInfo, TargetType, VariableDebugInfo,
};
pub use runtime::{
    ExecutionStatus, LoadStatus, ModuleLoadingStats, RuntimeCommand, RuntimeStatus,
    ScriptCompilationDetails, ScriptExecutionResult, TraceDefinition, TraceDetailInfo,
    TraceLoadDetail, TraceStatus, TraceSummaryInfo,
};
pub use source_path::{PathSubstitution, SourcePathInfo};
pub use trace_display::{
    BacktraceDisplay, BacktraceDisplayFrame, ComplexVariableDisplay, ExprErrorDisplay,
    TraceDisplayItem, UiTraceEvent, VariableDisplay,
};
pub use tui_event::TuiEvent;

#[cfg(test)]
mod tests {
    use super::*;
    use ghostscope_protocol::{ParsedInstruction, ParsedTraceEvent, TypeKind};

    fn sample_event(trace_id: u64) -> UiTraceEvent {
        UiTraceEvent {
            timestamp: 0,
            trace_id,
            pid: 42,
            tid: 42,
            items: vec![],
            execution_status: None,
        }
    }

    #[test]
    fn event_registry_uses_bounded_trace_channel_capacity() {
        let (_registry, channels) = EventRegistry::new_with_trace_capacity(1);
        assert_eq!(channels.trace_channel_capacity, 1);

        channels.trace_sender.try_send(sample_event(1)).unwrap();
        assert!(channels.trace_sender.try_send(sample_event(2)).is_err());
    }

    #[test]
    fn protocol_event_preserves_structured_print_items() {
        let event = ParsedTraceEvent {
            trace_id: 7,
            timestamp: 11,
            pid: 42,
            tid: 43,
            instructions: vec![
                ParsedInstruction::PrintString {
                    content: "value={}".to_string(),
                },
                ParsedInstruction::PrintVariable {
                    name: "counter".to_string(),
                    type_encoding: TypeKind::U64,
                    formatted_value: "99".to_string(),
                    raw_data: Vec::new(),
                },
                ParsedInstruction::PrintVariable {
                    name: "standalone".to_string(),
                    type_encoding: TypeKind::I32,
                    formatted_value: "-1".to_string(),
                    raw_data: Vec::new(),
                },
                ParsedInstruction::PrintComplexVariable {
                    name: "req".to_string(),
                    access_path: "req.method".to_string(),
                    type_index: 12,
                    formatted_value: "req.method = GET".to_string(),
                    raw_data: Vec::new(),
                },
                ParsedInstruction::ExprError {
                    expr: "memcmp(buf, hex(\"41\"), 1)".to_string(),
                    error_code: 2,
                    flags: 0x01,
                    failing_addr: 0x1234,
                },
                ParsedInstruction::EndInstruction {
                    total_instructions: 5,
                    execution_status: 1,
                },
            ],
        };

        let display = UiTraceEvent::from_protocol_event(&event);
        assert_eq!(display.items.len(), 4);
        assert!(matches!(
            &display.items[0],
            TraceDisplayItem::FormattedText { content } if content == "value=99"
        ));
        assert!(matches!(
            &display.items[1],
            TraceDisplayItem::Variable(variable)
                if variable.name == "standalone"
                    && variable.type_name == "I32"
                    && variable.formatted_value == "-1"
        ));
        assert!(matches!(
            &display.items[2],
            TraceDisplayItem::ComplexVariable(variable)
                if variable.display_name() == "req.method"
                    && variable.to_formatted_output() == "req.method = GET"
        ));
        assert!(matches!(
            &display.items[3],
            TraceDisplayItem::ExprError(error)
                if error.reason() == "read error"
                    && error.readable_flags().as_deref() == Some("first-arg read-fail")
        ));
        assert!(display.is_error());
        assert_eq!(
            display.to_formatted_output(),
            vec![
                "value=99".to_string(),
                "standalone (I32): -1".to_string(),
                "req.method = GET".to_string(),
                "ExprError: memcmp(buf, hex(\"41\"), 1) (read error at 0x0000000000001234, flags: first-arg read-fail)".to_string(),
            ]
        );
    }
}

use crate::config::{ScriptOutputMode, ScriptTimestampFormat};
use ghostscope_protocol::ParsedTraceEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptOutputOptions {
    pub mode: ScriptOutputMode,
    pub timestamp: ScriptTimestampFormat,
}

pub fn render_script_event_lines(
    event: &ParsedTraceEvent,
    options: ScriptOutputOptions,
) -> Vec<String> {
    let formatted_output = event.to_formatted_output();
    if formatted_output.is_empty() {
        return Vec::new();
    }

    match options.mode {
        ScriptOutputMode::Quiet => Vec::new(),
        ScriptOutputMode::Plain => formatted_output,
        ScriptOutputMode::Pretty => {
            let mut lines = Vec::with_capacity(formatted_output.len() + 1);
            lines.push(render_pretty_header(event, options.timestamp));
            lines.extend(formatted_output.into_iter().map(|line| format!("  {line}")));
            lines
        }
    }
}

fn render_pretty_header(event: &ParsedTraceEvent, timestamp: ScriptTimestampFormat) -> String {
    let metadata = format!(
        "TraceID:{} PID:{} TID:{}",
        event.trace_id, event.pid, event.tid
    );

    match timestamp {
        ScriptTimestampFormat::Local => format!(
            "[{}] {metadata}",
            ghostscope_ui::utils::format_timestamp_ns(event.timestamp)
        ),
        ScriptTimestampFormat::Boot => {
            format!(
                "[{}] {metadata}",
                format_boot_offset_timestamp(event.timestamp)
            )
        }
        ScriptTimestampFormat::None => metadata,
    }
}

fn format_boot_offset_timestamp(ns_timestamp: u64) -> String {
    let ms = ns_timestamp / 1_000_000;
    let seconds = ms / 1000;
    let ms_remainder = ms % 1000;
    format!("boot+{seconds}.{ms_remainder:03}s")
}

#[cfg(test)]
mod tests {
    use super::{render_script_event_lines, ScriptOutputOptions};
    use crate::config::{ScriptOutputMode, ScriptTimestampFormat};
    use ghostscope_protocol::{ParsedInstruction, ParsedTraceEvent};

    fn sample_event() -> ParsedTraceEvent {
        ParsedTraceEvent {
            trace_id: 7,
            timestamp: 1_234_567_890,
            pid: 4321,
            tid: 4322,
            instructions: vec![
                ParsedInstruction::PrintString {
                    content: "hello".to_string(),
                },
                ParsedInstruction::PrintString {
                    content: "value = 42".to_string(),
                },
                ParsedInstruction::EndInstruction {
                    total_instructions: 2,
                    execution_status: 0,
                },
            ],
        }
    }

    #[test]
    fn pretty_output_includes_boot_timestamp_and_metadata() {
        let lines = render_script_event_lines(
            &sample_event(),
            ScriptOutputOptions {
                mode: ScriptOutputMode::Pretty,
                timestamp: ScriptTimestampFormat::Boot,
            },
        );

        assert_eq!(
            lines,
            vec![
                "[boot+1.234s] TraceID:7 PID:4321 TID:4322".to_string(),
                "  hello".to_string(),
                "  value = 42".to_string(),
            ]
        );
    }

    #[test]
    fn plain_output_keeps_only_script_payload_lines() {
        let lines = render_script_event_lines(
            &sample_event(),
            ScriptOutputOptions {
                mode: ScriptOutputMode::Plain,
                timestamp: ScriptTimestampFormat::Local,
            },
        );

        assert_eq!(lines, vec!["hello".to_string(), "value = 42".to_string()]);
    }

    #[test]
    fn quiet_output_suppresses_stdout_lines() {
        let lines = render_script_event_lines(
            &sample_event(),
            ScriptOutputOptions {
                mode: ScriptOutputMode::Quiet,
                timestamp: ScriptTimestampFormat::Boot,
            },
        );

        assert!(lines.is_empty());
    }

    #[test]
    fn pretty_output_can_omit_timestamp() {
        let lines = render_script_event_lines(
            &sample_event(),
            ScriptOutputOptions {
                mode: ScriptOutputMode::Pretty,
                timestamp: ScriptTimestampFormat::None,
            },
        );

        assert_eq!(lines[0], "TraceID:7 PID:4321 TID:4322");
    }
}

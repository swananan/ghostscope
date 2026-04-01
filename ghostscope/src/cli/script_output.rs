use crate::config::{ScriptOutputMode, ScriptTimestampFormat};
use ghostscope_protocol::ParsedTraceEvent;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScriptOutputOptions {
    pub mode: ScriptOutputMode,
    pub timestamp: ScriptTimestampFormat,
    pub color_enabled: bool,
}

#[derive(Debug)]
pub struct ScriptOutputRenderer {
    mode: ScriptOutputMode,
    colors: crate::cli::color::CliColors,
    pretty_timestamp: Option<PrettyTimestampFormatter>,
}

impl ScriptOutputRenderer {
    pub fn new(options: ScriptOutputOptions) -> Self {
        let pretty_timestamp = match options.mode {
            ScriptOutputMode::Pretty => Some(PrettyTimestampFormatter::new(options.timestamp)),
            ScriptOutputMode::Plain | ScriptOutputMode::Quiet => None,
        };

        Self {
            mode: options.mode,
            colors: crate::cli::color::CliColors::new(options.color_enabled),
            pretty_timestamp,
        }
    }

    pub fn render_event_lines(&mut self, event: &ParsedTraceEvent) -> Vec<String> {
        match self.mode {
            ScriptOutputMode::Quiet => Vec::new(),
            ScriptOutputMode::Plain => {
                let formatted_output = event.to_formatted_output();
                if formatted_output.is_empty() {
                    Vec::new()
                } else {
                    formatted_output
                }
            }
            ScriptOutputMode::Pretty => {
                let formatted_output = event.to_formatted_output();
                if formatted_output.is_empty() {
                    return Vec::new();
                }

                let mut lines = Vec::with_capacity(formatted_output.len() + 1);
                lines.push(self.render_pretty_header(event));
                lines.extend(formatted_output.into_iter().map(|line| format!("  {line}")));
                lines
            }
        }
    }

    fn render_pretty_header(&mut self, event: &ParsedTraceEvent) -> String {
        let metadata = format!(
            "{}:{} {}:{} {}:{}",
            self.colors.cyan("TraceID"),
            event.trace_id,
            self.colors.cyan("PID"),
            event.pid,
            self.colors.cyan("TID"),
            event.tid
        );

        match self
            .pretty_timestamp
            .as_mut()
            .expect("pretty timestamp formatter must exist for pretty mode")
            .format(event.timestamp)
        {
            Some(timestamp) => format!("{} {metadata}", self.colors.dim(format!("[{timestamp}]"))),
            None => metadata,
        }
    }
}

#[derive(Debug)]
enum PrettyTimestampFormatter {
    Local(LocalTimestampFormatter),
    Boot,
    None,
}

impl PrettyTimestampFormatter {
    fn new(timestamp: ScriptTimestampFormat) -> Self {
        match timestamp {
            ScriptTimestampFormat::Local => Self::Local(LocalTimestampFormatter::new()),
            ScriptTimestampFormat::Boot => Self::Boot,
            ScriptTimestampFormat::None => Self::None,
        }
    }

    fn format(&mut self, ns_timestamp: u64) -> Option<String> {
        match self {
            Self::Local(formatter) => Some(formatter.format(ns_timestamp)),
            Self::Boot => Some(format_boot_offset_timestamp(ns_timestamp)),
            Self::None => None,
        }
    }
}

#[derive(Debug)]
struct LocalTimestampFormatter {
    boot_time_unix_ns: Option<u64>,
    cached_second: Option<u64>,
    cached_prefix: String,
}

impl LocalTimestampFormatter {
    fn new() -> Self {
        Self::with_boot_time_unix_ns(current_boot_time_unix_ns())
    }

    fn with_boot_time_unix_ns(boot_time_unix_ns: Option<u64>) -> Self {
        Self {
            boot_time_unix_ns,
            cached_second: None,
            cached_prefix: String::new(),
        }
    }

    fn format(&mut self, ns_timestamp: u64) -> String {
        let Some(actual_time_ns) = self.actual_time_unix_ns(ns_timestamp) else {
            return format_boot_offset_timestamp(ns_timestamp);
        };

        let actual_time_secs = actual_time_ns / 1_000_000_000;
        let actual_time_nanos = (actual_time_ns % 1_000_000_000) as u32;
        let Some(prefix) = self.local_prefix_for_second(actual_time_secs) else {
            return format_boot_offset_timestamp(ns_timestamp);
        };

        format!("{prefix}.{:03}", actual_time_nanos / 1_000_000)
    }

    fn actual_time_unix_ns(&self, ns_timestamp: u64) -> Option<u64> {
        self.boot_time_unix_ns?.checked_add(ns_timestamp)
    }

    fn local_prefix_for_second(&mut self, unix_seconds: u64) -> Option<&str> {
        if self.cached_second != Some(unix_seconds) {
            let utc_datetime = chrono::DateTime::from_timestamp(unix_seconds as i64, 0)?;
            let local_datetime: chrono::DateTime<chrono::Local> = utc_datetime.into();
            self.cached_second = Some(unix_seconds);
            self.cached_prefix = local_datetime.format("%Y-%m-%d %H:%M:%S").to_string();
        }

        Some(self.cached_prefix.as_str())
    }
}

fn format_boot_offset_timestamp(ns_timestamp: u64) -> String {
    let ms = ns_timestamp / 1_000_000;
    let seconds = ms / 1000;
    let ms_remainder = ms % 1000;
    format!("boot+{seconds}.{ms_remainder:03}s")
}

fn current_boot_time_unix_ns() -> Option<u64> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
    let now_unix_ns = u64::try_from(now.as_nanos()).ok()?;
    let uptime_ns = get_system_uptime_ns()?;
    now_unix_ns.checked_sub(uptime_ns)
}

fn get_system_uptime_ns() -> Option<u64> {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|content| {
            let uptime_secs: f64 = content.split_whitespace().next()?.parse().ok()?;
            Some((uptime_secs * 1_000_000_000.0) as u64)
        })
}

#[cfg(test)]
mod tests {
    use super::{LocalTimestampFormatter, ScriptOutputOptions, ScriptOutputRenderer};
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

    fn render_with_renderer(event: &ParsedTraceEvent, options: ScriptOutputOptions) -> Vec<String> {
        let mut renderer = ScriptOutputRenderer::new(options);
        renderer.render_event_lines(event)
    }

    #[test]
    fn pretty_output_includes_boot_timestamp_and_metadata() {
        let lines = render_with_renderer(
            &sample_event(),
            ScriptOutputOptions {
                mode: ScriptOutputMode::Pretty,
                timestamp: ScriptTimestampFormat::Boot,
                color_enabled: false,
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
        let lines = render_with_renderer(
            &sample_event(),
            ScriptOutputOptions {
                mode: ScriptOutputMode::Plain,
                timestamp: ScriptTimestampFormat::Local,
                color_enabled: false,
            },
        );

        assert_eq!(lines, vec!["hello".to_string(), "value = 42".to_string()]);
    }

    #[test]
    fn quiet_output_suppresses_stdout_lines() {
        let lines = render_with_renderer(
            &sample_event(),
            ScriptOutputOptions {
                mode: ScriptOutputMode::Quiet,
                timestamp: ScriptTimestampFormat::Boot,
                color_enabled: false,
            },
        );

        assert!(lines.is_empty());
    }

    #[test]
    fn pretty_output_can_omit_timestamp() {
        let lines = render_with_renderer(
            &sample_event(),
            ScriptOutputOptions {
                mode: ScriptOutputMode::Pretty,
                timestamp: ScriptTimestampFormat::None,
                color_enabled: false,
            },
        );

        assert_eq!(lines[0], "TraceID:7 PID:4321 TID:4322");
    }

    #[test]
    fn renderer_quiet_mode_short_circuits_without_lines() {
        let mut renderer = ScriptOutputRenderer::new(ScriptOutputOptions {
            mode: ScriptOutputMode::Quiet,
            timestamp: ScriptTimestampFormat::Local,
            color_enabled: false,
        });

        assert!(renderer.render_event_lines(&sample_event()).is_empty());
    }

    #[test]
    fn local_timestamp_formatter_reuses_same_second_prefix() {
        let mut formatter =
            LocalTimestampFormatter::with_boot_time_unix_ns(Some(1_700_000_000_000_000_000));

        let first = formatter.format(1_234_111_000);
        let second = formatter.format(1_789_222_000);

        assert_eq!(&first[..19], &second[..19]);
        assert_ne!(first, second);
        assert!(formatter.cached_second.is_some());
        assert!(!formatter.cached_prefix.is_empty());
    }

    #[test]
    fn pretty_output_can_colorize_header() {
        let lines = render_with_renderer(
            &sample_event(),
            ScriptOutputOptions {
                mode: ScriptOutputMode::Pretty,
                timestamp: ScriptTimestampFormat::Boot,
                color_enabled: true,
            },
        );

        assert!(lines[0].contains("\u{1b}["));
    }
}

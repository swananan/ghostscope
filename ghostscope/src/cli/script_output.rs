use crate::config::{ScriptOutputMode, ScriptTimestampFormat};
use ghostscope_protocol::ParsedTraceEvent;
use std::io::{self, Write};
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
            ScriptOutputMode::Plain => None,
        };

        Self {
            mode: options.mode,
            colors: crate::cli::color::CliColors::new(options.color_enabled),
            pretty_timestamp,
        }
    }

    #[cfg(test)]
    pub fn render_event_lines(&mut self, event: &ParsedTraceEvent) -> Vec<String> {
        match self.mode {
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
                lines.extend(
                    formatted_output
                        .iter()
                        .map(|line| self.render_pretty_payload_line(line)),
                );
                lines
            }
        }
    }

    pub fn write_event<W: Write>(
        &mut self,
        event: &ParsedTraceEvent,
        writer: &mut W,
    ) -> io::Result<bool> {
        match self.mode {
            ScriptOutputMode::Plain => {
                let mut wrote = false;
                event.try_for_each_formatted_output(|line| {
                    wrote = true;
                    writeln!(writer, "{line}")
                })?;
                Ok(wrote)
            }
            ScriptOutputMode::Pretty => {
                if !event.has_formatted_output() {
                    return Ok(false);
                }

                writeln!(writer, "{}", self.render_pretty_header(event))?;
                event.try_for_each_formatted_output(|line| {
                    writeln!(writer, "{}", self.render_pretty_payload_line(line))
                })?;
                Ok(true)
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

    fn render_pretty_payload_line(&self, line: &str) -> String {
        format!("  {}", self.colorize_pretty_payload_line(line))
    }

    fn colorize_pretty_payload_line(&self, line: &str) -> String {
        if !self.colors.enabled() {
            return line.to_string();
        }

        if let Some(colored) = self.colorize_backtrace_header(line) {
            return colored;
        }
        if let Some(colored) = self.colorize_backtrace_frame(line) {
            return colored;
        }
        if line.starts_with("stopped: ") {
            return self.colors.red(line);
        }

        line.to_string()
    }

    fn colorize_backtrace_header(&self, line: &str) -> Option<String> {
        let rest = line.strip_prefix("backtrace: ")?;
        let (status, tail) = rest.split_once(',')?;
        if !tail.contains(" frame") || !tail.contains(" (max ") {
            return None;
        }

        Some(format!(
            "{}: {},{}",
            self.colors.bold("backtrace"),
            self.colorize_backtrace_status(status),
            tail
        ))
    }

    fn colorize_backtrace_status(&self, status: &str) -> String {
        match status {
            "complete" => self.colors.green(status),
            "truncated" => self.colors.yellow(status),
            _ => self.colors.red(status),
        }
    }

    fn colorize_backtrace_frame(&self, line: &str) -> Option<String> {
        let leading_len = line.len() - line.trim_start().len();
        let leading = &line[..leading_len];
        let rest = &line[leading_len..];
        if !rest.starts_with('#') {
            return None;
        }
        if !rest[1..]
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_digit())
        {
            return None;
        }

        let (frame, body) = rest.split_once(' ')?;
        let body = body.trim_start();
        let (body, module) = match body.rsplit_once(" [") {
            Some((body, module)) if module.ends_with(']') => (body, Some(format!("[{module}"))),
            _ => (body, None),
        };
        let body = match body.split_once(" at ") {
            Some((function, location)) => format!(
                "{} at {}",
                self.colorize_backtrace_function(function),
                self.colors.dim(location)
            ),
            None => body.to_string(),
        };

        let module = module
            .map(|module| format!(" {}", self.colors.yellow(module)))
            .unwrap_or_default();

        Some(format!(
            "{}{} {}{}",
            leading,
            self.colors.blue(frame),
            body,
            module
        ))
    }

    fn colorize_backtrace_function(&self, function: &str) -> String {
        match split_function_parameters(function) {
            Some((name, parameters)) => {
                format!(
                    "{}{}",
                    self.colors.bold(name),
                    self.colors.magenta(parameters)
                )
            }
            None => self.colors.bold(function),
        }
    }
}

fn split_function_parameters(function: &str) -> Option<(&str, &str)> {
    if !function.ends_with(')') {
        return None;
    }

    let mut depth = 0usize;
    for (index, ch) in function.char_indices().rev() {
        match ch {
            ')' => depth = depth.saturating_add(1),
            '(' => {
                if depth == 0 {
                    return None;
                }
                depth -= 1;
                if depth == 0 {
                    let name = &function[..index];
                    if name.is_empty() {
                        return None;
                    }
                    return Some((name, &function[index..]));
                }
            }
            _ => {}
        }
    }

    None
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
    use super::{
        split_function_parameters, LocalTimestampFormatter, ScriptOutputOptions,
        ScriptOutputRenderer,
    };
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

    fn sample_expr_error_event() -> ParsedTraceEvent {
        ParsedTraceEvent {
            trace_id: 8,
            timestamp: 2_000_000_000,
            pid: 5001,
            tid: 5002,
            instructions: vec![
                ParsedInstruction::ExprError {
                    expr: "memcmp(buf, hex(\"41\"), 1)".to_string(),
                    error_code: 2,
                    flags: 0x01,
                    failing_addr: 0x1234,
                },
                ParsedInstruction::EndInstruction {
                    total_instructions: 1,
                    execution_status: 1,
                },
            ],
        }
    }

    fn sample_backtrace_event() -> ParsedTraceEvent {
        ParsedTraceEvent {
            trace_id: 9,
            timestamp: 3_000_000_000,
            pid: 6001,
            tid: 6002,
            instructions: vec![
                ParsedInstruction::PrintString {
                    content: "backtrace: complete, 2 frames (max 128)".to_string(),
                },
                ParsedInstruction::PrintString {
                    content: "  #0 ngx_http_process_request(ngx_http_request_s* r) at /tmp/ngx_http_request.c:2054:1 [nginx+0x16e233]".to_string(),
                },
                ParsedInstruction::PrintString {
                    content: "stopped: read error (return-address-read-failed, code=1)"
                        .to_string(),
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
    fn plain_output_preserves_runtime_expr_errors() {
        let lines = render_with_renderer(
            &sample_expr_error_event(),
            ScriptOutputOptions {
                mode: ScriptOutputMode::Plain,
                timestamp: ScriptTimestampFormat::None,
                color_enabled: false,
            },
        );

        assert_eq!(
            lines,
            vec![
                "ExprError: memcmp(buf, hex(\"41\"), 1) (read error at 0x0000000000001234, flags: first-arg read-fail)"
                    .to_string()
            ]
        );
    }

    #[test]
    fn pretty_output_preserves_runtime_expr_errors_with_metadata() {
        let lines = render_with_renderer(
            &sample_expr_error_event(),
            ScriptOutputOptions {
                mode: ScriptOutputMode::Pretty,
                timestamp: ScriptTimestampFormat::None,
                color_enabled: false,
            },
        );

        assert_eq!(
            lines,
            vec![
                "TraceID:8 PID:5001 TID:5002".to_string(),
                "  ExprError: memcmp(buf, hex(\"41\"), 1) (read error at 0x0000000000001234, flags: first-arg read-fail)"
                    .to_string(),
            ]
        );
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

    #[test]
    fn pretty_output_colorizes_backtrace_payload_only_when_enabled() {
        let colored = render_with_renderer(
            &sample_backtrace_event(),
            ScriptOutputOptions {
                mode: ScriptOutputMode::Pretty,
                timestamp: ScriptTimestampFormat::None,
                color_enabled: true,
            },
        );
        assert!(
            colored.iter().skip(1).any(|line| line.contains("\u{1b}[")),
            "expected ANSI color in pretty backtrace payload: {colored:?}"
        );
        assert!(
            colored.iter().any(|line| line.contains(
                "\u{1b}[1mngx_http_process_request\u{1b}[0m\u{1b}[35m(ngx_http_request_s* r)\u{1b}[0m"
            )),
            "expected function name and parameters to use distinct colors: {colored:?}"
        );

        let plain = render_with_renderer(
            &sample_backtrace_event(),
            ScriptOutputOptions {
                mode: ScriptOutputMode::Plain,
                timestamp: ScriptTimestampFormat::None,
                color_enabled: true,
            },
        );
        assert!(
            plain.iter().all(|line| !line.contains("\u{1b}[")),
            "plain script output must not colorize payload: {plain:?}"
        );
    }

    #[test]
    fn backtrace_signature_colorizer_splits_trailing_parameter_list() {
        assert_eq!(
            split_function_parameters("ngx_epoll_process_events(ngx_cycle_s* cycle, long unsigned int timer, long unsigned int flags)"),
            Some((
                "ngx_epoll_process_events",
                "(ngx_cycle_s* cycle, long unsigned int timer, long unsigned int flags)"
            ))
        );
        assert_eq!(
            split_function_parameters("operator()(int value)"),
            Some(("operator()", "(int value)"))
        );
        assert_eq!(
            split_function_parameters("call_with_callback(void (*cb)(int))"),
            Some(("call_with_callback", "(void (*cb)(int))"))
        );
        assert_eq!(split_function_parameters("<unknown function>"), None);
    }
}

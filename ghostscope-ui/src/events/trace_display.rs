use ghostscope_protocol::{
    trace_event::{backtrace_error_label, BacktraceStatus},
    ParsedInstruction, ParsedTraceEvent,
};

/// Runtime trace event after conversion into display items.
///
/// This keeps the UI transport structured without changing the eBPF/protocol
/// wire format. Backtraces, variables, and runtime expression errors keep their
/// fields for dedicated CLI/TUI rendering.
#[derive(Debug, Clone)]
pub struct UiTraceEvent {
    pub trace_id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub items: Vec<TraceDisplayItem>,
    pub execution_status: Option<u8>,
}

impl UiTraceEvent {
    pub fn from_protocol_event(event: &ParsedTraceEvent) -> Self {
        let execution_status = event.instructions.iter().rev().find_map(|instruction| {
            if let ghostscope_protocol::ParsedInstruction::EndInstruction {
                execution_status, ..
            } = instruction
            {
                Some(*execution_status)
            } else {
                None
            }
        });

        Self {
            trace_id: event.trace_id,
            timestamp: event.timestamp,
            pid: event.pid,
            tid: event.tid,
            items: protocol_instructions_to_display_items(&event.instructions),
            execution_status,
        }
    }

    pub fn text_event(
        trace_id: u64,
        timestamp: u64,
        pid: u32,
        tid: u32,
        content: String,
        execution_status: Option<u8>,
    ) -> Self {
        Self {
            trace_id,
            timestamp,
            pid,
            tid,
            items: vec![TraceDisplayItem::Text { content }],
            execution_status,
        }
    }

    pub fn to_formatted_output(&self) -> Vec<String> {
        self.items
            .iter()
            .flat_map(TraceDisplayItem::to_formatted_output)
            .collect()
    }

    pub fn is_error(&self) -> bool {
        self.execution_status
            .is_some_and(|status| status == 1 || status == 2)
            || self.items.iter().any(|item| match item {
                TraceDisplayItem::ExprError(_) => true,
                TraceDisplayItem::Backtrace(backtrace) => {
                    backtrace.status != BacktraceStatus::Complete
                        && backtrace.status != BacktraceStatus::Truncated
                }
                _ => false,
            })
    }
}

#[derive(Debug, Clone)]
pub enum TraceDisplayItem {
    Text { content: String },
    FormattedText { content: String },
    Variable(VariableDisplay),
    ComplexVariable(ComplexVariableDisplay),
    ExprError(ExprErrorDisplay),
    Backtrace(BacktraceDisplay),
}

impl TraceDisplayItem {
    pub fn to_formatted_output(&self) -> Vec<String> {
        match self {
            Self::Text { content } => vec![content.clone()],
            Self::FormattedText { content } => vec![content.clone()],
            Self::Variable(variable) => vec![variable.to_formatted_output()],
            Self::ComplexVariable(variable) => vec![variable.to_formatted_output()],
            Self::ExprError(error) => vec![error.to_formatted_output()],
            Self::Backtrace(backtrace) => backtrace.to_formatted_output(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct VariableDisplay {
    pub name: String,
    pub type_name: String,
    pub formatted_value: String,
}

impl VariableDisplay {
    pub fn to_formatted_output(&self) -> String {
        format!(
            "{} ({}): {}",
            self.name, self.type_name, self.formatted_value
        )
    }
}

#[derive(Debug, Clone)]
pub struct ComplexVariableDisplay {
    pub name: String,
    pub access_path: String,
    pub type_index: u16,
    pub formatted_value: String,
}

impl ComplexVariableDisplay {
    pub fn display_name(&self) -> &str {
        if self.access_path.is_empty() {
            &self.name
        } else {
            &self.access_path
        }
    }

    pub fn to_formatted_output(&self) -> String {
        self.formatted_value.clone()
    }
}

#[derive(Debug, Clone)]
pub struct ExprErrorDisplay {
    pub expr: String,
    pub error_code: u8,
    pub flags: u8,
    pub failing_addr: u64,
}

impl ExprErrorDisplay {
    pub fn reason(&self) -> &'static str {
        match self.error_code {
            1 => "null deref",
            2 => "read error",
            3 => "access error",
            4 => "truncated",
            5 => "offsets unavailable",
            6 => "zero length",
            _ => "error",
        }
    }

    pub fn readable_flags(&self) -> Option<String> {
        if self.flags == 0 {
            return None;
        }
        let mut tags: Vec<&'static str> = Vec::new();
        let is_memcmp = self.expr.contains("memcmp(");
        let is_strncmp = self.expr.contains("strncmp(") || self.expr.contains("starts_with(");
        if is_memcmp {
            if (self.flags & 0x01) != 0 {
                tags.push("first-arg read-fail");
            }
            if (self.flags & 0x02) != 0 {
                tags.push("second-arg read-fail");
            }
            if (self.flags & 0x04) != 0 {
                tags.push("len-clamped");
            }
            if (self.flags & 0x08) != 0 {
                tags.push("len=0");
            }
        } else if is_strncmp {
            if (self.flags & 0x01) != 0 {
                tags.push("read-fail");
            }
            if (self.flags & 0x04) != 0 {
                tags.push("len-clamped");
            }
            if (self.flags & 0x08) != 0 {
                tags.push("len=0");
            }
        } else {
            return Some(format!("0x{:02x}", self.flags));
        }

        (!tags.is_empty()).then(|| tags.join(","))
    }

    pub fn addr_text(&self) -> String {
        if self.failing_addr != 0 {
            format!("at 0x{:016x}", self.failing_addr)
        } else {
            "at NULL".to_string()
        }
    }

    pub fn to_formatted_output(&self) -> String {
        let base = format!(
            "ExprError: {} ({} {}",
            self.expr,
            self.reason(),
            self.addr_text()
        );
        match self.readable_flags() {
            Some(flags) => format!("{base}, flags: {flags})"),
            None => format!("{base})"),
        }
    }
}

fn protocol_instructions_to_display_items(
    instructions: &[ParsedInstruction],
) -> Vec<TraceDisplayItem> {
    let mut items = Vec::new();
    let mut index = 0usize;

    while index < instructions.len() {
        match &instructions[index] {
            ParsedInstruction::PrintString { content } => {
                if content.contains("{}") {
                    let (formatted, consumed) =
                        format_string_with_variable_items(content, instructions, index + 1);
                    items.push(TraceDisplayItem::FormattedText { content: formatted });
                    index += consumed;
                } else {
                    items.push(TraceDisplayItem::Text {
                        content: content.clone(),
                    });
                    index += 1;
                }
            }
            ParsedInstruction::PrintVariable {
                name,
                type_encoding,
                formatted_value,
                ..
            } => {
                items.push(TraceDisplayItem::Variable(VariableDisplay {
                    name: name.clone(),
                    type_name: format!("{type_encoding:?}"),
                    formatted_value: formatted_value.clone(),
                }));
                index += 1;
            }
            ParsedInstruction::ExprError {
                expr,
                error_code,
                flags,
                failing_addr,
            } => {
                items.push(TraceDisplayItem::ExprError(ExprErrorDisplay {
                    expr: expr.clone(),
                    error_code: *error_code,
                    flags: *flags,
                    failing_addr: *failing_addr,
                }));
                index += 1;
            }
            ParsedInstruction::PrintComplexFormat { formatted_output } => {
                items.push(TraceDisplayItem::FormattedText {
                    content: formatted_output.clone(),
                });
                index += 1;
            }
            ParsedInstruction::PrintComplexVariable {
                name,
                access_path,
                type_index,
                formatted_value,
                ..
            } => {
                items.push(TraceDisplayItem::ComplexVariable(ComplexVariableDisplay {
                    name: name.clone(),
                    access_path: access_path.clone(),
                    type_index: *type_index,
                    formatted_value: formatted_value.clone(),
                }));
                index += 1;
            }
            ParsedInstruction::Backtrace { .. } => {
                index += 1;
            }
            ParsedInstruction::EndInstruction { .. } => {
                index += 1;
            }
        }
    }

    items
}

fn format_string_with_variable_items(
    format_string: &str,
    instructions: &[ParsedInstruction],
    start_index: usize,
) -> (String, usize) {
    let placeholder_count = format_string.matches("{}").count();
    let mut consumed = 1;
    let mut result = String::with_capacity(format_string.len());
    let mut remaining = format_string;

    for instruction_index in start_index..(start_index + placeholder_count).min(instructions.len())
    {
        let Some(pos) = remaining.find("{}") else {
            break;
        };

        if let Some(ParsedInstruction::PrintVariable {
            formatted_value, ..
        }) = instructions.get(instruction_index)
        {
            result.push_str(&remaining[..pos]);
            result.push_str(formatted_value);
            consumed += 1;
            remaining = &remaining[pos + 2..];
        } else {
            break;
        }
    }
    result.push_str(remaining);

    (result, consumed)
}

#[derive(Debug, Clone)]
pub struct BacktraceDisplay {
    pub requested_depth: u8,
    pub physical_frame_count: usize,
    pub status: BacktraceStatus,
    pub error_code: u16,
    pub raw: bool,
    pub frames: Vec<BacktraceDisplayFrame>,
}

impl BacktraceDisplay {
    pub fn header_text(&self) -> String {
        let frame_word = if self.physical_frame_count == 1 {
            "frame"
        } else {
            "frames"
        };
        format!(
            "backtrace: {}, {} {} (max {})",
            self.status.label(),
            self.physical_frame_count,
            frame_word,
            self.requested_depth
        )
    }

    pub fn stopped_text(&self) -> Option<String> {
        if self.status == BacktraceStatus::Complete {
            return None;
        }

        let suffix = match backtrace_error_label(self.error_code) {
            Some("unknown") => format!(" (code={})", self.error_code),
            Some(label) => format!(" ({label}, code={})", self.error_code),
            None => String::new(),
        };
        Some(format!("stopped: {}{}", self.status.label(), suffix))
    }

    pub fn to_formatted_output(&self) -> Vec<String> {
        let mut output = Vec::with_capacity(self.frames.len() + 2);
        output.push(self.header_text());
        output.extend(
            self.frames
                .iter()
                .map(BacktraceDisplayFrame::to_formatted_output),
        );
        if let Some(stopped) = self.stopped_text() {
            output.push(stopped);
        }
        output
    }
}

#[derive(Debug, Clone)]
pub struct BacktraceDisplayFrame {
    pub index: usize,
    pub inline: bool,
    pub function: Option<String>,
    pub parameters: Vec<String>,
    pub address: Option<String>,
    pub location: Option<String>,
    pub module: String,
    pub raw_ip: Option<u64>,
    pub cookie: Option<u64>,
    pub flags: Option<u16>,
}

impl BacktraceDisplayFrame {
    pub fn to_formatted_output(&self) -> String {
        let mut line = String::from("  #");
        line.push_str(&self.index.to_string());
        if self.inline {
            line.push_str(".inline");
        }
        line.push(' ');

        if let Some(function) = &self.function {
            line.push_str(function);
            if !self.parameters.is_empty() {
                line.push('(');
                line.push_str(&self.parameters.join(", "));
                line.push(')');
            }
        } else if let Some(address) = &self.address {
            line.push_str(address);
        } else {
            line.push_str("<unknown function>");
        }

        if let Some(location) = &self.location {
            line.push_str(" at ");
            line.push_str(location);
        } else if self.function.is_some() {
            line.push_str(" at ??");
        }
        line.push_str(" [");
        line.push_str(&self.module);
        line.push(']');

        if let Some(raw_ip) = self.raw_ip {
            line.push_str(&format!(" raw=0x{raw_ip:x}"));
        }
        if let Some(cookie) = self.cookie {
            line.push_str(&format!(" cookie=0x{cookie:016x}"));
        }
        if let Some(flags) = self.flags {
            line.push_str(&format!(" flags=0x{flags:x}"));
        }

        line
    }
}

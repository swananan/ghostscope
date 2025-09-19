/// Snapshot of a trace instance for serialization and transfer
#[derive(Debug, Clone)]
pub struct TraceSnapshot {
    pub trace_id: u32,
    pub target: String,
    pub script_content: String,
    pub binary_path: String,
    pub target_display: String,
    pub target_pid: Option<u32>,
    pub is_enabled: bool,
    pub pc: u64,
    pub ebpf_function_name: String,
}

/// Summary statistics for all traces
#[derive(Debug, Clone)]
pub struct TraceSummary {
    pub total: usize,
    pub active: usize,
    pub disabled: usize,
}

impl TraceSummary {
    pub fn new() -> Self {
        Self {
            total: 0,
            active: 0,
            disabled: 0,
        }
    }

    pub fn format_for_display(&self) -> FormattedTraceInfo {
        FormattedTraceInfo::new(format!(
            "Total: {}, Active: {}, Disabled: {}",
            self.total, self.active, self.disabled
        ))
    }
}

/// Formatted trace information for display
#[derive(Debug, Clone)]
pub struct FormattedTraceInfo {
    pub is_enabled: bool,
    pub target_display: String,
    pub script_content: String,
    pub binary_path: String,
    pub target_pid: Option<u32>,
    pub pc: u64,
    pub error_message: Option<String>,
}

impl FormattedTraceInfo {
    pub fn new(content: String) -> Self {
        Self {
            is_enabled: false,
            target_display: content,
            script_content: String::new(),
            binary_path: String::new(),
            target_pid: None,
            pc: 0,
            error_message: None,
        }
    }

    pub fn display_line(&self) -> String {
        let status_icon = if self.is_enabled { "🟢" } else { "🔴" };
        let mut line = format!(
            "{} {} | PC: 0x{:x}",
            status_icon, self.target_display, self.pc
        );

        if let Some(pid) = self.target_pid {
            line.push_str(&format!(" | PID: {}", pid));
        }

        if let Some(ref error) = self.error_message {
            line.push_str(&format!(" | Error: {}", error));
        }

        line
    }
}

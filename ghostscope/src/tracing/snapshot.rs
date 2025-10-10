/// Snapshot of a trace instance for serialization and transfer
#[derive(Debug, Clone)]
pub struct TraceSnapshot {
    #[allow(dead_code)]
    pub trace_id: u32,
    pub target: String,
    pub script_content: String,
    pub binary_path: String,
    pub target_display: String,
    pub target_pid: Option<u32>,
    pub is_enabled: bool,
    pub pc: u64,
    #[allow(dead_code)]
    pub ebpf_function_name: String,
}

/// Summary statistics for all traces
#[derive(Debug, Clone)]
pub struct TraceSummary {
    pub total: usize,
    pub active: usize,
    pub disabled: usize,
}

impl TraceSummary {}

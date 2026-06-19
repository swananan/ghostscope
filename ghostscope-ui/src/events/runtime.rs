use super::debug_info::{
    SectionInfo, SharedLibraryInfo, SourceCodeInfo, SourceFileGroup, TargetDebugInfo,
};
use super::source_path::SourcePathInfo;
use unicode_width::UnicodeWidthStr;

/// Trace status enumeration for shared use between UI and runtime
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceStatus {
    Active,
    Disabled,
    Failed,
}

impl std::fmt::Display for TraceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceStatus::Active => write!(f, "Active"),
            TraceStatus::Disabled => write!(f, "Disabled"),
            TraceStatus::Failed => write!(f, "Failed"),
        }
    }
}

impl TraceStatus {
    /// Convert to emoji representation
    pub fn to_emoji(&self) -> String {
        match self {
            TraceStatus::Active => "✅".to_string(),
            TraceStatus::Disabled => "⏸️".to_string(),
            TraceStatus::Failed => "❌".to_string(),
        }
    }

    /// Parse from string (for backward compatibility)
    pub fn from_string(s: &str) -> Self {
        match s {
            "Active" => TraceStatus::Active,
            "Disabled" => TraceStatus::Disabled,
            "Failed" => TraceStatus::Failed,
            _ => TraceStatus::Failed, // Default to Failed for unknown status
        }
    }
}

/// Commands that TUI can send to runtime
#[derive(Debug, Clone)]
pub enum RuntimeCommand {
    ExecuteScript {
        command: String,
        selected_index: Option<usize>,
    },
    RequestSourceCode, // Request source code for current function/address
    DisableTrace(u32), // Disable specific trace by ID
    EnableTrace(u32),  // Enable specific trace by ID
    DisableAllTraces,  // Disable all traces
    EnableAllTraces,   // Enable all traces
    DeleteTrace(u32),  // Completely delete specific trace and all resources
    DeleteAllTraces,   // Delete all traces and resources
    InfoFunction {
        target: String,
        verbose: bool,
    }, // Get debug info for a function by name
    InfoLine {
        target: String,
        verbose: bool,
    }, // Get debug info for a source line (file:line)
    InfoAddress {
        target: String,
        verbose: bool,
    }, // Get debug info for a memory address (TODO: not implemented yet)
    InfoTrace {
        trace_id: Option<u32>,
    }, // Get info for one/all traces (individual messages)
    InfoTraceAll,
    InfoSource, // Get all source files information
    InfoShare,  // Get shared library information (like GDB's "info share")
    InfoFile,   // Get executable file information and sections (like GDB's "info file")
    SaveTraces {
        filename: Option<String>,
        filter: crate::components::command_panel::trace_persistence::SaveFilter,
    }, // Save traces to a file
    LoadTraces {
        filename: String,
        traces: Vec<TraceDefinition>,
    }, // Load traces from a file
    SrcPathList,
    SrcPathAddDir {
        dir: String,
    },
    SrcPathAddMap {
        from: String,
        to: String,
    },
    SrcPathRemove {
        pattern: String,
    },
    SrcPathClear,
    SrcPathReset,
    Shutdown,
}

/// Definition of a trace to be loaded
#[derive(Debug, Clone)]
pub struct TraceDefinition {
    pub target: String,
    pub script: String,
    pub enabled: bool,
    pub selected_index: Option<usize>,
}

/// Result of loading a single trace
#[derive(Debug, Clone)]
pub struct TraceLoadDetail {
    pub target: String,
    pub trace_id: Option<u32>,
    pub status: LoadStatus,
    pub error: Option<String>,
}

/// Status of loading a trace
#[derive(Debug, Clone)]
pub enum LoadStatus {
    Created,         // Successfully created and enabled
    CreatedDisabled, // Created but disabled
    Failed,          // Failed to create
    Skipped,         // Skipped (e.g., duplicate)
}

/// Execution status for individual script targets
#[derive(Debug, Clone)]
pub enum ExecutionStatus {
    Success,
    Failed(String),  // Contains error message
    Skipped(String), // Contains reason for skipping
}

/// Result of executing a single script target (PC/function)
#[derive(Debug, Clone)]
pub struct ScriptExecutionResult {
    pub pc_address: u64,
    pub target_name: String,
    pub binary_path: String, // Full path to the binary
    pub status: ExecutionStatus,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
    pub is_inline: Option<bool>,
}

/// Detailed compilation result for a script with multiple targets
#[derive(Debug, Clone)]
pub struct ScriptCompilationDetails {
    pub trace_ids: Vec<u32>, // List of generated trace IDs (one per successful compilation)
    pub results: Vec<ScriptExecutionResult>,
    pub total_count: usize,
    pub success_count: usize,
    pub failed_count: usize,
}

#[derive(Debug, Clone)]
pub enum RuntimeStatus {
    DwarfLoadingStarted,
    DwarfLoadingCompleted {
        symbols_count: usize,
    },
    DwarfLoadingFailed(String),
    ScriptCompilationCompleted {
        details: ScriptCompilationDetails, // Contains trace_ids, success/failed counts and results
    },
    UprobeAttached {
        function: String,
        address: u64,
    },
    UprobeDetached {
        function: String,
    },
    SourceCodeLoaded(SourceCodeInfo),
    SourceCodeLoadFailed(String),
    TraceEnabled {
        trace_id: u32,
    },
    TraceDisabled {
        trace_id: u32,
    },
    AllTracesEnabled {
        count: usize,
        error: Option<String>, // Error message if operation completely failed
    },
    AllTracesDisabled {
        count: usize,
        error: Option<String>, // Error message if operation completely failed
    },
    TraceEnableFailed {
        trace_id: u32,
        error: String,
    },
    TraceDisableFailed {
        trace_id: u32,
        error: String,
    },
    TraceDeleted {
        trace_id: u32,
    },
    AllTracesDeleted {
        count: usize,
        error: Option<String>, // Error message if operation completely failed
    },
    TraceDeleteFailed {
        trace_id: u32,
        error: String,
    },
    InfoFunctionResult {
        target: String,
        info: TargetDebugInfo,
        verbose: bool,
    },
    InfoFunctionFailed {
        target: String,
        error: String,
    },
    InfoLineResult {
        target: String,
        info: TargetDebugInfo,
        verbose: bool,
    },
    InfoLineFailed {
        target: String,
        error: String,
    },
    InfoAddressResult {
        target: String,
        info: TargetDebugInfo,
        verbose: bool,
    },
    InfoAddressFailed {
        target: String,
        error: String,
    },
    /// Detailed info for a trace (summary + PC)
    TraceInfo {
        trace_id: u32,
        target: String,
        status: TraceStatus,
        pid: Option<u32>,
        host_pid: Option<u32>,
        binary: String,
        script_preview: Option<String>,
        pc: u64,
    },
    /// All trace info with structured data for UI rendering
    TraceInfoAll {
        summary: TraceSummaryInfo,
        traces: Vec<TraceDetailInfo>,
    },
    /// Failed to get info for a specific trace
    TraceInfoFailed {
        trace_id: u32,
        error: String,
    },
    /// Source file information response (grouped by module)
    FileInfo {
        groups: Vec<SourceFileGroup>,
    },
    /// Failed to get file information
    FileInfoFailed {
        error: String,
    },
    /// Traces saved to file successfully
    TracesSaved {
        filename: String,
        saved_count: usize,
        total_count: usize,
    },
    /// Failed to save traces
    TracesSaveFailed {
        error: String,
    },
    /// Traces loaded from file successfully
    TracesLoaded {
        filename: String,
        total_count: usize,
        success_count: usize,
        failed_count: usize,
        disabled_count: usize,
        details: Vec<TraceLoadDetail>,
    },
    /// Failed to load traces
    TracesLoadFailed {
        filename: String,
        error: String,
    },
    /// Shared library information response
    ShareInfo {
        libraries: Vec<SharedLibraryInfo>,
    },
    /// Failed to get shared library information
    ShareInfoFailed {
        error: String,
    },
    /// Executable file information response
    ExecutableFileInfo {
        file_path: String,
        file_type: String,
        entry_point: Option<u64>,
        has_symbols: bool,
        has_debug_info: bool,
        debug_file_path: Option<String>,
        text_section: Option<SectionInfo>,
        data_section: Option<SectionInfo>,
        mode_description: String,
    },
    /// Failed to get executable file information
    ExecutableFileInfoFailed {
        error: String,
    },
    // Module-level loading progress (new)
    DwarfModuleDiscovered {
        module_path: String,
        total_modules: usize,
    },
    DwarfModuleLoadingStarted {
        module_path: String,
        current: usize,
        total: usize,
    },
    DwarfModuleLoadingCompleted {
        module_path: String,
        stats: ModuleLoadingStats,
        current: usize,
        total: usize,
    },
    DwarfModuleLoadingFailed {
        module_path: String,
        error: String,
        current: usize,
        total: usize,
    },
    SrcPathInfo {
        info: SourcePathInfo,
    },
    SrcPathUpdated {
        message: String,
    },
    SrcPathFailed {
        error: String,
    },
    /// Runtime->UI trace channel backpressure warning (events dropped)
    TraceBackpressure {
        dropped_since_last: u64,
        dropped_total: u64,
        queue_capacity: usize,
    },
    /// eBPF program failed to write events into the kernel output buffer.
    EbpfOutputLoss {
        trace_id: u32,
        target_display: String,
        lost_since_last: u64,
        lost_total: u64,
    },
}

/// Statistics for a loaded module
#[derive(Debug, Clone)]
pub struct ModuleLoadingStats {
    pub functions: usize,
    pub variables: usize,
    pub types: usize,
    pub debug_source: String,
    pub debug_source_path: Option<String>,
    pub load_time_ms: u64,
}

/// Summary information for all traces
#[derive(Debug, Clone)]
pub struct TraceSummaryInfo {
    pub total: usize,
    pub active: usize,
    pub disabled: usize,
}

/// Detailed information for a specific trace
#[derive(Debug, Clone)]
pub struct TraceDetailInfo {
    pub trace_id: u32,
    pub target_display: String,
    pub binary_path: String,
    pub pc: u64,
    pub status: TraceStatus,
    pub duration: String, // "5m32s", "1h5m", etc.
}

impl TraceDetailInfo {
    /// Format trace info line with binary path and PC information
    pub fn format_line(&self) -> String {
        // Extract binary name from path for cleaner display
        let binary_name = std::path::Path::new(&self.binary_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&self.binary_path);

        format!(
            "#{} | {}+0x{:x} | {} ({}) ",
            self.trace_id, binary_name, self.pc, self.target_display, self.status
        )
    }
}

impl RuntimeStatus {
    /// Format TraceInfo for enhanced display
    pub fn format_trace_info(&self) -> Option<String> {
        match self {
            RuntimeStatus::TraceInfo {
                trace_id,
                target,
                status,
                pid,
                host_pid,
                binary,
                script_preview,
                pc,
            } => {
                // Header line
                let mut result =
                    format!("🔎 Trace [{}] {} {}\n", trace_id, status.to_emoji(), status);

                // Collect fields for aligned key-value formatting
                let binary_name = std::path::Path::new(binary)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(binary);

                let mut fields: Vec<(&str, String)> = Vec::new();
                fields.push(("🎯 Target", target.clone()));
                fields.push(("📦 Binary", binary.clone()));
                fields.push(("📍 Address", format!("{binary_name}+0x{pc:x}")));
                match (pid, host_pid) {
                    (Some(proc_pid), Some(host_pid_val)) if proc_pid != host_pid_val => {
                        fields.push(("🏷️ PID(proc)", proc_pid.to_string()));
                        fields.push(("🏷️ PID(host)", host_pid_val.to_string()));
                    }
                    (Some(proc_pid), _) => {
                        fields.push(("🏷️ PID", proc_pid.to_string()));
                    }
                    (None, Some(host_pid_val)) => {
                        fields.push(("🏷️ PID(host)", host_pid_val.to_string()));
                    }
                    (None, None) => {}
                }
                if let Some(ref script) = script_preview {
                    fields.push(("📝 Script", script.clone()));
                }

                // Compute max key width (accounting for emoji display width)
                let max_key_width = fields.iter().map(|(k, _)| k.width()).max().unwrap_or(0);

                for (key, value) in fields {
                    let key_width = key.width();
                    let pad = max_key_width.saturating_sub(key_width);
                    let spaces = " ".repeat(pad);
                    result.push_str(&format!("  {key}{spaces}: {value}\n"));
                }

                Some(result)
            }
            _ => None,
        }
    }

    /// Styled version of TraceInfo for display
    pub fn format_trace_info_styled(&self) -> Option<Vec<ratatui::text::Line<'static>>> {
        use crate::components::command_panel::style_builder::{StylePresets, StyledLineBuilder};
        use ratatui::text::Line;

        match self {
            RuntimeStatus::TraceInfo {
                trace_id,
                target,
                status,
                pid,
                host_pid,
                binary,
                script_preview: _,
                pc,
            } => {
                let mut lines = Vec::new();

                // Title
                lines.push(
                    StyledLineBuilder::new()
                        .title(format!(
                            "🔎 Trace [{}] {} {}",
                            trace_id,
                            status.to_emoji(),
                            status
                        ))
                        .build(),
                );

                let binary_name = std::path::Path::new(binary)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(binary)
                    .to_string();

                lines.push(
                    StyledLineBuilder::new()
                        .text("  ")
                        .key("🎯 Target:")
                        .text(" ")
                        .value(target)
                        .build(),
                );
                lines.push(
                    StyledLineBuilder::new()
                        .text("  ")
                        .key("📦 Binary:")
                        .text(" ")
                        .value(binary)
                        .build(),
                );
                lines.push(
                    StyledLineBuilder::new()
                        .text("  ")
                        .key("📍 Address:")
                        .text(" ")
                        .value(format!("{binary_name}+0x{pc:x}"))
                        .build(),
                );

                match (pid, host_pid) {
                    (Some(proc_pid), Some(host_pid_val)) if proc_pid != host_pid_val => {
                        lines.push(
                            StyledLineBuilder::new()
                                .text("  ")
                                .key("🏷️ PID(proc):")
                                .text(" ")
                                .value(proc_pid.to_string())
                                .build(),
                        );
                        lines.push(
                            StyledLineBuilder::new()
                                .text("  ")
                                .key("🏷️ PID(host):")
                                .text(" ")
                                .value(host_pid_val.to_string())
                                .build(),
                        );
                    }
                    (Some(proc_pid), _) => {
                        lines.push(
                            StyledLineBuilder::new()
                                .text("  ")
                                .key("🏷️ PID:")
                                .text(" ")
                                .value(proc_pid.to_string())
                                .build(),
                        );
                    }
                    (None, Some(host_pid_val)) => {
                        lines.push(
                            StyledLineBuilder::new()
                                .text("  ")
                                .key("🏷️ PID(host):")
                                .text(" ")
                                .value(host_pid_val.to_string())
                                .build(),
                        );
                    }
                    (None, None) => {}
                }

                Some(lines)
            }
            RuntimeStatus::TraceInfoAll { summary, traces } => {
                let mut lines = Vec::new();
                // Title
                lines.push(
                    StyledLineBuilder::new()
                        .title(format!(
                            "🔍 All Traces ({} total, {} active):",
                            summary.total, summary.active
                        ))
                        .build(),
                );
                lines.push(Line::from(""));

                for t in traces {
                    let binary_name = std::path::Path::new(&t.binary_path)
                        .file_name()
                        .and_then(|name| name.to_str())
                        .unwrap_or(&t.binary_path)
                        .to_string();
                    let status_style = match t.status {
                        TraceStatus::Active => StylePresets::SUCCESS,
                        TraceStatus::Disabled => StylePresets::LOCATION,
                        TraceStatus::Failed => StylePresets::ERROR,
                    };
                    let line = StyledLineBuilder::new()
                        .text("  ")
                        .styled(format!("#{}", t.trace_id), StylePresets::ADDRESS)
                        .text("  | ")
                        .styled(format!("{}+0x{:x}", binary_name, t.pc), StylePresets::KEY)
                        .text("  | ")
                        .value(&t.target_display)
                        .text("  (")
                        .styled(t.status.to_string(), status_style)
                        .text(")")
                        .build();
                    lines.push(line);
                }

                Some(lines)
            }
            _ => None,
        }
    }
}

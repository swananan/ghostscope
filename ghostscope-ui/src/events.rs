use crossterm::event::{KeyEvent, MouseEvent};
use ghostscope_protocol::EventData;
use tokio::sync::mpsc;
use unicode_width::UnicodeWidthStr;

/// Trace status enumeration for shared use between UI and runtime
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceStatus {
    Active,
    Disabled,
    Failed,
}

impl TraceStatus {
    /// Convert to display string
    pub fn to_string(&self) -> String {
        match self {
            TraceStatus::Active => "Active".to_string(),
            TraceStatus::Disabled => "Disabled".to_string(),
            TraceStatus::Failed => "Failed".to_string(),
        }
    }

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

/// TUI events that can be handled by the application
#[derive(Debug, Clone)]
pub enum TuiEvent {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),
    Quit,
}

/// Registry for event communication between TUI and runtime
#[derive(Debug)]
pub struct EventRegistry {
    // TUI -> Runtime communication
    pub command_sender: mpsc::UnboundedSender<RuntimeCommand>,

    // Runtime -> TUI communication
    pub trace_receiver: mpsc::UnboundedReceiver<EventData>,
    pub status_receiver: mpsc::UnboundedReceiver<RuntimeStatus>,
}

/// Source code information for display in TUI
#[derive(Debug, Clone)]
pub struct SourceCodeInfo {
    pub file_path: String,
    pub current_line: Option<usize>,
}

/// Debug information for a target (function or source location)
#[derive(Debug, Clone)]
pub struct TargetDebugInfo {
    pub target: String,
    pub target_type: TargetType,
    pub file_path: Option<String>,
    pub line_number: Option<u32>,
    pub function_name: Option<String>,
    pub modules: Vec<ModuleDebugInfo>, // Grouped by module/binary
}

impl TargetDebugInfo {
    /// Format target debug info with tree-style layout for display
    pub fn format_for_display(&self) -> String {
        let mut result = String::new();

        // Calculate statistics
        let module_count = self.modules.len();
        let total_addresses: usize = self
            .modules
            .iter()
            .map(|module| module.address_mappings.len())
            .sum();

        // Enhanced header with target name and statistics
        result.push_str(&format!(
            "🔧 Function Debug Info: {} ({} modules, {} traceable addresses)\n\n",
            self.target, module_count, total_addresses
        ));

        // Format modules with tree structure - modules will show their own paths and source info
        for (module_idx, module) in self.modules.iter().enumerate() {
            let is_last_module = module_idx == self.modules.len() - 1;
            result.push_str(&module.format_for_display(
                is_last_module,
                &self.file_path,
                self.line_number,
            ));
        }

        result
    }
}

/// Debug information for a module (binary) containing one or more addresses
#[derive(Debug, Clone)]
pub struct ModuleDebugInfo {
    pub binary_path: String,
    pub address_mappings: Vec<AddressMapping>,
}

impl ModuleDebugInfo {
    /// Format module info with tree-style layout for display
    pub fn format_for_display(
        &self,
        is_last_module: bool,
        source_file: &Option<String>,
        source_line: Option<u32>,
    ) -> String {
        let mut result = String::new();

        // Module header with full path and source info
        result.push_str(&format!("📦 {}", &self.binary_path));

        // Add source information if available
        if let Some(ref file) = source_file {
            if let Some(line) = source_line {
                result.push_str(&format!(" @ {}:{}\n", file, line));
            } else {
                result.push_str(&format!(" @ {}\n", file));
            }
        } else {
            result.push('\n');
        }

        for (addr_idx, mapping) in self.address_mappings.iter().enumerate() {
            let is_last_addr = addr_idx == self.address_mappings.len() - 1;
            let addr_prefix = if is_last_module {
                if is_last_addr {
                    "   └─"
                } else {
                    "   ├─"
                }
            } else {
                if is_last_addr {
                    "│  └─"
                } else {
                    "│  ├─"
                }
            };

            // Enhanced PC address display
            let pc_description = format!("🎯 0x{:x}", mapping.address);

            result.push_str(&format!("{} {}\n", addr_prefix, pc_description));

            // Format parameters
            if !mapping.parameters.is_empty() {
                let param_prefix = if is_last_module {
                    if is_last_addr {
                        "      ├─"
                    } else {
                        "   │  ├─"
                    }
                } else {
                    if is_last_addr {
                        "│     ├─"
                    } else {
                        "│  │  ├─"
                    }
                };

                result.push_str(&format!("{} 📥 Parameters\n", param_prefix));

                for (param_idx, param) in mapping.parameters.iter().enumerate() {
                    let is_last_param =
                        param_idx == mapping.parameters.len() - 1 && mapping.variables.is_empty();
                    let item_prefix = if is_last_module {
                        if is_last_addr {
                            if is_last_param {
                                "      │  └─"
                            } else {
                                "      │  ├─"
                            }
                        } else {
                            if is_last_param {
                                "   │  │  └─"
                            } else {
                                "   │  │  ├─"
                            }
                        }
                    } else {
                        if is_last_addr {
                            if is_last_param {
                                "│     │  └─"
                            } else {
                                "│     │  ├─"
                            }
                        } else {
                            if is_last_param {
                                "│  │  │  └─"
                            } else {
                                "│  │  │  ├─"
                            }
                        }
                    };

                    let param_line = Self::format_variable_line(param);

                    result.push_str(&Self::wrap_long_line(
                        &format!("{} {}", item_prefix, param_line),
                        80,
                        &item_prefix,
                    ));
                }
            }

            // Format variables
            if !mapping.variables.is_empty() {
                let var_prefix = if is_last_module {
                    if is_last_addr {
                        "      └─"
                    } else {
                        "   │  └─"
                    }
                } else {
                    if is_last_addr {
                        "│     └─"
                    } else {
                        "│  │  └─"
                    }
                };

                result.push_str(&format!("{} 📦 Variables\n", var_prefix));

                for (var_idx, var) in mapping.variables.iter().enumerate() {
                    let is_last_var = var_idx == mapping.variables.len() - 1;
                    let item_prefix = if is_last_module {
                        if is_last_addr {
                            if is_last_var {
                                "         └─"
                            } else {
                                "         ├─"
                            }
                        } else {
                            if is_last_var {
                                "   │     └─"
                            } else {
                                "   │     ├─"
                            }
                        }
                    } else {
                        if is_last_addr {
                            if is_last_var {
                                "│        └─"
                            } else {
                                "│        ├─"
                            }
                        } else {
                            if is_last_var {
                                "│  │     └─"
                            } else {
                                "│  │     ├─"
                            }
                        }
                    };

                    let var_line = Self::format_variable_line(var);

                    result.push_str(&Self::wrap_long_line(
                        &format!("{} {}", item_prefix, var_line),
                        80,
                        &item_prefix,
                    ));
                }
            }
        }

        result
    }

    /// Format a variable with its location/evaluation result
    fn format_variable_with_location(name: &str, type_name: &str, location_desc: &str) -> String {
        // Only show variables that have meaningful location descriptions (evaluation results)
        if location_desc.is_empty() || location_desc == "None" {
            format!("{} ({})", name, type_name)
        } else {
            format!("{} ({}) = {}", name, type_name, location_desc)
        }
    }

    /// Overload helper: build from VariableDebugInfo
    pub fn format_variable_line(var: &VariableDebugInfo) -> String {
        // Use enhanced DWARF type display (includes type name and size)
        let type_display = var
            .type_pretty
            .as_ref()
            .filter(|pretty| !pretty.is_empty())
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        if var.location_description.is_empty() || var.location_description == "None" {
            format!("{} ({})", var.name, type_display)
        } else {
            format!(
                "{} ({}) = {}",
                var.name, type_display, var.location_description
            )
        }
    }

    /// Wrap long lines with proper indentation
    fn wrap_long_line(text: &str, max_width: usize, indent: &str) -> String {
        if text.len() <= max_width {
            format!("{}\n", text)
        } else {
            let mut result = String::new();
            let mut current_line = text.to_string();

            while current_line.len() > max_width {
                let break_point = current_line
                    .rfind(' ')
                    .unwrap_or(max_width.saturating_sub(10));
                let (first_part, rest) = current_line.split_at(break_point);
                result.push_str(&format!("{}\n", first_part));

                // Create continuation line with proper indentation
                let continuation_indent =
                    format!("{}   ", indent.replace("├─", "│ ").replace("└─", "  "));
                current_line = format!("{}{}", continuation_indent, rest.trim());
            }

            if !current_line.trim().is_empty() {
                result.push_str(&format!("{}\n", current_line));
            }

            result
        }
    }
}

/// Debug information for a specific address within a module
#[derive(Debug, Clone)]
pub struct AddressMapping {
    pub address: u64,
    pub binary_path: String, // Full binary path for this address
    pub function_name: Option<String>,
    pub variables: Vec<VariableDebugInfo>,
    pub parameters: Vec<VariableDebugInfo>,
}

/// Type of target being inspected
#[derive(Debug, Clone)]
pub enum TargetType {
    Function,
    SourceLocation,
    Address,
}

/// Variable debug information
#[derive(Debug, Clone)]
pub struct VariableDebugInfo {
    pub name: String,
    pub type_name: String,
    pub type_pretty: Option<String>,
    pub location_description: String,
    pub size: Option<u64>,
    pub scope_start: Option<u64>,
    pub scope_end: Option<u64>,
}

/// Commands that TUI can send to runtime
#[derive(Debug, Clone)]
pub enum RuntimeCommand {
    ExecuteScript { command: String },
    RequestSourceCode, // Request source code for current function/address
    DisableTrace(u32), // Disable specific trace by ID
    EnableTrace(u32),  // Enable specific trace by ID
    DisableAllTraces,  // Disable all traces
    EnableAllTraces,   // Enable all traces
    DeleteTrace(u32),  // Completely delete specific trace and all resources
    DeleteAllTraces,   // Delete all traces and resources
    InfoFunction { target: String }, // Get debug info for a function by name
    InfoLine { target: String }, // Get debug info for a source line (file:line)
    InfoAddress { target: String }, // Get debug info for a memory address (TODO: not implemented yet)
    InfoTrace { trace_id: Option<u32> }, // Get info for one/all traces (individual messages)
    InfoTraceAll,
    InfoSource, // Get all source files information
    InfoShare,  // Get shared library information (like GDB's "info share")
    Shutdown,
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
        details: ScriptCompilationDetails, // Now required, contains trace_ids
    },
    ScriptCompilationFailed {
        error: String,
        target: String, // Target instead of trace_id since we don't have trace_ids for failed compilations
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
    },
    AllTracesDisabled {
        count: usize,
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
    },
    TraceDeleteFailed {
        trace_id: u32,
        error: String,
    },
    InfoFunctionResult {
        target: String,
        info: TargetDebugInfo,
    },
    InfoFunctionFailed {
        target: String,
        error: String,
    },
    InfoLineResult {
        target: String,
        info: TargetDebugInfo,
    },
    InfoLineFailed {
        target: String,
        error: String,
    },
    InfoAddressResult {
        target: String,
        info: TargetDebugInfo,
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
    /// Shared library information response
    ShareInfo {
        libraries: Vec<SharedLibraryInfo>,
    },
    /// Failed to get shared library information
    ShareInfoFailed {
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
    Error(String),
}

/// Statistics for a loaded module
#[derive(Debug, Clone)]
pub struct ModuleLoadingStats {
    pub functions: usize,
    pub variables: usize,
    pub types: usize,
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
            "{} [{}] {}@{}+0x{:x} - {} ({})",
            self.status.to_emoji(),
            self.trace_id,
            self.target_display,
            binary_name,
            self.pc,
            self.status.to_string(),
            self.duration
        )
    }
}

/// Source file information
#[derive(Debug, Clone)]
pub struct SourceFileInfo {
    pub path: String,
    pub directory: String,
}

/// Group of source files for a specific module
#[derive(Debug, Clone)]
pub struct SourceFileGroup {
    pub module_path: String,
    pub files: Vec<SourceFileInfo>,
}

/// Shared library information (similar to GDB's "info share" output)
#[derive(Debug, Clone)]
pub struct SharedLibraryInfo {
    pub from_address: u64,          // Starting address in memory
    pub to_address: u64,            // Ending address in memory
    pub symbols_read: bool,         // Whether symbols were successfully read
    pub debug_info_available: bool, // Whether debug information is available
    pub library_path: String,       // Full path to the library file
    pub size: u64,                  // Size of the library in memory
}

impl EventRegistry {
    pub fn new() -> (Self, RuntimeChannels) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (trace_tx, trace_rx) = mpsc::unbounded_channel::<EventData>();
        let (status_tx, status_rx) = mpsc::unbounded_channel();

        let registry = EventRegistry {
            command_sender: command_tx,
            trace_receiver: trace_rx,
            status_receiver: status_rx,
        };

        let channels = RuntimeChannels {
            command_receiver: command_rx,
            trace_sender: trace_tx.clone(),
            status_sender: status_tx.clone(),
        };

        (registry, channels)
    }
}

/// Channels used by the runtime to receive commands and send events
#[derive(Debug)]
pub struct RuntimeChannels {
    pub command_receiver: mpsc::UnboundedReceiver<RuntimeCommand>,
    pub trace_sender: mpsc::UnboundedSender<EventData>,
    pub status_sender: mpsc::UnboundedSender<RuntimeStatus>,
}

impl RuntimeChannels {
    /// Create a status sender that can be shared with other tasks
    pub fn create_status_sender(&self) -> mpsc::UnboundedSender<RuntimeStatus> {
        self.status_sender.clone()
    }

    /// Create a trace sender that can be shared with other tasks
    pub fn create_trace_sender(&self) -> mpsc::UnboundedSender<EventData> {
        self.trace_sender.clone()
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
                binary,
                script_preview,
                pc,
            } => {
                // Header line
                let mut result = format!(
                    "🔎 Trace [{}] {} {}\n",
                    trace_id,
                    status.to_emoji(),
                    status.to_string()
                );

                // Collect fields for aligned key-value formatting
                let binary_name = std::path::Path::new(binary)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(binary);

                let mut fields: Vec<(&str, String)> = Vec::new();
                fields.push(("🎯 Target", target.clone()));
                fields.push(("📦 Binary", binary.clone()));
                fields.push(("📍 Address", format!("{}+0x{:x}", binary_name, pc)));
                if let Some(pid_val) = pid {
                    fields.push(("🏷️ PID", pid_val.to_string()));
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
                    result.push_str(&format!("  {}{}: {}\n", key, spaces, value));
                }

                Some(result)
            }
            _ => None,
        }
    }
}

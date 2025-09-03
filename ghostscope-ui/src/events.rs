use crossterm::event::{KeyEvent, MouseEvent};
use ghostscope_protocol::MessageType;
use tokio::sync::mpsc;

/// TUI events that can be handled by the application
#[derive(Debug, Clone)]
pub enum TuiEvent {
    Key(KeyEvent),
    Mouse(MouseEvent),
    Resize(u16, u16),
    Quit,
}

/// Structured trace event for TUI display
#[derive(Debug, Clone)]
pub struct TraceEvent {
    pub timestamp: u64, // Raw timestamp in nanoseconds, TUI will format for display
    pub trace_id: u64,
    pub pid: u32,
    pub message: String,         // Main trace message content
    pub trace_type: MessageType, // Use MessageType directly for trace categorization
}

/// Registry for event communication between TUI and runtime
#[derive(Debug)]
pub struct EventRegistry {
    // TUI -> Runtime communication
    pub command_sender: mpsc::UnboundedSender<RuntimeCommand>,

    // Runtime -> TUI communication
    pub trace_receiver: mpsc::UnboundedReceiver<TraceEvent>,
    pub status_receiver: mpsc::UnboundedReceiver<RuntimeStatus>,
}

/// Source code information for display in TUI
#[derive(Debug, Clone)]
pub struct SourceCodeInfo {
    pub file_path: String,
    pub content: Vec<String>,
    pub current_line: Option<usize>,
}

/// Commands that TUI can send to runtime
#[derive(Debug, Clone)]
pub enum RuntimeCommand {
    ExecuteScript { command: String, trace_id: u32 },
    AttachToProcess(u32),
    DetachFromProcess,
    ReloadBinary(String),
    RequestSourceCode, // Request source code for current function/address
    DisableTrace(u32), // Disable specific trace by ID
    EnableTrace(u32),  // Enable specific trace by ID
    DisableAllTraces,  // Disable all traces
    EnableAllTraces,   // Enable all traces
    DeleteTrace(u32),  // Completely delete specific trace and all resources
    DeleteAllTraces,   // Delete all traces and resources
    Shutdown,
}

/// Status updates from runtime to TUI
#[derive(Debug, Clone)]
pub enum RuntimeStatus {
    DwarfLoadingStarted,
    DwarfLoadingCompleted { symbols_count: usize },
    DwarfLoadingFailed(String),
    ScriptCompilationCompleted { trace_id: u32 },
    ScriptCompilationFailed { error: String, trace_id: u32 },
    UprobeAttached { function: String, address: u64 },
    UprobeDetached { function: String },
    ProcessAttached(u32),
    ProcessDetached,
    SourceCodeLoaded(SourceCodeInfo),
    SourceCodeLoadFailed(String),
    TraceEnabled { trace_id: u32 },
    TraceDisabled { trace_id: u32 },
    AllTracesEnabled { count: usize },
    AllTracesDisabled { count: usize },
    TraceEnableFailed { trace_id: u32, error: String },
    TraceDisableFailed { trace_id: u32, error: String },
    TraceDeleted { trace_id: u32 },
    AllTracesDeleted { count: usize },
    TraceDeleteFailed { trace_id: u32, error: String },
    Error(String),
}

impl EventRegistry {
    pub fn new() -> (Self, RuntimeChannels) {
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (trace_tx, trace_rx) = mpsc::unbounded_channel();
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
    pub trace_sender: mpsc::UnboundedSender<TraceEvent>,
    pub status_sender: mpsc::UnboundedSender<RuntimeStatus>,
}

impl RuntimeChannels {
    /// Create a status sender that can be shared with other tasks
    pub fn create_status_sender(&self) -> mpsc::UnboundedSender<RuntimeStatus> {
        self.status_sender.clone()
    }

    /// Create a trace sender that can be shared with other tasks
    pub fn create_trace_sender(&self) -> mpsc::UnboundedSender<TraceEvent> {
        self.trace_sender.clone()
    }
}

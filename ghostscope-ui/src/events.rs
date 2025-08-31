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

/// Events from the eBPF monitoring system
#[derive(Debug, Clone)]
pub struct RingbufEvent {
    pub timestamp: u64,
    pub message_type: MessageType,
    pub data: Vec<u8>,
}

/// Registry for event communication between TUI and runtime
#[derive(Debug)]
pub struct EventRegistry {
    // TUI -> Runtime communication
    pub script_sender: mpsc::UnboundedSender<String>,
    pub command_sender: mpsc::UnboundedSender<RuntimeCommand>,

    // Runtime -> TUI communication
    pub ringbuf_receiver: mpsc::UnboundedReceiver<RingbufEvent>,
    pub status_receiver: mpsc::UnboundedReceiver<RuntimeStatus>,
}

/// Commands that TUI can send to runtime
#[derive(Debug, Clone)]
pub enum RuntimeCommand {
    ExecuteScript(String),
    AttachToProcess(u32),
    DetachFromProcess,
    ReloadBinary(String),
    Shutdown,
}

/// Status updates from runtime to TUI
#[derive(Debug, Clone)]
pub enum RuntimeStatus {
    DwarfLoadingStarted,
    DwarfLoadingCompleted { symbols_count: usize },
    DwarfLoadingFailed(String),
    ScriptCompilationStarted,
    ScriptCompilationCompleted,
    ScriptCompilationFailed(String),
    UprobeAttached { function: String, address: u64 },
    UprobeDetached { function: String },
    ProcessAttached(u32),
    ProcessDetached,
    Error(String),
}

impl EventRegistry {
    pub fn new() -> (Self, RuntimeChannels) {
        let (script_tx, script_rx) = mpsc::unbounded_channel();
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (ringbuf_tx, ringbuf_rx) = mpsc::unbounded_channel();
        let (status_tx, status_rx) = mpsc::unbounded_channel();

        let registry = EventRegistry {
            script_sender: script_tx,
            command_sender: command_tx,
            ringbuf_receiver: ringbuf_rx,
            status_receiver: status_rx,
        };

        let channels = RuntimeChannels {
            script_receiver: script_rx,
            command_receiver: command_rx,
            ringbuf_sender: ringbuf_tx.clone(),
            status_sender: status_tx.clone(),
        };

        (registry, channels)
    }
}

/// Channels used by the runtime to receive commands and send events
#[derive(Debug)]
pub struct RuntimeChannels {
    pub script_receiver: mpsc::UnboundedReceiver<String>,
    pub command_receiver: mpsc::UnboundedReceiver<RuntimeCommand>,
    pub ringbuf_sender: mpsc::UnboundedSender<RingbufEvent>,
    pub status_sender: mpsc::UnboundedSender<RuntimeStatus>,
}

impl RuntimeChannels {
    /// Create a status sender that can be shared with other tasks
    pub fn create_status_sender(&self) -> mpsc::UnboundedSender<RuntimeStatus> {
        self.status_sender.clone()
    }

    /// Create a ringbuf sender that can be shared with other tasks  
    pub fn create_ringbuf_sender(&self) -> mpsc::UnboundedSender<RingbufEvent> {
        self.ringbuf_sender.clone()
    }
}

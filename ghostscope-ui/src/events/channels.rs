use super::runtime::{RuntimeCommand, RuntimeStatus};
use super::trace_display::UiTraceEvent;
use tokio::sync::mpsc;

/// Registry for event communication between TUI and runtime
#[derive(Debug)]
pub struct EventRegistry {
    // TUI -> Runtime communication
    pub command_sender: mpsc::UnboundedSender<RuntimeCommand>,

    // Runtime -> TUI communication
    pub trace_receiver: mpsc::Receiver<UiTraceEvent>,
    pub status_receiver: mpsc::UnboundedReceiver<RuntimeStatus>,
}

impl EventRegistry {
    pub fn new() -> (Self, RuntimeChannels) {
        Self::new_with_trace_capacity(DEFAULT_TRACE_CHANNEL_CAPACITY)
    }

    pub fn new_with_trace_capacity(trace_capacity: usize) -> (Self, RuntimeChannels) {
        let trace_capacity = trace_capacity.max(1);
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let (trace_tx, trace_rx) = mpsc::channel::<UiTraceEvent>(trace_capacity);
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
            trace_channel_capacity: trace_capacity,
        };

        (registry, channels)
    }
}

/// Default queue size for runtime->UI trace events.
pub const DEFAULT_TRACE_CHANNEL_CAPACITY: usize = 4096;

/// Channels used by the runtime to receive commands and send events
#[derive(Debug)]
pub struct RuntimeChannels {
    pub command_receiver: mpsc::UnboundedReceiver<RuntimeCommand>,
    pub trace_sender: mpsc::Sender<UiTraceEvent>,
    pub status_sender: mpsc::UnboundedSender<RuntimeStatus>,
    pub trace_channel_capacity: usize,
}

impl RuntimeChannels {
    /// Create a status sender that can be shared with other tasks
    pub fn create_status_sender(&self) -> mpsc::UnboundedSender<RuntimeStatus> {
        self.status_sender.clone()
    }

    /// Create a trace sender that can be shared with other tasks
    pub fn create_trace_sender(&self) -> mpsc::Sender<UiTraceEvent> {
        self.trace_sender.clone()
    }
}

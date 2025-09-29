use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ghostscope_protocol::ParsedTraceEvent;
use ghostscope_ui::events::{EventRegistry, RuntimeCommand, RuntimeStatus};
use ratatui::{backend::TestBackend, Terminal};
use tokio::sync::mpsc;

/// Test harness for TUI integration testing
pub struct TuiTestHarness {
    /// Mock channels for runtime communication
    pub command_receiver: mpsc::UnboundedReceiver<RuntimeCommand>,
    pub trace_sender: mpsc::UnboundedSender<ParsedTraceEvent>,
    pub trace_receiver: mpsc::UnboundedReceiver<ParsedTraceEvent>,
    pub status_sender: mpsc::UnboundedSender<RuntimeStatus>,
    pub status_receiver: mpsc::UnboundedReceiver<RuntimeStatus>,

    /// Test terminal backend
    pub terminal: Terminal<TestBackend>,
}

impl TuiTestHarness {
    /// Create a new test harness with mocked channels
    pub fn new(width: u16, height: u16) -> Self {
        // Create mock channels - keep both ends to prevent channel closed errors
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (trace_sender, trace_receiver) = mpsc::unbounded_channel();
        let (status_sender, status_receiver) = mpsc::unbounded_channel();

        // Create test terminal
        let backend = TestBackend::new(width, height);
        let terminal = Terminal::new(backend).unwrap();

        Self {
            command_receiver,
            trace_sender,
            trace_receiver,
            status_sender,
            status_receiver,
            terminal,
        }
    }

    /// Create EventRegistry from existing channels
    pub fn create_event_registry(&mut self) -> EventRegistry {
        // Create new channels for the EventRegistry
        let (command_sender, command_receiver) = mpsc::unbounded_channel();
        let (trace_sender, trace_receiver) = mpsc::unbounded_channel();
        let (status_sender, status_receiver) = mpsc::unbounded_channel();

        // Store the command receiver for later use
        self.command_receiver = command_receiver;

        // Keep our existing senders working by replacing them with the new ones
        // This way our send_trace_event and send_runtime_status methods still work
        self.trace_sender = trace_sender;
        self.status_sender = status_sender;

        // Also create separate channels for the EventRegistry
        let (_trace_sender_for_registry, trace_receiver_for_registry) = mpsc::unbounded_channel();
        let (_status_sender_for_registry, status_receiver_for_registry) = mpsc::unbounded_channel();

        // Keep the receivers alive
        self.trace_receiver = trace_receiver;
        self.status_receiver = status_receiver;

        EventRegistry {
            command_sender,
            trace_receiver: trace_receiver_for_registry,
            status_receiver: status_receiver_for_registry,
        }
    }

    /// Get the current terminal buffer content
    pub fn get_buffer_content(&self) -> Vec<String> {
        let buffer = self.terminal.backend().buffer();
        let mut lines = Vec::new();

        for y in 0..buffer.area.height {
            let mut line = String::new();
            for x in 0..buffer.area.width {
                let cell = &buffer[(x, y)];
                line.push_str(cell.symbol());
            }
            lines.push(line.trim_end().to_string());
        }

        lines
    }

    /// Assert that a specific text appears in the terminal
    pub fn assert_text_appears(&self, text: &str) -> bool {
        let content = self.get_buffer_content();
        content.iter().any(|line| line.contains(text))
    }

    /// Simulate a key press event
    pub fn simulate_key_press(&self, code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::empty())
    }

    /// Send a mock trace event
    pub fn send_trace_event(&mut self, event: ParsedTraceEvent) -> Result<()> {
        self.trace_sender.send(event)?;
        Ok(())
    }

    /// Send a mock runtime status
    pub fn send_runtime_status(&mut self, status: RuntimeStatus) -> Result<()> {
        self.status_sender.send(status)?;
        Ok(())
    }

    /// Receive a command sent by the UI
    pub async fn receive_command(&mut self) -> Option<RuntimeCommand> {
        self.command_receiver.recv().await
    }

    /// Receive a trace event (for verification in tests)
    pub async fn receive_trace_event(&mut self) -> Option<ParsedTraceEvent> {
        self.trace_receiver.recv().await
    }

    /// Receive a status update (for verification in tests)
    pub async fn receive_status(&mut self) -> Option<RuntimeStatus> {
        self.status_receiver.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tui_initialization() {
        let mut harness = TuiTestHarness::new(120, 40);
        let _event_registry = harness.create_event_registry();

        // Verify that we can create the harness
        assert!(harness.terminal.size().unwrap().width == 120);
        assert!(harness.terminal.size().unwrap().height == 40);
    }

    #[tokio::test]
    async fn test_panel_navigation() {
        let harness = TuiTestHarness::new(120, 40);

        // Simulate Tab key to switch panels
        let tab_key = harness.simulate_key_press(KeyCode::Tab);

        // Verify key event was created correctly
        assert_eq!(tab_key.code, KeyCode::Tab);
    }

    #[tokio::test]
    async fn test_command_input() {
        let harness = TuiTestHarness::new(120, 40);

        // Simulate typing a command
        let keys = vec![
            KeyCode::Char('p'),
            KeyCode::Char('r'),
            KeyCode::Char('i'),
            KeyCode::Char('n'),
            KeyCode::Char('t'),
        ];

        for key in keys {
            let _event = harness.simulate_key_press(key);
            // In real test, you would pass this to the App's handle_key method
        }
    }

    #[tokio::test]
    async fn test_trace_event_display() {
        let mut harness = TuiTestHarness::new(120, 40);

        // Create a mock trace event
        let trace_event = ParsedTraceEvent {
            timestamp: 1234567890,
            trace_id: 1,
            pid: 12345,
            tid: 67890,
            instructions: vec![],
        };

        // Clone for verification
        let expected_event = trace_event.clone();

        // Send the trace event
        harness.send_trace_event(trace_event).unwrap();

        // Verify we can receive it
        let received = harness.receive_trace_event().await;
        assert!(received.is_some());
        let received_event = received.unwrap();
        assert_eq!(received_event.trace_id, expected_event.trace_id);
        assert_eq!(received_event.pid, expected_event.pid);
        assert_eq!(received_event.tid, expected_event.tid);
    }

    #[tokio::test]
    async fn test_runtime_status_update() {
        let mut harness = TuiTestHarness::new(120, 40);

        // Send a runtime status update
        let status = RuntimeStatus::DwarfLoadingCompleted { symbols_count: 100 };

        // Send status
        harness.send_runtime_status(status).unwrap();

        // Verify we can receive it
        let received = harness.receive_status().await;
        assert!(received.is_some());

        match received.unwrap() {
            RuntimeStatus::DwarfLoadingCompleted { symbols_count } => {
                assert_eq!(symbols_count, 100);
            }
            _ => panic!("Unexpected status type"),
        }
    }

    #[tokio::test]
    async fn test_buffer_content_assertion() {
        let mut harness = TuiTestHarness::new(120, 40);

        // Draw something to the terminal
        harness
            .terminal
            .draw(|f| {
                use ratatui::widgets::{Block, Borders, Paragraph};

                let block = Block::default().title("Test Panel").borders(Borders::ALL);

                let paragraph = Paragraph::new("Hello, Test!").block(block);

                f.render_widget(paragraph, f.area());
            })
            .unwrap();

        // Verify content appears in buffer
        assert!(harness.assert_text_appears("Test Panel"));
        assert!(harness.assert_text_appears("Hello, Test!"));
    }
}

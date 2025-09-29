use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ghostscope_protocol::{streaming_parser::ParsedInstruction, ParsedTraceEvent};
use ghostscope_ui::events::{RuntimeCommand, RuntimeStatus};
use ratatui::{backend::TestBackend, Terminal};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

/// Mock App wrapper for testing
pub struct TestableApp {
    /// Mock terminal for rendering
    terminal: Arc<Mutex<Terminal<TestBackend>>>,

    /// Channels for mocking runtime communication
    _command_receiver: Arc<Mutex<mpsc::UnboundedReceiver<RuntimeCommand>>>,
    _trace_sender: mpsc::UnboundedSender<ParsedTraceEvent>,
    _status_sender: mpsc::UnboundedSender<RuntimeStatus>,

    /// Internal app state (simplified for testing)
    state: Arc<Mutex<AppTestState>>,
}

#[derive(Debug)]
struct AppTestState {
    current_panel: PanelType,
    command_input: String,
    trace_events: Vec<ParsedTraceEvent>,
    runtime_status: Option<RuntimeStatus>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PanelType {
    Command,
    Source,
    EbpfOutput,
}

impl TestableApp {
    /// Create a new testable app instance
    pub fn new(width: u16, height: u16) -> Self {
        // Create mock channels
        let (_command_sender, command_receiver) = mpsc::unbounded_channel();
        let (trace_sender, _trace_receiver) = mpsc::unbounded_channel();
        let (status_sender, _status_receiver) = mpsc::unbounded_channel();

        // Create test terminal
        let backend = TestBackend::new(width, height);
        let terminal = Terminal::new(backend).unwrap();

        // Initialize app state
        let state = AppTestState {
            current_panel: PanelType::Command,
            command_input: String::new(),
            trace_events: Vec::new(),
            runtime_status: None,
        };

        Self {
            terminal: Arc::new(Mutex::new(terminal)),
            _command_receiver: Arc::new(Mutex::new(command_receiver)),
            _trace_sender: trace_sender,
            _status_sender: status_sender,
            state: Arc::new(Mutex::new(state)),
        }
    }

    /// Simulate handling a key event
    pub async fn handle_key(&self, key: KeyEvent) -> Result<()> {
        let mut state = self.state.lock().await;

        match key.code {
            KeyCode::Tab => {
                // Switch panels
                state.current_panel = match state.current_panel {
                    PanelType::Command => PanelType::Source,
                    PanelType::Source => PanelType::EbpfOutput,
                    PanelType::EbpfOutput => PanelType::Command,
                };
            }
            KeyCode::Char(c) => {
                if state.current_panel == PanelType::Command {
                    state.command_input.push(c);
                }
            }
            KeyCode::Backspace => {
                if state.current_panel == PanelType::Command {
                    state.command_input.pop();
                }
            }
            KeyCode::Enter => {
                if state.current_panel == PanelType::Command && !state.command_input.is_empty() {
                    // Process command
                    let _cmd = state.command_input.clone();
                    state.command_input.clear();

                    // Send as RuntimeCommand (mock)
                    // In real implementation, this would parse and send the actual command
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Simulate receiving a trace event
    pub async fn receive_trace_event(&self, event: ParsedTraceEvent) -> Result<()> {
        let mut state = self.state.lock().await;
        state.trace_events.push(event);
        Ok(())
    }

    /// Simulate receiving runtime status
    pub async fn receive_runtime_status(&self, status: RuntimeStatus) -> Result<()> {
        let mut state = self.state.lock().await;
        state.runtime_status = Some(status);
        Ok(())
    }

    /// Render the UI and return the buffer content
    pub async fn render(&self) -> Result<Vec<String>> {
        let mut terminal = self.terminal.lock().await;
        let state = self.state.lock().await;

        terminal.draw(|f| {
            use ratatui::{
                layout::{Constraint, Direction, Layout},
                style::{Color, Style},
                widgets::{Block, Borders, List, ListItem, Paragraph},
            };

            // Create layout
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Percentage(30), // Command panel
                    Constraint::Percentage(40), // Source panel
                    Constraint::Percentage(30), // eBPF output panel
                ])
                .split(f.area());

            // Render command panel
            let command_block = Block::default()
                .title(format!(
                    " Command Panel {} ",
                    if state.current_panel == PanelType::Command {
                        "[FOCUSED]"
                    } else {
                        ""
                    }
                ))
                .borders(Borders::ALL)
                .border_style(if state.current_panel == PanelType::Command {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                });

            let command_text = format!("> {}", state.command_input);
            let command_widget = Paragraph::new(command_text).block(command_block);
            f.render_widget(command_widget, chunks[0]);

            // Render source panel
            let source_block = Block::default()
                .title(format!(
                    " Source Panel {} ",
                    if state.current_panel == PanelType::Source {
                        "[FOCUSED]"
                    } else {
                        ""
                    }
                ))
                .borders(Borders::ALL)
                .border_style(if state.current_panel == PanelType::Source {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                });

            let source_content = match &state.runtime_status {
                Some(RuntimeStatus::DwarfLoadingCompleted { symbols_count }) => {
                    format!("DWARF symbols loaded: {symbols_count}")
                }
                _ => "Not connected".to_string(),
            };

            let source_widget = Paragraph::new(source_content).block(source_block);
            f.render_widget(source_widget, chunks[1]);

            // Render eBPF output panel
            let ebpf_block = Block::default()
                .title(format!(
                    " eBPF Output {} ",
                    if state.current_panel == PanelType::EbpfOutput {
                        "[FOCUSED]"
                    } else {
                        ""
                    }
                ))
                .borders(Borders::ALL)
                .border_style(if state.current_panel == PanelType::EbpfOutput {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                });

            // Create list of trace events
            let items: Vec<ListItem> = state
                .trace_events
                .iter()
                .map(|event| {
                    let content =
                        format!("[{}] PID:{} TID:{}", event.timestamp, event.pid, event.tid);
                    ListItem::new(content)
                })
                .collect();

            let events_list = List::new(items).block(ebpf_block);
            f.render_widget(events_list, chunks[2]);
        })?;

        // Extract buffer content
        let buffer = terminal.backend().buffer();
        let mut lines = Vec::new();

        for y in 0..buffer.area.height {
            let mut line = String::new();
            for x in 0..buffer.area.width {
                let cell = &buffer[(x, y)];
                line.push_str(cell.symbol());
            }
            lines.push(line.trim_end().to_string());
        }

        Ok(lines)
    }

    /// Get current panel
    pub async fn get_current_panel(&self) -> PanelType {
        self.state.lock().await.current_panel.clone()
    }

    /// Get command input
    pub async fn get_command_input(&self) -> String {
        self.state.lock().await.command_input.clone()
    }

    /// Get trace events
    pub async fn get_trace_events(&self) -> Vec<ParsedTraceEvent> {
        self.state.lock().await.trace_events.clone()
    }

    /// Assert text appears in rendered output
    pub async fn assert_text_in_output(&self, text: &str) -> bool {
        let lines = self.render().await.unwrap();
        lines.iter().any(|line| line.contains(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_panel_navigation() {
        let app = TestableApp::new(120, 40);

        // Initial panel should be Command
        assert_eq!(app.get_current_panel().await, PanelType::Command);

        // Press Tab to switch to Source
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()))
            .await
            .unwrap();
        assert_eq!(app.get_current_panel().await, PanelType::Source);

        // Press Tab to switch to EbpfOutput
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()))
            .await
            .unwrap();
        assert_eq!(app.get_current_panel().await, PanelType::EbpfOutput);

        // Press Tab to cycle back to Command
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()))
            .await
            .unwrap();
        assert_eq!(app.get_current_panel().await, PanelType::Command);
    }

    #[tokio::test]
    async fn test_command_input() {
        let app = TestableApp::new(120, 40);

        // Type "print x"
        let command = "print x";
        for c in command.chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::empty()))
                .await
                .unwrap();
        }

        assert_eq!(app.get_command_input().await, "print x");

        // Test backspace
        app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::empty()))
            .await
            .unwrap();
        assert_eq!(app.get_command_input().await, "print ");

        // Test clear on Enter
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()))
            .await
            .unwrap();
        assert_eq!(app.get_command_input().await, "");
    }

    #[tokio::test]
    async fn test_trace_event_display() {
        let app = TestableApp::new(120, 40);

        // Add trace events
        let event1 = ParsedTraceEvent {
            timestamp: 1000,
            trace_id: 1,
            pid: 12345,
            tid: 67890,
            instructions: vec![ParsedInstruction::PrintString {
                content: "Entering main function".to_string(),
            }],
        };

        let event2 = ParsedTraceEvent {
            timestamp: 2000,
            trace_id: 2,
            pid: 12345,
            tid: 67890,
            instructions: vec![ParsedInstruction::PrintString {
                content: "Processing data: x=42".to_string(),
            }],
        };

        app.receive_trace_event(event1).await.unwrap();
        app.receive_trace_event(event2).await.unwrap();

        // Verify events are stored
        let events = app.get_trace_events().await;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].trace_id, 1);
        assert_eq!(events[1].trace_id, 2);

        // Verify rendering
        assert!(app.assert_text_in_output("12345").await);
        assert!(app.assert_text_in_output("67890").await);
    }

    #[tokio::test]
    async fn test_runtime_status_display() {
        let app = TestableApp::new(120, 40);

        // Set runtime status
        let status = RuntimeStatus::DwarfLoadingCompleted {
            symbols_count: 1500,
        };

        app.receive_runtime_status(status).await.unwrap();

        // Verify status appears in render
        assert!(app.assert_text_in_output("DWARF symbols loaded").await);
        assert!(app.assert_text_in_output("1500").await);
    }

    #[tokio::test]
    async fn test_panel_focus_indication() {
        let app = TestableApp::new(120, 40);

        // Command panel should be focused initially
        assert!(app.assert_text_in_output("Command Panel [FOCUSED]").await);

        // Switch to Source panel
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()))
            .await
            .unwrap();
        assert!(app.assert_text_in_output("Source Panel [FOCUSED]").await);

        // Switch to eBPF Output panel
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::empty()))
            .await
            .unwrap();
        assert!(app.assert_text_in_output("eBPF Output [FOCUSED]").await);
    }

    #[tokio::test]
    async fn test_complex_interaction_flow() {
        let app = TestableApp::new(120, 40);

        // 1. Connect to runtime
        let status = RuntimeStatus::DwarfLoadingCompleted {
            symbols_count: 2000,
        };
        app.receive_runtime_status(status).await.unwrap();

        // 2. Type and execute a command
        for c in "trace main".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::empty()))
                .await
                .unwrap();
        }
        assert_eq!(app.get_command_input().await, "trace main");

        // 3. Receive trace events
        for i in 0u64..5 {
            let event = ParsedTraceEvent {
                timestamp: 1000 + i * 100,
                trace_id: i,
                pid: 99999,
                tid: 11111,
                instructions: vec![ParsedInstruction::PrintString {
                    content: format!("Event {i}"),
                }],
            };
            app.receive_trace_event(event).await.unwrap();
        }

        // 4. Verify everything is displayed
        assert!(app.assert_text_in_output("2000").await);
        assert!(app.assert_text_in_output("trace main").await);
        assert!(app.assert_text_in_output("99999").await);
        assert!(app.assert_text_in_output("11111").await);
    }
}

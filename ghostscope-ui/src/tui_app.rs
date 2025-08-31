use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture, Event, EventStream, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures_util::StreamExt;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    Terminal,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::{
    events::{EventRegistry, RingbufEvent, RuntimeCommand, RuntimeStatus, TuiEvent},
    panels::{InputPanel, OutputPanel, SourceCodePanel},
};

pub struct TuiApp {
    should_quit: bool,

    // UI panels
    source_panel: SourceCodePanel,
    output_panel: OutputPanel,
    input_panel: InputPanel,

    // Layout state
    split_ratio: f32,
    focused_panel: FocusedPanel,
    expecting_window_nav: bool,

    // Event communication
    event_registry: EventRegistry,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum FocusedPanel {
    Source,
    Output,
    Input,
}

impl TuiApp {
    pub async fn new(event_registry: EventRegistry) -> Result<Self> {
        Ok(Self {
            should_quit: false,
            source_panel: SourceCodePanel::new(),
            output_panel: OutputPanel::new(),
            input_panel: InputPanel::new(),
            split_ratio: 0.6, // 60% for source code, 40% for output
            focused_panel: FocusedPanel::Input,
            expecting_window_nav: false,
            event_registry,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        info!("Starting TUI mode");

        // Create async event stream
        let mut event_stream = EventStream::new();
        let mut needs_render = true;

        // Initial render
        if let Err(e) = terminal.draw(|f| self.render(f)) {
            error!("Failed to render initial TUI: {}", e);
            return Err(e.into());
        }

        // Main event loop with event-driven rendering
        let result = loop {
            tokio::select! {
                // Handle crossterm events (keyboard, mouse, resize)
                Some(event_result) = event_stream.next() => {
                    match event_result {
                        Ok(event) => {
                            match event {
                                Event::Key(key) => {
                                    if self.handle_key_event(key).await? {
                                        break Ok(()); // Quit requested
                                    }
                                    needs_render = true;
                                }
                                Event::Mouse(mouse) => {
                                    debug!("Mouse event: {:?}", mouse);
                                    // TODO: Handle mouse events for panel resizing
                                }
                                Event::Resize(_, _) => {
                                    needs_render = true;
                                }
                                _ => {}
                            }
                        }
                        Err(e) => {
                            error!("Error reading terminal events: {}", e);
                            break Err(e.into());
                        }
                    }
                }

                // Handle runtime status updates
                Some(status) = self.event_registry.status_receiver.recv() => {
                    self.handle_runtime_status(status).await;
                    needs_render = true;
                }

                // Handle ringbuf events
                Some(event) = self.event_registry.ringbuf_receiver.recv() => {
                    self.handle_ringbuf_event(event).await;
                    needs_render = true;
                }
            }

            // Render only when needed (event-driven)
            if needs_render {
                if let Err(e) = terminal.draw(|f| self.render(f)) {
                    error!("Failed to render TUI: {}", e);
                    break Err(e.into());
                }
                needs_render = false;
            }

            if self.should_quit {
                break Ok(());
            }
        };

        // Cleanup terminal
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;
        terminal.show_cursor()?;

        info!("TUI mode exited");
        result
    }

    async fn handle_key_event(&mut self, key: crossterm::event::KeyEvent) -> Result<bool> {
        // Handle window navigation keys if expecting them
        if self.expecting_window_nav {
            match key.code {
                KeyCode::Char('j') => {
                    // Move focus down: Source -> Output -> Input -> Source (top to bottom)
                    self.focused_panel = match self.focused_panel {
                        FocusedPanel::Source => FocusedPanel::Output,
                        FocusedPanel::Output => FocusedPanel::Input,
                        FocusedPanel::Input => FocusedPanel::Source,
                    };
                    debug!("Window nav: moved focus to {:?}", self.focused_panel);
                    self.expecting_window_nav = false;
                    return Ok(false);
                }
                KeyCode::Char('k') => {
                    // Move focus up: Source -> Input -> Output -> Source (bottom to top)
                    self.focused_panel = match self.focused_panel {
                        FocusedPanel::Source => FocusedPanel::Input,
                        FocusedPanel::Input => FocusedPanel::Output,
                        FocusedPanel::Output => FocusedPanel::Source,
                    };
                    debug!("Window nav: moved focus to {:?}", self.focused_panel);
                    self.expecting_window_nav = false;
                    return Ok(false);
                }
                _ => {
                    // Any other key cancels window navigation expectation
                    self.expecting_window_nav = false;
                    // Fall through to normal key handling
                }
            }
        }

        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                info!("Quit requested via Ctrl+C");
                let _ = self
                    .event_registry
                    .command_sender
                    .send(RuntimeCommand::Shutdown);
                return Ok(true);
            }
            KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                info!("Quit requested via Ctrl+Q");
                let _ = self
                    .event_registry
                    .command_sender
                    .send(RuntimeCommand::Shutdown);
                return Ok(true);
            }
            KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                // Set expectation for next j/k key
                self.expecting_window_nav = true;
                debug!("Expecting window navigation key (j/k)");
            }
            KeyCode::Esc => {
                if self.focused_panel == FocusedPanel::Input {
                    info!("Quit requested via ESC");
                    let _ = self
                        .event_registry
                        .command_sender
                        .send(RuntimeCommand::Shutdown);
                    return Ok(true);
                }
            }
            KeyCode::Tab => {
                self.cycle_focus();
            }
            _ => {
                self.handle_panel_input(key).await?;
            }
        }
        Ok(false)
    }

    async fn handle_panel_input(&mut self, key: crossterm::event::KeyEvent) -> Result<()> {
        match self.focused_panel {
            FocusedPanel::Input => match key.code {
                KeyCode::Char(c) => {
                    self.input_panel.insert_char(c);
                }
                KeyCode::Backspace => {
                    self.input_panel.delete_char();
                }
                KeyCode::Left => {
                    self.input_panel.move_cursor_left();
                }
                KeyCode::Right => {
                    self.input_panel.move_cursor_right();
                }
                KeyCode::Up => {
                    self.input_panel.history_up();
                }
                KeyCode::Down => {
                    self.input_panel.history_down();
                }
                KeyCode::Enter => {
                    if let Some(command) = self.input_panel.submit_command() {
                        info!("User command: {}", command);
                        self.execute_user_command(command).await?;
                    }
                }
                _ => {}
            },
            FocusedPanel::Output => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.output_panel.scroll_up();
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.output_panel.scroll_down();
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    self.output_panel.scroll_offset = 0;
                    self.output_panel.auto_scroll = false;
                }
                KeyCode::End | KeyCode::Char('G') => {
                    self.output_panel.scroll_to_bottom();
                }
                _ => {}
            },
            FocusedPanel::Source => {
                // TODO: Implement source code navigation
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        if self.source_panel.current_line > 0 {
                            self.source_panel.current_line -= 1;
                        }
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        if self.source_panel.current_line + 1 < self.source_panel.content.len() {
                            self.source_panel.current_line += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    async fn execute_user_command(&mut self, command: String) -> Result<()> {
        let trimmed = command.trim();

        if trimmed.starts_with("trace ") {
            // This is a trace command, send it for compilation
            if let Err(e) = self.event_registry.script_sender.send(command.clone()) {
                error!("Failed to send script command: {}", e);
            }
        } else if trimmed.starts_with("attach ") {
            // Parse PID from "attach <pid>"
            if let Some(pid_str) = trimmed.strip_prefix("attach ") {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    let _ = self
                        .event_registry
                        .command_sender
                        .send(RuntimeCommand::AttachToProcess(pid));
                } else {
                    self.output_panel
                        .add_status_message(RuntimeStatus::Error(format!(
                            "Invalid PID: {}",
                            pid_str
                        )));
                }
            }
        } else if trimmed == "detach" {
            let _ = self
                .event_registry
                .command_sender
                .send(RuntimeCommand::DetachFromProcess);
        } else if trimmed == "quit" || trimmed == "exit" {
            let _ = self
                .event_registry
                .command_sender
                .send(RuntimeCommand::Shutdown);
            self.should_quit = true;
        } else if trimmed.is_empty() {
            // Ignore empty commands
        } else {
            // Unknown command
            self.output_panel
                .add_status_message(RuntimeStatus::Error(format!(
                    "Unknown command: {}",
                    trimmed
                )));
        }

        Ok(())
    }

    fn cycle_focus(&mut self) {
        // Tab navigation follows same order as visual layout: Source -> Output -> Input
        self.focused_panel = match self.focused_panel {
            FocusedPanel::Source => FocusedPanel::Output,
            FocusedPanel::Output => FocusedPanel::Input,
            FocusedPanel::Input => FocusedPanel::Source,
        };
    }

    async fn handle_runtime_status(&mut self, status: RuntimeStatus) {
        debug!("Runtime status: {:?}", status);
        self.output_panel.add_status_message(status);
    }

    async fn handle_ringbuf_event(&mut self, event: RingbufEvent) {
        debug!("Ringbuf event: {:?}", event);
        self.output_panel.add_ringbuf_event(event);
    }

    fn render(&mut self, frame: &mut ratatui::Frame) {
        let size = frame.area();

        // Create main layout: source code area and bottom area
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage((self.split_ratio * 100.0) as u16),
                Constraint::Min(1),
            ])
            .split(size);

        // Split bottom area into output and input
        let bottom_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(5),    // Output area (resizable)
                Constraint::Length(3), // Input area (fixed height)
            ])
            .split(main_chunks[1]);

        // Render panels with focus indication
        self.source_panel.render(
            frame,
            main_chunks[0],
            self.focused_panel == FocusedPanel::Source,
        );
        self.output_panel.render(
            frame,
            bottom_chunks[0],
            self.focused_panel == FocusedPanel::Output,
        );
        self.input_panel.render(
            frame,
            bottom_chunks[1],
            self.focused_panel == FocusedPanel::Input,
        );
    }
}

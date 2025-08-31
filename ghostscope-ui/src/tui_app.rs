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
    events::{
        EventRegistry, RingbufEvent, RuntimeCommand, RuntimeStatus, SourceCodeInfo, TuiEvent,
    },
    panels::{EbpfInfoPanel, InteractiveCommandPanel, SourceCodePanel, CommandAction, ResponseType},
};

pub struct TuiApp {
    should_quit: bool,

    // UI panels
    source_panel: SourceCodePanel,
    ebpf_info_panel: EbpfInfoPanel,
    interactive_command_panel: InteractiveCommandPanel,

    // Layout state
    layout_mode: LayoutMode,
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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LayoutMode {
    Horizontal, // 水平布局 (4:3:3)
    Vertical,   // 垂直布局 (上中下)
}

impl TuiApp {
    pub async fn new(event_registry: EventRegistry, layout_mode: LayoutMode) -> Result<Self> {
        Ok(Self {
            should_quit: false,
            source_panel: SourceCodePanel::new(),
            ebpf_info_panel: EbpfInfoPanel::new(),
            interactive_command_panel: InteractiveCommandPanel::new(),
            layout_mode,
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
                    // 垂直布局: j 向下移动焦点
                    if self.layout_mode == LayoutMode::Vertical {
                        self.move_focus("down");
                    }
                    debug!("Window nav: moved focus down to {:?}", self.focused_panel);
                    self.expecting_window_nav = false;
                    return Ok(false);
                }
                KeyCode::Char('k') => {
                    // 垂直布局: k 向上移动焦点
                    if self.layout_mode == LayoutMode::Vertical {
                        self.move_focus("up");
                    }
                    debug!("Window nav: moved focus up to {:?}", self.focused_panel);
                    self.expecting_window_nav = false;
                    return Ok(false);
                }
                KeyCode::Char('h') => {
                    // 水平布局: h 向左移动焦点
                    if self.layout_mode == LayoutMode::Horizontal {
                        self.move_focus("left");
                    }
                    debug!("Window nav: moved focus left to {:?}", self.focused_panel);
                    self.expecting_window_nav = false;
                    return Ok(false);
                }
                KeyCode::Char('l') => {
                    // 水平布局: l 向右移动焦点
                    if self.layout_mode == LayoutMode::Horizontal {
                        self.move_focus("right");
                    }
                    debug!("Window nav: moved focus right to {:?}", self.focused_panel);
                    self.expecting_window_nav = false;
                    return Ok(false);
                }
                KeyCode::Char('v') => {
                    // 切换布局模式
                    self.switch_layout();
                    debug!("Switched layout to {:?}", self.layout_mode);
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
                    self.interactive_command_panel.insert_char(c);
                }
                KeyCode::Backspace => {
                    self.interactive_command_panel.delete_char();
                }
                KeyCode::Left => {
                    self.interactive_command_panel.move_cursor_left();
                }
                KeyCode::Right => {
                    self.interactive_command_panel.move_cursor_right();
                }
                KeyCode::Up => {
                    self.interactive_command_panel.history_up();
                }
                KeyCode::Down => {
                    self.interactive_command_panel.history_down();
                }
                KeyCode::Enter => {
                    if let Some(action) = self.interactive_command_panel.submit_command() {
                        self.handle_command_action(action).await?;
                    }
                }
                KeyCode::Esc => {
                    if self.interactive_command_panel.cancel_script() {
                        info!("Script input cancelled");
                    }
                }
                _ => {}
            },
            FocusedPanel::Output => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.ebpf_info_panel.scroll_up();
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.ebpf_info_panel.scroll_down();
                }
                KeyCode::Home | KeyCode::Char('g') => {
                    self.ebpf_info_panel.scroll_offset = 0;
                    self.ebpf_info_panel.auto_scroll = false;
                }
                KeyCode::End | KeyCode::Char('G') => {
                    self.ebpf_info_panel.scroll_to_bottom();
                }
                _ => {}
            },
            FocusedPanel::Source => {
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.source_panel.move_up();
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.source_panel.move_down();
                    }
                    KeyCode::Left | KeyCode::Char('h') => {
                        self.source_panel.move_left();
                    }
                    KeyCode::Right | KeyCode::Char('l') => {
                        self.source_panel.move_right();
                    }
                    KeyCode::Char('g') => {
                        self.source_panel.move_to_top();
                    }
                    KeyCode::Char('G') => {
                        self.source_panel.move_to_bottom();
                    }
                    _ => {}
                }

                // Handle Ctrl+key combinations
                if key.modifiers.contains(KeyModifiers::CONTROL) {
                    match key.code {
                        KeyCode::Char('d') => {
                            self.source_panel.move_down_fast();
                        }
                        KeyCode::Char('u') => {
                            self.source_panel.move_up_fast();
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_command_action(&mut self, action: CommandAction) -> Result<()> {
        match action {
            CommandAction::ExecuteCommand(command) => {
                self.execute_user_command(command).await?;
            }
            CommandAction::EnterScriptMode(command) => {
                info!("Entering script mode for: {}", command);
                self.interactive_command_panel.add_response(
                    "Entering script mode. Type 'end' or '}' to finish.".to_string(),
                    ResponseType::Info,
                );
            }
            CommandAction::AddScriptLine(line) => {
                info!("Added script line: {}", line);
                // 脚本行已添加到面板中，这里可以添加额外的处理逻辑
            }
            CommandAction::SubmitScript(script) => {
                info!("Submitting script: {}", script);
                // 发送脚本到主程序处理
                if let Err(e) = self.event_registry.script_sender.send(script.clone()) {
                    error!("Failed to send script: {}", e);
                    self.interactive_command_panel.add_response(
                        format!("✗ Failed to send script: {}", e),
                        ResponseType::Error,
                    );
                } else {
                    self.interactive_command_panel.add_response(
                        "✓ Script submitted successfully".to_string(),
                        ResponseType::Success,
                    );
                }
            }
            CommandAction::CancelScript => {
                info!("Script cancelled");
                self.interactive_command_panel.add_response(
                    "⚠ Script input cancelled".to_string(),
                    ResponseType::Warning,
                );
            }
        }
        Ok(())
    }

    async fn execute_user_command(&mut self, command: String) -> Result<()> {
        let trimmed = command.trim();

        if trimmed == "help" {
            self.show_help();
        } else if trimmed.starts_with("trace ") {
            // This is a trace command, send it for compilation
            if let Err(e) = self.event_registry.script_sender.send(command.clone()) {
                error!("Failed to send script command: {}", e);
                self.interactive_command_panel.add_response(
                    format!("✗ Failed to send trace command: {}", e),
                    ResponseType::Error,
                );
            } else {
                self.interactive_command_panel.add_response(
                    "✓ Trace command sent".to_string(),
                    ResponseType::Success,
                );
            }
        } else if trimmed.starts_with("attach ") {
            // Parse PID from "attach <pid>"
            if let Some(pid_str) = trimmed.strip_prefix("attach ") {
                if let Ok(pid) = pid_str.parse::<u32>() {
                    let _ = self
                        .event_registry
                        .command_sender
                        .send(RuntimeCommand::AttachToProcess(pid));
                    self.interactive_command_panel.add_response(
                        format!("⏳ Attaching to process {}", pid),
                        ResponseType::Progress,
                    );
                } else {
                    self.interactive_command_panel.add_response(
                        format!("✗ Invalid PID: {}", pid_str),
                        ResponseType::Error,
                    );
                }
            }
        } else if trimmed == "detach" {
            let _ = self
                .event_registry
                .command_sender
                .send(RuntimeCommand::DetachFromProcess);
            self.interactive_command_panel.add_response(
                "✓ Detached from process".to_string(),
                ResponseType::Success,
            );
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
            self.interactive_command_panel.add_response(
                format!("✗ Unknown command: {}", trimmed),
                ResponseType::Error,
            );
        }

        Ok(())
    }

    fn show_help(&mut self) {
        let help_text = r#"Available commands:
  help     - Show this help message
  trace    - Start tracing a function (enters script mode)
  attach   - Attach to a process by PID
  detach   - Detach from current process
  quit     - Exit ghostscope
  exit     - Exit ghostscope"#;
        
        self.interactive_command_panel.add_response(
            help_text.to_string(),
            ResponseType::Info,
        );
    }

    fn cycle_focus(&mut self) {
        // Tab navigation follows same order as visual layout: Source -> Output -> Input
        self.focused_panel = match self.focused_panel {
            FocusedPanel::Source => FocusedPanel::Output,
            FocusedPanel::Output => FocusedPanel::Input,
            FocusedPanel::Input => FocusedPanel::Source,
        };
    }

    fn switch_layout(&mut self) {
        self.layout_mode = match self.layout_mode {
            LayoutMode::Horizontal => LayoutMode::Vertical,
            LayoutMode::Vertical => LayoutMode::Horizontal,
        };
    }

    fn move_focus(&mut self, direction: &str) {
        match self.layout_mode {
            LayoutMode::Horizontal => {
                // 水平布局: h/l 切换
                match direction {
                    "left" => {
                        self.focused_panel = match self.focused_panel {
                            FocusedPanel::Source => FocusedPanel::Input, // 循环到最右边
                            FocusedPanel::Output => FocusedPanel::Source,
                            FocusedPanel::Input => FocusedPanel::Output,
                        };
                    }
                    "right" => {
                        self.focused_panel = match self.focused_panel {
                            FocusedPanel::Source => FocusedPanel::Output,
                            FocusedPanel::Output => FocusedPanel::Input,
                            FocusedPanel::Input => FocusedPanel::Source, // 循环到最左边
                        };
                    }
                    _ => {}
                }
            }
            LayoutMode::Vertical => {
                // 垂直布局: j/k 切换
                match direction {
                    "up" => {
                        self.focused_panel = match self.focused_panel {
                            FocusedPanel::Source => FocusedPanel::Input, // 循环到最下面
                            FocusedPanel::Output => FocusedPanel::Source,
                            FocusedPanel::Input => FocusedPanel::Output,
                        };
                    }
                    "down" => {
                        self.focused_panel = match self.focused_panel {
                            FocusedPanel::Source => FocusedPanel::Output,
                            FocusedPanel::Output => FocusedPanel::Input,
                            FocusedPanel::Input => FocusedPanel::Source, // 循环到最上面
                        };
                    }
                    _ => {}
                }
            }
        }
    }

    async fn handle_runtime_status(&mut self, status: RuntimeStatus) {
        debug!("Runtime status: {:?}", status);

        match &status {
            RuntimeStatus::SourceCodeLoaded(source_info) => {
                self.source_panel.load_source(
                    source_info.file_path.clone(),
                    source_info.content.clone(),
                    source_info.current_line,
                );
            }
            RuntimeStatus::SourceCodeLoadFailed(_) => {
                self.source_panel.clear_source();
            }
            RuntimeStatus::DwarfLoadingCompleted { .. } => {
                // Auto-request source code when DWARF loading completes
                let _ = self
                    .event_registry
                    .command_sender
                    .send(RuntimeCommand::RequestSourceCode);
            }
            _ => {}
        }

        self.ebpf_info_panel.add_status_message(status);
    }

    async fn handle_ringbuf_event(&mut self, event: RingbufEvent) {
        debug!("Ringbuf event: {:?}", event);
        self.ebpf_info_panel.add_ringbuf_event(event);
    }

    fn render(&mut self, frame: &mut ratatui::Frame) {
        let size = frame.area();

        let chunks = match self.layout_mode {
            LayoutMode::Horizontal => {
                // 水平布局: 4:3:3 比例
                Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Ratio(4, 10), // Source code panel - 40%
                        Constraint::Ratio(3, 10), // eBPF output panel - 30%
                        Constraint::Ratio(3, 10), // Interactive command panel - 30%
                    ])
                    .split(size)
            }
            LayoutMode::Vertical => {
                // 垂直布局: 上中下
                Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Ratio(4, 10), // Source code panel - 40%
                        Constraint::Ratio(3, 10), // eBPF output panel - 30%
                        Constraint::Ratio(3, 10), // Interactive command panel - 30%
                    ])
                    .split(size)
            }
        };

        // Render panels with focus indication
        self.source_panel
            .render(frame, chunks[0], self.focused_panel == FocusedPanel::Source);
        self.ebpf_info_panel
            .render(frame, chunks[1], self.focused_panel == FocusedPanel::Output);
        self.interactive_command_panel.render(
            frame,
            chunks[2],
            self.focused_panel == FocusedPanel::Input,
        );
    }
}

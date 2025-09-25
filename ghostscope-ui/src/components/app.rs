use crate::action::{Action, PanelType};
use crate::components::loading::{LoadingState, LoadingUI};
use crate::events::EventRegistry;
use crate::model::ui_state::LayoutMode;
use crate::model::AppState;
use anyhow::Result;
use crossterm::{
    event::{Event, EventStream, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use futures_util::StreamExt;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    widgets::{Block, BorderType, Borders},
    Frame, Terminal,
};
use std::io;
use tracing::debug;

/// Modern TUI application using TEA architecture
pub struct App {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    state: AppState,
    should_quit: bool,
}

impl App {
    /// Create a new application instance
    pub async fn new(event_registry: EventRegistry, layout_mode: LayoutMode) -> Result<Self> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        // Mouse capture disabled to allow standard copy/paste functionality
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        let mut state = AppState::new(event_registry, layout_mode);

        // Request initial source code on startup
        if let Err(e) = state
            .event_registry
            .command_sender
            .send(crate::events::RuntimeCommand::RequestSourceCode)
        {
            tracing::warn!("Failed to send initial source code request: {}", e);
        } else {
            // Move to connecting state since we've sent the request
            state.set_loading_state(crate::components::loading::LoadingState::ConnectingToRuntime);
        }

        Ok(Self {
            terminal,
            state,
            should_quit: false,
        })
    }

    /// Create a new application instance with full UI configuration
    pub async fn new_with_config(
        event_registry: EventRegistry,
        ui_config: crate::model::ui_state::UiConfig,
    ) -> Result<Self> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        // Mouse capture disabled to allow standard copy/paste functionality
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        let mut state = AppState::new_with_config(event_registry, ui_config);

        // Request initial source code on startup
        if let Err(e) = state
            .event_registry
            .command_sender
            .send(crate::events::RuntimeCommand::RequestSourceCode)
        {
            tracing::warn!("Failed to send initial source code request: {}", e);
        } else {
            // Move to connecting state since we've sent the request
            state.set_loading_state(crate::components::loading::LoadingState::ConnectingToRuntime);
        }

        Ok(Self {
            terminal,
            state,
            should_quit: false,
        })
    }

    /// Main application loop
    pub async fn run(&mut self) -> Result<()> {
        debug!("Starting new TEA-based TUI application");

        // Create async event stream (proper crossterm async support)
        let mut event_stream = EventStream::new();
        let mut needs_render = true;

        // Create a timeout for loading - if no runtime response, go to ready
        const LOADING_TIMEOUT_SECS: u64 = 30;
        let loading_timeout =
            tokio::time::sleep(tokio::time::Duration::from_secs(LOADING_TIMEOUT_SECS));
        tokio::pin!(loading_timeout);

        // Initial render
        self.terminal.draw(|f| Self::draw_ui(f, &mut self.state))?;

        loop {
            // Handle events using select! to monitor multiple sources
            tokio::select! {
                // Handle crossterm events (keyboard, mouse, resize) - proper async
                Some(event_result) = event_stream.next() => {
                    match event_result {
                        Ok(event) => {
                            if let Event::Key(key) = &event {
                                tracing::debug!("Raw crossterm event: {:?}", key);
                            }
                            if let Err(e) = self.handle_event(event).await {
                                tracing::error!("Error handling terminal event: {}", e);
                            }
                            needs_render = true;
                        }
                        Err(e) => {
                            tracing::error!("Error reading terminal events: {}", e);
                            break;
                        }
                    }
                }

                // Handle runtime status messages
                Some(status) = self.state.event_registry.status_receiver.recv() => {
                    self.handle_runtime_status(status).await;
                    needs_render = true;
                }

                // Handle trace events
                Some(trace_event) = self.state.event_registry.trace_receiver.recv() => {
                    self.handle_trace_event(trace_event).await;
                    needs_render = true;
                }

                // Loading timeout - show error in loading UI
                () = &mut loading_timeout, if !self.state.loading_state.is_ready() && !self.state.loading_state.is_failed() => {
                    tracing::info!("No runtime response after {} seconds, connection timeout", LOADING_TIMEOUT_SECS);
                    self.state.set_loading_state(LoadingState::Failed("Connection timeout - no runtime response".to_string()));
                    needs_render = true;
                }

                // Check for jk escape sequence timeout periodically
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    // Check jk timeout
                    if crate::components::command_panel::input_handler::InputHandler::check_jk_timeout(&mut self.state.command_panel) {
                        needs_render = true;
                    }
                }
            }

            // Render only when needed (event-driven)
            if needs_render {
                self.terminal.draw(|f| Self::draw_ui(f, &mut self.state))?;
                needs_render = false;
            }

            // Check for quit condition
            if self.should_quit || self.state.should_quit {
                break;
            }
        }

        self.cleanup().await
    }

    /// Handle terminal events and convert to actions
    async fn handle_event(&mut self, event: Event) -> Result<bool> {
        // Only log non-mouse events to reduce noise
        if !matches!(event, Event::Mouse(_)) {
            tracing::debug!("handle_event called with: {:?}", event);
        }
        let mut actions_to_process = Vec::new();

        match event {
            Event::Key(key) => {
                tracing::debug!(
                    "Event received: key={:?}, is_loading={}",
                    key,
                    self.state.is_loading()
                );
                if key.kind == KeyEventKind::Press {
                    // Always handle input - loading state should not block user interaction
                    // Loading is purely a visual indication

                    // Handle window navigation mode first
                    if self.state.ui.focus.expecting_window_nav {
                        match key.code {
                            KeyCode::Char('h') => {
                                actions_to_process.push(Action::WindowNavMove(
                                    crate::action::WindowDirection::Left,
                                ));
                                actions_to_process.push(Action::ExitWindowNavMode);
                            }
                            KeyCode::Char('j') => {
                                actions_to_process.push(Action::WindowNavMove(
                                    crate::action::WindowDirection::Down,
                                ));
                                actions_to_process.push(Action::ExitWindowNavMode);
                            }
                            KeyCode::Char('k') => {
                                actions_to_process.push(Action::WindowNavMove(
                                    crate::action::WindowDirection::Up,
                                ));
                                actions_to_process.push(Action::ExitWindowNavMode);
                            }
                            KeyCode::Char('l') => {
                                actions_to_process.push(Action::WindowNavMove(
                                    crate::action::WindowDirection::Right,
                                ));
                                actions_to_process.push(Action::ExitWindowNavMode);
                            }
                            KeyCode::Char('v') => {
                                actions_to_process.push(Action::SwitchLayout);
                                actions_to_process.push(Action::ExitWindowNavMode);
                            }
                            KeyCode::Char('z') => {
                                actions_to_process.push(Action::ToggleFullscreen);
                                actions_to_process.push(Action::ExitWindowNavMode);
                            }
                            _ => {
                                // Any other key cancels window navigation
                                actions_to_process.push(Action::ExitWindowNavMode);
                            }
                        }
                    }

                    // Normal key handling
                    match key.code {
                        KeyCode::Char('q')
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL) =>
                        {
                            actions_to_process.push(Action::Quit);
                        }
                        KeyCode::Char('c')
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL) =>
                        {
                            // Special handling for different panel modes
                            if self.state.ui.focus.current_panel
                                == crate::action::PanelType::InteractiveCommand
                                && self.state.command_panel.is_in_history_search()
                            {
                                // Let Ctrl+C go to focused panel handler for history search exit
                                let panel_actions = self.handle_focused_panel_input(key)?;
                                actions_to_process.extend(panel_actions);
                            } else if self.state.ui.focus.current_panel
                                == crate::action::PanelType::Source
                                && self.state.source_panel.mode
                                    == crate::model::panel_state::SourcePanelMode::FileSearch
                            {
                                // Ctrl+C in file search mode should exit file search, not quit app
                                actions_to_process.push(Action::ExitFileSearch);
                            } else {
                                // Normal Ctrl+C behavior: quit application
                                actions_to_process.push(Action::Quit);
                            }
                        }
                        KeyCode::Char('w')
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL) =>
                        {
                            // Handle Ctrl+W based on current focus and mode - priority order matters!
                            if self.state.ui.focus.current_panel == crate::action::PanelType::Source
                                && self.state.source_panel.mode
                                    == crate::model::panel_state::SourcePanelMode::FileSearch
                            {
                                // HIGHEST PRIORITY: File search delete word
                                let delete_actions = crate::components::source_panel::SourceSearch::delete_word_file_search(
                                    &mut self.state.source_panel,
                                );
                                actions_to_process.extend(delete_actions);
                            } else if self.state.ui.focus.current_panel
                                == crate::action::PanelType::InteractiveCommand
                            {
                                match self.state.command_panel.mode {
                                    crate::model::panel_state::InteractionMode::Input => {
                                        actions_to_process.push(Action::DeletePreviousWord);
                                    }
                                    crate::model::panel_state::InteractionMode::ScriptEditor => {
                                        actions_to_process.push(Action::DeletePreviousWord);
                                    }
                                    _ => {
                                        // In command mode, use for window navigation
                                        actions_to_process.push(Action::EnterWindowNavMode);
                                    }
                                }
                            } else {
                                // In other panels, use for window navigation
                                actions_to_process.push(Action::EnterWindowNavMode);
                            }
                        }
                        KeyCode::Tab => {
                            // Handle Tab based on current panel and mode - priority order matters!
                            if self.state.ui.focus.current_panel == crate::action::PanelType::Source
                                && self.state.source_panel.mode
                                    == crate::model::panel_state::SourcePanelMode::FileSearch
                            {
                                // HIGHEST PRIORITY: File search navigation
                                let move_actions = crate::components::source_panel::SourceSearch::move_file_search_down(
                                        &mut self.state.source_panel,
                                    );
                                actions_to_process.extend(move_actions);
                            } else if self.state.ui.focus.current_panel
                                == crate::action::PanelType::InteractiveCommand
                                && self.state.command_panel.mode
                                    == crate::model::panel_state::InteractionMode::ScriptEditor
                            {
                                // Script editor Tab inserts spaces
                                actions_to_process.push(Action::InsertTab);
                            } else if self.state.ui.focus.current_panel
                                == crate::action::PanelType::InteractiveCommand
                                && self.state.command_panel.mode
                                    == crate::model::panel_state::InteractionMode::Input
                            {
                                // COMMAND INPUT MODE: Let Tab go to focused panel handler for auto-suggestion
                                let panel_actions = self.handle_focused_panel_input(key)?;
                                actions_to_process.extend(panel_actions);
                            } else {
                                // Normal Tab behavior: cycle focus
                                actions_to_process.push(Action::FocusNext);
                            }
                        }
                        KeyCode::BackTab => {
                            // Handle Shift+Tab based on current panel and mode
                            if self.state.ui.focus.current_panel == crate::action::PanelType::Source
                                && self.state.source_panel.mode
                                    == crate::model::panel_state::SourcePanelMode::FileSearch
                            {
                                // HIGHEST PRIORITY: File search navigation (up)
                                let move_actions = crate::components::source_panel::SourceSearch::move_file_search_up(
                                        &mut self.state.source_panel,
                                    );
                                actions_to_process.extend(move_actions);
                            } else {
                                // Normal Shift+Tab behavior: cycle focus backward
                                actions_to_process.push(Action::FocusPrevious);
                            }
                        }
                        KeyCode::F(1) => {
                            actions_to_process.push(Action::ToggleFullscreen);
                        }
                        KeyCode::F(2) => {
                            actions_to_process.push(Action::SwitchLayout);
                        }
                        _ => {
                            // Forward to focused panel handler
                            let panel_actions = self.handle_focused_panel_input(key)?;
                            actions_to_process.extend(panel_actions);
                        }
                    }
                }
            }
            Event::Resize(width, height) => {
                actions_to_process.push(Action::Resize(width, height));
            }
            _ => {}
        }

        // Process all actions
        for action in actions_to_process {
            let is_quit = matches!(action, Action::Quit);
            let additional_actions = self.handle_action(action)?;

            // Process any additional actions returned
            for additional_action in additional_actions {
                self.handle_action(additional_action)?;
            }

            if is_quit || self.state.should_quit {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Handle input for the currently focused panel
    fn handle_focused_panel_input(
        &mut self,
        key: crossterm::event::KeyEvent,
    ) -> Result<Vec<Action>> {
        let mut actions = Vec::new();

        match self.state.ui.focus.current_panel {
            PanelType::InteractiveCommand => {
                // First, try the new unified key event handler for history and suggestions
                let unified_actions = self
                    .state
                    .command_input_handler
                    .handle_key_event(&mut self.state.command_panel, key);

                if !unified_actions.is_empty() {
                    // The unified handler handled the key, mark for updates and return
                    self.state.command_renderer.mark_pending_updates();
                    return Ok(unified_actions);
                }

                // Fall back to existing character-based handling
                match key.code {
                    KeyCode::Char(c) => {
                        tracing::debug!(
                            "App received char='{}' (code={}), modifiers={:?}, current_panel={:?}",
                            c,
                            c as u32,
                            key.modifiers,
                            self.state.ui.focus.current_panel
                        );
                        // Handle Ctrl+key combinations first
                        if key
                            .modifiers
                            .contains(crossterm::event::KeyModifiers::CONTROL)
                        {
                            match c {
                                's' => {
                                    // Ctrl+S - only submit script in script mode
                                    if matches!(
                                        self.state.command_panel.mode,
                                        crate::model::panel_state::InteractionMode::ScriptEditor
                                    ) {
                                        actions.push(Action::SubmitScript);
                                    }
                                }
                                'a' => {
                                    match self.state.command_panel.mode {
                                        crate::model::panel_state::InteractionMode::ScriptEditor => {
                                            // Ctrl+A - move to beginning of current line in script mode
                                            let script_actions = crate::components::command_panel::ScriptEditor::move_to_beginning(
                                                &mut self.state.command_panel,
                                            );
                                            actions.extend(script_actions);
                                        }
                                        _ => {
                                            // Ctrl+A - move to beginning of line in input/command mode
                                            actions.push(Action::MoveCursor(crate::action::CursorDirection::Home));
                                        }
                                    }
                                }
                                'e' => {
                                    match self.state.command_panel.mode {
                                        crate::model::panel_state::InteractionMode::ScriptEditor => {
                                            // Ctrl+E - move to end of current line in script mode
                                            let script_actions = crate::components::command_panel::ScriptEditor::move_to_end(
                                                &mut self.state.command_panel,
                                            );
                                            actions.extend(script_actions);
                                        }
                                        _ => {
                                            // Ctrl+E - move to end of line in input/command mode
                                            actions.push(Action::MoveCursor(crate::action::CursorDirection::End));
                                        }
                                    }
                                }
                                'f' => {
                                    match self.state.command_panel.mode {
                                        crate::model::panel_state::InteractionMode::ScriptEditor => {
                                            // Ctrl+F - move cursor right (forward one character) in script mode
                                            let script_actions = crate::components::command_panel::ScriptEditor::move_cursor_right(
                                                &mut self.state.command_panel,
                                            );
                                            actions.extend(script_actions);
                                        }
                                        _ => {
                                            // Ctrl+F - move cursor right in input/command mode
                                            actions.push(Action::MoveCursor(crate::action::CursorDirection::Right));
                                        }
                                    }
                                }
                                'b' => {
                                    match self.state.command_panel.mode {
                                        crate::model::panel_state::InteractionMode::ScriptEditor => {
                                            // Ctrl+B - move cursor left (back one character) in script mode
                                            let script_actions = crate::components::command_panel::ScriptEditor::move_cursor_left(
                                                &mut self.state.command_panel,
                                            );
                                            actions.extend(script_actions);
                                        }
                                        _ => {
                                            // Ctrl+B - move cursor left in input/command mode
                                            actions.push(Action::MoveCursor(crate::action::CursorDirection::Left));
                                        }
                                    }
                                }
                                'u' => {
                                    match self.state.command_panel.mode {
                                        crate::model::panel_state::InteractionMode::ScriptEditor => {
                                            // Ctrl+U - delete from cursor to line start in script mode
                                            let script_actions = crate::components::command_panel::ScriptEditor::delete_to_line_start(
                                                &mut self.state.command_panel,
                                            );
                                            actions.extend(script_actions);
                                        }
                                        crate::model::panel_state::InteractionMode::Command => {
                                            // Ctrl+U - half page up in command mode (fast scroll)
                                            actions.push(Action::CommandHalfPageUp);
                                        }
                                        _ => {
                                            // Ctrl+U - delete to beginning in input mode
                                            actions.push(Action::DeleteToBeginning);
                                        }
                                    }
                                }
                                'd' => {
                                    match self.state.command_panel.mode {
                                        crate::model::panel_state::InteractionMode::Command => {
                                            // Ctrl+D - half page down in command mode (fast scroll)
                                            actions.push(Action::CommandHalfPageDown);
                                        }
                                        _ => {
                                            // Ctrl+D might be used for other purposes in other modes
                                        }
                                    }
                                }
                                'k' => {
                                    match self.state.command_panel.mode {
                                        crate::model::panel_state::InteractionMode::ScriptEditor => {
                                            // Ctrl+K - delete from cursor to line end in script mode
                                            let script_actions = crate::components::command_panel::ScriptEditor::delete_to_end(
                                                &mut self.state.command_panel,
                                            );
                                            actions.extend(script_actions);
                                        }
                                        _ => {
                                            // Ctrl+K - delete to end in input/command mode
                                            actions.push(Action::DeleteToEnd);
                                        }
                                    }
                                }
                                'w' => {
                                    match self.state.command_panel.mode {
                                        crate::model::panel_state::InteractionMode::ScriptEditor => {
                                            // Ctrl+W - delete previous word in script mode
                                            let script_actions = crate::components::command_panel::ScriptEditor::delete_previous_word(
                                                &mut self.state.command_panel,
                                            );
                                            actions.extend(script_actions);
                                        }
                                        _ => {
                                            // Ctrl+W - delete previous word in input/command mode
                                            actions.push(Action::DeletePreviousWord);
                                        }
                                    }
                                }
                                'p' => {
                                    match self.state.command_panel.mode {
                                        crate::model::panel_state::InteractionMode::Input => {
                                            // Ctrl+P - go to previous command in input mode
                                            actions.push(Action::HistoryPrevious);
                                        }
                                        crate::model::panel_state::InteractionMode::ScriptEditor => {
                                            // Ctrl+P - move cursor up (previous line) in script mode
                                            let script_actions = crate::components::command_panel::ScriptEditor::move_cursor_up(
                                                &mut self.state.command_panel,
                                            );
                                            actions.extend(script_actions);
                                        }
                                        _ => {
                                            // Other modes: use original behavior
                                            actions.push(Action::HistoryUp);
                                        }
                                    }
                                }
                                'n' => {
                                    match self.state.command_panel.mode {
                                        crate::model::panel_state::InteractionMode::Input => {
                                            // Ctrl+N - go to next command in input mode
                                            actions.push(Action::HistoryNext);
                                        }
                                        crate::model::panel_state::InteractionMode::ScriptEditor => {
                                            // Ctrl+N - move cursor down (next line) in script mode
                                            let script_actions = crate::components::command_panel::ScriptEditor::move_cursor_down(
                                                &mut self.state.command_panel,
                                            );
                                            actions.extend(script_actions);
                                        }
                                        _ => {
                                            // Other modes: use original behavior
                                            actions.push(Action::HistoryDown);
                                        }
                                    }
                                }
                                'i' => actions.push(Action::InsertTab),
                                'h' => {
                                    match self.state.command_panel.mode {
                                        crate::model::panel_state::InteractionMode::ScriptEditor => {
                                            // Ctrl+H - delete character (backspace) in script mode
                                            let script_actions = crate::components::command_panel::ScriptEditor::delete_char_at_cursor(
                                                &mut self.state.command_panel,
                                            );
                                            actions.extend(script_actions);
                                        }
                                        _ => {
                                            // Ctrl+H - Backspace in input/command mode
                                            let handler_actions = self
                                                .state
                                                .command_input_handler
                                                .handle_backspace(&mut self.state.command_panel);
                                            actions.extend(handler_actions);
                                            self.state.command_renderer.mark_pending_updates();
                                        }
                                    }
                                }
                                _ => {
                                    // Use optimized input handler for regular character input
                                    let handler_actions = self
                                        .state
                                        .command_input_handler
                                        .handle_char_input(&mut self.state.command_panel, c);
                                    actions.extend(handler_actions);
                                    self.state.command_renderer.mark_pending_updates();
                                }
                            }
                        } else {
                            // Handle non-Ctrl character input based on mode
                            match self.state.command_panel.mode {
                                crate::model::panel_state::InteractionMode::Command => {
                                    // In command mode, handle vim-style navigation
                                    match c {
                                        'j' => {
                                            // Move cursor down in unified line view
                                            actions.push(Action::CommandCursorDown);
                                        }
                                        'k' => {
                                            // Move cursor up in unified line view
                                            actions.push(Action::CommandCursorUp);
                                        }
                                        'h' => {
                                            // Move cursor left in current line
                                            actions.push(Action::CommandCursorLeft);
                                        }
                                        'l' => {
                                            // Move cursor right in current line
                                            actions.push(Action::CommandCursorRight);
                                        }
                                        'i' => {
                                            // Exit command mode and return to previous mode
                                            actions.push(Action::ExitCommandMode);
                                        }
                                        'g' => {
                                            // Go to top of history (vim style)
                                            self.state.command_panel.command_cursor_line = 0;
                                            self.state.command_panel.command_cursor_column = 0;
                                            self.state.command_renderer.mark_pending_updates();
                                        }
                                        'G' => {
                                            // Go to the last line of the entire content, including current input
                                            // Use wrapped lines to handle text that exceeds panel width
                                            let wrapped_lines = self
                                                .state
                                                .command_panel
                                                .get_command_mode_wrapped_lines(
                                                    self.state.command_panel_width,
                                                );

                                            if !wrapped_lines.is_empty() {
                                                let last_line =
                                                    wrapped_lines.len().saturating_sub(1);
                                                self.state.command_panel.command_cursor_line =
                                                    last_line;
                                                // Set column to end of the last line
                                                self.state.command_panel.command_cursor_column =
                                                    wrapped_lines[last_line].chars().count();
                                            }
                                            self.state.command_renderer.mark_pending_updates();
                                        }
                                        '$' => {
                                            // Go to end of current line
                                            if self.state.command_panel.command_cursor_line
                                                < self.state.command_panel.command_history.len()
                                            {
                                                self.state.command_panel.command_cursor_column =
                                                    self.state.command_panel.command_history[self
                                                        .state
                                                        .command_panel
                                                        .command_cursor_line]
                                                        .command
                                                        .chars()
                                                        .count();
                                            }
                                            self.state.command_renderer.mark_pending_updates();
                                        }
                                        '0' => {
                                            // Go to beginning of current line
                                            self.state.command_panel.command_cursor_column = 0;
                                            self.state.command_renderer.mark_pending_updates();
                                        }
                                        _ => {
                                            // For other characters in command mode, do nothing or handle as needed
                                        }
                                    }
                                }
                                _ => {
                                    // For input and script modes, use normal input handler
                                    let handler_actions = self
                                        .state
                                        .command_input_handler
                                        .handle_char_input(&mut self.state.command_panel, c);
                                    actions.extend(handler_actions);
                                    self.state.command_renderer.mark_pending_updates();
                                }
                            }
                        }
                    }
                    KeyCode::Backspace => {
                        let handler_actions = self
                            .state
                            .command_input_handler
                            .handle_backspace(&mut self.state.command_panel);
                        actions.extend(handler_actions);
                        self.state.command_renderer.mark_pending_updates();
                    }
                    KeyCode::Enter => {
                        actions.push(Action::SubmitCommand);
                    }
                    KeyCode::Up
                    | KeyCode::Down
                    | KeyCode::Left
                    | KeyCode::Right
                    | KeyCode::Home
                    | KeyCode::End => {
                        let direction = match key.code {
                            KeyCode::Up => crate::action::CursorDirection::Up,
                            KeyCode::Down => crate::action::CursorDirection::Down,
                            KeyCode::Left => crate::action::CursorDirection::Left,
                            KeyCode::Right => crate::action::CursorDirection::Right,
                            KeyCode::Home => crate::action::CursorDirection::Home,
                            KeyCode::End => crate::action::CursorDirection::End,
                            _ => unreachable!(),
                        };
                        let handler_actions = self
                            .state
                            .command_input_handler
                            .handle_movement(&mut self.state.command_panel, direction);
                        actions.extend(handler_actions);
                        self.state.command_renderer.mark_pending_updates();
                    }
                    KeyCode::Esc => {
                        // Handle Esc based on current mode
                        match self.state.command_panel.mode {
                            crate::model::panel_state::InteractionMode::ScriptEditor => {
                                // Script mode: Esc exits to input mode (traditional behavior)
                                actions.push(Action::ExitScriptMode);
                            }
                            crate::model::panel_state::InteractionMode::Input => {
                                // Input mode: Esc enters command mode
                                actions.push(Action::EnterCommandMode);
                            }
                            crate::model::panel_state::InteractionMode::Command => {
                                // Already in command mode, do nothing
                            }
                        }
                    }
                    _ => {}
                }
            }
            PanelType::Source => {
                // Handle source panel input based on current mode
                match self.state.source_panel.mode {
                    crate::model::panel_state::SourcePanelMode::Normal => match key.code {
                        KeyCode::Up => {
                            actions
                                .push(Action::NavigateSource(crate::action::SourceNavigation::Up));
                        }
                        KeyCode::Down => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::Down,
                            ));
                        }
                        KeyCode::Left => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::Left,
                            ));
                        }
                        KeyCode::Right => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::Right,
                            ));
                        }
                        KeyCode::PageUp => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::PageUp,
                            ));
                        }
                        KeyCode::PageDown => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::PageDown,
                            ));
                        }
                        KeyCode::Char('/') => {
                            actions.push(Action::EnterTextSearch);
                        }
                        KeyCode::Char('o') => {
                            actions.push(Action::EnterFileSearch);
                        }
                        KeyCode::Char('g') => {
                            actions.push(Action::SourceGoToLine);
                        }
                        KeyCode::Char('G') => {
                            actions.push(Action::SourceGoToBottom);
                        }
                        KeyCode::Char('h') => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::Left,
                            ));
                        }
                        KeyCode::Char('j') => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::Down,
                            ));
                        }
                        KeyCode::Char('k') => {
                            actions
                                .push(Action::NavigateSource(crate::action::SourceNavigation::Up));
                        }
                        KeyCode::Char('l') => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::Right,
                            ));
                        }
                        KeyCode::Char('n') => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::NextMatch,
                            ));
                        }
                        KeyCode::Char('N') => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::PrevMatch,
                            ));
                        }
                        KeyCode::Char('w') => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::WordForward,
                            ));
                        }
                        KeyCode::Char('b') => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::WordBackward,
                            ));
                        }
                        KeyCode::Char('^') => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::LineStart,
                            ));
                        }
                        KeyCode::Char('$') => {
                            actions.push(Action::NavigateSource(
                                crate::action::SourceNavigation::LineEnd,
                            ));
                        }
                        KeyCode::Char(c) => {
                            // Handle Ctrl+key combinations in source panel
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL)
                            {
                                match c {
                                    'd' => {
                                        // Ctrl+D - half page down (10 lines)
                                        actions.push(Action::NavigateSource(
                                            crate::action::SourceNavigation::HalfPageDown,
                                        ));
                                    }
                                    'u' => {
                                        // Ctrl+U - half page up (10 lines)
                                        actions.push(Action::NavigateSource(
                                            crate::action::SourceNavigation::HalfPageUp,
                                        ));
                                    }
                                    _ => {}
                                }
                            } else if c.is_ascii_digit() {
                                actions.push(Action::SourceNumberInput(c));
                            }
                        }
                        KeyCode::Esc => {
                            // Clear all search highlights and navigation state (like vim)
                            let clear_actions =
                                crate::components::source_panel::SourceNavigation::clear_all_state(
                                    &mut self.state.source_panel,
                                );
                            actions.extend(clear_actions);
                        }
                        _ => {}
                    },
                    crate::model::panel_state::SourcePanelMode::TextSearch => match key.code {
                        KeyCode::Char(c) => {
                            actions.push(Action::SourceSearchInput(c));
                        }
                        KeyCode::Backspace => {
                            actions.push(Action::SourceSearchBackspace);
                        }
                        KeyCode::Enter => {
                            actions.push(Action::SourceSearchConfirm);
                        }
                        KeyCode::Esc => {
                            actions.push(Action::ExitTextSearch);
                        }
                        _ => {}
                    },
                    crate::model::panel_state::SourcePanelMode::FileSearch => match key.code {
                        KeyCode::Char(c) => {
                            // Handle Ctrl+key combinations in file search
                            if key
                                .modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL)
                            {
                                match c {
                                    'n' => {
                                        // Ctrl+N - move down in file search
                                        let move_actions = crate::components::source_panel::SourceSearch::move_file_search_down(
                                            &mut self.state.source_panel,
                                        );
                                        actions.extend(move_actions);
                                    }
                                    'p' => {
                                        // Ctrl+P - move up in file search
                                        let move_actions = crate::components::source_panel::SourceSearch::move_file_search_up(
                                            &mut self.state.source_panel,
                                        );
                                        actions.extend(move_actions);
                                    }
                                    'd' => {
                                        // Ctrl+D - page down in file search (move down multiple items)
                                        for _ in 0..5 {
                                            let move_actions = crate::components::source_panel::SourceSearch::move_file_search_down(
                                                &mut self.state.source_panel,
                                            );
                                            actions.extend(move_actions);
                                        }
                                    }
                                    'u' => {
                                        // Ctrl+U - clear entire query
                                        let clear_actions = crate::components::source_panel::SourceSearch::clear_file_search_query(
                                            &mut self.state.source_panel,
                                        );
                                        actions.extend(clear_actions);
                                    }
                                    'a' => {
                                        // Ctrl+A - move cursor to beginning
                                        let move_actions = crate::components::source_panel::SourceSearch::move_cursor_to_start(
                                            &mut self.state.source_panel,
                                        );
                                        actions.extend(move_actions);
                                    }
                                    'e' => {
                                        // Ctrl+E - move cursor to end
                                        let move_actions = crate::components::source_panel::SourceSearch::move_cursor_to_end(
                                            &mut self.state.source_panel,
                                        );
                                        actions.extend(move_actions);
                                    }
                                    'w' => {
                                        // Ctrl+W - delete previous word
                                        let delete_actions = crate::components::source_panel::SourceSearch::delete_word_file_search(
                                            &mut self.state.source_panel,
                                        );
                                        actions.extend(delete_actions);
                                    }
                                    'b' => {
                                        // Ctrl+B - move cursor left
                                        let move_actions = crate::components::source_panel::SourceSearch::move_cursor_left(
                                            &mut self.state.source_panel,
                                        );
                                        actions.extend(move_actions);
                                    }
                                    'f' => {
                                        // Ctrl+F - move cursor right
                                        let move_actions = crate::components::source_panel::SourceSearch::move_cursor_right(
                                            &mut self.state.source_panel,
                                        );
                                        actions.extend(move_actions);
                                    }
                                    'h' => {
                                        // Ctrl+H - delete previous character (same as backspace)
                                        actions.push(Action::SourceFileSearchBackspace);
                                    }
                                    _ => {
                                        // Regular character input
                                        actions.push(Action::SourceFileSearchInput(c));
                                    }
                                }
                            } else {
                                // Regular character input
                                actions.push(Action::SourceFileSearchInput(c));
                            }
                        }
                        KeyCode::Backspace => {
                            actions.push(Action::SourceFileSearchBackspace);
                        }
                        KeyCode::Enter => {
                            actions.push(Action::SourceFileSearchConfirm);
                        }
                        KeyCode::Up => {
                            // Arrow Up - move up in file search
                            let move_actions =
                                crate::components::source_panel::SourceSearch::move_file_search_up(
                                    &mut self.state.source_panel,
                                );
                            actions.extend(move_actions);
                        }
                        KeyCode::Down => {
                            // Arrow Down - move down in file search
                            let move_actions = crate::components::source_panel::SourceSearch::move_file_search_down(
                                &mut self.state.source_panel,
                            );
                            actions.extend(move_actions);
                        }
                        KeyCode::Esc => {
                            actions.push(Action::ExitFileSearch);
                        }
                        _ => {}
                    },
                }
            }
            PanelType::EbpfInfo => {
                // Handle eBPF panel input using the dedicated handler
                let panel_actions = self
                    .state
                    .ebpf_panel_handler
                    .handle_key_event(&mut self.state.ebpf_panel, key);
                actions.extend(panel_actions);
            }
        }
        Ok(actions)
    }

    /// Handle actions (TEA Update)
    fn handle_action(&mut self, action: Action) -> Result<Vec<Action>> {
        debug!("Handling action: {:?}", action);
        let mut additional_actions = Vec::new();

        match action {
            Action::Quit => {
                self.state.should_quit = true;
            }
            Action::Resize(width, height) => {
                // Force refresh of all panel dimensions on terminal resize
                tracing::debug!("Terminal resized to {}x{}", width, height);
                // The render function will automatically pick up the new dimensions
                // and update panel sizes accordingly
            }
            Action::FocusNext => {
                self.state.ui.focus.cycle_next();
            }
            Action::FocusPrevious => {
                self.state.ui.focus.cycle_previous();
            }
            Action::FocusPanel(panel) => {
                self.state.ui.focus.set_panel(panel);
            }
            Action::ToggleFullscreen => {
                self.state.ui.layout.toggle_fullscreen();
            }
            Action::SwitchLayout => {
                self.state.ui.layout.switch_mode();
            }
            Action::EnterWindowNavMode => {
                self.state.ui.focus.expecting_window_nav = true;
            }
            Action::ExitWindowNavMode => {
                self.state.ui.focus.expecting_window_nav = false;
            }
            Action::WindowNavMove(direction) => {
                self.state
                    .ui
                    .focus
                    .move_focus_in_direction(direction, self.state.ui.layout.mode);
            }
            Action::InsertChar(c) => {
                let actions = crate::components::command_panel::InputHandler::insert_char(
                    &mut self.state.command_panel,
                    c,
                );
                additional_actions.extend(actions);
            }
            Action::DeleteChar => {
                let actions = crate::components::command_panel::InputHandler::delete_char(
                    &mut self.state.command_panel,
                );
                additional_actions.extend(actions);
            }
            Action::MoveCursor(direction) => {
                let actions = crate::components::command_panel::InputHandler::move_cursor(
                    &mut self.state.command_panel,
                    direction,
                );
                additional_actions.extend(actions);
            }
            Action::SubmitCommand => {
                let actions = self
                    .state
                    .command_input_handler
                    .handle_submit(&mut self.state.command_panel);
                additional_actions.extend(actions);
                self.state.command_renderer.mark_pending_updates();
            }
            Action::SubmitCommandWithText { command } => {
                // Handle command submission from history search mode
                // Add to history and process the command
                self.state.command_panel.add_command_to_history(&command);

                // Set the input text and submit it
                self.state.command_panel.input_text = command;
                let actions = self
                    .state
                    .command_input_handler
                    .handle_submit(&mut self.state.command_panel);
                additional_actions.extend(actions);
                self.state.command_renderer.mark_pending_updates();
            }
            Action::HistoryUp => {
                // Handled by input handler
            }
            Action::HistoryDown => {
                // Handled by input handler
            }
            Action::HistoryPrevious => {
                self.state.command_panel.history_previous();
                self.state.command_renderer.mark_pending_updates();
            }
            Action::HistoryNext => {
                self.state.command_panel.history_next();
                self.state.command_renderer.mark_pending_updates();
            }
            Action::EnterCommandMode => {
                self.state
                    .command_panel
                    .enter_command_mode(self.state.command_panel_width);
            }
            Action::ExitCommandMode => {
                self.state.command_panel.exit_command_mode();
            }
            Action::EnterInputMode => {
                self.state.command_panel.mode = crate::model::panel_state::InteractionMode::Input;
            }
            Action::CommandCursorUp => {
                self.state.command_panel.move_command_cursor_up();
                self.state.command_renderer.mark_pending_updates();
            }
            Action::CommandCursorDown => {
                self.state.command_panel.move_command_cursor_down();
                self.state.command_renderer.mark_pending_updates();
            }
            Action::CommandCursorLeft => {
                self.state.command_panel.move_command_cursor_left();
                self.state.command_renderer.mark_pending_updates();
            }
            Action::CommandCursorRight => {
                self.state.command_panel.move_command_cursor_right();
                self.state.command_renderer.mark_pending_updates();
            }
            Action::CommandHalfPageUp => {
                self.state.command_panel.move_command_half_page_up();
                self.state.command_renderer.mark_pending_updates();
            }
            Action::CommandHalfPageDown => {
                self.state.command_panel.move_command_half_page_down();
                self.state.command_renderer.mark_pending_updates();
            }
            Action::EnterScriptMode(command) => {
                let actions = crate::components::command_panel::ScriptEditor::enter_script_mode(
                    &mut self.state.command_panel,
                    &command,
                );
                additional_actions.extend(actions);
            }
            Action::ExitScriptMode => {
                let actions = crate::components::command_panel::ScriptEditor::exit_script_mode(
                    &mut self.state.command_panel,
                );
                additional_actions.extend(actions);
            }
            Action::SubmitScript => {
                let actions = crate::components::command_panel::ScriptEditor::submit_script(
                    &mut self.state.command_panel,
                );
                additional_actions.extend(actions);
            }
            Action::CancelScript => {
                let actions = crate::components::command_panel::ScriptEditor::exit_script_mode(
                    &mut self.state.command_panel,
                );
                additional_actions.extend(actions);
            }
            Action::AddResponse {
                content,
                response_type,
            } => {
                crate::components::command_panel::ResponseFormatter::add_response(
                    &mut self.state.command_panel,
                    content,
                    response_type,
                );
                self.state.command_renderer.mark_pending_updates();
            }
            // Removed old AddWelcomeMessage - now using AddStyledWelcomeMessage
            Action::AddStyledWelcomeMessage {
                styled_lines,
                response_type,
            } => {
                // New direct styled approach - no complex mapping needed
                self.state
                    .command_panel
                    .add_styled_welcome_lines(styled_lines, response_type);
                self.state.command_renderer.mark_pending_updates();
            }
            Action::SendRuntimeCommand(cmd) => {
                // Send command to runtime via event_registry
                debug!("Sending runtime command: {:?}", cmd);
                if let Err(e) = self.state.event_registry.command_sender.send(cmd) {
                    tracing::error!("Failed to send runtime command: {}", e);
                    // Add error response to command panel
                    let error_action = Action::AddResponse {
                        content: format!("Failed to send command to runtime: {e}"),
                        response_type: crate::action::ResponseType::Error,
                    };
                    additional_actions.push(error_action);
                }
            }
            Action::HandleRuntimeStatus(status) => {
                // TODO: Handle runtime status updates
                debug!("Would handle runtime status: {:?}", status);
            }
            Action::DeletePreviousWord => match self.state.command_panel.mode {
                crate::model::panel_state::InteractionMode::ScriptEditor => {
                    let actions =
                        crate::components::command_panel::ScriptEditor::delete_previous_word(
                            &mut self.state.command_panel,
                        );
                    additional_actions.extend(actions);
                }
                _ => {
                    let actions =
                        crate::components::command_panel::InputHandler::delete_previous_word(
                            &mut self.state.command_panel,
                        );
                    additional_actions.extend(actions);
                }
            },
            Action::DeleteToEnd => {
                let actions = crate::components::command_panel::InputHandler::delete_to_end(
                    &mut self.state.command_panel,
                );
                additional_actions.extend(actions);
            }
            Action::DeleteToBeginning => {
                let actions = crate::components::command_panel::InputHandler::delete_to_beginning(
                    &mut self.state.command_panel,
                );
                additional_actions.extend(actions);
            }
            Action::InsertTab => {
                if self.state.command_panel.mode
                    == crate::model::panel_state::InteractionMode::ScriptEditor
                {
                    let actions = crate::components::command_panel::ScriptEditor::insert_tab(
                        &mut self.state.command_panel,
                    );
                    additional_actions.extend(actions);
                }
            }
            Action::InsertNewline => {
                if self.state.command_panel.mode
                    == crate::model::panel_state::InteractionMode::ScriptEditor
                {
                    let actions = crate::components::command_panel::ScriptEditor::insert_newline(
                        &mut self.state.command_panel,
                    );
                    additional_actions.extend(actions);
                }
            }
            // Source panel actions
            Action::NavigateSource(direction) => {
                let actions = match direction {
                    crate::action::SourceNavigation::Up => {
                        crate::components::source_panel::SourceNavigation::move_up(
                            &mut self.state.source_panel,
                        )
                    }
                    crate::action::SourceNavigation::Down => {
                        crate::components::source_panel::SourceNavigation::move_down(
                            &mut self.state.source_panel,
                        )
                    }
                    crate::action::SourceNavigation::Left => {
                        crate::components::source_panel::SourceNavigation::move_left(
                            &mut self.state.source_panel,
                        )
                    }
                    crate::action::SourceNavigation::Right => {
                        crate::components::source_panel::SourceNavigation::move_right(
                            &mut self.state.source_panel,
                        )
                    }
                    crate::action::SourceNavigation::PageUp => {
                        crate::components::source_panel::SourceNavigation::move_up_fast(
                            &mut self.state.source_panel,
                        )
                    }
                    crate::action::SourceNavigation::PageDown => {
                        crate::components::source_panel::SourceNavigation::move_down_fast(
                            &mut self.state.source_panel,
                        )
                    }
                    crate::action::SourceNavigation::HalfPageUp => {
                        crate::components::source_panel::SourceNavigation::move_half_page_up(
                            &mut self.state.source_panel,
                        )
                    }
                    crate::action::SourceNavigation::HalfPageDown => {
                        crate::components::source_panel::SourceNavigation::move_half_page_down(
                            &mut self.state.source_panel,
                        )
                    }
                    crate::action::SourceNavigation::GoToLine(line) => {
                        crate::components::source_panel::SourceNavigation::go_to_line(
                            &mut self.state.source_panel,
                            line,
                        )
                    }
                    crate::action::SourceNavigation::NextMatch => {
                        crate::components::source_panel::SourceSearch::next_match(
                            &mut self.state.source_panel,
                        )
                    }
                    crate::action::SourceNavigation::PrevMatch => {
                        crate::components::source_panel::SourceSearch::prev_match(
                            &mut self.state.source_panel,
                        )
                    }
                    crate::action::SourceNavigation::WordForward => {
                        crate::components::source_panel::SourceNavigation::move_word_forward(
                            &mut self.state.source_panel,
                        )
                    }
                    crate::action::SourceNavigation::WordBackward => {
                        crate::components::source_panel::SourceNavigation::move_word_backward(
                            &mut self.state.source_panel,
                        )
                    }
                    crate::action::SourceNavigation::LineStart => {
                        crate::components::source_panel::SourceNavigation::move_to_line_start(
                            &mut self.state.source_panel,
                        )
                    }
                    crate::action::SourceNavigation::LineEnd => {
                        crate::components::source_panel::SourceNavigation::move_to_line_end(
                            &mut self.state.source_panel,
                        )
                    }
                };
                additional_actions.extend(actions);
            }
            Action::LoadSource { path, line } => {
                let actions = crate::components::source_panel::SourceNavigation::load_source(
                    &mut self.state.source_panel,
                    path,
                    line,
                );
                additional_actions.extend(actions);
            }
            Action::EnterTextSearch => {
                let actions = crate::components::source_panel::SourceSearch::enter_search_mode(
                    &mut self.state.source_panel,
                );
                additional_actions.extend(actions);
            }
            Action::ExitTextSearch => {
                let actions = crate::components::source_panel::SourceSearch::exit_search_mode(
                    &mut self.state.source_panel,
                );
                additional_actions.extend(actions);
            }
            Action::EnterFileSearch => {
                let actions = crate::components::source_panel::SourceSearch::enter_file_search_mode(
                    &mut self.state.source_panel,
                );
                additional_actions.extend(actions);

                // Set routing flag and request file information from runtime
                self.state.route_file_info_to_file_search = true;
                if let Err(e) = self
                    .state
                    .event_registry
                    .command_sender
                    .send(crate::events::RuntimeCommand::InfoSource)
                {
                    tracing::error!("Failed to send InfoSource command: {}", e);
                    // Clear routing flag if send failed
                    self.state.route_file_info_to_file_search = false;
                    let error_actions =
                        crate::components::source_panel::SourceSearch::set_file_search_error(
                            &mut self.state.source_panel,
                            "Failed to request file list".to_string(),
                        );
                    additional_actions.extend(error_actions);
                }
            }
            Action::ExitFileSearch => {
                let actions = crate::components::source_panel::SourceSearch::exit_file_search_mode(
                    &mut self.state.source_panel,
                );
                additional_actions.extend(actions);
            }
            Action::SourceSearchInput(ch) => {
                let actions = crate::components::source_panel::SourceSearch::push_search_char(
                    &mut self.state.source_panel,
                    ch,
                );
                additional_actions.extend(actions);
            }
            Action::SourceSearchBackspace => {
                let actions = crate::components::source_panel::SourceSearch::backspace_search(
                    &mut self.state.source_panel,
                );
                additional_actions.extend(actions);
            }
            Action::SourceSearchConfirm => {
                let actions = crate::components::source_panel::SourceSearch::confirm_search(
                    &mut self.state.source_panel,
                );
                additional_actions.extend(actions);
            }
            Action::SourceFileSearchInput(ch) => {
                let actions = crate::components::source_panel::SourceSearch::push_file_search_char(
                    &mut self.state.source_panel,
                    ch,
                );
                additional_actions.extend(actions);
            }
            Action::SourceFileSearchBackspace => {
                let actions = crate::components::source_panel::SourceSearch::backspace_file_search(
                    &mut self.state.source_panel,
                );
                additional_actions.extend(actions);
            }
            Action::SourceFileSearchConfirm => {
                if let Some(selected_file) =
                    crate::components::source_panel::SourceSearch::confirm_file_search(
                        &mut self.state.source_panel,
                    )
                {
                    // Load the selected file
                    additional_actions.push(Action::LoadSource {
                        path: selected_file,
                        line: None,
                    });
                }
            }
            Action::SourceNumberInput(ch) => {
                let actions =
                    crate::components::source_panel::SourceNavigation::handle_number_input(
                        &mut self.state.source_panel,
                        ch,
                    );
                additional_actions.extend(actions);
            }
            Action::SourceGoToLine => {
                let actions = crate::components::source_panel::SourceNavigation::handle_g_key(
                    &mut self.state.source_panel,
                );
                additional_actions.extend(actions);
            }
            Action::SourceGoToBottom => {
                let actions = crate::components::source_panel::SourceNavigation::handle_shift_g_key(
                    &mut self.state.source_panel,
                );
                additional_actions.extend(actions);
            }
            Action::NoOp => {
                // No operation - does nothing but prevents event fallback
            }
            _ => {
                debug!("Action not yet implemented: {:?}", action);
            }
        }

        Ok(additional_actions)
    }

    /// Add a module to the loading progress tracking
    pub fn add_module_to_loading(&mut self, module_path: String) {
        self.state.loading_ui.progress.add_module(module_path);
    }

    /// Start loading a specific module
    pub fn start_module_loading(&mut self, module_path: &str) {
        self.state
            .loading_ui
            .progress
            .start_module_loading(module_path);
    }

    /// Complete loading of a module with stats
    pub fn complete_module_loading(
        &mut self,
        module_path: &str,
        functions: usize,
        variables: usize,
        types: usize,
    ) {
        use crate::components::loading::ModuleStats;
        let stats = ModuleStats {
            functions,
            variables,
            types,
        };
        self.state
            .loading_ui
            .progress
            .complete_module(module_path, stats);
    }

    /// Fail loading of a module
    pub fn fail_module_loading(&mut self, module_path: &str, error: String) {
        self.state
            .loading_ui
            .progress
            .fail_module(module_path, error);
    }

    /// Set target PID for display
    pub fn set_target_pid(&mut self, pid: u32) {
        self.state.target_pid = Some(pid);
    }

    /// Transition to ready state with completion summary (after successful loading)
    pub fn transition_to_ready_with_completion(&mut self) {
        self.add_loading_completion_summary();
        self.state.set_loading_state(LoadingState::Ready);
    }

    /// Generate and add completion summary to command panel
    pub fn add_loading_completion_summary(&mut self) {
        let total_time = self.state.loading_ui.progress.elapsed_time();

        // Get styled welcome message lines
        let mut styled_lines = self.state.loading_ui.create_welcome_message(total_time);

        // Add process-specific information if available
        if let Some(pid) = self.state.target_pid {
            use ratatui::style::{Color, Style};
            use ratatui::text::{Line, Span};

            // Insert process info after the DWARF statistics line
            let mut enhanced_lines = Vec::new();
            let mut found_dwarf_stats = false;
            for line in styled_lines {
                enhanced_lines.push(line.clone());
                // Look for the DWARF statistics line (contains "indexed")
                let line_text: String = line
                    .spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect();
                if !found_dwarf_stats && line_text.starts_with("•") && line_text.contains("indexed")
                {
                    found_dwarf_stats = true;
                    enhanced_lines.push(Line::from("")); // Empty line
                    enhanced_lines.push(Line::from(Span::styled(
                        format!("Attached to process {pid}"),
                        Style::default().fg(Color::White),
                    )));
                    // TODO: Add process name when available
                }
            }
            styled_lines = enhanced_lines;
        }

        // Removed complex mapping - now using direct styled content approach

        // Use new simplified direct styled approach
        let action = Action::AddStyledWelcomeMessage {
            styled_lines,
            response_type: crate::action::ResponseType::Info,
        };
        if let Err(e) = self.handle_action(action) {
            tracing::error!("Failed to add completion summary: {}", e);
        }
    }

    /// Draw the UI (TEA View)
    fn draw_ui(f: &mut Frame, state: &mut AppState) {
        let size = f.area();

        // Show loading screen if still loading
        if state.is_loading() {
            // Use enhanced DWARF loading UI if we're loading symbols
            if matches!(state.loading_state, LoadingState::LoadingSymbols { .. }) {
                LoadingUI::render_dwarf_loading(
                    f,
                    &mut state.loading_ui,
                    &state.loading_state,
                    state.target_pid,
                );
            } else {
                // Use simple loading UI for other states
                LoadingUI::render_simple(
                    f,
                    &mut state.loading_ui,
                    state.loading_state.message(),
                    state.loading_state.progress(),
                );
            }
            return;
        }

        if state.ui.layout.is_fullscreen {
            // In fullscreen mode, give the focused panel the entire screen
            match state.ui.focus.current_panel {
                PanelType::Source => {
                    Self::draw_source_panel(f, size, state);
                }
                PanelType::EbpfInfo => {
                    Self::draw_ebpf_panel(f, size, state);
                }
                PanelType::InteractiveCommand => {
                    Self::draw_command_panel(f, size, state);
                }
            }
        } else {
            // Normal multi-panel layout
            // Get panel ratios from configuration
            let ratios = &state.ui.config.panel_ratios;
            let total_ratio: u32 = ratios.iter().map(|&x| x as u32).sum();

            let chunks = match state.ui.layout.mode {
                LayoutMode::Horizontal => {
                    Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints(
                            [
                                Constraint::Ratio(ratios[0] as u32, total_ratio), // Source code panel
                                Constraint::Ratio(ratios[1] as u32, total_ratio), // eBPF info panel
                                Constraint::Ratio(ratios[2] as u32, total_ratio), // Command panel
                            ]
                            .as_ref(),
                        )
                        .split(size)
                }
                LayoutMode::Vertical => {
                    Layout::default()
                        .direction(Direction::Vertical)
                        .constraints(
                            [
                                Constraint::Ratio(ratios[0] as u32, total_ratio), // Source code panel
                                Constraint::Ratio(ratios[1] as u32, total_ratio), // eBPF info panel
                                Constraint::Ratio(ratios[2] as u32, total_ratio), // Command panel
                            ]
                            .as_ref(),
                        )
                        .split(size)
                }
            };

            // Draw panels in proper layout
            Self::draw_source_panel(f, chunks[0], state);
            Self::draw_ebpf_panel(f, chunks[1], state);
            Self::draw_command_panel(f, chunks[2], state);
        }
    }

    /// Draw source panel
    fn draw_source_panel(f: &mut Frame, area: Rect, state: &AppState) {
        let is_focused = state.ui.focus.is_focused(PanelType::Source);
        // Create a mutable copy for rendering (area update)
        let mut source_state = state.source_panel.clone();
        crate::components::source_panel::SourceRenderer::render(
            f,
            area,
            &mut source_state,
            is_focused,
        );
    }

    /// Draw eBPF panel
    fn draw_ebpf_panel(f: &mut Frame, area: Rect, state: &mut AppState) {
        let is_focused = state.ui.focus.is_focused(PanelType::EbpfInfo);
        state
            .ebpf_panel_renderer
            .render(&mut state.ebpf_panel, f, area, is_focused);
    }

    /// Draw command panel
    fn draw_command_panel(f: &mut Frame, area: Rect, state: &mut AppState) {
        // Cache panel width for navigation calculations
        state.command_panel_width = area.width.saturating_sub(2); // Subtract borders
        state
            .command_panel
            .update_panel_width(state.command_panel_width);

        let is_focused = state.ui.focus.is_focused(PanelType::InteractiveCommand);
        let border_style = if is_focused {
            crate::ui::themes::UIThemes::panel_focused()
        } else {
            crate::ui::themes::UIThemes::panel_unfocused()
        };

        let block = Block::default()
            .title(crate::ui::strings::UIStrings::COMMAND_PANEL_TITLE)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(border_style);

        f.render_widget(block, area);

        // Use optimized renderer for command panel content
        state
            .command_renderer
            .render(f, area, &state.command_panel, is_focused);
    }

    /// Handle runtime status messages
    async fn handle_runtime_status(&mut self, status: crate::events::RuntimeStatus) {
        use crate::components::loading::LoadingState;
        use crate::events::RuntimeStatus;

        // Update loading state based on runtime status
        match &status {
            RuntimeStatus::DwarfLoadingStarted => {
                self.state.set_loading_state(LoadingState::LoadingSymbols {
                    progress: Some(0.0),
                });
            }
            RuntimeStatus::DwarfLoadingCompleted { .. } => {
                self.state
                    .set_loading_state(LoadingState::LoadingSourceCode);
            }
            RuntimeStatus::DwarfLoadingFailed(error) => {
                self.state
                    .set_loading_state(LoadingState::Failed(error.clone()));
            }
            // Module-level progress handling
            RuntimeStatus::DwarfModuleDiscovered {
                module_path,
                total_modules: _,
            } => {
                // Add module to progress tracking
                self.state
                    .loading_ui
                    .progress
                    .add_module(module_path.clone());
            }
            RuntimeStatus::DwarfModuleLoadingStarted {
                module_path,
                current,
                total,
            } => {
                // Start loading specific module
                self.state
                    .loading_ui
                    .progress
                    .start_module_loading(module_path);
                // Update overall progress based on current/total
                let progress = (*current as f64) / (*total as f64);
                self.state.set_loading_state(LoadingState::LoadingSymbols {
                    progress: Some(progress),
                });
            }
            RuntimeStatus::DwarfModuleLoadingCompleted {
                module_path,
                stats,
                current,
                total,
            } => {
                // Complete module loading with stats
                let module_stats = crate::components::loading::ModuleStats {
                    functions: stats.functions,
                    variables: stats.variables,
                    types: stats.types,
                };
                self.state
                    .loading_ui
                    .progress
                    .complete_module(module_path, module_stats);
                // Update overall progress
                let progress = (*current as f64) / (*total as f64);
                self.state.set_loading_state(LoadingState::LoadingSymbols {
                    progress: Some(progress),
                });
            }
            RuntimeStatus::DwarfModuleLoadingFailed {
                module_path,
                error,
                current: _,
                total: _,
            } => {
                // Mark module as failed
                self.state
                    .loading_ui
                    .progress
                    .fail_module(module_path, error.clone());
            }
            RuntimeStatus::SourceCodeLoaded(_) => {
                // Transition to ready state with completion summary
                self.transition_to_ready_with_completion();
            }
            RuntimeStatus::SourceCodeLoadFailed(error) => {
                self.state
                    .set_loading_state(LoadingState::Failed(error.clone()));
            }
            _ => {
                // For other status messages, if we're still initializing, move to connecting state
                if matches!(self.state.loading_state, LoadingState::Initializing) {
                    self.state
                        .set_loading_state(LoadingState::ConnectingToRuntime);
                }
            }
        }

        match status {
            RuntimeStatus::SourceCodeLoaded(source_info) => {
                // Load source code into source panel
                let actions = crate::components::source_panel::SourceNavigation::load_source(
                    &mut self.state.source_panel,
                    source_info.file_path,
                    source_info.current_line,
                );
                for action in actions {
                    let _ = self.handle_action(action);
                }
            }
            RuntimeStatus::FileInfo { groups } => {
                if self.state.route_file_info_to_file_search {
                    // Convert file groups to flat file list for search
                    let mut files = Vec::new();
                    for group in &groups {
                        for file in &group.files {
                            // Combine directory and filename for full path
                            let full_path = if file.directory.is_empty() {
                                file.path.clone()
                            } else {
                                format!("{}/{}", file.directory, file.path)
                            };
                            files.push(full_path);
                        }
                    }

                    let actions =
                        crate::components::source_panel::SourceSearch::set_file_search_files(
                            &mut self.state.source_panel,
                            files,
                        );
                    for action in actions {
                        let _ = self.handle_action(action);
                    }

                    // Reset routing flag
                    self.state.route_file_info_to_file_search = false;
                } else {
                    // Handle as command response (display in command panel)
                    self.clear_waiting_state();
                    let response =
                        crate::components::command_panel::ResponseFormatter::format_file_info(
                            &groups, false,
                        );
                    let action = Action::AddResponse {
                        content: response,
                        response_type: crate::action::ResponseType::Info,
                    };
                    let _ = self.handle_action(action);
                }
            }
            RuntimeStatus::FileInfoFailed { error } => {
                if self.state.route_file_info_to_file_search {
                    let actions =
                        crate::components::source_panel::SourceSearch::set_file_search_error(
                            &mut self.state.source_panel,
                            error,
                        );
                    for action in actions {
                        let _ = self.handle_action(action);
                    }
                    self.state.route_file_info_to_file_search = false;
                } else {
                    self.clear_waiting_state();
                    let action = Action::AddResponse {
                        content: format!("Failed to get file information: {error}"),
                        response_type: crate::action::ResponseType::Error,
                    };
                    let _ = self.handle_action(action);
                }
            }
            RuntimeStatus::InfoFunctionResult { target: _, info } => {
                // Mark command as completed
                self.clear_waiting_state();
                // Format and display function debug info
                let formatted_info = info.format_for_display();
                let action = Action::AddResponse {
                    content: formatted_info,
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::InfoFunctionFailed { target, error } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("Failed to get debug info for function '{target}': {error}"),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::InfoLineResult { target: _, info } => {
                // Mark command as completed
                self.clear_waiting_state();
                // Format and display line debug info
                let formatted_info = info.format_for_display();
                let action = Action::AddResponse {
                    content: formatted_info,
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::InfoLineFailed { target, error } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("Failed to get debug info for line '{target}': {error}"),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::InfoAddressResult { target: _, info } => {
                // Mark command as completed
                self.clear_waiting_state();
                // Format and display address debug info
                let formatted_info = info.format_for_display();
                let action = Action::AddResponse {
                    content: formatted_info,
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::InfoAddressFailed { target, error } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("Failed to get debug info for address '{target}': {error}"),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::ShareInfo { libraries } => {
                self.clear_waiting_state();
                let formatted_info =
                    crate::components::command_panel::ResponseFormatter::format_shared_library_info(
                        &libraries, false,
                    );
                let action = Action::AddResponse {
                    content: formatted_info,
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::ShareInfoFailed { error } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("Failed to get shared library information: {error}"),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceInfo {
                trace_id,
                target,
                status,
                pid,
                binary,
                script_preview,
                pc,
            } => {
                self.clear_waiting_state();
                // Format trace info with enhanced display
                let mut response = format!("🔍 Trace {trace_id} Info:\n");
                response.push_str(&format!("  Target: {target}\n"));
                response.push_str(&format!("  Status: {status}\n"));
                response.push_str(&format!("  Binary: {binary}\n"));
                response.push_str(&format!("  PC: 0x{pc:x}\n"));
                if let Some(p) = pid {
                    response.push_str(&format!("  PID: {p}\n"));
                }
                if let Some(ref preview) = script_preview {
                    response.push_str(&format!("  Script:\n{preview}\n"));
                }
                let action = Action::AddResponse {
                    content: response,
                    response_type: crate::action::ResponseType::Info,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceInfoAll { summary, traces } => {
                self.clear_waiting_state();
                let mut response = format!(
                    "🔍 All Traces ({} total, {} active):\n\n",
                    summary.total, summary.active
                );
                for trace in &traces {
                    response.push_str(&format!(
                        "  #{} - {} ({})\n",
                        trace.trace_id, trace.target_display, trace.status
                    ));
                }
                let action = Action::AddResponse {
                    content: response,
                    response_type: crate::action::ResponseType::Info,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceInfoFailed { trace_id, error } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("Failed to get info for trace {trace_id}: {error}"),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceEnabled { trace_id } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("✓ Trace {trace_id} enabled"),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceDisabled { trace_id } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("✓ Trace {trace_id} disabled"),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::AllTracesEnabled { count } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("✓ All traces enabled ({count} traces)"),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::AllTracesDisabled { count } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("✓ All traces disabled ({count} traces)"),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceEnableFailed { trace_id, error } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("✗ Failed to enable trace {trace_id}: {error}"),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceDisableFailed { trace_id, error } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("✗ Failed to disable trace {trace_id}: {error}"),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceDeleted { trace_id } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("✓ Trace {trace_id} deleted"),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::AllTracesDeleted { count } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("✓ All traces deleted ({count} traces)"),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceDeleteFailed { trace_id, error } => {
                self.clear_waiting_state();
                let action = Action::AddResponse {
                    content: format!("✗ Failed to delete trace {trace_id}: {error}"),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::ScriptCompilationFailed { error, target } => {
                self.clear_waiting_state();
                // Provide detailed script compilation failure information
                let mut formatted_error =
                    format!("❌ Script compilation failed for target '{target}':\n");

                // Parse and format the error for better readability
                if error.contains("error:") && error.contains("line") {
                    // Parse compiler-style errors
                    formatted_error.push_str("\n  Compilation Error Details:\n");
                    for line in error.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("error:")
                            || trimmed.starts_with("warning:")
                            || trimmed.starts_with("note:")
                            || line.contains("-->")
                        {
                            formatted_error.push_str(&format!("  {trimmed}\n"));
                        } else if !trimmed.is_empty() {
                            formatted_error.push_str(&format!("    {trimmed}\n"));
                        }
                    }
                } else {
                    // Simple error message
                    formatted_error.push_str(&format!("\n  Error: {error}\n"));
                }

                formatted_error.push_str("\n  Troubleshooting:");
                formatted_error.push_str("\n  • Check your script syntax");
                formatted_error.push_str("\n  • Verify function/variable names exist");
                formatted_error.push_str("\n  • Use 'info <target>' to check debug information");

                let action = Action::AddResponse {
                    content: formatted_error,
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            _ => {
                // Handle other runtime status messages (delegate to command panel or other components)
                // For now, pass them to command panel for display
                if let Some(content) = self.format_runtime_status_for_display(&status) {
                    let action = Action::AddResponse {
                        content,
                        response_type: self.get_response_type_for_status(&status),
                    };
                    let _ = self.handle_action(action);
                }
            }
        }
    }

    /// Handle trace events
    async fn handle_trace_event(&mut self, trace_event: ghostscope_protocol::ParsedTraceEvent) {
        tracing::debug!("Trace event: {:?}", trace_event);
        self.state.ebpf_panel.add_trace_event(trace_event);
    }

    /// Format runtime status for display in command panel
    fn format_runtime_status_for_display(
        &self,
        status: &crate::events::RuntimeStatus,
    ) -> Option<String> {
        use crate::events::RuntimeStatus;

        match status {
            RuntimeStatus::ScriptCompilationCompleted { details } => {
                // Check if compilation actually succeeded
                if details.success_count > 0 {
                    // Find the first successful result
                    let first_success = details
                        .results
                        .iter()
                        .find(|r| matches!(r.status, crate::events::ExecutionStatus::Success));

                    if let Some(result) = first_success {
                        // Get the corresponding trace ID from details.trace_ids
                        let trace_id = if !details.trace_ids.is_empty() {
                            Some(details.trace_ids[0]) // Use the first trace ID
                        } else {
                            None
                        };

                        let trace_details =
                            crate::components::command_panel::script_editor::TraceDetails {
                                trace_id,
                                binary_path: Some(result.binary_path.clone()),
                                address: Some(result.pc_address),
                                source_file: None, // Not available in current structure
                                line_number: None, // Not available in current structure
                                function_name: Some(result.target_name.clone()),
                            };

                        // Get script content from the current cache for better display
                        let script_content = self
                            .state
                            .command_panel
                            .script_cache
                            .as_ref()
                            .map(|cache| cache.lines.join("\n"));

                        Some(crate::components::command_panel::script_editor::ScriptEditor::format_trace_success_response_with_script(
                            &result.target_name,
                            Some(&trace_details),
                            script_content.as_deref(),
                            &self.state.emoji_config,
                        ))
                    } else {
                        None // No successful results found
                    }
                } else {
                    // All compilations failed - find the first failed result for error details
                    let first_failed = details.results.first();
                    if let Some(result) = first_failed {
                        if let crate::events::ExecutionStatus::Failed(error) = &result.status {
                            let error_details = crate::components::command_panel::script_editor::TraceErrorDetails {
                                compilation_errors: None,
                                uprobe_error: Some(error.clone()),
                                suggestion: Some("Check function name and ensure binary has debug symbols".to_string()),
                            };

                            // Get script content for error display
                            let script_content = self
                                .state
                                .command_panel
                                .script_cache
                                .as_ref()
                                .map(|cache| cache.lines.join("\n"));

                            Some(crate::components::command_panel::script_editor::ScriptEditor::format_trace_error_response_with_script(
                                &result.target_name,
                                error,
                                Some(&error_details),
                                script_content.as_deref(),
                                &self.state.emoji_config,
                            ))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            }
            RuntimeStatus::ScriptCompilationFailed { error, target } => {
                // Create detailed error information
                let error_details =
                    crate::components::command_panel::script_editor::TraceErrorDetails {
                        compilation_errors: None, // Could be enhanced to parse error details
                        uprobe_error: Some(error.clone()),
                        suggestion: Some(
                            "Check function name and ensure binary has debug symbols".to_string(),
                        ),
                    };

                // Get script content for error display
                let script_content = self
                    .state
                    .command_panel
                    .script_cache
                    .as_ref()
                    .map(|cache| cache.lines.join("\n"));

                Some(crate::components::command_panel::script_editor::ScriptEditor::format_trace_error_response_with_script(
                    target,
                    error,
                    Some(&error_details),
                    script_content.as_deref(),
                    &self.state.emoji_config,
                ))
            }
            RuntimeStatus::Error(msg) => {
                let error_emoji = self
                    .state
                    .emoji_config
                    .get_script_status(crate::ui::emoji::ScriptStatus::Error);
                Some(format!("{error_emoji} Error: {msg}"))
            }
            RuntimeStatus::TraceEnabled { trace_id } => {
                let success_emoji = self
                    .state
                    .emoji_config
                    .get_trace_status(crate::ui::emoji::TraceStatusType::Active);
                Some(format!("{success_emoji} Trace {trace_id} enabled"))
            }
            RuntimeStatus::TraceDisabled { trace_id } => {
                let disabled_emoji = self
                    .state
                    .emoji_config
                    .get_trace_status(crate::ui::emoji::TraceStatusType::Disabled);
                Some(format!("{disabled_emoji} Trace {trace_id} disabled"))
            }
            _ => None, // Don't display other status types in command panel
        }
    }

    /// Get response type for runtime status
    fn get_response_type_for_status(
        &self,
        status: &crate::events::RuntimeStatus,
    ) -> crate::action::ResponseType {
        use crate::events::RuntimeStatus;

        match status {
            RuntimeStatus::Error(_) | RuntimeStatus::ScriptCompilationFailed { .. } => {
                crate::action::ResponseType::Error
            }
            RuntimeStatus::ScriptCompilationCompleted { details } => {
                // Check if compilation actually succeeded
                if details.success_count > 0 {
                    crate::action::ResponseType::Success
                } else {
                    crate::action::ResponseType::Error
                }
            }
            _ => crate::action::ResponseType::Info,
        }
    }

    /// Clear waiting state to return to ready input mode
    fn clear_waiting_state(&mut self) {
        self.state.command_panel.input_state = crate::model::panel_state::InputState::Ready;
    }

    /// Cleanup terminal
    async fn cleanup(&mut self) -> Result<()> {
        disable_raw_mode()?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
        // Mouse capture was not enabled, so no need to disable it
        self.terminal.show_cursor()?;
        Ok(())
    }
}

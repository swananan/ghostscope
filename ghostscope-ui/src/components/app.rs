use crate::action::{Action, PanelType};
use crate::components::loading::{LoadingState, LoadingUI};
use crate::events::EventRegistry;
use crate::model::ui_state::LayoutMode;
use crate::model::AppState;
use anyhow::Result;
use crossterm::{
    event::{
        DisableBracketedPaste, EnableBracketedPaste, Event, EventStream, KeyCode, KeyEventKind,
    },
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
        // Enable bracketed paste to detect paste events (does not affect mouse selection copy)
        execute!(stdout, EnableBracketedPaste)?;
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
        // Enable bracketed paste to detect paste events (does not affect mouse selection copy)
        execute!(stdout, EnableBracketedPaste)?;
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

                    // Check for command response timeout
                    if let crate::model::panel_state::InputState::WaitingResponse { sent_time, command, .. } = &self.state.command_panel.input_state {
                        const COMMAND_TIMEOUT_SECS: u64 = 5;
                        if sent_time.elapsed().as_secs() >= COMMAND_TIMEOUT_SECS {
                            let timeout_msg = format!("Command timeout: '{command}' - no response after {COMMAND_TIMEOUT_SECS} seconds");
                            self.clear_waiting_state();
                            crate::components::command_panel::ResponseFormatter::add_response(
                                &mut self.state.command_panel,
                                timeout_msg,
                                crate::action::ResponseType::Error,
                            );
                            needs_render = true;
                        }
                    }

                    // Periodic cleanup of file completion cache
                    self.state.command_panel.cleanup_file_completion_cache();
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

        // Send shutdown command to runtime before cleanup
        if let Err(e) = self
            .state
            .event_registry
            .command_sender
            .send(crate::events::RuntimeCommand::Shutdown)
        {
            tracing::warn!("Failed to send shutdown command to runtime: {}", e);
        }

        self.cleanup().await
    }

    /// Handle terminal events and convert to actions
    async fn handle_event(&mut self, event: Event) -> Result<bool> {
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

                    // Clear Ctrl+C flag for any key that's not Ctrl+C
                    let is_ctrl_c = matches!(key.code, KeyCode::Char('c'))
                        && key
                            .modifiers
                            .contains(crossterm::event::KeyModifiers::CONTROL);
                    if !is_ctrl_c {
                        self.state.expecting_second_ctrl_c = false;
                    }

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
                            // Use the new centralized Ctrl+C handler
                            let ctrl_c_actions = self.handle_ctrl_c();
                            actions_to_process.extend(ctrl_c_actions);
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
                                if let Some(ref cache) =
                                    self.state.command_panel.file_completion_cache
                                {
                                    let delete_actions = crate::components::source_panel::SourceSearch::delete_word_file_search(
                                        &mut self.state.source_panel,
                                        cache,
                                    );
                                    actions_to_process.extend(delete_actions);
                                }
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
            Event::Paste(pasted) => {
                tracing::debug!("Event received: paste_len={}", pasted.len());
                // Batch insert pasted text depending on focused panel and mode
                match self.state.ui.focus.current_panel {
                    PanelType::InteractiveCommand => {
                        match self.state.command_panel.mode {
                            crate::model::panel_state::InteractionMode::Input => {
                                let actions = self
                                    .state
                                    .command_input_handler
                                    .insert_str(&mut self.state.command_panel, &pasted);
                                actions_to_process.extend(actions);
                                self.state.command_renderer.mark_pending_updates();
                            }
                            crate::model::panel_state::InteractionMode::ScriptEditor => {
                                let actions =
                                    crate::components::command_panel::ScriptEditor::insert_text(
                                        &mut self.state.command_panel,
                                        &pasted,
                                    );
                                actions_to_process.extend(actions);
                                self.state.command_renderer.mark_pending_updates();
                            }
                            crate::model::panel_state::InteractionMode::Command => {
                                // Ignore paste in command mode
                            }
                        }
                    }
                    _ => {
                        // Ignore paste in other panels
                    }
                }
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
                        KeyCode::Char(' ') => {
                            // Space key - set trace at current line
                            actions.push(Action::SetTraceFromSourceLine);
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
                                        if let Some(ref cache) =
                                            self.state.command_panel.file_completion_cache
                                        {
                                            let clear_actions = crate::components::source_panel::SourceSearch::clear_file_search_query(
                                                &mut self.state.source_panel,
                                                cache,
                                            );
                                            actions.extend(clear_actions);
                                        }
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
                                        if let Some(ref cache) =
                                            self.state.command_panel.file_completion_cache
                                        {
                                            let delete_actions = crate::components::source_panel::SourceSearch::delete_word_file_search(
                                                &mut self.state.source_panel,
                                                cache,
                                            );
                                            actions.extend(delete_actions);
                                        }
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

                // Realtime logging: write command to file if enabled
                if self.state.realtime_session_logger.enabled {
                    if let Some(command) = self
                        .state
                        .command_panel
                        .command_history
                        .last()
                        .map(|item| item.command.clone())
                    {
                        if let Err(e) = self.write_command_to_session_log(&command) {
                            tracing::error!("Failed to write command to session log: {}", e);
                        }
                    }
                }
            }
            Action::SubmitCommandWithText { command } => {
                // Handle command submission from history search mode
                // Add to history and process the command
                self.state.command_panel.add_command_to_history(&command);

                // Set the input text and submit it
                self.state.command_panel.input_text = command.clone();
                let actions = self
                    .state
                    .command_input_handler
                    .handle_submit(&mut self.state.command_panel);
                additional_actions.extend(actions);
                self.state.command_renderer.mark_pending_updates();

                // Realtime logging: write command to file if enabled
                if self.state.realtime_session_logger.enabled {
                    if let Err(e) = self.write_command_to_session_log(&command) {
                        tracing::error!("Failed to write command to session log: {}", e);
                    }
                }
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
                // Realtime logging: write response to file if enabled (before moving content)
                if self.state.realtime_session_logger.enabled {
                    if let Err(e) = self.write_response_to_session_log(&content) {
                        tracing::error!("Failed to write response to session log: {}", e);
                    }
                }

                crate::components::command_panel::ResponseFormatter::add_response(
                    &mut self.state.command_panel,
                    content,
                    response_type,
                );
                self.state.command_renderer.mark_pending_updates();
            }
            Action::AddResponseWithStyle {
                content,
                styled_lines,
                response_type,
            } => {
                // Realtime logging: write response to file if enabled (before moving content)
                if self.state.realtime_session_logger.enabled {
                    if let Err(e) = self.write_response_to_session_log(&content) {
                        tracing::error!("Failed to write response to session log: {}", e);
                    }
                }
                crate::components::command_panel::ResponseFormatter::add_response_with_style(
                    &mut self.state.command_panel,
                    content,
                    styled_lines,
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
                    let plain = format!("✗ Failed to send command to runtime: {e}");
                    let styled = vec![
                        crate::components::command_panel::style_builder::StyledLineBuilder::new()
                            .styled(plain.clone(), crate::components::command_panel::style_builder::StylePresets::ERROR)
                            .build(),
                    ];
                    let error_action = Action::AddResponseWithStyle {
                        content: plain,
                        styled_lines: Some(styled),
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

                // Use file cache to populate source panel search
                if let Some(ref mut cache) = self.state.command_panel.file_completion_cache {
                    if !cache.is_empty() {
                        // Use existing file cache
                        tracing::debug!("Using cached file list for source panel search");
                        let files = cache.get_all_files().to_vec();
                        let actions =
                            crate::components::source_panel::SourceSearch::set_file_search_files(
                                &mut self.state.source_panel,
                                cache,
                                files,
                            );
                        additional_actions.extend(actions);
                    }
                } else {
                    // Fallback: request file information from runtime
                    tracing::debug!("No cached files available, requesting from runtime");
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
                if let Some(ref cache) = self.state.command_panel.file_completion_cache {
                    let actions =
                        crate::components::source_panel::SourceSearch::push_file_search_char(
                            &mut self.state.source_panel,
                            cache,
                            ch,
                        );
                    additional_actions.extend(actions);
                }
            }
            Action::SourceFileSearchBackspace => {
                if let Some(ref cache) = self.state.command_panel.file_completion_cache {
                    let actions =
                        crate::components::source_panel::SourceSearch::backspace_file_search(
                            &mut self.state.source_panel,
                            cache,
                        );
                    additional_actions.extend(actions);
                }
            }
            Action::SourceFileSearchConfirm => {
                if let Some(ref cache) = self.state.command_panel.file_completion_cache {
                    if let Some(selected_file) =
                        crate::components::source_panel::SourceSearch::confirm_file_search(
                            &mut self.state.source_panel,
                            cache,
                        )
                    {
                        // Load the selected file
                        additional_actions.push(Action::LoadSource {
                            path: selected_file,
                            line: None,
                        });
                    }
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
            Action::SetTraceFromSourceLine => {
                // Get current file and line from source panel
                if let Some(file_path) = &self.state.source_panel.file_path {
                    let line_num = self.state.source_panel.cursor_line + 1; // Convert to 1-based

                    // Don't mark line as pending here - wait for trace response

                    // Build the trace command
                    let trace_command = format!("trace {file_path}:{line_num}");

                    // Exit fullscreen mode if enabled
                    if self.state.ui.layout.is_fullscreen {
                        self.state.ui.layout.is_fullscreen = false;
                    }

                    // Focus command panel
                    self.state.ui.focus.current_panel = PanelType::InteractiveCommand;

                    // Add command to history (unified method)
                    self.state.command_panel.add_command_entry(&trace_command);

                    // Clear input
                    self.state.command_panel.input_text.clear();
                    self.state.command_panel.cursor_position = 0;

                    // Enter script mode directly
                    additional_actions.push(Action::EnterScriptMode(trace_command));
                }
            }
            Action::SaveEbpfOutput { filename } => {
                // Start realtime eBPF output logging
                let (content, response_type) = match self.start_realtime_output_logging(filename) {
                    Ok(file_path) => (
                        format!(
                            "✅ Realtime eBPF output logging started: {}",
                            file_path.display()
                        ),
                        crate::action::ResponseType::Success,
                    ),
                    Err(e) => (
                        format!("✗ Failed to start output logging: {e}"),
                        crate::action::ResponseType::Error,
                    ),
                };

                // Directly add response to command history
                crate::components::command_panel::ResponseFormatter::add_response(
                    &mut self.state.command_panel,
                    content,
                    response_type,
                );
                self.state.command_renderer.mark_pending_updates();
            }
            Action::SaveCommandSession { filename } => {
                // Start realtime command session logging
                let (content, response_type) = match self.start_realtime_session_logging(filename) {
                    Ok(file_path) => (
                        format!(
                            "✅ Realtime session logging started: {}",
                            file_path.display()
                        ),
                        crate::action::ResponseType::Success,
                    ),
                    Err(e) => (
                        format!("✗ Failed to start session logging: {e}"),
                        crate::action::ResponseType::Error,
                    ),
                };

                // Directly add response to command history
                crate::components::command_panel::ResponseFormatter::add_response(
                    &mut self.state.command_panel,
                    content,
                    response_type,
                );
                self.state.command_renderer.mark_pending_updates();
            }
            Action::StopSaveOutput => {
                // Stop realtime eBPF output logging
                let (content, response_type) = match self.state.realtime_output_logger.stop() {
                    Ok(()) => (
                        "✅ Realtime eBPF output logging stopped".to_string(),
                        crate::action::ResponseType::Success,
                    ),
                    Err(e) => (
                        format!("✗ Failed to stop output logging: {e}"),
                        crate::action::ResponseType::Error,
                    ),
                };

                // Directly add response to command history
                crate::components::command_panel::ResponseFormatter::add_response(
                    &mut self.state.command_panel,
                    content,
                    response_type,
                );
                self.state.command_renderer.mark_pending_updates();
            }
            Action::StopSaveSession => {
                // Stop realtime command session logging
                let (content, response_type) = match self.state.realtime_session_logger.stop() {
                    Ok(()) => (
                        "✅ Realtime session logging stopped".to_string(),
                        crate::action::ResponseType::Success,
                    ),
                    Err(e) => (
                        format!("✗ Failed to stop session logging: {e}"),
                        crate::action::ResponseType::Error,
                    ),
                };

                // Directly add response to command history
                crate::components::command_panel::ResponseFormatter::add_response(
                    &mut self.state.command_panel,
                    content,
                    response_type,
                );
                self.state.command_renderer.mark_pending_updates();
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

    /// Sync file list to command panel for file completion
    fn sync_files_to_command_panel(&mut self, files: Vec<String>) {
        tracing::debug!(
            "Syncing {} files to command panel completion cache",
            files.len()
        );
        if !files.is_empty() {
            tracing::debug!(
                "First 5 files: {:?}",
                files.iter().take(5).collect::<Vec<_>>()
            );
        }

        // Create or update file completion cache
        if let Some(cache) = &mut self.state.command_panel.file_completion_cache {
            // Update existing cache
            let updated = cache.sync_from_source_panel(&files);
            tracing::debug!("Updated existing file completion cache: {}", updated);
        } else {
            // Create new cache only if there are files
            if !files.is_empty() {
                tracing::debug!(
                    "Creating new file completion cache with {} files",
                    files.len()
                );
                self.state.command_panel.file_completion_cache = Some(
                    crate::components::command_panel::file_completion::FileCompletionCache::new(
                        &files,
                    ),
                );
                tracing::debug!("File completion cache created successfully");
            } else {
                tracing::debug!("No files to create cache with");
            }
        }
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

        // Get cache reference (create empty cache if None)
        let empty_cache = crate::components::command_panel::FileCompletionCache::default();
        let cache = state
            .command_panel
            .file_completion_cache
            .as_ref()
            .unwrap_or(&empty_cache);

        crate::components::source_panel::SourceRenderer::render(
            f,
            area,
            &mut source_state,
            cache,
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

                // Auto-request file list for both file completion and source panel search
                tracing::debug!("Auto-requesting file list after source code loaded");
                if let Err(e) = self
                    .state
                    .event_registry
                    .command_sender
                    .send(crate::events::RuntimeCommand::InfoSource)
                {
                    tracing::warn!("Failed to auto-request file list: {}", e);
                }
            }
            RuntimeStatus::FileInfo { groups } => {
                // Convert file groups to flat file list
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

                // Always sync file list to command panel first
                self.sync_files_to_command_panel(files.clone());

                if self.state.route_file_info_to_file_search {
                    // Route to source panel file search
                    if let Some(ref mut cache) = self.state.command_panel.file_completion_cache {
                        let actions =
                            crate::components::source_panel::SourceSearch::set_file_search_files(
                                &mut self.state.source_panel,
                                cache,
                                files.clone(),
                            );
                        for action in actions {
                            let _ = self.handle_action(action);
                        }
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
                    let styled_lines = crate::components::command_panel::ResponseFormatter::format_file_info_styled(
                        &groups, false,
                    );
                    let action = Action::AddResponseWithStyle {
                        content: response,
                        styled_lines: Some(styled_lines),
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
                    let plain = format!("✗ Failed to get file information: {error}");
                    let styled = vec![
                        crate::components::command_panel::style_builder::StyledLineBuilder::new()
                            .styled(plain.clone(), crate::components::command_panel::style_builder::StylePresets::ERROR)
                            .build(),
                    ];
                    let action = Action::AddResponseWithStyle {
                        content: plain,
                        styled_lines: Some(styled),
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
                let styled_lines = info.format_for_display_styled();
                let action = Action::AddResponseWithStyle {
                    content: formatted_info,
                    styled_lines: Some(styled_lines),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::InfoFunctionFailed { target, error } => {
                self.clear_waiting_state();
                let text = format!("✗ Failed to get debug info for function '{target}': {error}");
                let styled = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&text);
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::InfoLineResult { target: _, info } => {
                // Mark command as completed
                self.clear_waiting_state();
                // Format and display line debug info
                let formatted_info = info.format_for_display();
                let styled_lines = info.format_for_display_styled();
                let action = Action::AddResponseWithStyle {
                    content: formatted_info,
                    styled_lines: Some(styled_lines),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::InfoLineFailed { target, error } => {
                self.clear_waiting_state();
                let text = format!("✗ Failed to get debug info for line '{target}': {error}");
                let styled = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&text);
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::InfoAddressResult { target: _, info } => {
                // Mark command as completed
                self.clear_waiting_state();
                // Format and display address debug info
                let formatted_info = info.format_for_display();
                let styled_lines = info.format_for_display_styled();
                let action = Action::AddResponseWithStyle {
                    content: formatted_info,
                    styled_lines: Some(styled_lines),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::InfoAddressFailed { target, error } => {
                self.clear_waiting_state();
                let text = format!("✗ Failed to get debug info for address '{target}': {error}");
                let styled = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&text);
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
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
                let styled_lines =
                    crate::components::command_panel::ResponseFormatter::format_shared_library_info_styled(
                        &libraries,
                        false,
                    );
                let action = Action::AddResponseWithStyle {
                    content: formatted_info,
                    styled_lines: Some(styled_lines),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::ShareInfoFailed { error } => {
                self.clear_waiting_state();
                let text = format!("✗ Failed to get shared library information: {error}");
                let styled = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&text);
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::ExecutableFileInfo {
                file_path,
                file_type,
                entry_point,
                has_symbols,
                has_debug_info,
                debug_file_path,
                text_section,
                data_section,
                mode_description,
            } => {
                self.clear_waiting_state();
                let info_display =
                    crate::components::command_panel::response_formatter::ExecutableFileInfoDisplay {
                        file_path: &file_path,
                        file_type: &file_type,
                        entry_point,
                        has_symbols,
                        has_debug_info,
                        debug_file_path: &debug_file_path,
                        text_section: &text_section,
                        data_section: &data_section,
                        mode_description: &mode_description,
                    };
                let formatted_info =
                    crate::components::command_panel::ResponseFormatter::format_executable_file_info(
                        &info_display,
                    );
                let styled_lines =
                    crate::components::command_panel::ResponseFormatter::format_executable_file_info_styled(
                        &info_display,
                    );
                let action = Action::AddResponseWithStyle {
                    content: formatted_info,
                    styled_lines: Some(styled_lines),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::ExecutableFileInfoFailed { error } => {
                self.clear_waiting_state();
                let text = format!("✗ Failed to get executable file information: {error}");
                let styled = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&text);
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::SrcPathInfo { info } => {
                self.clear_waiting_state();
                let formatted = info.format_for_display();
                let styled_lines = info.format_for_display_styled();
                let action = Action::AddResponseWithStyle {
                    content: formatted,
                    styled_lines: Some(styled_lines),
                    response_type: crate::action::ResponseType::Info,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::SrcPathUpdated { message } => {
                self.clear_waiting_state();

                // Set flag to route upcoming FileInfo to file search panel
                // This ensures file search list is updated with new path mappings
                self.state.route_file_info_to_file_search = true;

                let plain = format!("✅ {message}\n💡 Source code and file list reloading...");
                let styled = vec![
                    crate::components::command_panel::style_builder::StyledLineBuilder::new()
                        .styled(
                            format!("✅ {message}"),
                            crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                        )
                        .build(),
                    crate::components::command_panel::style_builder::StyledLineBuilder::new()
                        .styled(
                            "💡 Source code and file list reloading...",
                            crate::components::command_panel::style_builder::StylePresets::TIP,
                        )
                        .build(),
                ];
                let action = Action::AddResponseWithStyle {
                    content: plain,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::SrcPathFailed { error } => {
                self.clear_waiting_state();
                let text = format!("✗ {error}");
                let styled = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&text);
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
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

                // Extract source location from target (could be "file:line" or "function_name")
                // TODO: For function traces, we need source_file and source_line fields in TraceInfo
                // Currently only file:line format works for source panel updates
                if let Some(colon_pos) = target.rfind(':') {
                    let file_part = &target[..colon_pos];
                    if let Ok(line_num) = target[colon_pos + 1..].parse::<usize>() {
                        // Store the trace location
                        self.state
                            .source_panel
                            .trace_locations
                            .insert(trace_id, (file_part.to_string(), line_num));

                        // Update line colors if this is the current file
                        if self.state.source_panel.file_path.as_ref()
                            == Some(&file_part.to_string())
                        {
                            // Clear pending status if it exists
                            if self.state.source_panel.pending_trace_line == Some(line_num) {
                                self.state.source_panel.pending_trace_line = None;
                            }

                            // Update line color based on trace status
                            match status {
                                crate::events::TraceStatus::Active => {
                                    self.state.source_panel.disabled_lines.remove(&line_num);
                                    self.state.source_panel.traced_lines.insert(line_num);
                                }
                                crate::events::TraceStatus::Disabled => {
                                    self.state.source_panel.traced_lines.remove(&line_num);
                                    self.state.source_panel.disabled_lines.insert(line_num);
                                }
                                _ => {
                                    // For other statuses, don't color the line
                                    self.state.source_panel.traced_lines.remove(&line_num);
                                    self.state.source_panel.disabled_lines.remove(&line_num);
                                }
                            }
                        }
                    }
                }

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
                // Also create styled version
                let styled_lines = {
                    let temp = crate::events::RuntimeStatus::TraceInfo {
                        trace_id,
                        target: target.clone(),
                        status: status.clone(),
                        pid,
                        binary: binary.clone(),
                        script_preview: None,
                        pc,
                    };
                    if let Some(mut base) = temp.format_trace_info_styled() {
                        if let Some(ref preview) = script_preview {
                            use crate::components::command_panel::style_builder::StyledLineBuilder;
                            use ratatui::text::Line;
                            base.push(Line::from(""));
                            base.push(StyledLineBuilder::new().key("📝 Script:").build());
                            for line in preview.lines() {
                                base.push(StyledLineBuilder::new().text("  ").value(line).build());
                            }
                        }
                        Some(base)
                    } else {
                        None
                    }
                };

                let action = Action::AddResponseWithStyle {
                    content: response,
                    styled_lines,
                    response_type: crate::action::ResponseType::Info,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceInfoAll { summary, traces } => {
                self.clear_waiting_state();

                // Update source panel line colors based on trace status
                for trace in &traces {
                    // Try to extract file and line from target_display (format: "file:line" or "function_name")
                    // TODO: Need source_file and source_line fields for function traces
                    if let Some(colon_pos) = trace.target_display.rfind(':') {
                        let file_part = &trace.target_display[..colon_pos];
                        if let Ok(line_num) = trace.target_display[colon_pos + 1..].parse::<usize>()
                        {
                            // Store the trace location
                            self.state
                                .source_panel
                                .trace_locations
                                .insert(trace.trace_id, (file_part.to_string(), line_num));

                            // Update line colors if this is the current file
                            if self.state.source_panel.file_path.as_ref()
                                == Some(&file_part.to_string())
                            {
                                match trace.status {
                                    crate::events::TraceStatus::Active => {
                                        self.state.source_panel.disabled_lines.remove(&line_num);
                                        self.state.source_panel.traced_lines.insert(line_num);
                                    }
                                    crate::events::TraceStatus::Disabled => {
                                        self.state.source_panel.traced_lines.remove(&line_num);
                                        self.state.source_panel.disabled_lines.insert(line_num);
                                    }
                                    crate::events::TraceStatus::Failed => {
                                        self.state.source_panel.traced_lines.remove(&line_num);
                                        self.state.source_panel.disabled_lines.remove(&line_num);
                                    }
                                }
                            }
                        }
                    }
                }

                let mut response = format!(
                    "🔍 All Traces ({} total, {} active):\n\n",
                    summary.total, summary.active
                );
                for trace in &traces {
                    // Use format_line() to show detailed info including address and module
                    response.push_str(&format!("  {}\n", trace.format_line()));
                }
                // Styled version
                let styled_lines = (crate::events::RuntimeStatus::TraceInfoAll {
                    summary: summary.clone(),
                    traces: traces.clone(),
                })
                .format_trace_info_styled()
                .unwrap_or_default();
                let action = Action::AddResponseWithStyle {
                    content: response,
                    styled_lines: if styled_lines.is_empty() {
                        None
                    } else {
                        Some(styled_lines)
                    },
                    response_type: crate::action::ResponseType::Info,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceInfoFailed { trace_id, error } => {
                self.clear_waiting_state();
                let text = format!("✗ Failed to get info for trace {trace_id}: {error}");
                let styled = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&text);
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceEnabled { trace_id } => {
                self.clear_waiting_state();

                // Update source panel line color
                if let Some((file_path, line_num)) =
                    self.state.source_panel.trace_locations.get(&trace_id)
                {
                    if self.state.source_panel.file_path.as_ref() == Some(file_path) {
                        self.state.source_panel.disabled_lines.remove(line_num);
                        self.state.source_panel.traced_lines.insert(*line_num);
                    }
                }

                let text = format!("✅ Trace {trace_id} enabled");
                let styled = vec![
                    crate::components::command_panel::style_builder::StyledLineBuilder::new()
                        .styled(
                            text.clone(),
                            crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                        )
                        .build(),
                ];
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceDisabled { trace_id } => {
                self.clear_waiting_state();

                // Update source panel line color
                if let Some((file_path, line_num)) =
                    self.state.source_panel.trace_locations.get(&trace_id)
                {
                    if self.state.source_panel.file_path.as_ref() == Some(file_path) {
                        self.state.source_panel.traced_lines.remove(line_num);
                        self.state.source_panel.disabled_lines.insert(*line_num);
                    }
                }

                let text = format!("✅ Trace {trace_id} disabled");
                let styled = vec![
                    crate::components::command_panel::style_builder::StyledLineBuilder::new()
                        .styled(
                            text.clone(),
                            crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                        )
                        .build(),
                ];
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::AllTracesEnabled { count, error } => {
                self.clear_waiting_state();

                if error.is_none() {
                    // Move all known traces from disabled to enabled
                    for (file_path, line_num) in self.state.source_panel.trace_locations.values() {
                        if self.state.source_panel.file_path.as_ref() == Some(file_path) {
                            self.state.source_panel.disabled_lines.remove(line_num);
                            self.state.source_panel.traced_lines.insert(*line_num);
                        }
                    }
                }

                let (plain, rtype, style) = if let Some(ref err) = error {
                    (
                        format!("✗ Failed to enable traces: {err}"),
                        crate::action::ResponseType::Error,
                        crate::components::command_panel::style_builder::StylePresets::ERROR,
                    )
                } else {
                    (
                        format!("✅ All traces enabled ({count} traces)"),
                        crate::action::ResponseType::Success,
                        crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                    )
                };
                let styled = vec![
                    crate::components::command_panel::style_builder::StyledLineBuilder::new()
                        .styled(plain.clone(), style)
                        .build(),
                ];
                let action = Action::AddResponseWithStyle {
                    content: plain,
                    styled_lines: Some(styled),
                    response_type: rtype,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::AllTracesDisabled { count, error } => {
                self.clear_waiting_state();

                if error.is_none() {
                    // Move all known traces from enabled to disabled
                    for (file_path, line_num) in self.state.source_panel.trace_locations.values() {
                        if self.state.source_panel.file_path.as_ref() == Some(file_path) {
                            self.state.source_panel.traced_lines.remove(line_num);
                            self.state.source_panel.disabled_lines.insert(*line_num);
                        }
                    }
                }

                let (plain, rtype, style) = if let Some(ref err) = error {
                    (
                        format!("✗ Failed to disable traces: {err}"),
                        crate::action::ResponseType::Error,
                        crate::components::command_panel::style_builder::StylePresets::ERROR,
                    )
                } else {
                    (
                        format!("✅ All traces disabled ({count} traces)"),
                        crate::action::ResponseType::Success,
                        crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                    )
                };
                let styled = vec![
                    crate::components::command_panel::style_builder::StyledLineBuilder::new()
                        .styled(plain.clone(), style)
                        .build(),
                ];
                let action = Action::AddResponseWithStyle {
                    content: plain,
                    styled_lines: Some(styled),
                    response_type: rtype,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceEnableFailed { trace_id, error } => {
                self.clear_waiting_state();
                let text = format!("✗ Failed to enable trace {trace_id}: {error}");
                let styled = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&text);
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceDisableFailed { trace_id, error } => {
                self.clear_waiting_state();
                let text = format!("✗ Failed to disable trace {trace_id}: {error}");
                let styled = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&text);
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceDeleted { trace_id } => {
                self.clear_waiting_state();

                // Remove from source panel line colors
                if let Some((file_path, line_num)) =
                    self.state.source_panel.trace_locations.remove(&trace_id)
                {
                    if self.state.source_panel.file_path.as_ref() == Some(&file_path) {
                        self.state.source_panel.traced_lines.remove(&line_num);
                        self.state.source_panel.disabled_lines.remove(&line_num);
                    }
                }

                let text = format!("✅ Trace {trace_id} deleted");
                let styled = vec![
                    crate::components::command_panel::style_builder::StyledLineBuilder::new()
                        .styled(
                            text.clone(),
                            crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                        )
                        .build(),
                ];
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::AllTracesDeleted { count, error } => {
                self.clear_waiting_state();

                if error.is_none() {
                    // Clear all trace locations and colors
                    self.state.source_panel.traced_lines.clear();
                    self.state.source_panel.disabled_lines.clear();
                    self.state.source_panel.trace_locations.clear();
                }

                let (plain, rtype, style) = if let Some(ref err) = error {
                    (
                        format!("✗ Failed to delete traces: {err}"),
                        crate::action::ResponseType::Error,
                        crate::components::command_panel::style_builder::StylePresets::ERROR,
                    )
                } else {
                    (
                        format!("✅ All traces deleted ({count} traces)"),
                        crate::action::ResponseType::Success,
                        crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                    )
                };
                let styled = vec![
                    crate::components::command_panel::style_builder::StyledLineBuilder::new()
                        .styled(plain.clone(), style)
                        .build(),
                ];
                let action = Action::AddResponseWithStyle {
                    content: plain,
                    styled_lines: Some(styled),
                    response_type: rtype,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TraceDeleteFailed { trace_id, error } => {
                self.clear_waiting_state();
                let text = format!("✗ Failed to delete trace {trace_id}: {error}");
                let styled = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&text);
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TracesSaved {
                filename,
                saved_count,
                total_count,
            } => {
                self.clear_waiting_state();
                let text = format!("✅ Saved {saved_count} of {total_count} traces to {filename}");
                let styled = vec![
                    crate::components::command_panel::style_builder::StyledLineBuilder::new()
                        .styled(
                            text.clone(),
                            crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                        )
                        .build(),
                ];
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Success,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TracesSaveFailed { error } => {
                self.clear_waiting_state();
                let text = format!("✗ Failed to save traces: {error}");
                let styled = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&text);
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TracesLoaded {
                filename,
                total_count,
                success_count,
                failed_count,
                disabled_count,
                details,
            } => {
                self.clear_waiting_state();

                // Build response message
                let mut response = String::new();

                if failed_count == 0 {
                    // All traces loaded successfully
                    response.push_str(&format!(
                        "✓ Loaded {} traces from {} ({} enabled, {} disabled)",
                        total_count,
                        filename,
                        success_count - disabled_count,
                        disabled_count
                    ));
                } else {
                    // Some traces failed
                    response.push_str(&format!("⚠️ Partially loaded traces from {filename}\n"));
                    response.push_str(&format!(
                        "  ✓ {} traces created ({} enabled, {} disabled)\n",
                        success_count,
                        success_count - disabled_count,
                        disabled_count
                    ));

                    // Show failed traces
                    for detail in &details {
                        if let crate::events::LoadStatus::Failed = detail.status {
                            if let Some(ref error) = detail.error {
                                response.push_str(&format!("  ✗ {} - {}\n", detail.target, error));
                            }
                        }
                    }
                }

                // Styled version
                let mut styled = Vec::new();
                use crate::components::command_panel::style_builder::{
                    StylePresets, StyledLineBuilder,
                };
                if failed_count == 0 {
                    styled.push(
                        StyledLineBuilder::new()
                            .styled(
                                format!(
                                    "✅ Loaded {} traces from {} ({} enabled, {} disabled)",
                                    total_count,
                                    filename,
                                    success_count - disabled_count,
                                    disabled_count
                                ),
                                StylePresets::SUCCESS,
                            )
                            .build(),
                    );
                } else {
                    styled.push(
                        StyledLineBuilder::new()
                            .styled(
                                format!("⚠️ Partially loaded traces from {filename}"),
                                StylePresets::WARNING,
                            )
                            .build(),
                    );
                    styled.push(
                        StyledLineBuilder::new()
                            .text("  ")
                            .styled(
                                format!(
                                    "✅ {} traces created ({} enabled, {} disabled)",
                                    success_count,
                                    success_count - disabled_count,
                                    disabled_count
                                ),
                                StylePresets::SUCCESS,
                            )
                            .build(),
                    );
                    for detail in &details {
                        if let crate::events::LoadStatus::Failed = detail.status {
                            if let Some(ref err) = detail.error {
                                styled.push(
                                    StyledLineBuilder::new()
                                        .text("  ")
                                        .styled(
                                            format!("✗ {} - {}", detail.target, err),
                                            StylePresets::ERROR,
                                        )
                                        .build(),
                                );
                            }
                        }
                    }
                }

                let action = Action::AddResponseWithStyle {
                    content: response,
                    styled_lines: Some(styled),
                    response_type: if failed_count == 0 {
                        crate::action::ResponseType::Success
                    } else {
                        crate::action::ResponseType::Warning
                    },
                };
                let _ = self.handle_action(action);
            }
            RuntimeStatus::TracesLoadFailed { filename, error } => {
                self.clear_waiting_state();
                let text = format!("✗ Failed to load {filename}: {error}");
                let styled = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&text);
                let action = Action::AddResponseWithStyle {
                    content: text,
                    styled_lines: Some(styled),
                    response_type: crate::action::ResponseType::Error,
                };
                let _ = self.handle_action(action);
            }
            _ => {
                // Handle other runtime status messages (delegate to command panel or other components)
                // For now, pass them to command panel for display

                // Check if this is an error status or completed status that should clear waiting state
                let should_clear_waiting = matches!(
                    status,
                    RuntimeStatus::AllTracesEnabled { .. }
                        | RuntimeStatus::AllTracesDisabled { .. }
                        | RuntimeStatus::AllTracesDeleted { .. }
                        | RuntimeStatus::ScriptCompilationCompleted { .. }
                        | RuntimeStatus::TraceInfoFailed { .. }
                        | RuntimeStatus::FileInfoFailed { .. }
                        | RuntimeStatus::ShareInfoFailed { .. }
                        | RuntimeStatus::ExecutableFileInfoFailed { .. }
                        | RuntimeStatus::SrcPathFailed { .. }
                );

                if should_clear_waiting {
                    self.clear_waiting_state();
                }

                if let Some(content) = self.format_runtime_status_for_display(&status) {
                    let styled_lines = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&content);
                    let action = Action::AddResponseWithStyle {
                        content,
                        styled_lines: Some(styled_lines),
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

        // Realtime logging: write eBPF event to file if enabled
        if self.state.realtime_output_logger.enabled {
            if let Err(e) = self.write_ebpf_event_to_output_log(&trace_event) {
                tracing::error!("Failed to write eBPF event to output log: {}", e);
            }
        }

        self.state.ebpf_panel.add_trace_event(trace_event);
    }

    /// Format runtime status for display in command panel
    fn format_runtime_status_for_display(
        &mut self,
        status: &crate::events::RuntimeStatus,
    ) -> Option<String> {
        use crate::events::RuntimeStatus;

        match status {
            RuntimeStatus::ScriptCompilationCompleted { details } => {
                // Check if this is part of a batch load operation
                if let Some(ref mut batch) = self.state.command_panel.batch_loading {
                    // Update batch loading state
                    batch.completed_count += 1;
                    if details.success_count > 0 {
                        batch.success_count += details.success_count;
                        // Add successful trace details
                        for result in &details.results {
                            if matches!(result.status, crate::events::ExecutionStatus::Success) {
                                let trace_id = details.trace_ids.first().copied();
                                batch.details.push(crate::events::TraceLoadDetail {
                                    target: result.target_name.clone(),
                                    trace_id,
                                    status: crate::events::LoadStatus::Created,
                                    error: None,
                                });
                            }
                        }
                    } else {
                        batch.failed_count += 1;
                        // Add failed trace details
                        for result in &details.results {
                            if let crate::events::ExecutionStatus::Failed(error) = &result.status {
                                batch.details.push(crate::events::TraceLoadDetail {
                                    target: result.target_name.clone(),
                                    trace_id: None,
                                    status: crate::events::LoadStatus::Failed,
                                    error: Some(error.clone()),
                                });
                            }
                        }
                    }

                    // Check if all traces have been processed
                    if batch.completed_count >= batch.total_count {
                        // All traces processed, show summary
                        let filename = batch.filename.clone();
                        let total_count = batch.total_count;
                        let success_count = batch.success_count;
                        let failed_count = batch.failed_count;
                        let disabled_count = batch.disabled_count;
                        let details = batch.details.clone();

                        // Clear batch loading state
                        self.state.command_panel.batch_loading = None;

                        // Clear waiting state
                        self.clear_waiting_state();

                        // Show summary response
                        let mut response = format!("📂 Loaded traces from {filename}\n");
                        response.push_str(&format!(
                            "  Total: {total_count}, Success: {success_count}, Failed: {failed_count}"
                        ));
                        if disabled_count > 0 {
                            response.push_str(&format!(", Disabled: {disabled_count}"));
                        }
                        response.push('\n');

                        // Show details
                        if !details.is_empty() {
                            response.push_str("\n📊 Details:\n");
                            for detail in &details {
                                match detail.status {
                                    crate::events::LoadStatus::Created => {
                                        if let Some(id) = detail.trace_id {
                                            response.push_str(&format!(
                                                "  ✓ {} → trace #{}\n",
                                                detail.target, id
                                            ));
                                        } else {
                                            response.push_str(&format!("  ✓ {}\n", detail.target));
                                        }
                                    }
                                    crate::events::LoadStatus::CreatedDisabled => {
                                        if let Some(id) = detail.trace_id {
                                            response.push_str(&format!(
                                                "  ⊘ {} → trace #{} (disabled)\n",
                                                detail.target, id
                                            ));
                                        } else {
                                            response.push_str(&format!(
                                                "  ⊘ {} (disabled)\n",
                                                detail.target
                                            ));
                                        }
                                    }
                                    crate::events::LoadStatus::Failed => {
                                        if let Some(ref error) = detail.error {
                                            response.push_str(&format!(
                                                "  ✗ {}: {}\n",
                                                detail.target, error
                                            ));
                                        } else {
                                            response.push_str(&format!("  ✗ {}\n", detail.target));
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }

                        let action = Action::AddResponse {
                            content: response,
                            response_type: if failed_count > 0 {
                                crate::action::ResponseType::Warning
                            } else {
                                crate::action::ResponseType::Success
                            },
                        };
                        let _ = self.handle_action(action);

                        // Don't return - continue to allow individual trace display to be suppressed
                        return None;
                    } else {
                        // Still waiting for more traces, suppress individual response
                        return None;
                    }
                }

                // Not batch loading, handle normally
                // Clear waiting state for non-batch trace commands
                self.clear_waiting_state();

                // Check if compilation actually succeeded
                if details.success_count > 0 || details.failed_count > 0 {
                    // Get script content from the current cache for better display
                    let script_content = self
                        .state
                        .command_panel
                        .script_cache
                        .as_ref()
                        .map(|cache| cache.lines.join("\n"));

                    // Use new format_compilation_results to show all traces
                    Some(crate::components::command_panel::script_editor::ScriptEditor::format_compilation_results(
                        details,
                        script_content.as_deref(),
                        &self.state.emoji_config,
                    ))
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
            RuntimeStatus::AllTracesEnabled { count, error } => {
                if let Some(ref err) = error {
                    let error_emoji = self
                        .state
                        .emoji_config
                        .get_script_status(crate::ui::emoji::ScriptStatus::Error);
                    Some(format!("{error_emoji} {err}"))
                } else if *count > 0 {
                    let success_emoji = self
                        .state
                        .emoji_config
                        .get_trace_status(crate::ui::emoji::TraceStatusType::Active);
                    Some(format!("{success_emoji} Enabled {count} traces"))
                } else {
                    None
                }
            }
            RuntimeStatus::AllTracesDisabled { count, error } => {
                if let Some(ref err) = error {
                    let error_emoji = self
                        .state
                        .emoji_config
                        .get_script_status(crate::ui::emoji::ScriptStatus::Error);
                    Some(format!("{error_emoji} {err}"))
                } else if *count > 0 {
                    let disabled_emoji = self
                        .state
                        .emoji_config
                        .get_trace_status(crate::ui::emoji::TraceStatusType::Disabled);
                    Some(format!("{disabled_emoji} Disabled {count} traces"))
                } else {
                    None
                }
            }
            RuntimeStatus::AllTracesDeleted { count, error } => {
                if let Some(ref err) = error {
                    let error_emoji = self
                        .state
                        .emoji_config
                        .get_script_status(crate::ui::emoji::ScriptStatus::Error);
                    Some(format!("{error_emoji} {err}"))
                } else if *count > 0 {
                    Some(format!("✓ Deleted {count} traces"))
                } else {
                    None
                }
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
            RuntimeStatus::ScriptCompilationCompleted { details } => {
                // Check if compilation actually succeeded
                if details.success_count > 0 {
                    crate::action::ResponseType::Success
                } else {
                    crate::action::ResponseType::Error
                }
            }
            RuntimeStatus::AllTracesEnabled { error, .. }
            | RuntimeStatus::AllTracesDisabled { error, .. }
            | RuntimeStatus::AllTracesDeleted { error, .. } => {
                if error.is_some() {
                    crate::action::ResponseType::Error
                } else {
                    crate::action::ResponseType::Success
                }
            }
            _ => crate::action::ResponseType::Info,
        }
    }

    /// Clear waiting state to return to ready input mode
    fn clear_waiting_state(&mut self) {
        self.state.command_panel.input_state = crate::model::panel_state::InputState::Ready;
    }

    /// Validate and resolve file path for saving
    /// Returns the absolute path if valid, or an error if the path is unsafe
    fn validate_and_resolve_path(filename: &str) -> anyhow::Result<std::path::PathBuf> {
        use std::path::{Path, PathBuf};

        // Check for path traversal attempts
        if filename.contains("..") {
            return Err(anyhow::anyhow!(
                "Path traversal not allowed (contains '..')"
            ));
        }

        // Resolve to absolute path
        let file_path = if Path::new(filename).is_relative() {
            let current_dir = std::env::current_dir()?;
            current_dir.join(filename)
        } else {
            PathBuf::from(filename)
        };

        // Canonicalize and verify the path stays within allowed directory
        // For relative paths, ensure they resolve within current directory
        if Path::new(filename).is_relative() {
            let current_dir = std::env::current_dir()?;
            let canonical_current = current_dir
                .canonicalize()
                .unwrap_or_else(|_| current_dir.clone());

            // Check parent directory exists before canonicalizing
            if let Some(parent) = file_path.parent() {
                if !parent.exists() {
                    return Err(anyhow::anyhow!(
                        "Directory does not exist: {}",
                        parent.display()
                    ));
                }

                // Verify resolved path is within current directory
                let canonical_parent = parent
                    .canonicalize()
                    .unwrap_or_else(|_| parent.to_path_buf());
                if !canonical_parent.starts_with(&canonical_current) {
                    return Err(anyhow::anyhow!("Cannot save outside current directory"));
                }
            }
        }

        Ok(file_path)
    }

    /// Start realtime eBPF output logging
    fn start_realtime_output_logging(
        &mut self,
        filename: Option<String>,
    ) -> anyhow::Result<std::path::PathBuf> {
        use chrono::Local;

        // Check if already logging
        if self.state.realtime_output_logger.enabled {
            return Err(anyhow::anyhow!(
                "Realtime output logging already active to: {}",
                self.state
                    .realtime_output_logger
                    .file_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }

        // Generate filename if not provided
        let filename = filename.unwrap_or_else(|| {
            let timestamp = Local::now().format("%Y%m%d_%H%M%S");
            format!("ebpf_output_{timestamp}.log")
        });

        // Validate and resolve path
        let file_path = Self::validate_and_resolve_path(&filename)?;

        // Determine if this is a new file
        let is_new_file = !file_path.exists();

        // Start the logger
        self.state.realtime_output_logger.start(file_path.clone())?;

        // Write header if this is a new file
        if is_new_file {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            self.state
                .realtime_output_logger
                .write_line("# GhostScope eBPF Output Log (Realtime)")?;
            self.state
                .realtime_output_logger
                .write_line(&format!("# Session: {timestamp}"))?;
            self.state
                .realtime_output_logger
                .write_line("# ========================================")?;
            self.state.realtime_output_logger.write_line("")?;
        } else {
            // Add separator for continuation
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            self.state.realtime_output_logger.write_line("")?;
            self.state
                .realtime_output_logger
                .write_line("# ----------------------------------------")?;
            self.state
                .realtime_output_logger
                .write_line(&format!("# Resumed: {timestamp}"))?;
            self.state
                .realtime_output_logger
                .write_line("# ----------------------------------------")?;
            self.state.realtime_output_logger.write_line("")?;
        }

        Ok(file_path)
    }

    /// Write an eBPF event to the output log (realtime)
    fn write_ebpf_event_to_output_log(
        &mut self,
        event: &ghostscope_protocol::ParsedTraceEvent,
    ) -> anyhow::Result<()> {
        if self.state.realtime_output_logger.enabled {
            // Format timestamp
            let secs = event.timestamp / 1_000_000_000;
            let nanos = event.timestamp % 1_000_000_000;
            let formatted_ts = format!(
                "{:02}:{:02}:{:02}.{:06}",
                (secs / 3600) % 24,
                (secs / 60) % 60,
                secs % 60,
                nanos / 1000
            );

            // Format output from instructions
            let formatted_output = event.to_formatted_output();
            let message = formatted_output.join(" ");

            // Write: [timestamp] [PID xxxx/TID yyyy] Trace #id: message
            self.state.realtime_output_logger.write_line(&format!(
                "[{}] [PID {}/TID {}] Trace #{}: {}",
                formatted_ts, event.pid, event.tid, event.trace_id, message
            ))?;
        }
        Ok(())
    }

    /// Write a command to the session log (realtime)
    fn write_command_to_session_log(&mut self, command: &str) -> anyhow::Result<()> {
        if self.state.realtime_session_logger.enabled {
            self.state.realtime_session_logger.write_line("")?;
            self.state
                .realtime_session_logger
                .write_line(&format!(">>> {command}"))?;
        }
        Ok(())
    }

    /// Write a response to the session log (realtime)
    fn write_response_to_session_log(&mut self, response: &str) -> anyhow::Result<()> {
        if self.state.realtime_session_logger.enabled {
            for line in response.lines() {
                self.state
                    .realtime_session_logger
                    .write_line(&format!("    {line}"))?;
            }
        }
        Ok(())
    }

    /// Start realtime command session logging
    fn start_realtime_session_logging(
        &mut self,
        filename: Option<String>,
    ) -> anyhow::Result<std::path::PathBuf> {
        use chrono::Local;

        // Check if already logging
        if self.state.realtime_session_logger.enabled {
            return Err(anyhow::anyhow!(
                "Realtime session logging already active to: {}",
                self.state
                    .realtime_session_logger
                    .file_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }

        // Generate filename if not provided
        let filename = filename.unwrap_or_else(|| {
            let timestamp = Local::now().format("%Y%m%d_%H%M%S");
            format!("command_session_{timestamp}.log")
        });

        // Validate and resolve path
        let file_path = Self::validate_and_resolve_path(&filename)?;

        // Determine if this is a new file
        let is_new_file = !file_path.exists();

        // Start the logger
        self.state
            .realtime_session_logger
            .start(file_path.clone())?;

        // Write header if this is a new file
        if is_new_file {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            self.state
                .realtime_session_logger
                .write_line("# GhostScope Command Session Log (Realtime)")?;
            self.state
                .realtime_session_logger
                .write_line(&format!("# Session: {timestamp}"))?;
            self.state
                .realtime_session_logger
                .write_line("# ========================================")?;
            self.state.realtime_session_logger.write_line("")?;

            // Write static lines (welcome messages)
            for static_line in &self.state.command_panel.static_lines {
                self.state
                    .realtime_session_logger
                    .write_line(&static_line.content)?;
            }
            self.state.realtime_session_logger.write_line("")?;
        } else {
            // Add separator for continuation
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            self.state.realtime_session_logger.write_line("")?;
            self.state
                .realtime_session_logger
                .write_line("# ----------------------------------------")?;
            self.state
                .realtime_session_logger
                .write_line(&format!("# Resumed: {timestamp}"))?;
            self.state
                .realtime_session_logger
                .write_line("# ----------------------------------------")?;
            self.state.realtime_session_logger.write_line("")?;
        }

        Ok(file_path)
    }

    /// Handle Ctrl+C with double-press quit and special mode handling
    fn handle_ctrl_c(&mut self) -> Vec<Action> {
        // Check if this is a double Ctrl+C press (consecutive, no timeout)
        let is_double_press = self.state.expecting_second_ctrl_c;

        // Set flag for next Ctrl+C press
        self.state.expecting_second_ctrl_c = true;

        // Handle double press - always quit
        if is_double_press {
            tracing::info!("Double Ctrl+C detected, quitting application");
            return vec![Action::Quit];
        }

        // Single Ctrl+C - handle based on current context
        match self.state.ui.focus.current_panel {
            crate::action::PanelType::InteractiveCommand => {
                // Command panel specific handling
                if self.state.command_panel.is_in_history_search() {
                    // In history search mode - exit search directly
                    self.state.command_panel.exit_history_search();
                    self.state.command_panel.input_text.clear();
                    self.state.command_panel.cursor_position = 0;
                    // Don't add empty response - would overwrite previous command's response
                    vec![]
                } else {
                    match self.state.command_panel.mode {
                        crate::model::panel_state::InteractionMode::ScriptEditor => {
                            // In script mode - exit to input mode
                            vec![Action::ExitScriptMode]
                        }
                        crate::model::panel_state::InteractionMode::Input => {
                            // In input mode - clear input and add "quit" command
                            self.state.command_panel.input_text.clear();
                            self.state.command_panel.cursor_position = 0;
                            self.state.command_panel.input_text = "quit".to_string();
                            self.state.command_panel.cursor_position = 4;
                            // Clear auto-suggestion to prevent suggestions after "quit"
                            self.state.command_panel.auto_suggestion.clear();
                            // Don't add response here - it would attach to previous command in history
                            // User will see "quit" in input box, which is clear enough
                            vec![]
                        }
                        _ => {
                            // Other modes - no action needed
                            vec![]
                        }
                    }
                }
            }
            crate::action::PanelType::Source => {
                if self.state.source_panel.mode
                    == crate::model::panel_state::SourcePanelMode::FileSearch
                {
                    // In file search mode - exit file search
                    vec![Action::ExitFileSearch]
                } else {
                    // Normal source panel - no action needed
                    vec![]
                }
            }
            _ => {
                // Other panels - no action needed
                vec![]
            }
        }
    }

    /// Cleanup terminal
    async fn cleanup(&mut self) -> Result<()> {
        disable_raw_mode()?;
        // Disable bracketed paste before leaving alternate screen
        execute!(self.terminal.backend_mut(), DisableBracketedPaste)?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
        // Mouse capture was not enabled, so no need to disable it
        self.terminal.show_cursor()?;
        Ok(())
    }
}

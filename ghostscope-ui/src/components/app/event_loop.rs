use super::App;
use crate::action::{Action, PanelType};
use crate::components::loading::LoadingState;
use anyhow::Result;
use crossterm::{
    event::{DisableBracketedPaste, Event, EventStream, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, LeaveAlternateScreen},
};
use futures_util::StreamExt;
use tracing::debug;

impl App {
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

        // Create a 1-second interval for loading UI updates (elapsed time, spinner, etc.)
        let mut loading_ui_ticker = tokio::time::interval(tokio::time::Duration::from_secs(1));
        loading_ui_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        // Periodic housekeeping ticker for lightweight timeout/cleanup checks.
        // Use an interval instead of recreating sleep futures in each select iteration.
        let mut housekeeping_ticker = tokio::time::interval(tokio::time::Duration::from_millis(50));
        housekeeping_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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

                // Update loading UI periodically (elapsed time, spinner animation)
                _ = loading_ui_ticker.tick(), if self.state.is_loading() => {
                    // Just trigger a redraw to update elapsed time and spinner
                    // No state changes needed - the UI will read fresh elapsed time on render
                    needs_render = true;
                }

                // Check for jk escape sequence timeout and periodic cleanup
                _ = housekeeping_ticker.tick() => {
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
                            crate::components::command_panel::ResponseFormatter::add_simple_styled_response(
                                &mut self.state.command_panel,
                                timeout_msg,
                                crate::components::command_panel::style_builder::StylePresets::ERROR,
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

    fn handle_ctrl_c(&mut self) -> Vec<Action> {
        // If eBPF panel is in expanded view, close it on single Ctrl+C
        if self.state.ui.focus.current_panel == crate::action::PanelType::EbpfInfo
            && self.state.ebpf_panel.is_expanded()
        {
            self.state.ebpf_panel.close_expanded();
            // Do not treat as first press for quitting
            self.state.expecting_second_ctrl_c = false;
            return vec![];
        }
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

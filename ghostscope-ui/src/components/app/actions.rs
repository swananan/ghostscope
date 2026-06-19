use super::App;
use crate::action::{Action, PanelType};
use anyhow::Result;
use tracing::debug;

impl App {
    pub(super) fn handle_action(&mut self, action: Action) -> Result<Vec<Action>> {
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
                let src_enabled = self.state.ui.config.show_source_panel;
                self.state.ui.focus.cycle_next(src_enabled);
            }
            Action::FocusPrevious => {
                let src_enabled = self.state.ui.config.show_source_panel;
                self.state.ui.focus.cycle_previous(src_enabled);
            }
            Action::FocusPanel(panel) => {
                if panel == crate::action::PanelType::Source
                    && !self.state.ui.config.show_source_panel
                {
                    // Ignore focusing hidden source panel; fallback to command panel
                    self.state
                        .ui
                        .focus
                        .set_panel(crate::action::PanelType::InteractiveCommand);
                } else {
                    self.state.ui.focus.set_panel(panel);
                }
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
                let src_enabled = self.state.ui.config.show_source_panel;
                self.state.ui.focus.move_focus_in_direction(
                    direction,
                    self.state.ui.layout.mode,
                    src_enabled,
                );
            }
            Action::SetSourcePanelVisibility(show) => {
                let currently_shown = self.state.ui.config.show_source_panel;
                if show == currently_shown {
                    return Ok(Vec::new());
                }
                self.state.ui.config.show_source_panel = show;
                if show {
                    // If enabling, request source code immediately
                    if let Err(e) = self
                        .state
                        .event_registry
                        .command_sender
                        .send(crate::events::RuntimeCommand::RequestSourceCode)
                    {
                        tracing::warn!("Failed to send source request after enabling: {}", e);
                    }
                    // Inform user
                    let plain =
                        "✅ Source panel enabled. Use 'ui source off' to hide it.".to_string();
                    let styled = vec![
                        crate::components::command_panel::style_builder::StyledLineBuilder::new()
                            .styled(
                                plain.clone(),
                                crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                            )
                            .build(),
                    ];
                    additional_actions.push(Action::AddResponseWithStyle {
                        content: plain,
                        styled_lines: Some(styled),
                        response_type: crate::action::ResponseType::Success,
                    });
                } else {
                    // If disabling and focus is Source or fullscreen Source, move focus away
                    if self.state.ui.focus.current_panel == crate::action::PanelType::Source {
                        self.state
                            .ui
                            .focus
                            .set_panel(crate::action::PanelType::InteractiveCommand);
                    }
                    if self.state.ui.layout.is_fullscreen
                        && matches!(
                            self.state.ui.focus.current_panel,
                            crate::action::PanelType::Source
                        )
                    {
                        self.state.ui.layout.is_fullscreen = false;
                    }
                    // Inform user
                    let plain = "✅ Source panel disabled. Panels: eBPF output + command. Use 'ui source on' to enable.".to_string();
                    let styled = vec![
                        crate::components::command_panel::style_builder::StyledLineBuilder::new()
                            .styled(
                                plain.clone(),
                                crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                            )
                            .build(),
                    ];
                    additional_actions.push(Action::AddResponseWithStyle {
                        content: plain,
                        styled_lines: Some(styled),
                        response_type: crate::action::ResponseType::Success,
                    });
                }
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
                self.state.command_renderer.mark_pending_updates();
            }
            Action::ExitScriptMode => {
                let actions = crate::components::command_panel::ScriptEditor::exit_script_mode(
                    &mut self.state.command_panel,
                );
                additional_actions.extend(actions);
                self.state.command_renderer.mark_pending_updates();
            }
            Action::SubmitScript => {
                let actions = crate::components::command_panel::ScriptEditor::submit_script(
                    &mut self.state.command_panel,
                );
                additional_actions.extend(actions);
                self.state.command_renderer.mark_pending_updates();
            }
            Action::CancelScript => {
                let actions = crate::components::command_panel::ScriptEditor::exit_script_mode(
                    &mut self.state.command_panel,
                );
                additional_actions.extend(actions);
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

                    // Focus command panel (keep fullscreen state if enabled)
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
                let (content, response_type, style_preset) =
                    match self.start_realtime_output_logging(filename) {
                        Ok(file_path) => (
                            format!(
                                "✅ Realtime eBPF output logging started: {}",
                                file_path.display()
                            ),
                            crate::action::ResponseType::Success,
                            crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                        ),
                        Err(e) => (
                            format!("✗ Failed to start output logging: {e}"),
                            crate::action::ResponseType::Error,
                            crate::components::command_panel::style_builder::StylePresets::ERROR,
                        ),
                    };

                // Directly add response to command history
                crate::components::command_panel::ResponseFormatter::add_simple_styled_response(
                    &mut self.state.command_panel,
                    content,
                    style_preset,
                    response_type,
                );
                self.state.command_renderer.mark_pending_updates();
            }
            Action::SaveCommandSession { filename } => {
                // Start realtime command session logging
                let (content, response_type, style_preset) =
                    match self.start_realtime_session_logging(filename) {
                        Ok(file_path) => (
                            format!(
                                "✅ Realtime session logging started: {}",
                                file_path.display()
                            ),
                            crate::action::ResponseType::Success,
                            crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                        ),
                        Err(e) => (
                            format!("✗ Failed to start session logging: {e}"),
                            crate::action::ResponseType::Error,
                            crate::components::command_panel::style_builder::StylePresets::ERROR,
                        ),
                    };

                // Directly add response to command history
                crate::components::command_panel::ResponseFormatter::add_simple_styled_response(
                    &mut self.state.command_panel,
                    content,
                    style_preset,
                    response_type,
                );
                self.state.command_renderer.mark_pending_updates();
            }
            Action::StopSaveOutput => {
                // Stop realtime eBPF output logging
                let (content, response_type, style_preset) =
                    match self.state.realtime_output_logger.stop() {
                        Ok(()) => (
                            "✅ Realtime eBPF output logging stopped".to_string(),
                            crate::action::ResponseType::Success,
                            crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                        ),
                        Err(e) => (
                            format!("✗ Failed to stop output logging: {e}"),
                            crate::action::ResponseType::Error,
                            crate::components::command_panel::style_builder::StylePresets::ERROR,
                        ),
                    };

                // Directly add response to command history
                crate::components::command_panel::ResponseFormatter::add_simple_styled_response(
                    &mut self.state.command_panel,
                    content,
                    style_preset,
                    response_type,
                );
                self.state.command_renderer.mark_pending_updates();
            }
            Action::StopSaveSession => {
                // Stop realtime command session logging
                let (content, response_type, style_preset) =
                    match self.state.realtime_session_logger.stop() {
                        Ok(()) => (
                            "✅ Realtime session logging stopped".to_string(),
                            crate::action::ResponseType::Success,
                            crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                        ),
                        Err(e) => (
                            format!("✗ Failed to stop session logging: {e}"),
                            crate::action::ResponseType::Error,
                            crate::components::command_panel::style_builder::StylePresets::ERROR,
                        ),
                    };

                // Directly add response to command history
                crate::components::command_panel::ResponseFormatter::add_simple_styled_response(
                    &mut self.state.command_panel,
                    content,
                    style_preset,
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
}

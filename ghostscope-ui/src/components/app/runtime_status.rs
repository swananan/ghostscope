use super::App;
use crate::action::Action;
use crate::components::loading::LoadingState;

impl App {
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
            debug_source: "unknown".to_string(),
            debug_source_path: None,
            dwarf_index: "unknown".to_string(),
            dwarf_index_warning: None,
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

    pub(super) async fn handle_runtime_status(&mut self, status: crate::events::RuntimeStatus) {
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
                if self.state.ui.config.show_source_panel {
                    self.state
                        .set_loading_state(LoadingState::LoadingSourceCode);
                } else {
                    // If source panel is disabled, we're effectively ready after symbols
                    self.transition_to_ready_with_completion();
                    // But we still need file info to power command panel completion/search
                    tracing::debug!(
                        "Source panel hidden on startup; requesting file list for completion cache"
                    );
                    if let Err(e) = self
                        .state
                        .event_registry
                        .command_sender
                        .send(crate::events::RuntimeCommand::InfoSource)
                    {
                        tracing::warn!("Failed to auto-request file list: {}", e);
                    }
                }
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
                    debug_source: stats.debug_source.clone(),
                    debug_source_path: stats.debug_source_path.clone(),
                    dwarf_index: stats.dwarf_index.clone(),
                    dwarf_index_warning: stats.dwarf_index_warning.clone(),
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

                // Also display the error in the source panel
                crate::components::source_panel::SourceNavigation::show_error_message(
                    &mut self.state.source_panel,
                    error.clone(),
                );
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
            RuntimeStatus::InfoFunctionResult {
                target: _,
                info,
                verbose,
            } => {
                // Mark command as completed
                self.clear_waiting_state();
                // Format and display function debug info
                let formatted_info = info.format_for_display(verbose);
                let styled_lines = info.format_for_display_styled(verbose);
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
            RuntimeStatus::InfoLineResult {
                target: _,
                info,
                verbose,
            } => {
                // Mark command as completed
                self.clear_waiting_state();
                // Format and display line debug info
                let formatted_info = info.format_for_display(verbose);
                let styled_lines = info.format_for_display_styled(verbose);
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
            RuntimeStatus::InfoAddressResult {
                target: _,
                info,
                verbose,
            } => {
                // Mark command as completed
                self.clear_waiting_state();
                // Format and display address debug info
                let formatted_info = info.format_for_display(verbose);
                let styled_lines = info.format_for_display_styled(verbose);
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
                // Determine whether to show all libraries or only those with debug info
                let show_all = matches!(
                    self.state.command_panel.input_state,
                    crate::model::panel_state::InputState::WaitingResponse {
                        command_type: crate::model::panel_state::CommandType::InfoShareAll,
                        ..
                    }
                );

                self.clear_waiting_state();

                let total = libraries.len();
                let display_libs: Vec<_> = if show_all {
                    libraries
                } else {
                    libraries
                        .into_iter()
                        .filter(|l| l.debug_info_available)
                        .collect()
                };

                // If filtering removed all entries, avoid misleading "No shared libraries" message
                if !show_all && display_libs.is_empty() && total > 0 {
                    let content = format!(
                        "📚 Shared Libraries ({total} total)\n\n⚠️  No libraries with debug info found. Use 'info share all' to view all libraries."
                    );
                    let styled = crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&content);
                    let action = Action::AddResponseWithStyle {
                        content,
                        styled_lines: Some(styled),
                        response_type: crate::action::ResponseType::Success,
                    };
                    let _ = self.handle_action(action);
                } else {
                    let formatted_info =
                        crate::components::command_panel::ResponseFormatter::format_shared_library_info(
                            &display_libs, false,
                        );
                    let styled_lines =
                        crate::components::command_panel::ResponseFormatter::format_shared_library_info_styled(
                            &display_libs,
                            false,
                        );
                    let action = Action::AddResponseWithStyle {
                        content: formatted_info,
                        styled_lines: Some(styled_lines),
                        response_type: crate::action::ResponseType::Success,
                    };
                    let _ = self.handle_action(action);
                }
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
                let text = format!(
                    "✗ {error}\n\n📘 No source available? You can hide the Source panel:\n  ui source off            # in UI command mode\n  --no-source-panel        # CLI flag\n  [ui].show_source_panel=false  # in config.toml"
                );
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
                host_pid,
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
                match (pid, host_pid) {
                    (Some(proc_pid), Some(host_pid_val)) if proc_pid != host_pid_val => {
                        response.push_str(&format!("  PID(proc): {proc_pid}\n"));
                        response.push_str(&format!("  PID(host): {host_pid_val}\n"));
                    }
                    (Some(proc_pid), _) => {
                        response.push_str(&format!("  PID: {proc_pid}\n"));
                    }
                    (None, Some(host_pid_val)) => {
                        response.push_str(&format!("  PID(host): {host_pid_val}\n"));
                    }
                    (None, None) => {}
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
                        host_pid,
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
                let mut text =
                    format!("✅ Saved {saved_count} of {total_count} traces to {filename}\n");
                text.push_str("   • Selected indices are preserved in the save file\n");

                use crate::components::command_panel::style_builder::{
                    StylePresets, StyledLineBuilder,
                };
                let styled = vec![
                    StyledLineBuilder::new()
                        .styled(
                            format!("✅ Saved {saved_count} of {total_count} traces to {filename}"),
                            StylePresets::SUCCESS,
                        )
                        .build(),
                    StyledLineBuilder::new()
                        .text("   • ")
                        .styled(
                            "Selected indices are preserved in the save file",
                            StylePresets::TIP,
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
                    response.push('\n');
                    response.push_str("   • Selected indices from the file are restored\n");
                } else {
                    // Some traces failed
                    response.push_str(&format!("⚠️ Partially loaded traces from {filename}\n"));
                    response.push_str(&format!(
                        "  ✓ {} traces created ({} enabled, {} disabled)\n",
                        success_count,
                        success_count - disabled_count,
                        disabled_count
                    ));
                    response
                        .push_str("  • Selected indices from the file are restored when present\n");

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
                    styled.push(
                        StyledLineBuilder::new()
                            .text("   • ")
                            .styled(
                                "Selected indices from the file are restored",
                                StylePresets::TIP,
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
                    styled.push(
                        StyledLineBuilder::new()
                            .text("  • ")
                            .styled(
                                "Selected indices from the file are restored when present",
                                StylePresets::TIP,
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
            RuntimeStatus::TraceBackpressure {
                dropped_since_last,
                dropped_total,
                queue_capacity,
            } => {
                self.show_trace_backpressure_alert(
                    dropped_since_last,
                    dropped_total,
                    queue_capacity,
                );
            }
            RuntimeStatus::EbpfOutputLoss {
                trace_id,
                target_display,
                lost_since_last,
                lost_total,
            } => {
                self.show_ebpf_output_loss_alert(
                    trace_id,
                    target_display,
                    lost_since_last,
                    lost_total,
                );
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
                    // Don't use styled_lines if content contains ANSI color codes
                    // Let the renderer handle ANSI parsing instead
                    let styled_lines = if content.contains("\x1b[") {
                        None
                    } else {
                        Some(crate::components::command_panel::ResponseFormatter::style_generic_message_lines(&content))
                    };
                    let action = Action::AddResponseWithStyle {
                        content,
                        styled_lines,
                        response_type: self.get_response_type_for_status(&status),
                    };
                    let _ = self.handle_action(action);
                }
            }
        }
    }

    /// Handle trace events
    pub(super) async fn handle_trace_event(&mut self, trace_event: crate::events::UiTraceEvent) {
        tracing::debug!("Trace event: {:?}", trace_event);

        // Realtime logging: write eBPF event to file if enabled
        if self.state.realtime_output_logger.enabled {
            if let Err(e) = self.write_ebpf_event_to_output_log(&trace_event) {
                tracing::error!("Failed to write eBPF event to output log: {}", e);
            }
        }

        self.state.ebpf_panel.add_trace_event(trace_event);
    }

    fn add_ebpf_runtime_warning(&mut self, content: String) {
        let event = crate::model::panel_state::EbpfPanelState::runtime_warning_event(
            content,
            current_boot_timestamp_ns(),
        );

        if self.state.realtime_output_logger.enabled {
            if let Err(e) = self.write_ebpf_event_to_output_log(&event) {
                tracing::error!("Failed to write eBPF runtime warning to output log: {}", e);
            }
        }

        self.state.ebpf_panel.add_trace_event(event);
    }

    fn show_trace_backpressure_alert(
        &mut self,
        dropped_since_last: u64,
        dropped_total: u64,
        queue_capacity: usize,
    ) {
        let content = format!(
            "⚠ Trace queue saturated: dropped {dropped_since_last} events in last 1s (total {dropped_total}, capacity {queue_capacity})"
        );
        let styled_lines =
            crate::components::command_panel::ResponseFormatter::style_generic_message_lines(
                &content,
            );
        crate::components::command_panel::ResponseFormatter::upsert_runtime_alert_with_style(
            &mut self.state.command_panel,
            content,
            Some(styled_lines),
            crate::action::ResponseType::Warning,
        );
        self.state.command_renderer.mark_pending_updates();

        self.add_ebpf_runtime_warning(format!(
            "Warning: TUI trace queue saturated; dropped {dropped_since_last} events before display in last 1s (total {dropped_total}, capacity {queue_capacity})"
        ));
    }

    fn show_ebpf_output_loss_alert(
        &mut self,
        trace_id: u32,
        target_display: String,
        lost_since_last: u64,
        lost_total: u64,
    ) {
        let content = format!(
            "⚠ eBPF output helper failed: trace #{trace_id} ({target_display}) lost {lost_since_last} events in kernel before userspace delivery (total {lost_total})"
        );
        let styled_lines =
            crate::components::command_panel::ResponseFormatter::style_generic_message_lines(
                &content,
            );
        crate::components::command_panel::ResponseFormatter::upsert_runtime_alert_with_style(
            &mut self.state.command_panel,
            content,
            Some(styled_lines),
            crate::action::ResponseType::Warning,
        );
        self.state.command_renderer.mark_pending_updates();

        self.add_ebpf_runtime_warning(format!(
            "Warning: eBPF output helper failed; trace #{trace_id} ({target_display}) lost {lost_since_last} events in kernel before userspace delivery (total {lost_total})"
        ));
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
                    batch.record_script_compilation(details);

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

                        // Create styled version using helper method
                        let styled_lines =
                            crate::components::command_panel::ResponseFormatter::format_batch_load_summary_styled(
                                &filename,
                                total_count,
                                success_count,
                                failed_count,
                                disabled_count,
                                &details,
                            );

                        let action = Action::AddResponseWithStyle {
                            content: response,
                            styled_lines: Some(styled_lines),
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
    pub(super) fn clear_waiting_state(&mut self) {
        self.state.command_panel.input_state = crate::model::panel_state::InputState::Ready;
    }
}

fn current_boot_timestamp_ns() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|contents| {
            contents
                .split_whitespace()
                .next()
                .and_then(|secs| secs.parse::<f64>().ok())
        })
        .map(|secs| (secs * 1_000_000_000.0) as u64)
        .unwrap_or(0)
}

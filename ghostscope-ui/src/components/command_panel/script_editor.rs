use crate::action::{Action, ResponseType};
use crate::model::panel_state::{CommandPanelState, InteractionMode, ScriptCache, ScriptStatus};
use crate::ui::emoji::{EmojiConfig, ScriptStatus as EmojiScriptStatus, TraceElement};
use crate::ui::strings::UIStrings;

/// Detailed information for successful trace operations
#[derive(Debug, Clone)]
pub struct TraceDetails {
    pub trace_id: Option<u32>,
    pub binary_path: Option<String>,
    pub address: Option<u64>,
    pub source_file: Option<String>,
    pub line_number: Option<u32>,
    pub function_name: Option<String>,
}

/// Detailed error information for failed trace operations
#[derive(Debug, Clone)]
pub struct TraceErrorDetails {
    pub compilation_errors: Option<Vec<(u32, String)>>, // (line_number, error_message)
    pub uprobe_error: Option<String>,
    pub suggestion: Option<String>,
}

/// Handles script editing functionality for the command panel
pub struct ScriptEditor;

impl ScriptEditor {
    /// Enter script editing mode for a trace command
    pub fn enter_script_mode(state: &mut CommandPanelState, command: &str) -> Vec<Action> {
        let target = command.trim_start_matches("trace").trim();

        if target.is_empty() {
            let plain =
                "Usage: trace <function_name|file:line|0xADDR|module_suffix:0xADDR>".to_string();
            let styled = vec![
                crate::components::command_panel::style_builder::StyledLineBuilder::new()
                    .styled(
                        plain.clone(),
                        crate::components::command_panel::style_builder::StylePresets::ERROR,
                    )
                    .build(),
            ];
            return vec![Action::AddResponseWithStyle {
                content: plain,
                styled_lines: Some(styled),
                response_type: ResponseType::Error,
            }];
        }

        // Check if we have a cached script for this target
        let (lines, cursor_line, cursor_col, restored_from_cache) =
            if let Some(ref cache) = state.script_cache {
                if let Some(saved_script) = cache.saved_scripts.get(target) {
                    let mut lines: Vec<String> =
                        saved_script.content.lines().map(String::from).collect();
                    // Ensure at least one line exists (empty string.lines() returns empty iterator)
                    if lines.is_empty() {
                        lines.push(String::new());
                    }
                    (
                        lines,
                        saved_script.cursor_line,
                        saved_script.cursor_col,
                        true,
                    )
                } else {
                    (vec![String::new()], 0, 0, false)
                }
            } else {
                (vec![String::new()], 0, 0, false)
            };

        // Create or update script cache
        state.script_cache = Some(ScriptCache {
            target: target.to_string(),
            original_command: command.to_string(),
            lines,
            cursor_line,
            cursor_col,
            status: ScriptStatus::Draft,
            saved_scripts: state
                .script_cache
                .as_ref()
                .map(|c| c.saved_scripts.clone())
                .unwrap_or_default(),
        });

        // Switch to script editor mode
        state.mode = InteractionMode::ScriptEditor;

        let message = if restored_from_cache {
            format!("📝 Script editor opened for '{target}' (restored from cache)\nPress Ctrl+S to submit, ESC to cancel, F3 to clear")
        } else {
            format!("📝 Script editor opened for '{target}'\nPress Ctrl+S to submit, ESC to cancel, F3 to clear")
        };

        let styled = vec![
            crate::components::command_panel::style_builder::StyledLineBuilder::new()
                .styled(
                    message.clone(),
                    crate::components::command_panel::style_builder::StylePresets::TIP,
                )
                .build(),
        ];

        vec![Action::AddResponseWithStyle {
            content: message,
            styled_lines: Some(styled),
            response_type: ResponseType::Info,
        }]
    }

    /// Exit script editing mode
    pub fn exit_script_mode(state: &mut CommandPanelState) -> Vec<Action> {
        // Save current script state before exiting (always save, even if empty)
        if let Some(ref mut cache) = state.script_cache {
            let script_content = cache.lines.join("\n");
            // Always save script state to cache, even if empty
            // This ensures second entry will properly restore cursor and content
            cache.saved_scripts.insert(
                cache.target.clone(),
                crate::model::panel_state::SavedScript {
                    content: script_content,
                    cursor_line: cache.cursor_line,
                    cursor_col: cache.cursor_col,
                },
            );
        }

        state.mode = InteractionMode::Input;

        let plain = "Script editing cancelled".to_string();
        let styled = vec![
            crate::components::command_panel::style_builder::StyledLineBuilder::new()
                .styled(
                    plain.clone(),
                    crate::components::command_panel::style_builder::StylePresets::WARNING,
                )
                .build(),
        ];

        vec![Action::AddResponseWithStyle {
            content: plain,
            styled_lines: Some(styled),
            response_type: ResponseType::Warning,
        }]
    }

    /// Submit the current script
    pub fn submit_script(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            // Remove empty lines at the end
            while cache
                .lines
                .last()
                .is_some_and(|line| line.trim().is_empty())
            {
                cache.lines.pop();
            }

            // Ensure at least one line
            if cache.lines.is_empty() {
                cache.lines.push(String::new());
            }

            let script_content = cache.lines.join("\n");
            // Wrap script content in braces for proper syntax
            let wrapped_script = if script_content.trim().is_empty() {
                "{}".to_string()
            } else {
                format!("{{{script_content}}}")
            };
            let full_script = format!("trace {target} {wrapped_script}", target = cache.target);

            // Save script to cache with cursor position
            cache.saved_scripts.insert(
                cache.target.clone(),
                crate::model::panel_state::SavedScript {
                    content: script_content,
                    cursor_line: cache.cursor_line,
                    cursor_col: cache.cursor_col,
                },
            );
            cache.status = ScriptStatus::Submitted;

            // Set waiting state for trace command
            state.input_state = crate::model::panel_state::InputState::WaitingResponse {
                command: format!("trace {}", cache.target),
                sent_time: std::time::Instant::now(),
                command_type: crate::model::panel_state::CommandType::Script,
            };

            // Exit script editor mode
            state.mode = InteractionMode::Input;

            return vec![Action::SendRuntimeCommand(
                crate::action::RuntimeCommand::ExecuteScript {
                    command: full_script,
                },
            )];
        }

        let plain = "No script to submit".to_string();
        let styled = vec![
            crate::components::command_panel::style_builder::StyledLineBuilder::new()
                .styled(
                    plain.clone(),
                    crate::components::command_panel::style_builder::StylePresets::ERROR,
                )
                .build(),
        ];

        vec![Action::AddResponseWithStyle {
            content: plain,
            styled_lines: Some(styled),
            response_type: ResponseType::Error,
        }]
    }

    /// Clear the current script
    pub fn clear_script(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            cache.lines = vec![String::new()];
            cache.cursor_line = 0;
            cache.cursor_col = 0;
            cache.status = ScriptStatus::Draft;
        }

        Vec::new()
    }

    /// Insert a character at the cursor position in script
    pub fn insert_char(state: &mut CommandPanelState, c: char) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_line < cache.lines.len() {
                let line = &mut cache.lines[cache.cursor_line];
                let byte_pos = Self::char_pos_to_byte_pos(line, cache.cursor_col);
                line.insert(byte_pos, c);
                cache.cursor_col += 1;
            }
        }
        Vec::new()
    }

    /// Insert a string at the cursor position (supports newlines)
    pub fn insert_text(state: &mut CommandPanelState, text: &str) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            // Normalize line endings to LF
            let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
            let mut iter = normalized.split('\n');

            if cache.cursor_line >= cache.lines.len() {
                cache.lines.push(String::new());
                cache.cursor_line = cache.lines.len() - 1;
                cache.cursor_col = 0;
            }

            // Insert first segment into current line
            if let Some(first) = iter.next() {
                let line = &mut cache.lines[cache.cursor_line];
                let byte_pos = Self::char_pos_to_byte_pos(line, cache.cursor_col);
                line.insert_str(byte_pos, first);
                cache.cursor_col += first.chars().count();
            }

            // Remaining segments: create new lines
            let mut is_first_newline = true;
            for seg in iter {
                // Split current line at cursor once to move the right part down
                if is_first_newline {
                    let byte_pos = Self::char_pos_to_byte_pos(
                        &cache.lines[cache.cursor_line],
                        cache.cursor_col,
                    );
                    let right = cache.lines[cache.cursor_line].split_off(byte_pos);
                    let new_line = format!("{seg}{right}");
                    cache.cursor_line += 1;
                    cache.lines.insert(cache.cursor_line, new_line);
                    cache.cursor_col = seg.chars().count();
                    is_first_newline = false;
                } else {
                    cache.cursor_line += 1;
                    cache.lines.insert(cache.cursor_line, seg.to_string());
                    cache.cursor_col = seg.chars().count();
                }
            }
        }
        Vec::new()
    }

    /// Insert a newline at the cursor position
    pub fn insert_newline(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_line < cache.lines.len() {
                let byte_pos =
                    Self::char_pos_to_byte_pos(&cache.lines[cache.cursor_line], cache.cursor_col);

                // Split the current line at cursor position
                let current_line = cache.lines[cache.cursor_line].clone();
                let (left, right) = current_line.split_at(byte_pos);
                cache.lines[cache.cursor_line] = left.to_string();
                cache.lines.insert(cache.cursor_line + 1, right.to_string());

                // Move cursor to beginning of new line
                cache.cursor_line += 1;
                cache.cursor_col = 0;
            }
        }
        Vec::new()
    }

    /// Insert a tab (4 spaces) at the cursor position
    pub fn insert_tab(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_line < cache.lines.len() {
                let line = &mut cache.lines[cache.cursor_line];
                let byte_pos = Self::char_pos_to_byte_pos(line, cache.cursor_col);
                line.insert_str(byte_pos, "    ");
                cache.cursor_col += 4;
            }
        }
        Vec::new()
    }

    /// Delete character before cursor in script
    pub fn delete_char(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_col > 0 {
                // Delete character in current line
                if cache.cursor_line < cache.lines.len() {
                    let line = &mut cache.lines[cache.cursor_line];
                    cache.cursor_col -= 1;
                    let byte_pos = Self::char_pos_to_byte_pos(line, cache.cursor_col);
                    if byte_pos < line.len() {
                        let mut end_pos = byte_pos + 1;
                        while end_pos < line.len() && !line.is_char_boundary(end_pos) {
                            end_pos += 1;
                        }
                        line.drain(byte_pos..end_pos);
                    }
                }
            } else if cache.cursor_line > 0 {
                // Merge with previous line
                let current_line = cache.lines.remove(cache.cursor_line);
                cache.cursor_line -= 1;
                cache.cursor_col = cache.lines[cache.cursor_line].chars().count();
                cache.lines[cache.cursor_line].push_str(&current_line);
            }
        }
        Vec::new()
    }

    /// Move cursor up in script
    pub fn move_cursor_up(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_line > 0 {
                cache.cursor_line -= 1;
                let line_len = cache.lines[cache.cursor_line].chars().count();
                cache.cursor_col = cache.cursor_col.min(line_len);
            }
        }
        Vec::new()
    }

    /// Move cursor down in script
    pub fn move_cursor_down(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_line + 1 < cache.lines.len() {
                cache.cursor_line += 1;
                let line_len = cache.lines[cache.cursor_line].chars().count();
                cache.cursor_col = cache.cursor_col.min(line_len);
            }
        }
        Vec::new()
    }

    /// Move cursor left in script
    pub fn move_cursor_left(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_col > 0 {
                cache.cursor_col -= 1;
            } else if cache.cursor_line > 0 {
                // Move to end of previous line
                cache.cursor_line -= 1;
                cache.cursor_col = cache.lines[cache.cursor_line].chars().count();
            }
        }
        Vec::new()
    }

    /// Move cursor right in script
    pub fn move_cursor_right(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_line < cache.lines.len() {
                let line_len = cache.lines[cache.cursor_line].chars().count();
                if cache.cursor_col < line_len {
                    cache.cursor_col += 1;
                } else if cache.cursor_line + 1 < cache.lines.len() {
                    // Move to beginning of next line
                    cache.cursor_line += 1;
                    cache.cursor_col = 0;
                }
            }
        }
        Vec::new()
    }

    /// Move cursor to beginning of line
    pub fn move_to_beginning(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            cache.cursor_col = 0;
        }
        Vec::new()
    }

    /// Move cursor to end of line
    pub fn move_to_end(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_line < cache.lines.len() {
                cache.cursor_col = cache.lines[cache.cursor_line].chars().count();
            }
        }
        Vec::new()
    }

    /// Move cursor to next word (Ctrl+f)
    pub fn move_to_next_word(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_line < cache.lines.len() {
                let line = &cache.lines[cache.cursor_line];
                let chars: Vec<char> = line.chars().collect();
                let mut pos = cache.cursor_col;

                // Skip current word if we're in the middle of one
                while pos < chars.len() && !chars[pos].is_whitespace() {
                    pos += 1;
                }
                // Skip whitespace
                while pos < chars.len() && chars[pos].is_whitespace() {
                    pos += 1;
                }

                cache.cursor_col = pos;
            }
        }
        Vec::new()
    }

    /// Move cursor to previous word (Ctrl+b)
    pub fn move_to_previous_word(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_line < cache.lines.len() {
                let line = &cache.lines[cache.cursor_line];
                let chars: Vec<char> = line.chars().collect();
                let mut pos = cache.cursor_col;

                // Skip whitespace backwards
                while pos > 0 && chars[pos - 1].is_whitespace() {
                    pos -= 1;
                }
                // Skip current word backwards
                while pos > 0 && !chars[pos - 1].is_whitespace() {
                    pos -= 1;
                }

                cache.cursor_col = pos;
            }
        }
        Vec::new()
    }

    /// Delete previous word (Ctrl+w)
    pub fn delete_previous_word(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_line < cache.lines.len() {
                let line = &mut cache.lines[cache.cursor_line];
                let start_pos = cache.cursor_col;
                let mut end_pos = start_pos;

                // Find start of current word
                let chars: Vec<char> = line.chars().collect();
                while end_pos > 0 && chars[end_pos - 1].is_whitespace() {
                    end_pos -= 1;
                }
                while end_pos > 0 && !chars[end_pos - 1].is_whitespace() {
                    end_pos -= 1;
                }

                // Convert to byte positions
                let start_byte = Self::char_pos_to_byte_pos(line, end_pos);
                let end_byte = Self::char_pos_to_byte_pos(line, start_pos);

                // Remove the word
                line.drain(start_byte..end_byte);
                cache.cursor_col = end_pos;
            }
        }
        Vec::new()
    }

    /// Delete from cursor to end of line
    pub fn delete_to_end(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_line < cache.lines.len() {
                let line = &mut cache.lines[cache.cursor_line];
                let byte_pos = Self::char_pos_to_byte_pos(line, cache.cursor_col);
                line.truncate(byte_pos);
            }
        }
        Vec::new()
    }

    /// Delete from cursor to beginning of line (Ctrl+u)
    pub fn delete_to_line_start(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_line < cache.lines.len() {
                let line = &mut cache.lines[cache.cursor_line];
                let byte_pos = Self::char_pos_to_byte_pos(line, cache.cursor_col);
                let remaining = line[byte_pos..].to_string();
                cache.lines[cache.cursor_line] = remaining;
                cache.cursor_col = 0;
            }
        }
        Vec::new()
    }

    /// Delete from cursor to beginning of line (legacy name for compatibility)
    pub fn delete_to_beginning(state: &mut CommandPanelState) -> Vec<Action> {
        Self::delete_to_line_start(state)
    }

    /// Delete character at cursor position (Ctrl+h - backspace)
    pub fn delete_char_at_cursor(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.cursor_line < cache.lines.len() && cache.cursor_col > 0 {
                let line = &mut cache.lines[cache.cursor_line];
                let char_pos = cache.cursor_col - 1;
                let byte_pos = Self::char_pos_to_byte_pos(line, char_pos);
                let next_byte_pos = Self::char_pos_to_byte_pos(line, cache.cursor_col);

                // Remove the character at cursor-1 position
                line.drain(byte_pos..next_byte_pos);
                cache.cursor_col = char_pos;
            }
        }
        Vec::new()
    }

    /// Check if script editor can be re-entered
    pub fn can_edit_script(state: &CommandPanelState) -> bool {
        state
            .script_cache
            .as_ref()
            .is_some_and(|cache| cache.status == ScriptStatus::Submitted)
    }

    /// Re-enter script editing mode for last submitted script
    pub fn edit_script_again(state: &mut CommandPanelState) -> Vec<Action> {
        if let Some(ref mut cache) = state.script_cache {
            if cache.status == ScriptStatus::Submitted {
                cache.status = ScriptStatus::Draft;
                state.mode = InteractionMode::ScriptEditor;

                let plain = format!("📝 Re-editing script for '{}'", cache.target);
                let styled = vec![
                    crate::components::command_panel::style_builder::StyledLineBuilder::new()
                        .styled(
                            plain.clone(),
                            crate::components::command_panel::style_builder::StylePresets::TIP,
                        )
                        .build(),
                ];

                return vec![Action::AddResponseWithStyle {
                    content: plain,
                    styled_lines: Some(styled),
                    response_type: ResponseType::Info,
                }];
            }
        }
        Vec::new()
    }

    /// Format script for display with emoji configuration
    pub fn format_script_display_with_config(
        target: &str,
        lines: &[String],
        emoji_config: &EmojiConfig,
    ) -> String {
        let mut result = Vec::new();

        // Header with target info
        let target_emoji = emoji_config.get_trace_element(TraceElement::Target);

        result.push(format!(
            "{} {} {}",
            target_emoji,
            UIStrings::SCRIPT_TARGET_PREFIX,
            target
        ));
        result.push(UIStrings::SCRIPT_SEPARATOR.repeat(50));

        // Script content with line numbers
        if lines.is_empty() || (lines.len() == 1 && lines[0].trim().is_empty()) {
            result.push(format!(
                "  {} No script content",
                emoji_config.get_script_status(EmojiScriptStatus::Error)
            ));
        } else {
            for (line_idx, line) in lines.iter().enumerate() {
                if line.trim().is_empty() {
                    result.push(format!("{:3} │", line_idx + 1));
                } else {
                    result.push(format!("{:3} │ {line}", line_idx + 1));
                }
            }
        }

        result.push(UIStrings::SCRIPT_SEPARATOR.repeat(50));

        // Footer with compilation status
        let compile_emoji = emoji_config.get_script_status(EmojiScriptStatus::Compiling);
        result.push(format!("{compile_emoji} Compiling and loading script..."));

        result.join("\n")
    }

    /// Format trace success response with detailed information
    pub fn format_trace_success_response(
        target: &str,
        details: Option<&TraceDetails>,
        emoji_config: &EmojiConfig,
    ) -> String {
        Self::format_trace_success_response_with_script(target, details, None, emoji_config)
    }

    pub fn format_trace_success_response_with_script(
        target: &str,
        details: Option<&TraceDetails>,
        script_content: Option<&str>,
        emoji_config: &EmojiConfig,
    ) -> String {
        let mut result = Vec::new();

        // 📝 Script section
        if let Some(script) = script_content {
            let script_lines = Self::format_script_display_section(script, emoji_config);
            result.extend(script_lines);
        }

        // 🎯 Target line
        let target_emoji = emoji_config.get_trace_element(crate::ui::emoji::TraceElement::Target);
        result.push(format!("{target_emoji} Target: {target}"));

        // Empty line for separation
        result.push("".to_string());

        // ✅ Results line with trace details
        let success_emoji = emoji_config.get_script_status(crate::ui::emoji::ScriptStatus::Success);

        if let Some(details) = details {
            let address_display = if let Some(address) = details.address {
                format!("(0x{address:x})")
            } else {
                "".to_string()
            };

            result.push(format!(
                "{success_emoji} Trace Results: \x1b[32m1 successful\x1b[0m, 0 failed"
            ));

            if let Some(trace_id) = details.trace_id {
                result.push(format!(
                    "  • {target} {address_display} → trace_id: {trace_id}"
                ));
            } else {
                result.push(format!("  • {target} {address_display} → trace attached"));
            }
        } else {
            result.push(format!(
                "{success_emoji} Trace Results: \x1b[32m1 successful\x1b[0m, 0 failed"
            ));
            result.push(format!("  • {target} → trace attached"));
        }

        result.join("\n")
    }

    /// Format compilation results with all successful and failed traces
    pub fn format_compilation_results(
        compilation_details: &crate::events::ScriptCompilationDetails,
        script_content: Option<&str>,
        emoji_config: &EmojiConfig,
    ) -> String {
        let mut result = Vec::new();

        // 📝 Script section
        if let Some(script) = script_content {
            let script_lines = Self::format_script_display_section(script, emoji_config);
            result.extend(script_lines);
        }

        // 🎯 Target line (use first result's target or generic message)
        let target_emoji = emoji_config.get_trace_element(crate::ui::emoji::TraceElement::Target);
        let target = compilation_details
            .results
            .first()
            .map(|r| r.target_name.clone())
            .unwrap_or_else(|| "unknown".to_string());
        result.push(format!("{target_emoji} Target: {target}"));

        // Empty line for separation
        result.push("".to_string());

        // ✅ Results summary
        let success_emoji = emoji_config.get_script_status(crate::ui::emoji::ScriptStatus::Success);
        let error_emoji = emoji_config.get_script_status(crate::ui::emoji::ScriptStatus::Error);

        let summary_emoji = if compilation_details.failed_count > 0 {
            error_emoji
        } else {
            success_emoji
        };

        // Format with colors: green for successful (if > 0), red for failed (if > 0)
        let success_part = if compilation_details.success_count > 0 {
            format!(
                "\x1b[32m{} successful\x1b[0m",
                compilation_details.success_count
            )
        } else {
            format!("{} successful", compilation_details.success_count)
        };

        let failed_part = if compilation_details.failed_count > 0 {
            format!("\x1b[31m{} failed\x1b[0m", compilation_details.failed_count)
        } else {
            format!("{} failed", compilation_details.failed_count)
        };

        result.push(format!(
            "{summary_emoji} Trace Results: {success_part}, {failed_part}"
        ));

        // List all successful traces
        let mut trace_idx = 0;
        for exec_result in &compilation_details.results {
            match &exec_result.status {
                crate::events::ExecutionStatus::Success => {
                    let trace_id = compilation_details.trace_ids.get(trace_idx).copied();
                    if let Some(tid) = trace_id {
                        result.push(format!(
                            "  • {} (0x{:x}) → trace_id: {}",
                            exec_result.target_name, exec_result.pc_address, tid
                        ));
                        trace_idx += 1;
                    } else {
                        result.push(format!(
                            "  • {} (0x{:x}) → trace attached",
                            exec_result.target_name, exec_result.pc_address
                        ));
                    }
                }
                crate::events::ExecutionStatus::Failed(error) => {
                    result.push(format!(
                        "  ✗ {} (0x{:x}): {}",
                        exec_result.target_name, exec_result.pc_address, error
                    ));
                }
                crate::events::ExecutionStatus::Skipped(reason) => {
                    result.push(format!(
                        "  ⊘ {} (0x{:x}): {}",
                        exec_result.target_name, exec_result.pc_address, reason
                    ));
                }
            }
        }

        result.join("\n")
    }

    /// Format trace error response with detailed information
    pub fn format_trace_error_response(
        target: &str,
        error: &str,
        details: Option<&TraceErrorDetails>,
        emoji_config: &EmojiConfig,
    ) -> String {
        Self::format_trace_error_response_with_script(target, error, details, None, emoji_config)
    }

    pub fn format_trace_error_response_with_script(
        target: &str,
        error: &str,
        _details: Option<&TraceErrorDetails>,
        script_content: Option<&str>,
        emoji_config: &EmojiConfig,
    ) -> String {
        let mut result = Vec::new();

        // 📝 Script section (if available)
        if let Some(script) = script_content {
            let script_lines = Self::format_script_display_section(script, emoji_config);
            result.extend(script_lines);
        }

        // 🎯 Target line
        let target_emoji = emoji_config.get_trace_element(crate::ui::emoji::TraceElement::Target);
        result.push(format!("{target_emoji} Target: {target}"));

        // Empty line for separation
        result.push("".to_string());

        // ❌ Error summary
        let error_emoji = emoji_config.get_script_status(crate::ui::emoji::ScriptStatus::Error);
        result.push(format!(
            "{error_emoji} Trace Results: 0 successful, \x1b[31m1 failed\x1b[0m"
        ));

        // Simplified error message (remove redundant prefixes)
        let clean_error = if error.contains("eBPF Loading Error:") {
            error.replace("eBPF Loading Error:", "").trim().to_string()
        } else if error.contains("Uprobe Attachment Error:") {
            error
                .replace("Uprobe Attachment Error:", "")
                .trim()
                .to_string()
        } else if error.contains("Code Generation Error:") {
            error
                .replace("Code Generation Error:", "")
                .trim()
                .to_string()
        } else if error.contains("Script compilation failed") {
            error
                .replace("Script compilation failed", "")
                .trim()
                .to_string()
        } else {
            error.to_string()
        };

        result.push(format!("  • {target} → {clean_error}"));

        result.join("\n")
    }

    /// Format script display section with line numbers (like script mode)
    fn format_script_display_section(script: &str, emoji_config: &EmojiConfig) -> Vec<String> {
        let mut result = Vec::new();
        let script_emoji = emoji_config.get_trace_element(crate::ui::emoji::TraceElement::Line);

        if script.trim().is_empty() {
            result.push(format!("{script_emoji} Script: {{}}"));
        } else {
            let script_lines: Vec<&str> = script.lines().collect();
            if script_lines.len() == 1 {
                // Single line - compact format
                result.push(format!("{script_emoji} Script: {}", script.trim()));
            } else {
                // Multi-line - use block format with line numbers (similar to script mode)
                result.push(format!("{script_emoji} Script:"));
                for (idx, line) in script_lines.iter().enumerate() {
                    result.push(format!("  {:2} │ {line}", idx + 1));
                }
            }
        }

        result
    }

    /// Utility function to convert character position to byte position
    fn char_pos_to_byte_pos(text: &str, char_pos: usize) -> usize {
        text.char_indices()
            .nth(char_pos)
            .map_or(text.len(), |(pos, _)| pos)
    }
}

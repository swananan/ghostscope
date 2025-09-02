use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem},
    Frame,
};
use std::collections::HashMap;
use std::time::Instant;
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InteractionMode {
    Input,        // Normal input mode
    Command,      // Command mode (previously VimCommand)
    ScriptEditor, // Multi-line script editing mode
}

#[derive(Debug, Clone, PartialEq)]
pub enum InputState {
    Ready, // Normal input state, shows (ghostscope)
    WaitingResponse {
        // Waiting for response, completely hide input
        command: String,
        sent_time: Instant,
    },
    ScriptEditor, // Script editing mode
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScriptStatus {
    Draft,     // Script is being edited
    Submitted, // Script was submitted successfully
    Error,     // Script had errors
}

#[derive(Debug, Clone)]
pub struct ScriptCache {
    pub target: String,           // Trace target (function name or file:line)
    pub original_command: String, // Original trace command (e.g., "trace main")
    pub lines: Vec<String>,       // Script lines
    pub cursor_line: usize,       // Current cursor line (0-based)
    pub cursor_col: usize,        // Current cursor column (0-based)
    pub status: ScriptStatus,     // Current script status
    pub saved_scripts: HashMap<String, String>, // target -> complete script cache
}

#[derive(Debug, Clone)]
pub struct CommandHistoryItem {
    pub command: String,
    pub response: Option<String>,
    pub timestamp: std::time::Instant,
    pub prompt: String,
    pub response_type: Option<ResponseType>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResponseType {
    Success,
    Error,
    Warning,
    Info,
    Progress,
    ScriptDisplay, // Specifically for script content display
}

#[derive(Debug, Clone)]
pub struct StaticTextLine {
    pub content: String,
    pub line_type: LineType,
    pub history_index: Option<usize>,
    pub response_type: Option<ResponseType>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LineType {
    Command,
    Response,
    CurrentInput,
}

pub struct InteractiveCommandPanel {
    pub input_text: String,
    pub cursor_position: usize,
    pub command_history: Vec<CommandHistoryItem>,
    pub history_index: Option<usize>,
    pub mode: InteractionMode,
    pub input_state: InputState, // Input state management
    pub max_history_items: usize,

    // Script editing state
    pub script_cache: Option<ScriptCache>,

    // Command mode navigation (vim-like)
    pub command_cursor_line: usize,
    pub command_cursor_column: usize,

    pub static_lines: Vec<StaticTextLine>,

    // UI state
    pub scroll_offset: usize,
}

impl InteractiveCommandPanel {
    pub fn new() -> Self {
        let mut panel = Self {
            input_text: String::new(),
            cursor_position: 0,
            command_history: Vec::new(),
            history_index: None,
            mode: InteractionMode::Input,
            input_state: InputState::Ready, // Initialize to ready state
            max_history_items: 1000,
            script_cache: None,
            command_cursor_line: 0,
            command_cursor_column: 0,
            static_lines: Vec::new(),
            scroll_offset: 0,
        };
        panel.update_static_lines();
        panel
    }

    pub fn get_prompt(&self) -> String {
        // Don't show prompt when waiting for response
        if !self.should_show_input_prompt() {
            return "".to_string();
        }

        self.get_history_prompt()
    }

    /// Get prompt for history display (always shows, regardless of input state)
    fn get_history_prompt(&self) -> String {
        match self.mode {
            InteractionMode::Input => "(ghostscope) ".to_string(),
            InteractionMode::Command => "(ghostscope) ".to_string(),
            InteractionMode::ScriptEditor => "(ghostscope) ".to_string(),
        }
    }

    /// Check if input prompt should be displayed
    pub fn should_show_input_prompt(&self) -> bool {
        let should_show = matches!(self.input_state, InputState::Ready);
        debug!(
            "should_show_input_prompt: {:?} -> {}",
            self.input_state, should_show
        );
        should_show
    }

    /// Get panel title based on state
    pub fn get_panel_title(&self) -> String {
        match &self.input_state {
            InputState::Ready => match self.mode {
                InteractionMode::Input => "Interactive Command (input mode)".to_string(),
                InteractionMode::Command => "Interactive Command (command mode)".to_string(),
                InteractionMode::ScriptEditor => "Interactive Command (script mode)".to_string(),
            },
            InputState::WaitingResponse { .. } => {
                "Interactive Command (waiting for response...)".to_string()
            }
            InputState::ScriptEditor => "Interactive Command (script mode)".to_string(),
        }
    }

    /// Handle response from main thread and return to ready state
    pub fn handle_command_response(&mut self, response: String, is_success: bool) {
        // Add the response to display
        let response_type = if is_success {
            ResponseType::Success
        } else {
            ResponseType::Error
        };
        self.add_response(response, response_type);

        // Return to ready state
        self.input_state = InputState::Ready;
    }

    /// Check if command has timed out (optional timeout handling)
    pub fn check_timeout(&mut self, timeout_secs: u64) -> bool {
        if let InputState::WaitingResponse { sent_time, .. } = &self.input_state {
            if sent_time.elapsed().as_secs() > timeout_secs {
                self.add_response(
                    "⚠️ Command timeout - returning to input mode".to_string(),
                    ResponseType::Error,
                );
                self.input_state = InputState::Ready;
                return true;
            }
        }
        false
    }

    /// Reset panel state for accepting new input after script completion
    pub fn reset_for_new_input(&mut self) {
        // Clear any waiting response state
        self.input_state = InputState::Ready;

        // Ensure we're in the right mode for new input
        if self.mode != InteractionMode::Input {
            self.mode = InteractionMode::Input;
        }

        // Clear input buffer and reset cursor
        self.input_text.clear();
        self.cursor_position = 0;

        // Update display to show ready prompt
        self.update_static_lines();

        debug!(
            "Panel reset for new input, state: {:?}, mode: {:?}",
            self.input_state, self.mode
        );
    }

    pub fn insert_char(&mut self, c: char) {
        // Don't accept input when waiting for response
        if !self.should_show_input_prompt() {
            return;
        }

        self.input_text.insert(self.cursor_position, c);
        self.cursor_position += 1;
        self.update_static_lines();
    }

    pub fn delete_char(&mut self) {
        // Don't accept input when waiting for response
        if !self.should_show_input_prompt() {
            return;
        }

        if self.cursor_position > 0 {
            self.input_text.remove(self.cursor_position - 1);
            self.cursor_position -= 1;
            self.update_static_lines();
        }
    }

    pub fn move_cursor_left(&mut self) {
        if self.mode == InteractionMode::Command {
            if self.command_cursor_column > 0 {
                self.command_cursor_column -= 1;
            }
        } else {
            if self.cursor_position > 0 {
                self.cursor_position -= 1;
            }
        }
    }

    pub fn move_cursor_right(&mut self) {
        if self.mode == InteractionMode::Command {
            if let Some(line) = self.static_lines.get(self.command_cursor_line) {
                if self.command_cursor_column < line.content.len() {
                    self.command_cursor_column += 1;
                }
            }
        } else {
            if self.cursor_position < self.input_text.len() {
                self.cursor_position += 1;
            }
        }
    }

    pub fn move_to_next_word(&mut self) {
        let text = &self.input_text;
        let mut pos = self.cursor_position;

        // Skip current word if we're in the middle of one
        while pos < text.len() && !text.chars().nth(pos).unwrap_or(' ').is_whitespace() {
            pos += 1;
        }

        // Skip whitespace
        while pos < text.len() && text.chars().nth(pos).unwrap_or(' ').is_whitespace() {
            pos += 1;
        }

        self.cursor_position = pos;
    }

    pub fn move_to_previous_word(&mut self) {
        let text = &self.input_text;
        let mut pos = self.cursor_position;

        // Skip whitespace backwards
        while pos > 0 && text.chars().nth(pos - 1).unwrap_or(' ').is_whitespace() {
            pos -= 1;
        }

        // Skip current word backwards
        while pos > 0 && !text.chars().nth(pos - 1).unwrap_or(' ').is_whitespace() {
            pos -= 1;
        }

        self.cursor_position = pos;
    }

    pub fn move_to_next_word_in_history(&mut self) {
        if let Some(line) = self.static_lines.get(self.command_cursor_line) {
            let content = &line.content;
            let mut pos = self.command_cursor_column;

            // Skip current word if we're in the middle of one
            while pos < content.len() && !content.chars().nth(pos).unwrap_or(' ').is_whitespace() {
                pos += 1;
            }

            // Skip whitespace
            while pos < content.len() && content.chars().nth(pos).unwrap_or(' ').is_whitespace() {
                pos += 1;
            }

            self.command_cursor_column = pos;
        }
    }

    pub fn move_to_previous_word_in_history(&mut self) {
        if let Some(line) = self.static_lines.get(self.command_cursor_line) {
            let content = &line.content;
            let mut pos = self.command_cursor_column;

            // Skip whitespace backwards
            while pos > 0 && content.chars().nth(pos - 1).unwrap_or(' ').is_whitespace() {
                pos -= 1;
            }

            // Skip current word backwards
            while pos > 0 && !content.chars().nth(pos - 1).unwrap_or(' ').is_whitespace() {
                pos -= 1;
            }

            self.command_cursor_column = pos;
        }
    }

    pub fn submit_command(&mut self) -> Option<CommandAction> {
        if self.input_text.trim().is_empty() {
            return None;
        }

        let command = self.input_text.clone();
        let action = match self.mode {
            InteractionMode::Input => {
                if command.trim().starts_with("trace ") {
                    // Two-step trace interaction: parse target and enter script editor
                    self.enter_script_editor_for_trace(&command)
                } else {
                    CommandAction::ExecuteCommand(command.clone())
                }
            }
            InteractionMode::Command => {
                // Handle command mode commands
                CommandAction::ExecuteCommand(command.clone())
            }
            InteractionMode::ScriptEditor => {
                // Should not happen - script editor handles its own submission
                return None;
            }
        };

        // Always add command to history for immediate user feedback
        self.add_to_history(command, None);

        self.update_static_lines();

        self.input_text.clear();
        self.cursor_position = 0;
        self.history_index = None;

        Some(action)
    }

    /// Parse trace command and enter script editor mode
    fn enter_script_editor_for_trace(&mut self, command: &str) -> CommandAction {
        let target = command.trim_start_matches("trace").trim();

        if target.is_empty() {
            return CommandAction::ExecuteCommand(
                "Usage: trace <function_name|file:line>".to_string(),
            );
        }

        // Check if we have a cached script for this target
        let (lines, restored_from_cache) = if let Some(ref cache) = self.script_cache {
            if let Some(cached_script) = cache.saved_scripts.get(target) {
                (cached_script.lines().map(String::from).collect(), true)
            } else {
                (vec![String::new()], false)
            }
        } else {
            (vec![String::new()], false)
        };

        // Create new script cache
        self.script_cache = Some(ScriptCache {
            target: target.to_string(),
            original_command: command.to_string(),
            lines,
            cursor_line: 0, // Start at first line
            cursor_col: 0,
            status: ScriptStatus::Draft,
            saved_scripts: self
                .script_cache
                .as_ref()
                .map(|c| c.saved_scripts.clone())
                .unwrap_or_else(HashMap::new),
        });

        // Switch to script editor mode
        self.mode = InteractionMode::ScriptEditor;

        if restored_from_cache {
            CommandAction::EnterScriptMode(format!(
                "🔨 Entering script mode for target: {} [Restored from cache]",
                target
            ))
        } else {
            CommandAction::EnterScriptMode(format!(
                "🔨 Entering script mode for target: {}",
                target
            ))
        }
    }

    /// Submit the current script but keep editor displayed
    pub fn submit_script(&mut self) -> Option<CommandAction> {
        // Add debug logging
        debug!(
            "submit_script called, script_cache: {:?}",
            self.script_cache.is_some()
        );

        if let Some(ref cache) = self.script_cache {
            debug!(
                "Script cache has {} lines: {:?}",
                cache.lines.len(),
                cache.lines
            );
        }
        debug!("Current mode: {:?}", self.mode);
        debug!("Current input_state: {:?}", self.input_state);

        if let Some(cache) = &self.script_cache {
            debug!(
                "Found script cache, target: {}, lines: {:?}",
                cache.target, cache.lines
            );
            debug!("Script cache status: {:?}", cache.status);
            debug!(
                "Script cache cursor: line={}, col={}",
                cache.cursor_line, cache.cursor_col
            );

            // Extract data first to avoid borrow conflicts
            let script_lines = cache.lines.join("\n");
            let target = cache.target.clone();
            let original_command = cache.original_command.clone();
            let lines = cache.lines.clone();

            // Wrap script content with function body braces
            let script_content =
                if script_lines.trim().starts_with('{') && script_lines.trim().ends_with('}') {
                    // Already has braces, use as-is
                    script_lines
                } else {
                    // Add braces to create a complete function body
                    format!("{{\n{}\n}}", script_lines)
                };

            let command = format!("trace {} {}", target, script_content);

            debug!("Generated command: {}", command);

            // 1. Save script to history (before clearing cache)
            if let Some(ref mut cache) = self.script_cache {
                cache
                    .saved_scripts
                    .insert(target.clone(), script_content.clone());
                cache.status = ScriptStatus::Submitted;
            }

            // 2. Switch to Input mode and clear script cache
            self.mode = InteractionMode::Input;
            self.script_cache = None; // Clear the script cache
            debug!("Cleared script_cache, now using history approach");

            // 3. Create formatted script display for history
            let mut script_display = Vec::new();
            script_display.push("📝 Script content:".to_string());

            // Add script lines with line numbers (skip empty lines and default comments)
            for (line_idx, line) in lines.iter().enumerate() {
                if !line.trim().is_empty() {
                    let formatted_line = format!("  {} │ {}", line_idx + 1, line);
                    script_display.push(formatted_line);
                    debug!("Added script line {}: {}", line_idx + 1, line);
                }
            }

            // 4. Find the last history item (should be the trace command) and replace its response with script display
            if let Some(last_item) = self.command_history.last_mut() {
                // Check if this is the trace command we just entered
                if last_item.command == original_command {
                    // Replace any existing response with the script display
                    last_item.response = Some(script_display.join("\n"));
                    debug!("Replaced existing response with script display for trace command");
                } else {
                    // Fallback: create new history item (shouldn't happen in normal flow)
                    debug!("Creating new history item for script display (fallback)");
                    self.add_to_history(original_command.clone(), Some(script_display.join("\n")));
                }
            } else {
                // Fallback: create new history item (shouldn't happen in normal flow)
                debug!("No existing history items, creating new one for script display");
                self.add_to_history(original_command.clone(), Some(script_display.join("\n")));
            }

            // Set response type for syntax highlighting detection
            if let Some(last_item) = self.command_history.last_mut() {
                last_item.response_type = Some(ResponseType::ScriptDisplay);
            }

            // 5. Update display
            self.update_static_lines();

            // 6. Set waiting state - this hides input box but stays in Input mode
            self.input_state = InputState::WaitingResponse {
                command: command.clone(),
                sent_time: Instant::now(),
            };
            debug!("Set input_state to WaitingResponse");

            debug!(
                "Before final check, script_cache exists = {}",
                self.script_cache.is_some()
            );
            debug!("Returning CommandAction::SubmitScript");
            Some(CommandAction::SubmitScript(command))
        } else {
            debug!("No script cache found, returning None");
            debug!("script_cache is None, this might be the issue!");
            None
        }
    }

    /// Cancel script editing and return to input mode
    pub fn cancel_script_editor(&mut self) {
        if self.mode == InteractionMode::ScriptEditor {
            // Add termination message before switching modes
            self.add_response(
                "⚠️ Script editing cancelled".to_string(),
                ResponseType::Warning,
            );

            self.mode = InteractionMode::Input; // ESC should go to input mode
                                                // Keep script_cache for potential restoration

            // Ensure input state is ready to show prompt
            self.input_state = InputState::Ready;

            // Update static lines to show the input prompt again
            self.update_static_lines();
        }
    }

    pub fn cancel_script(&mut self) -> bool {
        match self.mode {
            InteractionMode::ScriptEditor => {
                self.cancel_script_editor();
                true
            }
            _ => false,
        }
    }

    /// Add script editing helper methods
    pub fn insert_char_in_script(&mut self, c: char) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_line < cache.lines.len() {
                cache.lines[cache.cursor_line].insert(cache.cursor_col, c);
                cache.cursor_col += 1;
                cache.status = ScriptStatus::Draft;
            } else if cache.cursor_line == cache.lines.len() {
                // Cursor is after last line, create a new line
                let mut new_line = String::new();
                new_line.insert(0, c);
                cache.lines.push(new_line);
                cache.cursor_col = 1;
                cache.status = ScriptStatus::Draft;
            }
        }
    }

    pub fn delete_char_in_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_line < cache.lines.len() && cache.cursor_col > 0 {
                // Delete character within current line
                cache.lines[cache.cursor_line].remove(cache.cursor_col - 1);
                cache.cursor_col -= 1;
                cache.status = ScriptStatus::Draft;
            } else if cache.cursor_col == 0 && cache.cursor_line > 0 {
                // Delete at beginning of line - merge with previous line
                let current_line = cache.lines.remove(cache.cursor_line);
                cache.cursor_line -= 1;
                cache.cursor_col = cache.lines[cache.cursor_line].len();
                cache.lines[cache.cursor_line].push_str(&current_line);
                cache.status = ScriptStatus::Draft;
            }
        }
    }

    pub fn insert_newline_in_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_line < cache.lines.len() {
                // Split current line at cursor position
                let current_line = cache.lines[cache.cursor_line].clone();
                let (left, right) = current_line.split_at(cache.cursor_col);

                cache.lines[cache.cursor_line] = left.to_string();
                cache.lines.insert(cache.cursor_line + 1, right.to_string());

                cache.cursor_line += 1;
                cache.cursor_col = 0;
                cache.status = ScriptStatus::Draft;
            } else if cache.cursor_line == cache.lines.len() {
                // Cursor is after last line, add a new empty line
                cache.lines.push(String::new());
                cache.cursor_line += 1;
                cache.cursor_col = 0;
                cache.status = ScriptStatus::Draft;
            }
        }
    }

    pub fn move_cursor_up_in_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_line > 0 {
                cache.cursor_line -= 1;
                // Adjust cursor column if new line is shorter
                if cache.cursor_col > cache.lines[cache.cursor_line].len() {
                    cache.cursor_col = cache.lines[cache.cursor_line].len();
                }
            }
        }
    }

    pub fn move_cursor_down_in_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_line + 1 < cache.lines.len() {
                cache.cursor_line += 1;
                // Adjust cursor column if new line is shorter
                if cache.cursor_col > cache.lines[cache.cursor_line].len() {
                    cache.cursor_col = cache.lines[cache.cursor_line].len();
                }
            } else if cache.cursor_line + 1 == cache.lines.len() {
                // Allow moving to position after last line for new input
                cache.cursor_line += 1;
                cache.cursor_col = 0;
            }
        }
    }

    pub fn move_cursor_left_in_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_col > 0 {
                cache.cursor_col -= 1;
            }
        }
    }

    pub fn move_cursor_right_in_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_line < cache.lines.len()
                && cache.cursor_col < cache.lines[cache.cursor_line].len()
            {
                cache.cursor_col += 1;
            }
        }
    }

    /// Check if we can edit again (F2 key)
    pub fn can_edit_script(&self) -> bool {
        if let Some(ref cache) = self.script_cache {
            cache.status == ScriptStatus::Submitted
        } else {
            false
        }
    }

    /// Re-enter script editing mode (F2 key)
    pub fn edit_script_again(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.status == ScriptStatus::Submitted {
                cache.status = ScriptStatus::Draft;
                self.mode = InteractionMode::ScriptEditor;
            }
        }
    }

    /// Clear current script (F3 key)  
    pub fn clear_current_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            cache.lines = vec![String::new()];
            cache.cursor_line = 0;
            cache.cursor_col = 0;
            cache.status = ScriptStatus::Draft;
        }
    }

    pub fn enter_command_mode(&mut self) {
        self.mode = InteractionMode::Command;
        self.update_static_lines();
        // Position cursor at the last line (current input line)
        self.command_cursor_line = self.static_lines.len().saturating_sub(1);
        self.command_cursor_column = self.get_prompt().len() + self.cursor_position;
    }

    pub fn enter_input_mode(&mut self) {
        self.mode = InteractionMode::Input;
    }

    pub fn exit_command_mode(&mut self) {
        self.mode = InteractionMode::Input;
        if let Some(line) = self.static_lines.get(self.command_cursor_line) {
            if line.line_type == LineType::CurrentInput {
                let prompt_len = self.get_prompt().len();
                if self.command_cursor_column >= prompt_len {
                    self.cursor_position = self.command_cursor_column - prompt_len;
                } else {
                    self.cursor_position = 0;
                }
            }
        }
    }

    pub fn handle_vim_navigation(&mut self, key: &str) -> bool {
        match key {
            "i" => {
                // Enter input mode from command mode
                self.exit_command_mode();
                true
            }
            "h" => {
                // Move left with boundary check
                self.move_cursor_left();
                true
            }
            "l" => {
                // Move right with boundary check
                self.move_cursor_right();
                true
            }
            "j" => {
                // Move down with boundary check
                self.move_cursor_down();
                true
            }
            "k" => {
                // Move up with boundary check
                self.move_cursor_up();
                true
            }
            "g" => {
                // Go to top of history (vim style)
                self.command_cursor_line = 0;
                self.command_cursor_column = 0;
                true
            }
            "G" => {
                // Go to current input line (bottom of all content)
                self.command_cursor_line = self.static_lines.len().saturating_sub(1);
                if let Some(line) = self.static_lines.get(self.command_cursor_line) {
                    self.command_cursor_column = line.content.len();
                }
                true
            }
            "0" => {
                // Go to beginning of current line
                self.command_cursor_column = 0;
                true
            }
            "$" => {
                // Go to end of current line
                if let Some(line) = self.static_lines.get(self.command_cursor_line) {
                    self.command_cursor_column = line.content.len();
                }
                true
            }
            "w" => {
                // Move to next word (vim style) in current history line
                self.move_to_next_word_in_history();
                true
            }
            "b" => {
                // Move to previous word (vim style) in current history line
                self.move_to_previous_word_in_history();
                true
            }
            _ => false,
        }
    }

    fn move_cursor_up(&mut self) {
        if self.command_cursor_line > 0 {
            self.command_cursor_line -= 1;
            // Adjust column position to stay within line bounds
            if let Some(line) = self.static_lines.get(self.command_cursor_line) {
                self.command_cursor_column = self.command_cursor_column.min(line.content.len());
            }
        }
    }

    fn move_cursor_down(&mut self) {
        if self.command_cursor_line < self.static_lines.len().saturating_sub(1) {
            self.command_cursor_line += 1;
            // Adjust column position to stay within line bounds
            if let Some(line) = self.static_lines.get(self.command_cursor_line) {
                self.command_cursor_column = self.command_cursor_column.min(line.content.len());
            }
        }
    }

    fn move_to_next_word_in_current_line(&mut self) {
        if let Some(line) = self.static_lines.get(self.command_cursor_line) {
            let content = &line.content;
            let mut pos = self.command_cursor_column;

            // Skip current word if we're in the middle of one
            while pos < content.len() && !content.chars().nth(pos).unwrap_or(' ').is_whitespace() {
                pos += 1;
            }

            // Skip whitespace
            while pos < content.len() && content.chars().nth(pos).unwrap_or(' ').is_whitespace() {
                pos += 1;
            }

            self.command_cursor_column = pos;
        }
    }

    fn move_to_previous_word_in_current_line(&mut self) {
        if let Some(line) = self.static_lines.get(self.command_cursor_line) {
            let content = &line.content;
            let mut pos = self.command_cursor_column;

            // Skip whitespace backwards
            while pos > 0 && content.chars().nth(pos - 1).unwrap_or(' ').is_whitespace() {
                pos -= 1;
            }

            // Skip current word backwards
            while pos > 0 && !content.chars().nth(pos - 1).unwrap_or(' ').is_whitespace() {
                pos -= 1;
            }

            self.command_cursor_column = pos;
        }
    }

    pub fn add_response(&mut self, response: String, response_type: ResponseType) {
        if let Some(last_item) = self.command_history.last_mut() {
            // If the last item is ScriptDisplay, create a new history item for the response
            if last_item.response_type == Some(ResponseType::ScriptDisplay) {
                debug!("Last item is ScriptDisplay, creating new history item for response");
                self.add_to_history("".to_string(), Some(response));
                if let Some(new_item) = self.command_history.last_mut() {
                    new_item.response_type = Some(response_type);
                }
            } else {
                last_item.response = Some(response);
                last_item.response_type = Some(response_type);
            }
        }
        self.update_static_lines();
    }

    /// Add a response specifically for script completion - appends to existing script display
    pub fn add_script_completion_response(
        &mut self,
        response: String,
        response_type: ResponseType,
    ) {
        if let Some(last_item) = self.command_history.last_mut() {
            debug!("Last history item {:?}", last_item);
            // Append to the existing script display response
            if last_item.response_type == Some(ResponseType::ScriptDisplay) {
                if let Some(existing_response) = &last_item.response {
                    last_item.response = Some(format!("{}\n\n{}", existing_response, response));
                } else {
                    last_item.response = Some(response);
                }
                debug!(
                    "Appended script completion response {:?} to existing script display",
                    last_item.response
                );
            } else {
                // Fallback to normal response handling
                last_item.response = Some(response);
                last_item.response_type = Some(response_type);
            }
        }
        self.update_static_lines();
    }

    fn add_to_history(&mut self, command: String, response: Option<String>) {
        let prompt = self.get_history_prompt();
        let item = CommandHistoryItem {
            command,
            response,
            timestamp: std::time::Instant::now(),
            prompt,
            response_type: None,
        };

        self.command_history.push(item);

        if self.command_history.len() > self.max_history_items {
            self.command_history.remove(0);
        }
    }

    pub fn history_up(&mut self) {
        if self.command_history.is_empty() {
            return;
        }

        let new_index = match self.history_index {
            None => self.command_history.len() - 1,
            Some(i) if i > 0 => i - 1,
            Some(_) => return,
        };

        self.history_index = Some(new_index);
        let item = &self.command_history[new_index];
        self.input_text = item.command.clone();
        self.cursor_position = self.input_text.len();
        self.update_static_lines();
    }

    pub fn history_down(&mut self) {
        match self.history_index {
            None => return,
            Some(i) if i < self.command_history.len() - 1 => {
                let new_index = i + 1;
                self.history_index = Some(new_index);
                let item = &self.command_history[new_index];
                self.input_text = item.command.clone();
                self.cursor_position = self.input_text.len();
            }
            Some(_) => {
                self.history_index = None;
                self.input_text.clear();
                self.cursor_position = 0;
            }
        }
        self.update_static_lines();
    }

    fn update_static_lines(&mut self) {
        self.static_lines.clear();
        debug!(
            "update_static_lines: Processing {} history items",
            self.command_history.len()
        );

        // Add history records
        for (history_idx, item) in self.command_history.iter().enumerate() {
            debug!(
                "Processing history item {}: command='{}', response_type={:?}",
                history_idx,
                item.command.chars().take(30).collect::<String>(),
                item.response_type
            );

            if !item.command.trim().is_empty() {
                let command_line = format!("{}{}", item.prompt, item.command);
                debug!(
                    "Adding new response to static lines: response_type={:?}, command_line='{}'",
                    item.response_type,
                    command_line.chars().take(50).collect::<String>()
                );
                self.static_lines.push(StaticTextLine {
                    content: command_line,
                    line_type: LineType::Command,
                    history_index: Some(history_idx),
                    response_type: None, // Commands don't have response type
                });
            }

            if let Some(ref response) = item.response {
                debug!(
                    "Adding response to static lines: response_type={:?}, content_preview='{}'",
                    item.response_type,
                    response.chars().take(50).collect::<String>()
                );
                self.static_lines.push(StaticTextLine {
                    content: response.clone(),
                    line_type: LineType::Response,
                    history_index: Some(history_idx),
                    response_type: item.response_type, // Use saved response type
                });
            }
        }

        // Only add current input line when not waiting for response and not in script editor mode
        if self.should_show_input_prompt() && self.mode != InteractionMode::ScriptEditor {
            let prompt = self.get_prompt();
            let current_line = format!("{}{}", prompt, self.input_text);
            self.static_lines.push(StaticTextLine {
                content: current_line,
                line_type: LineType::CurrentInput,
                history_index: None,
                response_type: None, // Current input doesn't have response type
            });
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        // Use script editor layout only in script editor mode
        if self.mode == InteractionMode::ScriptEditor {
            self.render_script_integrated_layout(frame, area, is_focused);
        } else {
            // Use original layout for normal input/command modes
            self.render_original_layout(frame, area, is_focused);
        }
    }

    fn should_show_script_editor(&self) -> bool {
        self.mode == InteractionMode::ScriptEditor || self.script_cache.is_some()
    }

    fn render_original_layout(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let border_style = if matches!(self.input_state, InputState::WaitingResponse { .. }) {
            // Show yellow border when waiting for response
            Style::default().fg(Color::Yellow)
        } else if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let available_height = area.height.saturating_sub(2) as usize; // Account for borders
        let content_area = Rect::new(
            area.x + 1,
            area.y + 1,
            area.width.saturating_sub(2),
            available_height as u16,
        );

        // Render static text content using original method
        self.render_static_content(frame, content_area, is_focused);

        // Render border
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(if is_focused {
                BorderType::Thick
            } else {
                BorderType::Plain
            })
            .title(self.get_panel_title())
            .border_style(border_style);

        frame.render_widget(block, area);
    }

    fn render_script_integrated_layout(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let available_height = area.height.saturating_sub(2) as usize;
        let content_area = Rect::new(
            area.x + 1,
            area.y + 1,
            area.width.saturating_sub(2),
            available_height as u16,
        );

        // Render script content
        self.render_script_integrated_content(frame, content_area, is_focused);

        // Render border with unified title
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(if is_focused {
                BorderType::Thick
            } else {
                BorderType::Plain
            })
            .title(self.get_panel_title())
            .border_style(border_style);

        frame.render_widget(block, area);
    }

    fn render_script_integrated_content(&self, frame: &mut Frame, area: Rect, _is_focused: bool) {
        let available_width = area.width as usize;
        let available_height = area.height as usize;
        let mut rendered_lines = Vec::new();

        // First, render all command history using consistent styling
        for line in &self.static_lines {
            let wrapped_lines = self.wrap_text(&line.content, available_width);

            let style = match line.line_type {
                LineType::Command => Style::default().fg(Color::Gray),
                LineType::Response => self.get_response_style(&line.content),
                LineType::CurrentInput => {
                    // In ScriptEditor mode, show the trace command that started script mode with different color
                    if self.mode == InteractionMode::ScriptEditor {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    }
                }
            };

            for wrapped_line in wrapped_lines {
                rendered_lines.push(ListItem::new(Line::from(vec![Span::styled(
                    wrapped_line,
                    style,
                )])));
            }
        }

        // Add script editor section if in script mode
        if let Some(ref cache) = self.script_cache {
            // Add a separator line
            rendered_lines.push(ListItem::new(Line::from(vec![Span::styled(
                "─".repeat(available_width.saturating_sub(2)),
                Style::default().fg(Color::Cyan),
            )])));

            // Add script editor prompt with line wrapping support
            let script_prompt = "Script Editor (Ctrl+s to submit, Esc to cancel):";
            let prompt_wrapped = self.wrap_text(script_prompt, available_width.saturating_sub(2));
            for prompt_line in prompt_wrapped {
                rendered_lines.push(ListItem::new(Line::from(vec![Span::styled(
                    prompt_line,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )])));
            }

            // Add script lines with syntax highlighting and word wrapping
            for (line_idx, script_line) in cache.lines.iter().enumerate() {
                let is_cursor_line = line_idx == cache.cursor_line;
                let cursor_indicator = if is_cursor_line { "▶" } else { " " };
                let line_prefix = format!("{}{:2} │ ", cursor_indicator, line_idx + 1);

                // Calculate available width for content (accounting for prefix)
                let prefix_width = line_prefix.chars().count();
                let content_width = available_width.saturating_sub(prefix_width + 2);

                if script_line.chars().count() <= content_width {
                    // Single line - no wrapping needed
                    let mut spans = vec![Span::styled(
                        line_prefix,
                        Style::default().fg(Color::DarkGray),
                    )];

                    // Add syntax-highlighted content (cursor handled by ratatui)
                    spans.extend(self.syntax_highlight_line(script_line));

                    rendered_lines.push(ListItem::new(Line::from(spans)));
                } else {
                    // Multi-line - need wrapping
                    let wrapped_parts = self.wrap_script_line_with_syntax(
                        script_line,
                        content_width,
                        is_cursor_line,
                        if is_cursor_line {
                            Some(cache.cursor_col)
                        } else {
                            None
                        },
                    );

                    for (_part_idx, (content_spans, is_first_line)) in
                        wrapped_parts.into_iter().enumerate()
                    {
                        let prefix = if is_first_line {
                            line_prefix.clone()
                        } else {
                            // Continuation line - use spaces to match the first line's prefix length
                            " ".repeat(line_prefix.chars().count())
                        };

                        let mut line_spans =
                            vec![Span::styled(prefix, Style::default().fg(Color::DarkGray))];
                        line_spans.extend(content_spans);

                        rendered_lines.push(ListItem::new(Line::from(line_spans)));
                    }
                }
            }

            // Add empty line for new input
            if cache.lines.is_empty() || cache.cursor_line == cache.lines.len() {
                let cursor_indicator = if cache.cursor_line == cache.lines.len() {
                    "▶"
                } else {
                    " "
                };
                let line_content = format!("{}{:2} │ ", cursor_indicator, cache.lines.len() + 1);
                rendered_lines.push(ListItem::new(Line::from(vec![Span::styled(
                    line_content,
                    Style::default().fg(Color::DarkGray),
                )])));
            }
        }

        // Calculate scroll position to show latest content
        let scroll_position = if rendered_lines.len() > available_height {
            rendered_lines.len().saturating_sub(available_height)
        } else {
            0
        };

        let visible_lines: Vec<_> = rendered_lines.into_iter().skip(scroll_position).collect();

        let list = List::new(visible_lines);
        frame.render_widget(list, area);

        // Render cursor for script editor mode
        if let Some(ref cache) = self.script_cache {
            self.render_script_cursor(frame, area, cache, scroll_position);
        }
    }

    fn render_static_content(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let max_lines = area.height as usize;
        let content_width = area.width.saturating_sub(2) as usize;

        // Calculate which lines to show
        let total_lines = self.static_lines.len();
        let start_idx = if self.mode == InteractionMode::Command {
            // In command mode, ensure cursor line is visible
            if self.command_cursor_line >= max_lines {
                self.command_cursor_line + 1 - max_lines
            } else {
                0
            }
        } else {
            // In input mode, ensure current input line is always visible
            self.calculate_scroll_to_show_current_input(max_lines, content_width)
        };

        let end_idx = (start_idx + max_lines).min(total_lines);

        // Render visible lines
        let mut items = Vec::new();
        debug!(
            "Rendering {} static lines (showing {}-{})",
            self.static_lines.len(),
            start_idx,
            end_idx
        );
        for i in start_idx..end_idx {
            if let Some(line) = self.static_lines.get(i) {
                {
                    debug!(
                        "Regular line: line_type={:?}, response_type={:?}",
                        line.line_type, line.response_type
                    );
                    // Handle text wrapping and styling for other content
                    let wrapped_lines = self.wrap_text(&line.content, content_width);

                    for wrapped_line in wrapped_lines {
                        let spans = {
                            match line.line_type {
                                LineType::Command => {
                                    vec![Span::styled(
                                        wrapped_line,
                                        Style::default().fg(Color::Gray),
                                    )]
                                }
                                LineType::Response => {
                                    // Special handling for ScriptDisplay in history
                                    if line.response_type == Some(ResponseType::ScriptDisplay) {
                                        self.format_script_display_line(&wrapped_line)
                                    } else {
                                        // Regular response styling
                                        let style = self.get_response_style(&line.content);
                                        vec![Span::styled(wrapped_line, style)]
                                    }
                                }
                                LineType::CurrentInput => {
                                    let style = if self.mode == InteractionMode::Input {
                                        Style::default()
                                            .fg(Color::Yellow)
                                            .add_modifier(Modifier::BOLD)
                                    } else {
                                        Style::default().fg(Color::White)
                                    };
                                    vec![Span::styled(wrapped_line, style)]
                                }
                            }
                        };

                        items.push(ListItem::new(Line::from(spans)));
                    }
                }
            }
        }

        let list = List::new(items);
        frame.render_widget(list, area);

        // Render cursor
        if is_focused {
            self.render_cursor(frame, area, start_idx);
        }
    }

    fn render_cursor(&self, frame: &mut Frame, area: Rect, start_idx: usize) {
        // Don't render cursor when waiting for response
        if !self.should_show_input_prompt() {
            return;
        }

        if self.mode == InteractionMode::Input {
            // Input mode: render cursor on current input line, considering text wrapping
            let content_width = area.width.saturating_sub(2) as usize;
            let prompt = self.get_prompt();
            let prompt_len = prompt.len();
            let full_text = format!("{}{}", prompt, self.input_text);

            // Calculate cursor position in wrapped text
            let mut remaining_cursor_pos = self.cursor_position;
            let mut cursor_line_offset = 0;

            // Calculate which line the cursor should be on
            let wrapped_lines = self.wrap_text(&full_text, content_width);
            for (line_idx, line) in wrapped_lines.iter().enumerate() {
                let line_content_len = if line_idx == 0 {
                    // First line includes prompt
                    line.len().saturating_sub(prompt_len)
                } else {
                    line.len()
                };

                if remaining_cursor_pos <= line_content_len {
                    // Cursor is on this line
                    cursor_line_offset = line_idx;
                    break;
                } else {
                    remaining_cursor_pos -= line_content_len;
                }
            }

            // Find the current input line's position in the rendered display
            let mut total_rendered_lines_before_scroll = 0;
            let mut current_input_rendered_start = 0;
            let mut found_current_input = false;

            // First, calculate total rendered lines from beginning to current input line
            for (static_idx, line) in self.static_lines.iter().enumerate() {
                if line.line_type == LineType::CurrentInput {
                    current_input_rendered_start = total_rendered_lines_before_scroll;
                    found_current_input = true;
                    break;
                }
                let wrapped_lines = self.wrap_text(&line.content, content_width);
                total_rendered_lines_before_scroll += wrapped_lines.len();
            }

            if found_current_input {
                // Calculate cursor's absolute rendered position
                let cursor_absolute_rendered_pos =
                    current_input_rendered_start + cursor_line_offset;

                // Convert start_idx (static line index) to rendered line offset
                let mut rendered_lines_before_start_idx = 0;
                for static_idx in 0..start_idx {
                    if let Some(line) = self.static_lines.get(static_idx) {
                        let wrapped_lines = self.wrap_text(&line.content, content_width);
                        rendered_lines_before_start_idx += wrapped_lines.len();
                    }
                }

                // Calculate relative position in the visible area
                let relative_line =
                    cursor_absolute_rendered_pos.saturating_sub(rendered_lines_before_start_idx);

                if relative_line < area.height as usize {
                    let cursor_x = if cursor_line_offset == 0 {
                        area.x + prompt_len as u16 + remaining_cursor_pos as u16
                    } else {
                        area.x + remaining_cursor_pos as u16
                    };
                    let cursor_y = area.y + relative_line as u16;

                    if cursor_x < area.x + area.width && cursor_y < area.y + area.height {
                        frame.render_widget(
                            Block::default()
                                .style(Style::default().bg(Color::White).fg(Color::Black)),
                            Rect::new(cursor_x, cursor_y, 1, 1),
                        );
                    }
                }
            }
        } else if self.mode == InteractionMode::Command {
            // Command mode: render cursor on selected line, considering text wrapping
            if self.command_cursor_line < self.static_lines.len() {
                let content_width = area.width.saturating_sub(2) as usize;

                // Calculate the actual rendered position of the selected line
                let mut rendered_line_pos = 0;
                for i in start_idx..self.static_lines.len() {
                    if i == self.command_cursor_line {
                        break;
                    }
                    if let Some(line) = self.static_lines.get(i) {
                        let wrapped_lines = self.wrap_text(&line.content, content_width);
                        rendered_line_pos += wrapped_lines.len();
                    }
                }

                // Add the wrapped lines of the selected line up to the cursor position
                if let Some(selected_line) = self.static_lines.get(self.command_cursor_line) {
                    let wrapped_lines = self.wrap_text(&selected_line.content, content_width);

                    // Find which wrapped line the cursor is on
                    let mut remaining_cursor_pos = self.command_cursor_column;
                    let mut cursor_line_offset = 0;

                    for (line_idx, line) in wrapped_lines.iter().enumerate() {
                        if remaining_cursor_pos <= line.len() {
                            cursor_line_offset = line_idx;
                            break;
                        } else {
                            remaining_cursor_pos -= line.len();
                        }
                    }

                    rendered_line_pos += cursor_line_offset;
                    let relative_line = rendered_line_pos.saturating_sub(start_idx);

                    if relative_line < area.height as usize {
                        let cursor_x = area.x + remaining_cursor_pos as u16;
                        let cursor_y = area.y + relative_line as u16;

                        if cursor_x < area.x + area.width && cursor_y < area.y + area.height {
                            frame.render_widget(
                                Block::default()
                                    .style(Style::default().bg(Color::White).fg(Color::Black)),
                                Rect::new(cursor_x, cursor_y, 1, 1),
                            );
                        }
                    }
                }
            }
        }
    }

    /// Wrap text to fit within the specified width
    /// Simple character-based wrapping to avoid word breaking issues
    fn wrap_text(&self, text: &str, width: usize) -> Vec<String> {
        if width == 0 || text.is_empty() {
            return vec![text.to_string()];
        }

        let mut lines = Vec::new();
        let mut current_line = String::new();

        for ch in text.chars() {
            if ch == '\n' {
                // Handle explicit line breaks
                lines.push(current_line);
                current_line = String::new();
            } else if current_line.len() >= width {
                // Line is full, start a new one
                lines.push(current_line);
                current_line = ch.to_string();
            } else {
                // Add character to current line
                current_line.push(ch);
            }
        }

        // Add the last line if it's not empty
        if !current_line.is_empty() {
            lines.push(current_line);
        }

        // Ensure we always return at least one line
        if lines.is_empty() {
            vec![text.to_string()]
        } else {
            lines
        }
    }

    fn get_response_style(&self, response: &str) -> Style {
        if response.starts_with("✓") {
            Style::default().fg(Color::Green)
        } else if response.starts_with("✗") {
            Style::default().fg(Color::Red)
        } else if response.starts_with("⚠") {
            Style::default().fg(Color::Yellow)
        } else if response.starts_with("⏳") {
            Style::default().fg(Color::Blue)
        } else if response.starts_with("🔨") {
            Style::default().fg(Color::Cyan)
        } else if response.starts_with("📝") {
            // Script display - use script highlighting style
            Style::default().fg(Color::Magenta)
        } else {
            Style::default()
        }
    }

    /// Format a script display line from history with proper syntax highlighting
    fn format_script_display_line(&self, line: &str) -> Vec<Span> {
        debug!("Formatting script display line: '{}'", line);

        // Handle different types of lines in script display
        if line.starts_with("📝") {
            // Header line - green and bold
            vec![Span::styled(
                line.to_string(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            )]
        } else if line.chars().all(|c| c == '─' || c.is_whitespace()) {
            // Separator line - dark gray
            vec![Span::styled(
                line.to_string(),
                Style::default().fg(Color::DarkGray),
            )]
        } else if line.starts_with("⏳") {
            // Status message - blue
            vec![Span::styled(
                line.to_string(),
                Style::default().fg(Color::Blue),
            )]
        } else if line.contains(" │ ") {
            // Script line with line number - apply syntax highlighting
            if let Some(separator_pos) = line.find(" │ ") {
                let separator_str = " │ ";
                let end_byte_pos = separator_pos + separator_str.len();

                if end_byte_pos <= line.len() {
                    let line_number_part = &line[..end_byte_pos];
                    let code_part = if end_byte_pos < line.len() {
                        &line[end_byte_pos..]
                    } else {
                        ""
                    };

                    let mut spans = vec![Span::styled(
                        line_number_part.to_string(),
                        Style::default().fg(Color::DarkGray),
                    )];

                    // Apply syntax highlighting to code part
                    spans.extend(self.syntax_highlight_line(code_part));
                    spans
                } else {
                    // Fallback
                    vec![Span::styled(
                        line.to_string(),
                        Style::default().fg(Color::White),
                    )]
                }
            } else {
                // Fallback
                vec![Span::styled(
                    line.to_string(),
                    Style::default().fg(Color::White),
                )]
            }
        } else {
            // Other lines - default styling
            vec![Span::styled(
                line.to_string(),
                Style::default().fg(Color::White),
            )]
        }
    }

    /// Syntax highlighting for script lines
    fn syntax_highlight_line(&self, line: &str) -> Vec<Span> {
        debug!("Starting syntax_highlight_line for: '{}'", line);
        let mut spans = Vec::new();
        let mut current_pos = 0;
        let line_chars: Vec<char> = line.chars().collect();

        debug!("Line chars length: {}", line_chars.len());

        if line_chars.is_empty() {
            debug!("Empty line, returning empty spans");
            return spans;
        }

        // Define keywords and their styles
        let keywords = &[
            (
                "print",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            (
                "if",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            (
                "else",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            (
                "elseif",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
        ];

        while current_pos < line_chars.len() {
            debug!(
                "Processing position {} of {}",
                current_pos,
                line_chars.len()
            );

            // Check for comments (// style)
            if current_pos + 1 < line_chars.len()
                && line_chars[current_pos] == '/'
                && line_chars[current_pos + 1] == '/'
            {
                debug!("Found comment at position {}", current_pos);
                // Rest of line is comment
                let comment_text: String = line_chars[current_pos..].iter().collect();
                spans.push(Span::styled(
                    comment_text,
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                ));
                break;
            }

            // Check for string literals
            if current_pos < line_chars.len() && line_chars[current_pos] == '"' {
                debug!("Found string literal at position {}", current_pos);
                let mut end_pos = current_pos + 1;
                while end_pos < line_chars.len() && line_chars[end_pos] != '"' {
                    if line_chars[end_pos] == '\\' && end_pos + 1 < line_chars.len() {
                        end_pos += 2; // Skip escaped character
                    } else {
                        end_pos += 1;
                    }
                }
                if end_pos < line_chars.len() {
                    end_pos += 1; // Include closing quote
                }

                let string_text: String = line_chars[current_pos..end_pos].iter().collect();
                spans.push(Span::styled(string_text, Style::default().fg(Color::Green)));
                current_pos = end_pos;
                continue;
            }

            // Check for keywords
            let mut keyword_found = false;
            for (keyword, style) in keywords {
                if self.match_keyword_at_position(&line_chars, current_pos, keyword) {
                    spans.push(Span::styled(keyword.to_string(), *style));
                    current_pos += keyword.len();
                    keyword_found = true;
                    break;
                }
            }

            if keyword_found {
                continue;
            }

            // Check for numbers
            if current_pos < line_chars.len() && line_chars[current_pos].is_ascii_digit() {
                debug!("Found number at position {}", current_pos);
                let mut end_pos = current_pos;
                while end_pos < line_chars.len()
                    && (line_chars[end_pos].is_ascii_digit() || line_chars[end_pos] == '.')
                {
                    end_pos += 1;
                }

                let number_text: String = line_chars[current_pos..end_pos].iter().collect();
                spans.push(Span::styled(
                    number_text,
                    Style::default()
                        .fg(Color::Blue)
                        .add_modifier(Modifier::BOLD),
                ));
                current_pos = end_pos;
                continue;
            }

            // Default: regular text
            if current_pos < line_chars.len() {
                debug!(
                    "Adding regular char '{}' at position {}",
                    line_chars[current_pos], current_pos
                );
                spans.push(Span::styled(
                    line_chars[current_pos].to_string(),
                    Style::default().fg(Color::Cyan),
                ));
                current_pos += 1;
            } else {
                debug!(
                    "Position {} is beyond line length {}, breaking",
                    current_pos,
                    line_chars.len()
                );
                break;
            }
        }

        spans
    }

    /// Calculate scroll position to ensure current input line is visible
    fn calculate_scroll_to_show_current_input(
        &self,
        max_lines: usize,
        content_width: usize,
    ) -> usize {
        // Find current input line and calculate all rendered line positions
        let mut current_input_static_idx = None;
        let mut rendered_positions = Vec::new();
        let mut total_rendered_lines = 0;

        for (static_idx, line) in self.static_lines.iter().enumerate() {
            let wrapped_lines = self.wrap_text(&line.content, content_width);
            let line_rendered_count = wrapped_lines.len();

            rendered_positions.push((total_rendered_lines, line_rendered_count));

            if line.line_type == LineType::CurrentInput {
                current_input_static_idx = Some(static_idx);
            }

            total_rendered_lines += line_rendered_count;
        }

        let Some(current_input_idx) = current_input_static_idx else {
            // No current input line, use original logic
            return if self.static_lines.len() > max_lines {
                self.static_lines.len() - max_lines
            } else {
                0
            };
        };

        let (current_input_start, current_input_count) = rendered_positions[current_input_idx];
        let current_input_end = current_input_start + current_input_count;

        // Strategy: Ensure the ENTIRE current input line is visible at the bottom of the screen
        if current_input_end <= max_lines {
            // Everything fits, show from the beginning
            return 0;
        }

        // Calculate how much we need to scroll to show the current input line at the bottom
        let target_scroll_start = current_input_end.saturating_sub(max_lines);

        // Find the static line index that corresponds to this rendered position
        // We want to be conservative and ensure we don't cut off the current input line
        let mut best_static_idx = 0;
        let mut best_rendered_start = 0;

        for (static_idx, &(rendered_start, rendered_count)) in rendered_positions.iter().enumerate()
        {
            // We want the rendered_start to be <= target_scroll_start
            // but also want to get as close as possible without exceeding
            if rendered_start <= target_scroll_start {
                best_static_idx = static_idx;
                best_rendered_start = rendered_start;
            } else {
                break;
            }
        }

        // Double-check: ensure current input line will be fully visible
        let visible_start = best_rendered_start;
        let visible_end = visible_start + max_lines;

        if current_input_end > visible_end {
            // Current input line would be cut off, need to scroll more
            // Find a static line that ensures current input is fully visible
            for (static_idx, &(rendered_start, _)) in rendered_positions.iter().enumerate() {
                let test_visible_end = rendered_start + max_lines;
                if current_input_end <= test_visible_end {
                    return static_idx;
                }
            }
        }

        best_static_idx
    }

    /// Helper function to check if a keyword matches at a specific position
    fn match_keyword_at_position(&self, chars: &[char], pos: usize, keyword: &str) -> bool {
        let keyword_chars: Vec<char> = keyword.chars().collect();

        // Check if there's enough space for the keyword
        if pos + keyword_chars.len() > chars.len() {
            return false;
        }

        // Check if keyword matches
        for (i, &kw_char) in keyword_chars.iter().enumerate() {
            if chars[pos + i] != kw_char {
                return false;
            }
        }

        // Check word boundaries (keyword should not be part of a larger word)
        let before_is_boundary = pos == 0 || !chars[pos - 1].is_alphabetic();
        let after_pos = pos + keyword_chars.len();
        let after_is_boundary = after_pos >= chars.len() || !chars[after_pos].is_alphabetic();

        before_is_boundary && after_is_boundary
    }

    /// Syntax highlighting with cursor display for the current line
    fn syntax_highlight_line_with_cursor(&self, line: &str, cursor_col: usize) -> Vec<Span> {
        let line_chars: Vec<char> = line.chars().collect();
        let safe_cursor_pos = cursor_col.min(line_chars.len());

        // Get syntax highlighting spans for the entire line
        let mut base_spans = self.syntax_highlight_line(line);

        // Insert cursor at the correct position
        let mut result_spans = Vec::new();
        let mut char_position = 0;

        for span in base_spans {
            let span_text = span.content.to_string();
            let span_chars: Vec<char> = span_text.chars().collect();
            let span_start = char_position;
            let span_end = char_position + span_chars.len();

            if safe_cursor_pos >= span_start && safe_cursor_pos <= span_end {
                // Cursor is within this span
                let cursor_pos_in_span = safe_cursor_pos - span_start;

                if cursor_pos_in_span == 0 {
                    // Cursor at the beginning of span
                    result_spans.push(Span::styled(
                        "▎",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ));
                    result_spans.push(span);
                } else if cursor_pos_in_span == span_chars.len() {
                    // Cursor at the end of span
                    result_spans.push(span);
                    result_spans.push(Span::styled(
                        "▎",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ));
                } else {
                    // Cursor in the middle of span - split the span
                    let before: String = span_chars[..cursor_pos_in_span].iter().collect();
                    let after: String = span_chars[cursor_pos_in_span..].iter().collect();

                    if !before.is_empty() {
                        result_spans.push(Span::styled(before, span.style));
                    }
                    result_spans.push(Span::styled(
                        "▎",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ));
                    if !after.is_empty() {
                        result_spans.push(Span::styled(after, span.style));
                    }
                }
            } else {
                result_spans.push(span);
            }

            char_position = span_end;
        }

        // If cursor is at the very end of the line, add it
        if safe_cursor_pos >= line_chars.len() {
            result_spans.push(Span::styled(
                "▎",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ));
        }

        result_spans
    }

    /// Wrap a script line with syntax highlighting, preserving cursor position
    fn wrap_script_line_with_syntax(
        &self,
        line: &str,
        content_width: usize,
        is_cursor_line: bool,
        cursor_col: Option<usize>,
    ) -> Vec<(Vec<Span>, bool)> {
        if content_width == 0 {
            return vec![(Vec::new(), true)];
        }

        // Get syntax highlighted spans (cursor handled separately)
        let spans = self.syntax_highlight_line(line);

        let mut result = Vec::new();
        let mut current_line_spans = Vec::new();
        let mut current_line_width = 0;
        let mut is_first_line = true;

        for span in spans {
            let span_text = span.content.to_string();
            let span_chars: Vec<char> = span_text.chars().collect();

            if span_chars.is_empty() {
                continue;
            }

            // If the entire span fits in the current line
            if current_line_width + span_chars.len() <= content_width {
                current_line_spans.push(span);
                current_line_width += span_chars.len();
            } else {
                // Need to split the span
                let mut remaining_chars = span_chars;
                let mut current_style = span.style;

                while !remaining_chars.is_empty() {
                    let space_left = content_width - current_line_width;

                    if space_left == 0 {
                        // Start a new line
                        if !current_line_spans.is_empty() {
                            result.push((current_line_spans, is_first_line));
                            current_line_spans = Vec::new();
                            current_line_width = 0;
                            is_first_line = false;
                        }
                        continue;
                    }

                    let chunk_size = space_left.min(remaining_chars.len());
                    let chunk: String = remaining_chars[..chunk_size].iter().collect();

                    current_line_spans.push(Span::styled(chunk, current_style));
                    current_line_width += chunk_size;

                    remaining_chars = remaining_chars[chunk_size..].to_vec();

                    if current_line_width >= content_width {
                        // Line is full, start a new one
                        result.push((current_line_spans, is_first_line));
                        current_line_spans = Vec::new();
                        current_line_width = 0;
                        is_first_line = false;
                    }
                }
            }
        }

        // Add the last line if it has content
        if !current_line_spans.is_empty() {
            result.push((current_line_spans, is_first_line));
        }

        // Ensure we always return at least one line
        if result.is_empty() {
            result.push((Vec::new(), true));
        }

        result
    }

    /// Render cursor for script editor mode, similar to insert mode cursor
    fn render_script_cursor(
        &self,
        frame: &mut Frame,
        area: Rect,
        cache: &ScriptCache,
        scroll_offset: usize,
    ) {
        let available_width = area.width as usize;
        let mut total_visual_lines = 0;

        // Count ALL visual lines in the rendered content (including history)
        // 1. Count history lines
        for line in &self.static_lines {
            let wrapped_lines = self.wrap_text(&line.content, available_width);
            total_visual_lines += wrapped_lines.len();
        }

        // 2. Count separator line
        total_visual_lines += 1;

        // 3. Count prompt lines (with wrapping)
        let script_prompt = "Script Editor (Ctrl+s to submit, Esc to cancel):";
        let prompt_wrapped = self.wrap_text(script_prompt, available_width.saturating_sub(2));
        total_visual_lines += prompt_wrapped.len();

        // 4. Count script lines up to cursor line
        for line_idx in 0..cache.cursor_line {
            if let Some(script_line) = cache.lines.get(line_idx) {
                let cursor_indicator = " "; // Non-cursor lines use space
                let line_prefix = format!("{}{:2} │ ", cursor_indicator, line_idx + 1);
                let prefix_width = line_prefix.chars().count();
                let content_width = available_width.saturating_sub(prefix_width + 2);

                if script_line.chars().count() <= content_width {
                    total_visual_lines += 1; // Single line
                } else {
                    // Multi-line - count wrapped lines
                    let line_count =
                        (script_line.chars().count() + content_width - 1) / content_width;
                    total_visual_lines += line_count;
                }
            }
        }

        // 5. Calculate cursor position within current line
        if let Some(_current_line) = cache.lines.get(cache.cursor_line) {
            let cursor_indicator = "▶";
            let line_prefix = format!("{}{:2} │ ", cursor_indicator, cache.cursor_line + 1);
            let prefix_width = line_prefix.chars().count();
            let content_width = available_width.saturating_sub(prefix_width + 2);

            // Find which visual line the cursor is on for this logical line
            let cursor_visual_offset = if content_width > 0 {
                cache.cursor_col / content_width
            } else {
                0
            };
            total_visual_lines += cursor_visual_offset;

            // Calculate cursor column position within the visual line
            let cursor_col_in_visual_line = if content_width > 0 {
                cache.cursor_col % content_width
            } else {
                0
            };
            let cursor_x = area.x + prefix_width as u16 + cursor_col_in_visual_line as u16;
            let cursor_y = area.y + (total_visual_lines.saturating_sub(scroll_offset)) as u16;

            // Only draw cursor if it's within the visible area
            if cursor_y < area.y + area.height && cursor_x < area.x + area.width {
                frame.set_cursor_position((cursor_x, cursor_y));
            }
        } else if cache.cursor_line == cache.lines.len() {
            // Cursor is on empty line at the end
            let cursor_indicator = "▶";
            let line_prefix = format!("{}{:2} │ ", cursor_indicator, cache.lines.len() + 1);
            let prefix_width = line_prefix.chars().count();

            let cursor_x = area.x + prefix_width as u16;
            let cursor_y = area.y + (total_visual_lines.saturating_sub(scroll_offset)) as u16;

            // Only draw cursor if it's within the visible area
            if cursor_y < area.y + area.height && cursor_x < area.x + area.width {
                frame.set_cursor_position((cursor_x, cursor_y));
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum CommandAction {
    ExecuteCommand(String),
    EnterScriptMode(String),
    AddScriptLine(String),
    SubmitScript(String),
    CancelScript,
}

use crate::action::{Action, CursorDirection};
use crate::model::panel_state::{CommandPanelState, InputState, InteractionMode, JkEscapeState};
use ratatui::crossterm::event::KeyEvent;
use std::time::Instant;

/// Optimized input handler with vim-like controls
#[derive(Debug)]
pub struct OptimizedInputHandler {
    // jk escape sequence handling
    jk_timeout_ms: u64,

    // Input debouncing (though we use frame-based rendering now)
    last_input_time: Instant,
}

impl OptimizedInputHandler {
    pub fn new() -> Self {
        Self {
            jk_timeout_ms: 100,
            last_input_time: Instant::now(),
        }
    }

    /// Handle key event with priority-based routing (delegates to InputHandler)
    pub fn handle_key_event(
        &mut self,
        state: &mut CommandPanelState,
        key: KeyEvent,
    ) -> Vec<Action> {
        self.last_input_time = Instant::now();

        // Delegate to the main InputHandler for priority-based handling
        crate::components::command_panel::InputHandler::handle_key_event(state, key)
    }

    /// Handle character input in different modes
    pub fn handle_char_input(&mut self, state: &mut CommandPanelState, ch: char) -> Vec<Action> {
        tracing::debug!(
            "handle_char_input: received char='{}' (code={}), mode={:?}",
            ch,
            ch as u32,
            state.mode
        );
        self.last_input_time = Instant::now();

        let result = match state.mode {
            InteractionMode::Input => self.handle_input_mode_char(state, ch),
            InteractionMode::Command => self.handle_command_mode_char(state, ch),
            InteractionMode::ScriptEditor => self.handle_script_mode_char(state, ch),
        };

        tracing::debug!(
            "handle_char_input: after processing, input_text='{}', cursor_pos={}",
            state.input_text,
            state.cursor_position
        );
        result
    }

    /// Handle character input in Input mode (normal typing)
    fn handle_input_mode_char(&mut self, state: &mut CommandPanelState, ch: char) -> Vec<Action> {
        // Handle jk escape sequence first
        match self.handle_jk_escape(state, ch) {
            JkResult::Continue => {
                // Normal character insertion
                self.insert_char_at_cursor(state, ch);
                Vec::new()
            }
            JkResult::WaitForK => {
                // Don't insert 'j' yet, just wait for potential 'k'
                Vec::new()
            }
            JkResult::InsertJThenChar => {
                // Insert pending 'j' then current character
                self.insert_char_at_cursor(state, 'j');
                self.insert_char_at_cursor(state, ch);
                Vec::new()
            }
            JkResult::SwitchToCommand => {
                // Switch to command mode
                vec![Action::EnterCommandMode]
            }
        }
    }

    /// Handle character input in Command mode (vim-like navigation)
    fn handle_command_mode_char(&mut self, state: &mut CommandPanelState, ch: char) -> Vec<Action> {
        match ch {
            // Movement commands (vim-like)
            'j' => {
                self.move_history_down(state);
                Vec::new()
            }
            'k' => {
                self.move_history_up(state);
                Vec::new()
            }
            'h' => {
                // Move cursor left in current line
                if state.command_cursor_column > 0 {
                    state.command_cursor_column -= 1;
                }
                Vec::new()
            }
            'l' => {
                // Move cursor right in current line
                self.move_cursor_right_in_command(state);
                Vec::new()
            }
            'g' => {
                // Go to top
                self.go_to_top(state);
                Vec::new()
            }
            'G' => {
                // Go to bottom
                self.go_to_bottom(state);
                Vec::new()
            }
            '0' | '^' => {
                // Go to beginning of line
                state.command_cursor_column = 0;
                Vec::new()
            }
            '$' => {
                // Go to end of line
                self.move_to_end_of_line(state);
                Vec::new()
            }

            // Mode switching
            'i' => {
                // Enter insert mode at current cursor position
                self.copy_current_line_to_input_if_needed(state);
                vec![Action::EnterInputMode]
            }
            'a' => {
                // Enter insert mode (after cursor)
                self.copy_current_line_to_input_if_needed(state);
                self.move_cursor_right_if_possible(state);
                vec![Action::EnterInputMode]
            }
            'A' => {
                // Enter insert mode at end of line
                self.copy_current_line_to_input_if_needed(state);
                self.move_to_end_of_input(state);
                vec![Action::EnterInputMode]
            }
            'I' => {
                // Enter insert mode at beginning of line
                self.copy_current_line_to_input_if_needed(state);
                state.cursor_position = 0;
                vec![Action::EnterInputMode]
            }
            'o' => {
                // Open new line below and enter insert mode
                state.input_text.clear();
                state.cursor_position = 0;
                vec![Action::EnterInputMode]
            }
            'O' => {
                // Open new line above and enter insert mode (same as 'o' for command input)
                state.input_text.clear();
                state.cursor_position = 0;
                vec![Action::EnterInputMode]
            }

            // Command execution
            '\n' | '\r' => {
                // Execute current command (if we're on a command line)
                self.execute_current_command(state)
            }

            // Copy and edit commands
            'y' => {
                // Yank (copy) current line to input
                self.copy_current_line_to_input_if_needed(state);
                Vec::new()
            }

            // Search in history
            '/' => {
                // Start search in command history (to be implemented later)
                Vec::new()
            }

            // Escape (stay in command mode, but clear any selection)
            '\u{1b}' => {
                // Clear any visual selection or multi-char commands
                Vec::new()
            }

            // Ignore other characters in command mode
            _ => Vec::new(),
        }
    }

    /// Handle character input in Script Editor mode
    fn handle_script_mode_char(&mut self, state: &mut CommandPanelState, ch: char) -> Vec<Action> {
        use crate::components::command_panel::ScriptEditor;
        ScriptEditor::insert_char(state, ch)
    }

    /// Handle jk escape sequence for vim-like mode switching
    fn handle_jk_escape(&mut self, state: &mut CommandPanelState, ch: char) -> JkResult {
        match state.jk_escape_state {
            JkEscapeState::None => {
                if ch == 'j' {
                    state.jk_escape_state = JkEscapeState::J;
                    state.jk_timer = Some(Instant::now());
                    JkResult::WaitForK
                } else {
                    JkResult::Continue
                }
            }
            JkEscapeState::J => {
                state.jk_escape_state = JkEscapeState::None;
                state.jk_timer = None;

                if ch == 'k' {
                    JkResult::SwitchToCommand
                } else {
                    JkResult::InsertJThenChar
                }
            }
        }
    }

    /// Check for jk timeout and handle it
    pub fn check_jk_timeout(&mut self, state: &mut CommandPanelState) -> bool {
        if let JkEscapeState::J = state.jk_escape_state {
            if let Some(timer) = state.jk_timer {
                if timer.elapsed().as_millis() > self.jk_timeout_ms as u128 {
                    // Timeout - insert the pending 'j'
                    state.jk_escape_state = JkEscapeState::None;
                    state.jk_timer = None;
                    self.insert_char_at_cursor(state, 'j');
                    return true;
                }
            }
        }
        false
    }

    /// Insert character at current cursor position
    fn insert_char_at_cursor(&self, state: &mut CommandPanelState, ch: char) {
        tracing::debug!(
            "insert_char_at_cursor: inserting '{}' at cursor_pos={}, before: '{}'",
            ch,
            state.cursor_position,
            state.input_text
        );
        let byte_pos = self.char_pos_to_byte_pos(&state.input_text, state.cursor_position);
        state.input_text.insert(byte_pos, ch);
        state.cursor_position += 1;

        // Update auto suggestion after character insertion
        state.update_auto_suggestion();

        tracing::debug!(
            "insert_char_at_cursor: after insertion: '{}', cursor_pos={}",
            state.input_text,
            state.cursor_position
        );
    }

    /// Move in history (j = down, k = up) - line by line as requested
    fn move_history_down(&self, state: &mut CommandPanelState) {
        let total_lines = self.get_total_display_lines(state);
        if state.command_cursor_line + 1 < total_lines {
            state.command_cursor_line += 1;
            self.adjust_cursor_column_for_line(state);
        }
    }

    fn move_history_up(&self, state: &mut CommandPanelState) {
        if state.command_cursor_line > 0 {
            state.command_cursor_line -= 1;
            self.adjust_cursor_column_for_line(state);
        }
    }

    /// Navigate to top of history
    fn go_to_top(&self, state: &mut CommandPanelState) {
        state.command_cursor_line = 0;
        state.command_cursor_column = 0;
    }

    /// Navigate to bottom of history (current input)
    fn go_to_bottom(&self, state: &mut CommandPanelState) {
        state.command_cursor_line = self.get_total_display_lines(state).saturating_sub(1);
        self.adjust_cursor_column_for_line(state);
    }

    /// Execute command at current cursor position
    fn execute_current_command(&self, state: &mut CommandPanelState) -> Vec<Action> {
        // If we're on the current input line, submit it
        let total_lines = self.get_total_display_lines(state);
        if state.command_cursor_line + 1 >= total_lines {
            // On current input line
            if !state.input_text.trim().is_empty() {
                vec![Action::SubmitCommand]
            } else {
                Vec::new()
            }
        } else {
            // On a history line - copy it to current input
            if let Some(content) = self.get_line_content_at_cursor(state) {
                state.input_text = content;
                state.cursor_position = state.input_text.chars().count();
                vec![Action::EnterInputMode]
            } else {
                Vec::new()
            }
        }
    }

    /// Move cursor right in command mode
    fn move_cursor_right_in_command(&self, state: &mut CommandPanelState) {
        if let Some(line_content) = self.get_line_content_at_cursor(state) {
            if state.command_cursor_column < line_content.chars().count() {
                state.command_cursor_column += 1;
            }
        }
    }

    /// Move to end of current line
    fn move_to_end_of_line(&self, state: &mut CommandPanelState) {
        if let Some(line_content) = self.get_line_content_at_cursor(state) {
            state.command_cursor_column = line_content.chars().count();
        }
    }

    /// Move to end of input text
    fn move_to_end_of_input(&self, state: &mut CommandPanelState) {
        state.cursor_position = state.input_text.chars().count();
    }

    /// Move cursor right if possible
    fn move_cursor_right_if_possible(&self, state: &mut CommandPanelState) {
        let input_len = state.input_text.chars().count();
        if state.cursor_position < input_len {
            state.cursor_position += 1;
        }
    }

    /// Adjust cursor column when moving between lines
    fn adjust_cursor_column_for_line(&self, state: &mut CommandPanelState) {
        if let Some(line_content) = self.get_line_content_at_cursor(state) {
            let line_len = line_content.chars().count();
            state.command_cursor_column = state.command_cursor_column.min(line_len);
        }
    }

    /// Get content of line at current cursor position
    fn get_line_content_at_cursor(&self, state: &CommandPanelState) -> Option<String> {
        // Build the display lines structure similar to what the renderer does
        let mut display_lines = Vec::new();

        // Add command history
        for item in &state.command_history {
            // Command line - use (ghostscope) prompt for consistency
            let command_line = format!("(ghostscope) {}", item.command);
            display_lines.push(command_line);

            // Response lines (if any)
            if let Some(ref response) = item.response {
                for response_line in response.lines() {
                    display_lines.push(response_line.to_string());
                }
            }
        }

        // Current input line
        if matches!(state.input_state, InputState::Ready) {
            let prompt = "(ghostscope) ";
            let input_line = format!("{prompt}{input_text}", input_text = state.input_text);
            display_lines.push(input_line);
        }

        // Return the line at current cursor position
        display_lines.get(state.command_cursor_line).cloned()
    }

    /// Get total number of display lines
    fn get_total_display_lines(&self, state: &CommandPanelState) -> usize {
        // Calculate total lines: history + responses + current input
        let mut total = 0;

        for item in &state.command_history {
            total += 1; // Command line
            if let Some(ref response) = item.response {
                total += response.lines().count();
            }
        }

        total += 1; // Current input line
        total
    }

    /// Handle basic movement (arrow keys, etc.)
    pub fn handle_movement(
        &mut self,
        state: &mut CommandPanelState,
        direction: CursorDirection,
    ) -> Vec<Action> {
        match state.mode {
            InteractionMode::Input => self.handle_input_movement(state, direction),
            InteractionMode::Command => self.handle_command_movement(state, direction),
            InteractionMode::ScriptEditor => self.handle_script_movement(state, direction),
        }
    }

    /// Handle movement in input mode
    fn handle_input_movement(
        &self,
        state: &mut CommandPanelState,
        direction: CursorDirection,
    ) -> Vec<Action> {
        match direction {
            CursorDirection::Left => {
                if state.cursor_position > 0 {
                    state.cursor_position -= 1;
                }
            }
            CursorDirection::Right => {
                let input_len = state.input_text.chars().count();
                if state.cursor_position < input_len {
                    state.cursor_position += 1;
                }
            }
            CursorDirection::Up => {
                return self.history_up(state);
            }
            CursorDirection::Down => {
                return self.history_down(state);
            }
            CursorDirection::Home => {
                state.cursor_position = 0;
            }
            CursorDirection::End => {
                state.cursor_position = state.input_text.chars().count();
            }
        }
        Vec::new()
    }

    /// Handle movement in command mode (vim-like)
    fn handle_command_movement(
        &self,
        state: &mut CommandPanelState,
        direction: CursorDirection,
    ) -> Vec<Action> {
        match direction {
            CursorDirection::Left => {
                if state.command_cursor_column > 0 {
                    state.command_cursor_column -= 1;
                }
            }
            CursorDirection::Right => {
                self.move_cursor_right_in_command(state);
            }
            CursorDirection::Up => {
                self.move_history_up(state);
            }
            CursorDirection::Down => {
                self.move_history_down(state);
            }
            CursorDirection::Home => {
                state.command_cursor_column = 0;
            }
            CursorDirection::End => {
                self.move_to_end_of_line(state);
            }
        }
        Vec::new()
    }

    /// Handle movement in script editor mode
    fn handle_script_movement(
        &self,
        state: &mut CommandPanelState,
        direction: CursorDirection,
    ) -> Vec<Action> {
        use crate::components::command_panel::ScriptEditor;
        match direction {
            CursorDirection::Left => ScriptEditor::move_cursor_left(state),
            CursorDirection::Right => ScriptEditor::move_cursor_right(state),
            CursorDirection::Up => ScriptEditor::move_cursor_up(state),
            CursorDirection::Down => ScriptEditor::move_cursor_down(state),
            CursorDirection::Home => ScriptEditor::move_to_beginning(state),
            CursorDirection::End => ScriptEditor::move_to_end(state),
        }
    }

    /// Handle Enter key for script editor
    pub fn handle_enter(&mut self, state: &mut CommandPanelState) -> Vec<Action> {
        match state.mode {
            InteractionMode::ScriptEditor => {
                use crate::components::command_panel::ScriptEditor;
                ScriptEditor::insert_newline(state)
            }
            _ => Vec::new(), // Enter handling for other modes done elsewhere
        }
    }

    /// Handle Delete key (Ctrl+D) - delete character at cursor position
    pub fn handle_delete(&mut self, state: &mut CommandPanelState) -> Vec<Action> {
        match state.mode {
            InteractionMode::Input => {
                // Delete character at cursor position
                if state.cursor_position < state.input_text.chars().count() {
                    let chars: Vec<char> = state.input_text.chars().collect();
                    let before: String = chars[..state.cursor_position].iter().collect();
                    let after: String = chars[state.cursor_position + 1..].iter().collect();
                    state.input_text = format!("{before}{after}");
                }
                Vec::new()
            }
            InteractionMode::Command => {
                // In command mode, delete doesn't do anything
                Vec::new()
            }
            InteractionMode::ScriptEditor => {
                // Delete character in script editor
                if let Some(ref mut cache) = state.script_cache {
                    if cache.cursor_line < cache.lines.len() {
                        let line = &cache.lines[cache.cursor_line];
                        if cache.cursor_col < line.chars().count() {
                            let chars: Vec<char> = line.chars().collect();
                            let before: String = chars[..cache.cursor_col].iter().collect();
                            let after: String = chars[cache.cursor_col + 1..].iter().collect();
                            cache.lines[cache.cursor_line] = format!("{before}{after}");
                        }
                    }
                }
                Vec::new()
            }
        }
    }

    /// Handle Tab key for script editor
    pub fn handle_tab(&mut self, state: &mut CommandPanelState) -> Vec<Action> {
        match state.mode {
            InteractionMode::ScriptEditor => {
                use crate::components::command_panel::ScriptEditor;
                ScriptEditor::insert_tab(state)
            }
            _ => Vec::new(), // Tab handling for other modes done elsewhere
        }
    }

    /// Handle command submission (Enter key)
    pub fn handle_submit(&mut self, state: &mut CommandPanelState) -> Vec<Action> {
        match state.mode {
            InteractionMode::Input => {
                // Submit the current input as a command
                let command = state.input_text.clone();
                if !command.trim().is_empty() {
                    // First add the command to history
                    self.add_command_to_history(state, &command);

                    // Reset history navigation to start from newest command next time
                    state.history_index = None;

                    // Then parse and execute the command
                    use crate::components::command_panel::CommandParser;
                    let actions = CommandParser::parse_command(state, &command);

                    // Clear input after command submission
                    state.input_text.clear();
                    state.cursor_position = 0;

                    // Clear auto-suggestion since input is cleared
                    state.auto_suggestion.clear();

                    actions
                } else {
                    // Even for empty commands, clear the input line
                    state.input_text.clear();
                    state.cursor_position = 0;
                    state.auto_suggestion.clear();
                    Vec::new()
                }
            }
            InteractionMode::ScriptEditor => {
                // Enter in script editor should insert newline
                self.handle_enter(state)
            }
            InteractionMode::Command => {
                // Command mode: copy current line to input and submit
                self.copy_current_line_to_input_if_needed(state);

                let command = state.input_text.clone();
                if !command.trim().is_empty() {
                    // Switch back to input mode and submit
                    state.mode = InteractionMode::Input;
                    use crate::components::command_panel::CommandParser;
                    CommandParser::parse_command(state, &command)
                } else {
                    Vec::new()
                }
            }
        }
    }

    /// Handle history up (traditional arrow key behavior)
    fn history_up(&self, state: &mut CommandPanelState) -> Vec<Action> {
        if state.command_history.is_empty() {
            return Vec::new();
        }

        match state.history_index {
            None => {
                // First time accessing history
                if !state.input_text.is_empty() {
                    state.unsent_input_backup = Some(state.input_text.clone());
                }
                state.history_index = Some(state.command_history.len() - 1);
            }
            Some(current_index) => {
                if current_index > 0 {
                    state.history_index = Some(current_index - 1);
                }
            }
        }

        // Load the selected history item
        if let Some(index) = state.history_index {
            if let Some(item) = state.command_history.get(index) {
                state.input_text = item.command.clone();
                state.cursor_position = state.input_text.chars().count();
            }
        }

        Vec::new()
    }

    /// Handle history down (traditional arrow key behavior)
    fn history_down(&self, state: &mut CommandPanelState) -> Vec<Action> {
        match state.history_index {
            None => Vec::new(), // Not in history mode
            Some(current_index) => {
                let max_index = state.command_history.len() - 1;
                if current_index < max_index {
                    state.history_index = Some(current_index + 1);
                    if let Some(item) = state.command_history.get(current_index + 1) {
                        state.input_text = item.command.clone();
                        state.cursor_position = state.input_text.chars().count();
                    }
                } else {
                    // Reached the end of history, restore unsent input or clear
                    state.history_index = None;
                    if let Some(backup) = state.unsent_input_backup.take() {
                        state.input_text = backup;
                    } else {
                        state.input_text.clear();
                    }
                    state.cursor_position = state.input_text.chars().count();
                }
                Vec::new()
            }
        }
    }

    /// Handle backspace/delete
    pub fn handle_backspace(&mut self, state: &mut CommandPanelState) -> Vec<Action> {
        match state.mode {
            InteractionMode::Input => {
                if state.cursor_position > 0 {
                    state.cursor_position -= 1;
                    let byte_pos =
                        self.char_pos_to_byte_pos(&state.input_text, state.cursor_position);
                    if byte_pos < state.input_text.len() {
                        let mut end_pos = byte_pos + 1;
                        while end_pos < state.input_text.len()
                            && !state.input_text.is_char_boundary(end_pos)
                        {
                            end_pos += 1;
                        }
                        state.input_text.drain(byte_pos..end_pos);
                    }
                    // Update auto suggestion after character deletion
                    state.update_auto_suggestion();
                }
            }
            InteractionMode::Command => {
                // In command mode, backspace might switch back to input mode
                // For now, ignore
            }
            InteractionMode::ScriptEditor => {
                use crate::components::command_panel::ScriptEditor;
                return ScriptEditor::delete_char(state);
            }
        }
        Vec::new()
    }

    /// Utility: Convert character position to byte position
    fn char_pos_to_byte_pos(&self, text: &str, char_pos: usize) -> usize {
        text.char_indices()
            .nth(char_pos)
            .map_or(text.len(), |(pos, _)| pos)
    }

    /// Copy current history line to input if we're not on the input line
    fn copy_current_line_to_input_if_needed(&self, state: &mut CommandPanelState) {
        let total_lines = self.get_total_display_lines(state);

        // If we're not on the last line (current input), copy the current line
        if state.command_cursor_line + 1 < total_lines {
            if let Some(content) = self.get_line_content_at_cursor(state) {
                // Extract command part if it's a command line (remove prompt)
                if let Some(stripped) = content.strip_prefix("(ghostscope) ") {
                    state.input_text = stripped.to_string(); // "(ghostscope) ".len() = 13
                } else {
                    // For response lines, copy as-is (user might want to edit it as a command)
                    state.input_text = content;
                }
                state.cursor_position = state.input_text.chars().count();
            }
        }
    }

    /// Add a command to the command history
    fn add_command_to_history(&self, state: &mut CommandPanelState, command: &str) {
        use crate::model::panel_state::CommandHistoryItem;
        use std::time::Instant;

        // Add to new history manager (persistent)
        state.add_command_to_history(command);

        // Also add to old command_history for display compatibility
        let item = CommandHistoryItem {
            command: command.to_string(),
            response: None, // Will be filled when response arrives
            timestamp: Instant::now(),
            prompt: "(ghostscope) ".to_string(),
            response_type: None,
        };

        state.command_history.push(item);
        tracing::debug!(
            "add_command_to_history: Added command '{}', history length now: {}",
            command,
            state.command_history.len()
        );

        // Limit history size
        const MAX_HISTORY: usize = 1000;
        if state.command_history.len() > MAX_HISTORY {
            state.command_history.remove(0);
        }
        // Note: Renderer will display command_history directly
    }
}

impl Default for OptimizedInputHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of jk escape sequence processing
#[derive(Debug, PartialEq)]
enum JkResult {
    Continue,        // Normal processing
    WaitForK,        // 'j' was pressed, waiting for potential 'k'
    InsertJThenChar, // Insert pending 'j' then current char
    SwitchToCommand, // Switch to command mode
}

use crate::action::{Action, CursorDirection};
use crate::model::panel_state::{
    CommandPanelState, InputState, InteractionMode, JkEscapeState, LineType,
};
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::crossterm::event::KeyEvent;
use std::time::Instant;
use tracing::debug;

/// Handles input processing for the command panel
pub struct InputHandler;

impl InputHandler {
    /// Handle special key events for history and suggestions (only handles specific keys)
    pub fn handle_key_event(state: &mut CommandPanelState, key: KeyEvent) -> Vec<Action> {
        // Priority 1: History search mode handling (handles ALL keys when in search mode)
        if state.is_in_history_search() {
            return Self::handle_history_search_keys(state, key);
        }

        // Priority 2: Input mode special keys (only specific keys)
        if state.mode == InteractionMode::Input {
            match (key.code, key.modifiers) {
                // Ctrl+R: Start history search
                (KeyCode::Char('r'), KeyModifiers::CONTROL) => {
                    state.start_history_search();
                    // Return NoOp action to prevent fallback character processing
                    return vec![Action::NoOp];
                }
                // Tab or Ctrl+E: Accept auto suggestion (only if there's a suggestion)
                (KeyCode::Tab, KeyModifiers::NONE)
                | (KeyCode::Char('e'), KeyModifiers::CONTROL) => {
                    tracing::debug!(
                        "Tab/Ctrl+E pressed, suggestion available: {}",
                        state.get_suggestion_text().is_some()
                    );
                    if let Some(suggestion_text) = state.get_suggestion_text() {
                        tracing::debug!("Accepting auto suggestion: '{}'", suggestion_text);
                        state.accept_auto_suggestion();
                        // Return NoOp action to prevent fallback processing
                        return vec![Action::NoOp];
                    } else {
                        tracing::debug!("No suggestion available, Tab/Ctrl+E ignored");
                        // Return NoOp action to prevent fallback processing
                        return vec![Action::NoOp];
                    }
                }
                // Other keys are not handled by this function
                _ => {}
            }
        }

        // Return empty vector for keys we don't handle
        Vec::new()
    }

    /// Handle key events during history search mode
    fn handle_history_search_keys(state: &mut CommandPanelState, key: KeyEvent) -> Vec<Action> {
        match (key.code, key.modifiers) {
            // ESC: Exit search mode, set matched command as new input text
            (KeyCode::Esc, _) => {
                // Use the matched command if available, otherwise keep search query
                let selected_command = if let Some(matched_command) = state
                    .history_search
                    .current_match(&state.command_history_manager)
                {
                    matched_command.to_string()
                } else {
                    state.get_history_search_query().to_string()
                };

                state.exit_history_search_with_selection(&selected_command);
                vec![Action::AddResponse {
                    content: String::new(),
                    response_type: crate::action::ResponseType::Info,
                }]
            }
            // Ctrl+C: Exit search mode and clear input
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                state.exit_history_search();
                state.input_text.clear();
                state.cursor_position = 0;
                vec![Action::AddResponse {
                    content: String::new(),
                    response_type: crate::action::ResponseType::Info,
                }]
            }
            // Enter: Execute the current search result
            (KeyCode::Enter, _) => {
                // Get the command to execute (matched command if available, otherwise search query)
                let command_to_execute = if let Some(matched_command) = state
                    .history_search
                    .current_match(&state.command_history_manager)
                {
                    matched_command.to_string()
                } else {
                    state.get_history_search_query().to_string()
                };

                state.exit_history_search();

                if !command_to_execute.trim().is_empty() {
                    vec![Action::SubmitCommandWithText {
                        command: command_to_execute,
                    }]
                } else {
                    vec![Action::AddResponse {
                        content: String::new(),
                        response_type: crate::action::ResponseType::Info,
                    }]
                }
            }
            // Ctrl+R: Next search result
            (KeyCode::Char('r'), KeyModifiers::CONTROL) => {
                state.next_history_match();
                // No action needed - just move to next match
                vec![]
            }
            // Backspace: Remove character from search query
            (KeyCode::Backspace, _) => {
                let mut query = state.get_history_search_query().to_string();
                if !query.is_empty() {
                    query.pop();
                    state.update_history_search(query.clone());

                    // Update input_text to match the search query and cursor position
                    state.input_text = query.clone();
                    state.cursor_position = query.len();
                } else {
                    state.exit_history_search();
                }
                // Return NoOp action to prevent fallback to regular input handling
                vec![Action::NoOp]
            }
            // Regular characters: Add to search query
            (KeyCode::Char(c), KeyModifiers::NONE) => {
                let mut query = state.get_history_search_query().to_string();
                query.push(c);
                state.update_history_search(query.clone());

                // Update input_text to match the search query and cursor position
                state.input_text = query.clone();
                state.cursor_position = query.len();

                // Return NoOp action to prevent fallback to regular input handling
                vec![Action::NoOp]
            }
            // Other keys: Ignore during search but prevent fallback
            _ => vec![Action::NoOp],
        }
    }

    /// Insert a character at the current cursor position
    pub fn insert_char(state: &mut CommandPanelState, c: char) -> Vec<Action> {
        let mut actions = Vec::new();

        match state.mode {
            InteractionMode::Input => {
                // Handle jk escape sequence for vim-like mode switching
                let jk_result = Self::handle_jk_escape_sequence(state, c);
                match jk_result {
                    JkEscapeResult::Continue => {
                        // Reset history navigation when user starts typing new content
                        if state.history_index.is_some() {
                            state.history_index = None;
                            state.unsent_input_backup = None;
                        }

                        // Normal character insertion
                        let byte_pos =
                            Self::char_pos_to_byte_pos(&state.input_text, state.cursor_position);
                        state.input_text.insert(byte_pos, c);
                        state.cursor_position += 1;

                        // Update auto suggestion after character insertion
                        state.update_auto_suggestion();

                        actions.push(Action::AddResponse {
                            content: String::new(),
                            response_type: crate::action::ResponseType::Info,
                        });
                    }
                    JkEscapeResult::WaitForK => {
                        // Don't insert 'j' yet, just wait for potential 'k'
                        // No action needed, the timer is already set
                    }
                    JkEscapeResult::InsertPreviousJ => {
                        // Insert the previous 'j' that was held
                        let byte_pos =
                            Self::char_pos_to_byte_pos(&state.input_text, state.cursor_position);
                        state.input_text.insert(byte_pos, 'j');
                        state.cursor_position += 1;

                        // Then insert the current character
                        let byte_pos =
                            Self::char_pos_to_byte_pos(&state.input_text, state.cursor_position);
                        state.input_text.insert(byte_pos, c);
                        state.cursor_position += 1;

                        // Update auto suggestion after character insertion
                        state.update_auto_suggestion();
                    }
                    JkEscapeResult::SwitchToCommand => {
                        actions.push(Action::EnterCommandMode);
                    }
                }
            }
            InteractionMode::ScriptEditor => {
                Self::insert_char_in_script(state, c);
            }
            InteractionMode::Command => {
                // In command mode, characters might trigger navigation
                // This would be handled by command navigation logic
            }
        }

        actions
    }

    /// Delete character before cursor
    pub fn delete_char(state: &mut CommandPanelState) -> Vec<Action> {
        match state.mode {
            InteractionMode::Input => {
                if state.cursor_position > 0 {
                    state.cursor_position -= 1;
                    let byte_pos =
                        Self::char_pos_to_byte_pos(&state.input_text, state.cursor_position);
                    if byte_pos < state.input_text.len() {
                        // Find the end of the character to remove
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
            InteractionMode::ScriptEditor => {
                Self::delete_char_in_script(state);
            }
            InteractionMode::Command => {
                // Command mode doesn't support deletion
            }
        }
        Vec::new()
    }

    /// Move cursor in specified direction
    pub fn move_cursor(state: &mut CommandPanelState, direction: CursorDirection) -> Vec<Action> {
        match state.mode {
            InteractionMode::Input => match direction {
                CursorDirection::Left => Self::move_cursor_left(state),
                CursorDirection::Right => Self::move_cursor_right(state),
                CursorDirection::Up => Self::history_up(state),
                CursorDirection::Down => Self::history_down(state),
                CursorDirection::Home => Self::move_cursor_to_beginning(state),
                CursorDirection::End => Self::move_cursor_to_end(state),
            },
            InteractionMode::ScriptEditor => {
                Self::move_cursor_in_script(state, direction);
            }
            InteractionMode::Command => {
                Self::move_cursor_in_command_mode(state, direction);
            }
        }
        Vec::new()
    }

    /// Handle jk escape sequence for vim-like mode switching
    fn handle_jk_escape_sequence(state: &mut CommandPanelState, c: char) -> JkEscapeResult {
        const JK_TIMEOUT_MS: u64 = 100;

        match state.jk_escape_state {
            JkEscapeState::None => {
                if c == 'j' {
                    state.jk_escape_state = JkEscapeState::J;
                    state.jk_timer = Some(Instant::now());
                    JkEscapeResult::WaitForK
                } else {
                    JkEscapeResult::Continue
                }
            }
            JkEscapeState::J => {
                state.jk_escape_state = JkEscapeState::None;
                state.jk_timer = None;

                if c == 'k' {
                    JkEscapeResult::SwitchToCommand
                } else {
                    JkEscapeResult::InsertPreviousJ
                }
            }
        }
    }

    /// Check and handle jk timeout (should be called periodically)
    pub fn check_jk_timeout(state: &mut CommandPanelState) -> bool {
        const JK_TIMEOUT_MS: u64 = 100;

        if let JkEscapeState::J = state.jk_escape_state {
            if let Some(timer) = state.jk_timer {
                if timer.elapsed().as_millis() > JK_TIMEOUT_MS as u128 {
                    // Timeout occurred, need to insert pending 'j'
                    state.jk_escape_state = JkEscapeState::None;
                    state.jk_timer = None;

                    // Insert the pending 'j' character
                    if Self::should_show_input_prompt(state) {
                        let byte_pos =
                            Self::char_pos_to_byte_pos(&state.input_text, state.cursor_position);
                        state.input_text.insert(byte_pos, 'j');
                        state.cursor_position += 1;
                        // Update auto suggestion after timeout insertion
                        state.update_auto_suggestion();
                    }
                    return true;
                }
            }
        }
        false
    }

    fn move_cursor_left(state: &mut CommandPanelState) {
        if state.cursor_position > 0 {
            state.cursor_position -= 1;
        }
    }

    fn move_cursor_right(state: &mut CommandPanelState) {
        let input_len = state.input_text.chars().count();
        if state.cursor_position < input_len {
            state.cursor_position += 1;
        }
    }

    fn history_up(state: &mut CommandPanelState) {
        if state.command_history.is_empty() {
            return;
        }

        match state.history_index {
            None => {
                // First time accessing history, backup current input
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
    }

    fn history_down(state: &mut CommandPanelState) {
        match state.history_index {
            None => return, // Not in history mode
            Some(current_index) => {
                let max_index = state.command_history.len() - 1;
                if current_index < max_index {
                    state.history_index = Some(current_index + 1);
                    // Load the selected history item
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
            }
        }
    }

    // Script editing functions
    fn insert_char_in_script(state: &mut CommandPanelState, c: char) {
        if let Some(ref mut script) = state.script_cache {
            if script.cursor_line < script.lines.len() {
                let line = &mut script.lines[script.cursor_line];
                let byte_pos = Self::char_pos_to_byte_pos(line, script.cursor_col);
                line.insert(byte_pos, c);
                script.cursor_col += 1;
            }
        }
    }

    fn delete_char_in_script(state: &mut CommandPanelState) {
        if let Some(ref mut script) = state.script_cache {
            if script.cursor_line < script.lines.len() && script.cursor_col > 0 {
                let line = &mut script.lines[script.cursor_line];
                script.cursor_col -= 1;
                let byte_pos = Self::char_pos_to_byte_pos(line, script.cursor_col);
                if byte_pos < line.len() {
                    let mut end_pos = byte_pos + 1;
                    while end_pos < line.len() && !line.is_char_boundary(end_pos) {
                        end_pos += 1;
                    }
                    line.drain(byte_pos..end_pos);
                }
            }
        }
    }

    fn move_cursor_in_script(state: &mut CommandPanelState, direction: CursorDirection) {
        if let Some(ref mut script) = state.script_cache {
            match direction {
                CursorDirection::Left => {
                    if script.cursor_col > 0 {
                        script.cursor_col -= 1;
                    }
                }
                CursorDirection::Right => {
                    if script.cursor_line < script.lines.len() {
                        let line_len = script.lines[script.cursor_line].chars().count();
                        if script.cursor_col < line_len {
                            script.cursor_col += 1;
                        }
                    }
                }
                CursorDirection::Up => {
                    if script.cursor_line > 0 {
                        script.cursor_line -= 1;
                        let line_len = script.lines[script.cursor_line].chars().count();
                        script.cursor_col = script.cursor_col.min(line_len);
                    }
                }
                CursorDirection::Down => {
                    if script.cursor_line + 1 < script.lines.len() {
                        script.cursor_line += 1;
                        let line_len = script.lines[script.cursor_line].chars().count();
                        script.cursor_col = script.cursor_col.min(line_len);
                    }
                }
                CursorDirection::Home => {
                    script.cursor_col = 0;
                }
                CursorDirection::End => {
                    if script.cursor_line < script.lines.len() {
                        script.cursor_col = script.lines[script.cursor_line].chars().count();
                    }
                }
            }
        }
    }

    fn move_cursor_in_command_mode(state: &mut CommandPanelState, direction: CursorDirection) {
        match direction {
            CursorDirection::Left => {
                if state.command_cursor_column > 0 {
                    state.command_cursor_column -= 1;
                }
            }
            CursorDirection::Right => {
                if let Some(line) = state.static_lines.get(state.command_cursor_line) {
                    if state.command_cursor_column < line.content.len() {
                        state.command_cursor_column += 1;
                    }
                }
            }
            CursorDirection::Up => {
                if state.command_cursor_line > 0 {
                    state.command_cursor_line -= 1;
                    // Adjust column if new line is shorter
                    if let Some(line) = state.static_lines.get(state.command_cursor_line) {
                        state.command_cursor_column =
                            state.command_cursor_column.min(line.content.len());
                    }
                }
            }
            CursorDirection::Down => {
                if state.command_cursor_line + 1 < state.static_lines.len() {
                    state.command_cursor_line += 1;
                    // Adjust column if new line is shorter
                    if let Some(line) = state.static_lines.get(state.command_cursor_line) {
                        state.command_cursor_column =
                            state.command_cursor_column.min(line.content.len());
                    }
                }
            }
            CursorDirection::Home => {
                state.command_cursor_column = 0;
            }
            CursorDirection::End => {
                if let Some(line) = state.static_lines.get(state.command_cursor_line) {
                    state.command_cursor_column = line.content.len();
                }
            }
        }
    }

    // Utility functions
    fn char_pos_to_byte_pos(text: &str, char_pos: usize) -> usize {
        text.char_indices()
            .nth(char_pos)
            .map_or(text.len(), |(pos, _)| pos)
    }

    fn should_show_input_prompt(state: &CommandPanelState) -> bool {
        matches!(state.input_state, InputState::Ready)
    }

    /// Delete the previous word from the cursor position
    pub fn delete_previous_word(state: &mut CommandPanelState) -> Vec<Action> {
        if state.mode != InteractionMode::Input {
            return Vec::new();
        }

        let chars: Vec<char> = state.input_text.chars().collect();
        if state.cursor_position > 0 && !chars.is_empty() {
            let mut new_cursor = state.cursor_position;

            // Skip whitespace
            while new_cursor > 0 && chars[new_cursor - 1].is_whitespace() {
                new_cursor -= 1;
            }

            // Delete word characters
            while new_cursor > 0 && !chars[new_cursor - 1].is_whitespace() {
                new_cursor -= 1;
            }

            let start_byte = Self::char_pos_to_byte_pos(&state.input_text, new_cursor);
            let end_byte = Self::char_pos_to_byte_pos(&state.input_text, state.cursor_position);
            state.input_text.drain(start_byte..end_byte);
            state.cursor_position = new_cursor;
            // Update auto suggestion after word deletion
            state.update_auto_suggestion();
        }

        Vec::new()
    }

    /// Delete from cursor to end of line
    pub fn delete_to_end(state: &mut CommandPanelState) -> Vec<Action> {
        if state.mode != InteractionMode::Input {
            return Vec::new();
        }

        let byte_pos = Self::char_pos_to_byte_pos(&state.input_text, state.cursor_position);
        state.input_text.truncate(byte_pos);
        // Update auto suggestion after deletion to end
        state.update_auto_suggestion();

        Vec::new()
    }

    /// Delete from cursor to beginning of line
    pub fn delete_to_beginning(state: &mut CommandPanelState) -> Vec<Action> {
        if state.mode != InteractionMode::Input {
            return Vec::new();
        }

        let byte_pos = Self::char_pos_to_byte_pos(&state.input_text, state.cursor_position);
        let remaining = state.input_text[byte_pos..].to_string();
        state.input_text = remaining;
        state.cursor_position = 0;
        // Update auto suggestion after deletion to beginning
        state.update_auto_suggestion();

        Vec::new()
    }

    /// Move cursor to beginning of line
    fn move_cursor_to_beginning(state: &mut CommandPanelState) {
        state.cursor_position = 0;
    }

    /// Move cursor to end of line
    fn move_cursor_to_end(state: &mut CommandPanelState) {
        state.cursor_position = state.input_text.chars().count();
    }
}

#[derive(Debug, PartialEq)]
enum JkEscapeResult {
    Continue,
    WaitForK,
    InsertPreviousJ,
    SwitchToCommand,
}

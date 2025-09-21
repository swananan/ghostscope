use crate::action::Action;
use crate::model::panel_state::{SourcePanelMode, SourcePanelState};

/// Handles source panel navigation functionality
pub struct SourceNavigation;

impl SourceNavigation {
    /// Move cursor up
    pub fn move_up(state: &mut SourcePanelState) -> Vec<Action> {
        if state.cursor_line > 0 {
            state.cursor_line -= 1;
            Self::ensure_column_bounds(state);
        }
        Vec::new()
    }

    /// Move cursor down
    pub fn move_down(state: &mut SourcePanelState) -> Vec<Action> {
        if state.cursor_line < state.content.len().saturating_sub(1) {
            state.cursor_line += 1;
            Self::ensure_column_bounds(state);
        }
        Vec::new()
    }

    /// Move cursor left
    pub fn move_left(state: &mut SourcePanelState) -> Vec<Action> {
        if state.cursor_col > 0 {
            state.cursor_col -= 1;
        } else if state.cursor_line > 0 {
            // Move to end of previous line (last character, not newline position)
            state.cursor_line -= 1;
            if let Some(prev_line_content) = state.content.get(state.cursor_line) {
                // Jump to the last character of the previous line, not the newline position
                state.cursor_col = if prev_line_content.is_empty() {
                    0
                } else {
                    prev_line_content.chars().count().saturating_sub(1)
                };
            }
        }
        Self::ensure_column_bounds(state);
        Vec::new()
    }

    /// Move cursor right
    pub fn move_right(state: &mut SourcePanelState) -> Vec<Action> {
        if let Some(current_line_content) = state.content.get(state.cursor_line) {
            let max_column = if current_line_content.is_empty() {
                0
            } else {
                current_line_content.chars().count().saturating_sub(1)
            };

            if state.cursor_col < max_column {
                state.cursor_col += 1;
            } else if state.cursor_line < state.content.len().saturating_sub(1) {
                // Move to beginning of next line
                state.cursor_line += 1;
                state.cursor_col = 0;
            }
        }
        Self::ensure_column_bounds(state);
        Vec::new()
    }

    /// Fast move up (Page Up)
    pub fn move_up_fast(state: &mut SourcePanelState) -> Vec<Action> {
        // Note: page_size should use actual panel height, but for now use a conservative estimate
        let page_size = 10; // Conservative page size for compatibility
        state.cursor_line = state.cursor_line.saturating_sub(page_size);
        Self::ensure_column_bounds(state);
        Vec::new()
    }

    /// Fast move down (Page Down)
    pub fn move_down_fast(state: &mut SourcePanelState) -> Vec<Action> {
        // Note: page_size should use actual panel height, but for now use a conservative estimate
        let page_size = 10; // Conservative page size for compatibility
        state.cursor_line =
            (state.cursor_line + page_size).min(state.content.len().saturating_sub(1));
        Self::ensure_column_bounds(state);
        Vec::new()
    }

    /// Half page up (Ctrl+U) - move up 10 lines
    pub fn move_half_page_up(state: &mut SourcePanelState) -> Vec<Action> {
        state.cursor_line = state.cursor_line.saturating_sub(10);
        Self::ensure_column_bounds(state);
        Vec::new()
    }

    /// Half page down (Ctrl+D) - move down 10 lines
    pub fn move_half_page_down(state: &mut SourcePanelState) -> Vec<Action> {
        state.cursor_line = (state.cursor_line + 10).min(state.content.len().saturating_sub(1));
        Self::ensure_column_bounds(state);
        Vec::new()
    }

    /// Move to top of file
    pub fn move_to_top(state: &mut SourcePanelState) -> Vec<Action> {
        state.cursor_line = 0;
        state.cursor_col = 0;
        state.scroll_offset = 0;
        state.horizontal_scroll_offset = 0;
        Vec::new()
    }

    /// Move to bottom of file
    pub fn move_to_bottom(state: &mut SourcePanelState) -> Vec<Action> {
        state.cursor_line = state.content.len().saturating_sub(1);
        state.cursor_col = 0;
        Vec::new()
    }

    /// Move to next word (w key) - vim-style word movement
    pub fn move_word_forward(state: &mut SourcePanelState) -> Vec<Action> {
        if let Some(current_line) = state.content.get(state.cursor_line) {
            let chars: Vec<char> = current_line.chars().collect();
            let mut pos = state.cursor_col;

            if pos >= chars.len() {
                // At end of line, go to next line
                if state.cursor_line < state.content.len().saturating_sub(1) {
                    state.cursor_line += 1;
                    state.cursor_col = 0;
                    // Skip leading whitespace on next line
                    if let Some(next_line) = state.content.get(state.cursor_line) {
                        let next_chars: Vec<char> = next_line.chars().collect();
                        let mut next_pos = 0;
                        while next_pos < next_chars.len() && next_chars[next_pos].is_whitespace() {
                            next_pos += 1;
                        }
                        state.cursor_col = next_pos;
                    }
                }
            } else {
                // Determine current character type
                let current_char = chars[pos];

                if current_char.is_whitespace() {
                    // Skip whitespace to find next word
                    while pos < chars.len() && chars[pos].is_whitespace() {
                        pos += 1;
                    }
                } else if current_char.is_alphanumeric() || current_char == '_' {
                    // Skip current word (alphanumeric)
                    while pos < chars.len() && (chars[pos].is_alphanumeric() || chars[pos] == '_') {
                        pos += 1;
                    }
                    // Skip following whitespace
                    while pos < chars.len() && chars[pos].is_whitespace() {
                        pos += 1;
                    }
                } else {
                    // Skip current group of special characters
                    while pos < chars.len()
                        && !chars[pos].is_whitespace()
                        && !chars[pos].is_alphanumeric()
                        && chars[pos] != '_'
                    {
                        pos += 1;
                    }
                    // Skip following whitespace
                    while pos < chars.len() && chars[pos].is_whitespace() {
                        pos += 1;
                    }
                }

                // If we reached end of line, go to next line
                if pos >= chars.len() {
                    if state.cursor_line < state.content.len().saturating_sub(1) {
                        state.cursor_line += 1;
                        state.cursor_col = 0;
                        // Skip leading whitespace on next line
                        if let Some(next_line) = state.content.get(state.cursor_line) {
                            let next_chars: Vec<char> = next_line.chars().collect();
                            let mut next_pos = 0;
                            while next_pos < next_chars.len()
                                && next_chars[next_pos].is_whitespace()
                            {
                                next_pos += 1;
                            }
                            state.cursor_col = next_pos;
                        }
                    } else {
                        // Stay at end of last line
                        state.cursor_col = chars.len().saturating_sub(1).max(0);
                    }
                } else {
                    state.cursor_col = pos;
                }
            }
        }

        Self::ensure_column_bounds(state);
        Vec::new()
    }

    /// Move to previous word (b key) - vim-style word movement
    pub fn move_word_backward(state: &mut SourcePanelState) -> Vec<Action> {
        if state.cursor_col == 0 {
            // If at beginning of line, go to end of previous line
            if state.cursor_line > 0 {
                state.cursor_line -= 1;
                if let Some(prev_line) = state.content.get(state.cursor_line) {
                    if prev_line.is_empty() {
                        state.cursor_col = 0;
                    } else {
                        // Find the beginning of the last word on previous line
                        let chars: Vec<char> = prev_line.chars().collect();
                        let mut pos = chars.len().saturating_sub(1);

                        // Skip trailing whitespace
                        while pos > 0 && chars[pos].is_whitespace() {
                            pos = pos.saturating_sub(1);
                        }

                        // Move to beginning of last word
                        if chars[pos].is_alphanumeric() || chars[pos] == '_' {
                            while pos > 0
                                && (chars[pos.saturating_sub(1)].is_alphanumeric()
                                    || chars[pos.saturating_sub(1)] == '_')
                            {
                                pos = pos.saturating_sub(1);
                            }
                        } else {
                            // Special characters
                            while pos > 0
                                && !chars[pos.saturating_sub(1)].is_whitespace()
                                && !chars[pos.saturating_sub(1)].is_alphanumeric()
                                && chars[pos.saturating_sub(1)] != '_'
                            {
                                pos = pos.saturating_sub(1);
                            }
                        }

                        state.cursor_col = pos;
                    }
                }
            }
        } else if let Some(current_line) = state.content.get(state.cursor_line) {
            let chars: Vec<char> = current_line.chars().collect();
            let mut pos = state.cursor_col;

            // Move to previous character first
            pos = pos.saturating_sub(1);

            // Skip whitespace backwards
            while pos > 0 && chars[pos].is_whitespace() {
                pos = pos.saturating_sub(1);
            }

            // Check what type of character we're on
            if pos < chars.len() {
                if chars[pos].is_alphanumeric() || chars[pos] == '_' {
                    // Skip word backwards (alphanumeric)
                    while pos > 0
                        && (chars[pos.saturating_sub(1)].is_alphanumeric()
                            || chars[pos.saturating_sub(1)] == '_')
                    {
                        pos = pos.saturating_sub(1);
                    }
                } else if !chars[pos].is_whitespace() {
                    // Skip special characters backwards
                    while pos > 0
                        && !chars[pos.saturating_sub(1)].is_whitespace()
                        && !chars[pos.saturating_sub(1)].is_alphanumeric()
                        && chars[pos.saturating_sub(1)] != '_'
                    {
                        pos = pos.saturating_sub(1);
                    }
                }
            }

            state.cursor_col = pos;
        }

        Self::ensure_column_bounds(state);
        Vec::new()
    }

    /// Move to line start (^ key) - beginning of line
    pub fn move_to_line_start(state: &mut SourcePanelState) -> Vec<Action> {
        // Move to absolute beginning of line (position 0)
        state.cursor_col = 0;

        Self::ensure_column_bounds(state);
        Vec::new()
    }

    /// Move to line end ($ key)
    pub fn move_to_line_end(state: &mut SourcePanelState) -> Vec<Action> {
        if let Some(current_line) = state.content.get(state.cursor_line) {
            if current_line.is_empty() {
                state.cursor_col = 0;
            } else {
                state.cursor_col = current_line.chars().count().saturating_sub(1);
            }
        } else {
            state.cursor_col = 0;
        }

        Self::ensure_column_bounds(state);
        Vec::new()
    }

    /// Jump to specific line
    pub fn jump_to_line(state: &mut SourcePanelState, line_number: usize) -> Vec<Action> {
        if line_number > 0 && line_number <= state.content.len() {
            state.cursor_line = line_number - 1; // Convert to 0-based
            state.cursor_col = 0;
        }
        Vec::new()
    }

    /// Go to specific line (alias for jump_to_line to match Action handler)
    pub fn go_to_line(state: &mut SourcePanelState, line_number: usize) -> Vec<Action> {
        Self::jump_to_line(state, line_number)
    }

    /// Handle number input for line jumping
    pub fn handle_number_input(state: &mut SourcePanelState, ch: char) -> Vec<Action> {
        if ch.is_ascii_digit() {
            state.number_buffer.push(ch);
        }
        Vec::new()
    }

    /// Handle 'g' key for navigation
    pub fn handle_g_key(state: &mut SourcePanelState) -> Vec<Action> {
        if state.g_pressed {
            // Second 'g' - go to top
            state.g_pressed = false;
            state.number_buffer.clear();
            Self::move_to_top(state)
        } else {
            state.g_pressed = true;
            Vec::new()
        }
    }

    /// Handle 'G' key for navigation
    pub fn handle_shift_g_key(state: &mut SourcePanelState) -> Vec<Action> {
        if state.number_buffer.is_empty() {
            // Go to bottom
            Self::move_to_bottom(state)
        } else {
            // Jump to line number
            if let Ok(line_num) = state.number_buffer.parse::<usize>() {
                let result = Self::jump_to_line(state, line_num);
                state.number_buffer.clear();
                state.g_pressed = false;
                result
            } else {
                state.number_buffer.clear();
                state.g_pressed = false;
                Vec::new()
            }
        }
    }

    /// Load source file
    pub fn load_source(
        state: &mut SourcePanelState,
        file_path: String,
        highlight_line: Option<usize>,
    ) -> Vec<Action> {
        tracing::info!("wtf {file_path}");
        match std::fs::read_to_string(&file_path) {
            Ok(content) => {
                let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
                state.file_path = Some(file_path.clone());
                state.content = if lines.is_empty() {
                    vec!["// Empty file".to_string()]
                } else {
                    lines
                };

                // Detect language based on file extension
                state.language = Self::detect_language(&file_path);

                // Set cursor to highlight line or start at top
                if let Some(line) = highlight_line {
                    state.cursor_line = line.saturating_sub(1); // Convert to 0-based
                                                                // Center the view around the current line
                                                                // Note: should use actual panel height, but for now use conservative estimate
                    let estimated_half_height = 15; // Conservative estimate
                    if state.cursor_line >= estimated_half_height {
                        state.scroll_offset = state.cursor_line - estimated_half_height;
                    } else {
                        state.scroll_offset = 0;
                    }
                } else {
                    state.cursor_line = 0;
                    state.scroll_offset = 0;
                }
                state.cursor_col = 0;
                state.horizontal_scroll_offset = 0;

                // Clear search state
                state.search_query.clear();
                state.search_matches.clear();
                state.current_match = None;
                state.mode = SourcePanelMode::Normal;
            }
            Err(e) => {
                // Show error if file cannot be read
                Self::show_error(
                    state,
                    format!(
                        "Cannot read source file '{}': {}. \
                        Ensure source files are accessible at the paths recorded in debug info.",
                        file_path, e
                    ),
                );
            }
        }
        Vec::new()
    }

    /// Clear source content
    pub fn clear_source(state: &mut SourcePanelState) -> Vec<Action> {
        state.content = vec!["// No source code loaded".to_string()];
        state.file_path = None;
        state.cursor_line = 0;
        state.cursor_col = 0;
        state.scroll_offset = 0;
        state.horizontal_scroll_offset = 0;
        state.search_query.clear();
        state.search_matches.clear();
        state.current_match = None;
        state.mode = SourcePanelMode::Normal;
        Vec::new()
    }

    /// Clear all transient state (ESC behavior)
    pub fn clear_all_state(state: &mut SourcePanelState) -> Vec<Action> {
        // Clear search state
        state.search_query.clear();
        state.search_matches.clear();
        state.current_match = None;

        // Clear navigation state
        state.number_buffer.clear();
        state.expecting_g = false;
        state.g_pressed = false;

        // Return to normal mode
        state.mode = SourcePanelMode::Normal;

        Vec::new()
    }

    /// Show error message in source panel
    fn show_error(state: &mut SourcePanelState, error_message: String) {
        let (path_display, dir_display) = match &state.file_path {
            Some(p) if p != "Error" => {
                let dir = std::path::Path::new(p)
                    .parent()
                    .and_then(|d| d.to_str())
                    .unwrap_or("")
                    .to_string();
                (p.clone(), dir)
            }
            _ => ("<unknown>".to_string(), "".to_string()),
        };

        state.content = vec![
            "// Source code loading failed".to_string(),
            "//".to_string(),
            format!("// File: {}", path_display),
            if dir_display.is_empty() {
                "// Dir: <unknown>".to_string()
            } else {
                format!("// Dir: {}", dir_display)
            },
            "//".to_string(),
            format!("// Error: {}", error_message),
            "//".to_string(),
            "// To fix this issue:".to_string(),
            "// 1. Ensure the binary was compiled with debug symbols (-g flag)".to_string(),
            "// 2. Run from the directory containing source files".to_string(),
            "// 3. Check that source files are accessible".to_string(),
        ];
        state.file_path = Some("Error".to_string());
        state.cursor_line = 0;
        state.cursor_col = 0;
        state.scroll_offset = 0;
        state.horizontal_scroll_offset = 0;
    }

    /// Detect programming language from file extension
    fn detect_language(file_path: &str) -> String {
        if let Some(extension) = file_path.split('.').last() {
            match extension.to_lowercase().as_str() {
                "c" => "c".to_string(),
                "cpp" | "cc" | "cxx" | "hpp" | "hxx" => "cpp".to_string(),
                "rs" => "rust".to_string(),
                _ => "c".to_string(), // Default to C
            }
        } else {
            "c".to_string() // Default to C
        }
    }

    /// Ensure cursor is visible in the current view with vim-style scrolloff
    pub fn ensure_cursor_visible(state: &mut SourcePanelState, panel_height: u16) {
        let visible_lines = panel_height.saturating_sub(2) as usize; // Account for borders
        let total_lines = state.content.len();

        if visible_lines == 0 || total_lines == 0 {
            return;
        }

        // Calculate dynamic scrolloff: 1/5 of visible lines, min 2, max 5
        let vertical_scrolloff = (visible_lines / 5).max(2).min(5);

        // Calculate cursor position relative to current scroll
        let cursor_in_view = state.cursor_line.saturating_sub(state.scroll_offset);

        // Check if cursor is too close to top edge
        if cursor_in_view < vertical_scrolloff && state.scroll_offset > 0 {
            // Move scroll up to give cursor more space
            state.scroll_offset = state.cursor_line.saturating_sub(vertical_scrolloff);
        }
        // Check if cursor is too close to bottom edge
        else if cursor_in_view >= visible_lines.saturating_sub(vertical_scrolloff) {
            // Move scroll down to give cursor more space
            let target_pos = visible_lines.saturating_sub(vertical_scrolloff + 1);
            state.scroll_offset = state.cursor_line.saturating_sub(target_pos);
        }

        // Handle edge cases and bounds checking
        let max_scroll = total_lines.saturating_sub(visible_lines);
        state.scroll_offset = state.scroll_offset.min(max_scroll);

        // Special handling for beginning of file
        if state.cursor_line < vertical_scrolloff {
            state.scroll_offset = 0;
        }

        // Special handling for end of file - try to show as much content as possible
        if state.cursor_line >= total_lines.saturating_sub(vertical_scrolloff)
            && total_lines > visible_lines
        {
            // Near end of file, but still maintain some scrolloff if possible
            let lines_after_cursor = total_lines.saturating_sub(state.cursor_line + 1);
            if lines_after_cursor < vertical_scrolloff {
                // At the very end, show as much as possible
                state.scroll_offset = max_scroll;
            }
        }
    }

    /// Ensure cursor column is within line bounds (prevent cursor on newline)
    fn ensure_column_bounds(state: &mut SourcePanelState) {
        if let Some(current_line) = state.content.get(state.cursor_line) {
            if current_line.is_empty() {
                // Empty line, stay at column 0
                state.cursor_col = 0;
            } else {
                // Ensure column is within bounds, but prefer last character over newline position
                let max_column = current_line.chars().count().saturating_sub(1); // Last character position
                if state.cursor_col > max_column {
                    state.cursor_col = max_column;
                }
            }
        }
    }

    /// Ensure horizontal cursor is visible
    pub fn ensure_horizontal_cursor_visible(state: &mut SourcePanelState, panel_width: u16) {
        if let Some(current_line_content) = state.content.get(state.cursor_line) {
            // Use the same calculation as renderer for consistency
            const LINE_NUMBER_WIDTH: u16 = 5; // "1234 " format
            const BORDER_WIDTH: u16 = 2; // left and right borders

            let available_width =
                (panel_width.saturating_sub(LINE_NUMBER_WIDTH + BORDER_WIDTH)) as usize;

            if available_width == 0 {
                return; // Avoid division by zero or invalid calculations
            }

            let line_char_count = current_line_content.chars().count();
            let old_scroll_offset = state.horizontal_scroll_offset;

            // Apply vim-style scrolloff regardless of line length
            let horizontal_scrolloff = (available_width / 4).max(3).min(8); // Dynamic scrolloff, 3-8 chars

            // Calculate cursor position relative to current scroll
            let cursor_in_view = state
                .cursor_col
                .saturating_sub(state.horizontal_scroll_offset);

            // Check if cursor is too close to left edge
            if cursor_in_view < horizontal_scrolloff && state.cursor_col >= horizontal_scrolloff {
                // Move scroll left to give cursor more space
                state.horizontal_scroll_offset =
                    state.cursor_col.saturating_sub(horizontal_scrolloff);
            }
            // Check if cursor is too close to right edge
            else if cursor_in_view + horizontal_scrolloff >= available_width {
                // Move scroll right to give cursor more space
                let target_pos = available_width.saturating_sub(horizontal_scrolloff + 1);
                state.horizontal_scroll_offset = state.cursor_col.saturating_sub(target_pos);
            }

            // Ensure we don't scroll beyond reasonable bounds if line is shorter
            if line_char_count <= available_width && state.horizontal_scroll_offset > 0 {
                // Line fits entirely but we have scrolled - only allow minimal scroll for short lines
                let max_scroll_for_short_line =
                    line_char_count.saturating_sub(available_width / 2).max(0);
                state.horizontal_scroll_offset = state
                    .horizontal_scroll_offset
                    .min(max_scroll_for_short_line);
            }

            // Ensure we don't scroll before the beginning
            if state.cursor_col < horizontal_scrolloff {
                state.horizontal_scroll_offset = 0;
            } else if state.horizontal_scroll_offset > state.cursor_col {
                // If scroll went beyond cursor position, adjust
                state.horizontal_scroll_offset =
                    state.cursor_col.saturating_sub(horizontal_scrolloff);
            }

            // Final boundary check - ensure cursor is visible
            if state.cursor_col < state.horizontal_scroll_offset {
                state.horizontal_scroll_offset = state.cursor_col;
            } else if state.cursor_col >= state.horizontal_scroll_offset + available_width {
                state.horizontal_scroll_offset =
                    state.cursor_col.saturating_sub(available_width - 1);
            }
        }
    }
}

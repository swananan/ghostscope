use crate::action::Action;
use crate::model::panel_state::{SourcePanelMode, SourcePanelState};

/// Handles source panel search functionality
pub struct SourceSearch;

impl SourceSearch {
    /// Enter text search mode
    pub fn enter_search_mode(state: &mut SourcePanelState) -> Vec<Action> {
        state.mode = SourcePanelMode::TextSearch;
        state.search_query.clear();
        state.search_matches.clear();
        state.current_match = None;
        Vec::new()
    }

    /// Exit search mode
    pub fn exit_search_mode(state: &mut SourcePanelState) -> Vec<Action> {
        state.mode = SourcePanelMode::Normal;
        state.search_query.clear();
        state.search_matches.clear();
        state.current_match = None;
        Vec::new()
    }

    /// Add character to search query
    pub fn push_search_char(state: &mut SourcePanelState, ch: char) -> Vec<Action> {
        if state.mode == SourcePanelMode::TextSearch {
            state.search_query.push(ch);
            Self::update_search_matches(state);
            // Auto-jump to first match as user types
            if !state.search_matches.is_empty() {
                state.current_match = Some(0);
                Self::jump_to_match(state, 0);
            }
        }
        Vec::new()
    }

    /// Remove character from search query
    pub fn backspace_search(state: &mut SourcePanelState) -> Vec<Action> {
        if state.mode == SourcePanelMode::TextSearch {
            state.search_query.pop();
            Self::update_search_matches(state);
            // Auto-jump to first match after backspace
            if !state.search_matches.is_empty() {
                state.current_match = Some(0);
                Self::jump_to_match(state, 0);
            } else {
                state.current_match = None;
            }
        }
        Vec::new()
    }

    /// Confirm search and keep highlights visible (like vim)
    pub fn confirm_search(state: &mut SourcePanelState) -> Vec<Action> {
        if state.mode == SourcePanelMode::TextSearch {
            // Exit search input mode but keep matches highlighted
            state.mode = SourcePanelMode::Normal;

            // If we have matches, stay at current match or go to first
            if !state.search_matches.is_empty() && state.current_match.is_none() {
                state.current_match = Some(0);
                Self::jump_to_match(state, 0);
            }
        }
        Vec::new()
    }

    /// Move to next search match (wraps to first when at last)
    pub fn next_match(state: &mut SourcePanelState) -> Vec<Action> {
        if !state.search_matches.is_empty() {
            let current = state.current_match.unwrap_or(0);
            let next = (current + 1) % state.search_matches.len();
            state.current_match = Some(next);
            Self::jump_to_match(state, next);

            // Show wrap-around message if we went from last to first
            if current == state.search_matches.len() - 1 && next == 0 {
                tracing::info!("Search wrapped to top");
            }
        }
        Vec::new()
    }

    /// Move to previous search match (wraps to last when at first)
    pub fn prev_match(state: &mut SourcePanelState) -> Vec<Action> {
        if !state.search_matches.is_empty() {
            let current = state.current_match.unwrap_or(0);
            let prev = if current == 0 {
                state.search_matches.len() - 1
            } else {
                current - 1
            };
            state.current_match = Some(prev);
            Self::jump_to_match(state, prev);

            // Show wrap-around message if we went from first to last
            if current == 0 && prev == state.search_matches.len() - 1 {
                tracing::info!("Search wrapped to bottom");
            }
        }
        Vec::new()
    }

    /// Enter file search mode
    pub fn enter_file_search_mode(state: &mut SourcePanelState) -> Vec<Action> {
        state.mode = SourcePanelMode::FileSearch;
        state.file_search_query.clear();
        state.file_search_cursor_pos = 0;
        state.file_search_results.clear();
        state.file_search_filtered_indices.clear();
        state.file_search_selected = 0;
        state.file_search_scroll = 0;
        state.file_search_message = Some("Loading files...".to_string());
        Vec::new()
    }

    /// Exit file search mode
    pub fn exit_file_search_mode(state: &mut SourcePanelState) -> Vec<Action> {
        state.mode = SourcePanelMode::Normal;
        state.file_search_query.clear();
        state.file_search_cursor_pos = 0;
        state.file_search_results.clear();
        state.file_search_filtered_indices.clear();
        state.file_search_selected = 0;
        state.file_search_scroll = 0;
        state.file_search_message = None;
        Vec::new()
    }

    /// Add character to file search query
    pub fn push_file_search_char(state: &mut SourcePanelState, ch: char) -> Vec<Action> {
        if state.mode == SourcePanelMode::FileSearch {
            let mut chars: Vec<char> = state.file_search_query.chars().collect();
            chars.insert(state.file_search_cursor_pos, ch);
            state.file_search_query = chars.into_iter().collect();
            state.file_search_cursor_pos += 1;
            Self::update_file_search_results(state);
        }
        Vec::new()
    }

    /// Remove character from file search query
    pub fn backspace_file_search(state: &mut SourcePanelState) -> Vec<Action> {
        if state.mode == SourcePanelMode::FileSearch && state.file_search_cursor_pos > 0 {
            let mut chars: Vec<char> = state.file_search_query.chars().collect();
            chars.remove(state.file_search_cursor_pos - 1);
            state.file_search_query = chars.into_iter().collect();
            state.file_search_cursor_pos -= 1;
            Self::update_file_search_results(state);
        }
        Vec::new()
    }

    /// Clear entire file search query (Ctrl+U)
    pub fn clear_file_search_query(state: &mut SourcePanelState) -> Vec<Action> {
        if state.mode == SourcePanelMode::FileSearch {
            state.file_search_query.clear();
            state.file_search_cursor_pos = 0;
            Self::update_file_search_results(state);
        }
        Vec::new()
    }

    /// Delete previous word from file search query (Ctrl+W)
    pub fn delete_word_file_search(state: &mut SourcePanelState) -> Vec<Action> {
        if state.mode == SourcePanelMode::FileSearch && state.file_search_cursor_pos > 0 {
            let chars: Vec<char> = state.file_search_query.chars().collect();
            let mut start_pos = state.file_search_cursor_pos;

            // Define word separators for file paths (include whitespace and path separators)
            let is_separator = |c: char| {
                c.is_whitespace() || c == '/' || c == '\\' || c == '.' || c == '-' || c == '_'
            };

            // Skip trailing separators backwards from cursor
            while start_pos > 0 && is_separator(chars[start_pos - 1]) {
                start_pos -= 1;
            }

            // Delete word characters backwards (until we hit a separator)
            while start_pos > 0 && !is_separator(chars[start_pos - 1]) {
                start_pos -= 1;
            }

            // Create new string by combining before start_pos and after cursor_pos
            let mut new_chars = chars[..start_pos].to_vec();
            new_chars.extend_from_slice(&chars[state.file_search_cursor_pos..]);

            state.file_search_query = new_chars.into_iter().collect();
            state.file_search_cursor_pos = start_pos;
            Self::update_file_search_results(state);
        }
        Vec::new()
    }

    /// Move cursor to beginning of search query (Ctrl+A)
    pub fn move_cursor_to_start(state: &mut SourcePanelState) -> Vec<Action> {
        if state.mode == SourcePanelMode::FileSearch {
            state.file_search_cursor_pos = 0;
        }
        Vec::new()
    }

    /// Move cursor to end of search query (Ctrl+E)
    pub fn move_cursor_to_end(state: &mut SourcePanelState) -> Vec<Action> {
        if state.mode == SourcePanelMode::FileSearch {
            state.file_search_cursor_pos = state.file_search_query.chars().count();
        }
        Vec::new()
    }

    /// Move cursor left one character (Ctrl+B)
    pub fn move_cursor_left(state: &mut SourcePanelState) -> Vec<Action> {
        if state.mode == SourcePanelMode::FileSearch && state.file_search_cursor_pos > 0 {
            state.file_search_cursor_pos -= 1;
        }
        Vec::new()
    }

    /// Move cursor right one character (Ctrl+F)
    pub fn move_cursor_right(state: &mut SourcePanelState) -> Vec<Action> {
        if state.mode == SourcePanelMode::FileSearch {
            let max_pos = state.file_search_query.chars().count();
            if state.file_search_cursor_pos < max_pos {
                state.file_search_cursor_pos += 1;
            }
        }
        Vec::new()
    }

    /// Move file search selection up
    pub fn move_file_search_up(state: &mut SourcePanelState) -> Vec<Action> {
        if state.mode == SourcePanelMode::FileSearch
            && !state.file_search_filtered_indices.is_empty()
        {
            if state.file_search_selected > 0 {
                state.file_search_selected -= 1;
            } else {
                state.file_search_selected = state.file_search_filtered_indices.len() - 1;
            }
            Self::ensure_file_search_visible(state);
        }
        Vec::new()
    }

    /// Move file search selection down
    pub fn move_file_search_down(state: &mut SourcePanelState) -> Vec<Action> {
        if state.mode == SourcePanelMode::FileSearch
            && !state.file_search_filtered_indices.is_empty()
        {
            state.file_search_selected =
                (state.file_search_selected + 1) % state.file_search_filtered_indices.len();
            Self::ensure_file_search_visible(state);
        }
        Vec::new()
    }

    /// Confirm file search selection
    pub fn confirm_file_search(state: &mut SourcePanelState) -> Option<String> {
        if state.mode == SourcePanelMode::FileSearch
            && !state.file_search_filtered_indices.is_empty()
        {
            let real_idx = state.file_search_filtered_indices[state.file_search_selected];
            let selected_file = state.file_search_results.get(real_idx).cloned();
            Self::exit_file_search_mode(state);
            selected_file
        } else {
            None
        }
    }

    /// Set file search results
    pub fn set_file_search_files(state: &mut SourcePanelState, files: Vec<String>) -> Vec<Action> {
        state.file_search_results = files;
        state.file_search_message = None;
        Self::update_file_search_results(state);
        Vec::new()
    }

    /// Set file search error
    pub fn set_file_search_error(state: &mut SourcePanelState, error: String) -> Vec<Action> {
        state.file_search_message = Some(format!("✗ {error}"));
        state.file_search_results.clear();
        state.file_search_filtered_indices.clear();
        Vec::new()
    }

    /// Update search matches based on current query
    fn update_search_matches(state: &mut SourcePanelState) {
        let old_cursor_line = state.cursor_line;
        let old_cursor_col = state.cursor_col;

        state.search_matches.clear();
        state.current_match = None;

        if state.search_query.is_empty() {
            return;
        }

        let query = state.search_query.to_lowercase();
        for (line_idx, line) in state.content.iter().enumerate() {
            let line_lower = line.to_lowercase();
            let mut start = 0;
            while let Some(pos) = line_lower[start..].find(&query) {
                let match_start = start + pos;
                let match_end = match_start + query.len();
                state
                    .search_matches
                    .push((line_idx, match_start, match_end));
                start = match_start + 1;
            }
        }

        // Find the first match at or after current cursor position
        if !state.search_matches.is_empty() {
            let mut best_match = 0;
            for (idx, (line_idx, col_start, _)) in state.search_matches.iter().enumerate() {
                if *line_idx > old_cursor_line
                    || (*line_idx == old_cursor_line && *col_start >= old_cursor_col)
                {
                    best_match = idx;
                    break;
                }
            }
            state.current_match = Some(best_match);
        }
    }

    /// Jump to specific match
    fn jump_to_match(state: &mut SourcePanelState, match_idx: usize) {
        if let Some((line_idx, col_start, _)) = state.search_matches.get(match_idx) {
            state.cursor_line = *line_idx;
            state.cursor_col = *col_start; // Move cursor to match position

            // Ensure cursor is visible vertically
            // Note: should use actual panel height, but for now use conservative estimate
            let visible_lines = 30; // Conservative estimate
            if state.cursor_line < state.scroll_offset {
                state.scroll_offset = state.cursor_line;
            } else if state.cursor_line >= state.scroll_offset + visible_lines {
                state.scroll_offset = state
                    .cursor_line
                    .saturating_sub(visible_lines.saturating_sub(1));
            }

            // Ensure cursor is visible horizontally
            if let Some(current_line) = state.content.get(state.cursor_line) {
                let line_number_width = 5; // "1234 " format
                let border_width = 2; // left and right borders
                let available_width = (state
                    .area_width
                    .saturating_sub(line_number_width + border_width))
                    as usize;

                if current_line.len() <= available_width {
                    // Line fits entirely, no horizontal scrolling needed
                    state.horizontal_scroll_offset = 0;
                } else {
                    // Line is longer than available width, need horizontal scrolling
                    let scrolloff = available_width / 3; // Keep some context around cursor

                    // Calculate ideal horizontal scroll position to center match
                    let ideal_scroll = state.cursor_col.saturating_sub(scrolloff);

                    // Calculate maximum possible scroll
                    let max_scroll = current_line.len().saturating_sub(available_width);

                    // Check if we're near the end of the line
                    let near_end = state.cursor_col >= max_scroll.saturating_add(scrolloff);

                    if near_end {
                        // Near the end, scroll to show the end
                        state.horizontal_scroll_offset = max_scroll;
                    } else {
                        // Normal case, scroll to keep cursor visible with context
                        state.horizontal_scroll_offset = ideal_scroll.min(max_scroll);
                    }
                }
            }
        }
    }

    /// Update file search filtered results based on query
    fn update_file_search_results(state: &mut SourcePanelState) {
        state.file_search_filtered_indices.clear();
        state.file_search_selected = 0;
        state.file_search_scroll = 0;

        if state.file_search_query.is_empty() {
            // Show all files
            state.file_search_filtered_indices = (0..state.file_search_results.len()).collect();
        } else {
            // Filter files based on query
            let query = state.file_search_query.to_lowercase();
            for (idx, file) in state.file_search_results.iter().enumerate() {
                if file.to_lowercase().contains(&query) {
                    state.file_search_filtered_indices.push(idx);
                }
            }
        }
    }

    /// Ensure file search selection is visible
    fn ensure_file_search_visible(state: &mut SourcePanelState) {
        let visible_count = 10; // Show up to 10 files

        if state.file_search_selected < state.file_search_scroll {
            state.file_search_scroll = state.file_search_selected;
        } else if state.file_search_selected >= state.file_search_scroll + visible_count {
            state.file_search_scroll = state.file_search_selected.saturating_sub(visible_count - 1);
        }
    }
}

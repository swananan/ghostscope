use crate::syntax_highlight::SyntaxHighlighter;
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem},
    Frame,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcePanelMode {
    Normal,
    TextSearch,
    FileSearch,
}

pub struct SourceCodePanel {
    pub content: Vec<String>,
    pub current_line: usize,
    pub current_column: usize, // Add horizontal cursor position
    pub scroll_offset: usize,
    pub horizontal_scroll_offset: usize, // Add horizontal scroll offset
    pub file_path: Option<String>,
    pub area_height: u16, // Store the current area height for scroll calculations
    pub area_width: u16,  // Store the current area width for horizontal scroll calculations
    pub language: String, // Programming language for syntax highlighting
    pub syntax_highlighter: SyntaxHighlighter,

    pub number_buffer: String, // Buffer for collecting numbers before 'g'
    pub expecting_g: bool,     // Whether we're expecting a 'g' after numbers
    pub g_pressed: bool,       // Whether 'g' was pressed (for 'gg' combination)

    // Mode state
    pub mode: SourcePanelMode,
    pub search_query: String,
    pub search_matches: Vec<(usize, usize, usize)>, // (line_idx, start, end)
    pub current_match_index: Option<usize>,

    // File search (quick open) state
    pub file_search_query: String,
    pub file_search_files: Vec<String>,
    pub file_search_filtered_indices: Vec<usize>,
    pub file_search_selected: usize,
    pub file_search_message: Option<String>,
    pub file_search_scroll: usize,
}

impl SourceCodePanel {
    pub fn new() -> Self {
        Self {
            content: vec!["// No source code loaded".to_string()],
            current_line: 0,
            current_column: 0,
            scroll_offset: 0,
            horizontal_scroll_offset: 0,
            file_path: None,
            area_height: 10,           // Default height
            area_width: 80,            // Default width
            language: "c".to_string(), // Default to C
            syntax_highlighter: SyntaxHighlighter::new(),
            number_buffer: String::new(),
            expecting_g: false,
            g_pressed: false,
            mode: SourcePanelMode::Normal,
            search_query: String::new(),
            search_matches: Vec::new(),
            current_match_index: None,
            file_search_query: String::new(),
            file_search_files: Vec::new(),
            file_search_filtered_indices: Vec::new(),
            file_search_selected: 0,
            file_search_message: None,
            file_search_scroll: 0,
        }
    }

    pub fn load_source(&mut self, file_path: String, highlight_line: Option<usize>) {
        // Try to read the file
        match std::fs::read_to_string(&file_path) {
            Ok(content) => {
                let lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
                self.file_path = Some(file_path.clone());
                self.content = lines;

                // Detect language based on file extension
                self.language = self.detect_language(&file_path);

                // Set cursor to highlight line or start at top
                if let Some(line) = highlight_line {
                    self.current_line = line.saturating_sub(1); // Convert to 0-based
                                                                // Center the view around the current line
                    if self.current_line >= self.area_height as usize / 2 {
                        self.scroll_offset = self.current_line - self.area_height as usize / 2;
                    } else {
                        self.scroll_offset = 0;
                    }
                } else {
                    self.current_line = 0;
                    self.scroll_offset = 0;
                }
                self.current_column = 0;
                self.horizontal_scroll_offset = 0;
                self.clear_search_state();
            }
            Err(e) => {
                // Show error if file cannot be read
                self.show_error(format!(
                    "Cannot read source file '{}': {}. \
                    Ensure source files are accessible at the paths recorded in debug info.",
                    file_path, e
                ));
            }
        }
    }

    fn detect_language(&self, file_path: &str) -> String {
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

    fn highlight_line(&self, line: &str) -> Vec<Span> {
        let tokens = self.syntax_highlighter.highlight_line(line, &self.language);
        let mut spans = Vec::new();
        let mut current_pos = 0;

        for token in tokens {
            // Add any characters that come before this token
            if token.start > current_pos {
                let normal_text = &line[current_pos..token.start];
                if !normal_text.is_empty() {
                    spans.push(Span::styled(normal_text.to_string(), Style::default()));
                }
            }

            // Add the token with its style
            let style = self.syntax_highlighter.get_token_style(&token.token_type);
            spans.push(Span::styled(token.text.clone(), style));

            current_pos = token.end;
        }

        // Add any remaining characters after the last token
        if current_pos < line.len() {
            let remaining_text = &line[current_pos..];
            if !remaining_text.is_empty() {
                spans.push(Span::styled(remaining_text.to_string(), Style::default()));
            }
        }

        spans
    }

    pub fn clear_source(&mut self) {
        self.content = vec!["// No source code loaded".to_string()];
        self.file_path = None;
        self.current_line = 0;
        self.current_column = 0;
        self.scroll_offset = 0;
        self.horizontal_scroll_offset = 0;
        self.clear_search_state();
    }

    pub fn show_error(&mut self, error_message: String) {
        let (path_display, dir_display) = match &self.file_path {
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
        self.content = vec![
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
        self.file_path = Some("Error".to_string());
        self.current_line = 0;
        self.current_column = 0;
        self.scroll_offset = 0;
        self.horizontal_scroll_offset = 0;
        self.clear_search_state();
    }

    pub fn move_up(&mut self) {
        if self.current_line > 0 {
            let old_column = self.current_column;
            self.current_line -= 1;
            self.adjust_column_for_new_line(old_column);
            self.ensure_cursor_visible();
        }
    }

    pub fn move_down(&mut self) {
        if self.current_line + 1 < self.content.len() {
            let old_column = self.current_column;
            self.current_line += 1;
            self.adjust_column_for_new_line(old_column);
            self.ensure_cursor_visible();
        }
    }

    pub fn move_up_fast(&mut self) {
        let new_line = self.current_line.saturating_sub(10);
        self.current_line = new_line;
        self.ensure_column_bounds();
        self.ensure_cursor_visible();
    }

    pub fn move_down_fast(&mut self) {
        let new_line = (self.current_line + 10).min(self.content.len().saturating_sub(1));
        self.current_line = new_line;
        self.ensure_column_bounds();
        self.ensure_cursor_visible();
    }

    pub fn move_to_top(&mut self) {
        self.current_line = 0;
        self.current_column = 0;
        self.scroll_offset = 0;
        self.horizontal_scroll_offset = 0;
    }

    pub fn move_to_bottom(&mut self) {
        if !self.content.is_empty() {
            self.current_line = self.content.len() - 1;
            self.current_column = 0;
            self.ensure_cursor_visible();
        }
    }

    // ===== Search features (vim-like) =====
    pub fn enter_search_mode(&mut self) {
        self.mode = SourcePanelMode::TextSearch;
        self.search_query.clear();
        self.search_matches.clear();
        self.current_match_index = None;
    }

    pub fn exit_search_mode(&mut self) {
        if self.mode == SourcePanelMode::TextSearch {
            self.mode = SourcePanelMode::Normal;
        }
    }

    pub fn clear_search_state(&mut self) {
        self.mode = SourcePanelMode::Normal;
        self.search_query.clear();
        self.search_matches.clear();
        self.current_match_index = None;
        // clear file search transient state too
        self.file_search_query.clear();
        self.file_search_filtered_indices.clear();
        self.file_search_selected = 0;
        self.file_search_message = None;
        self.file_search_scroll = 0;
        self.file_search_files.clear();
    }

    pub fn push_search_char(&mut self, ch: char) {
        self.search_query.push(ch);
        self.update_search_matches();
        self.jump_to_first_match_if_any();
    }

    pub fn backspace_search(&mut self) {
        self.search_query.pop();
        self.update_search_matches();
        self.jump_to_first_match_if_any();
    }

    pub fn confirm_search(&mut self) {
        // Leave input mode but keep highlights
        self.exit_search_mode();
    }

    pub fn next_match(&mut self) {
        if self.search_matches.is_empty() {
            return;
        }
        let next_index = match self.current_match_index {
            Some(idx) => (idx + 1) % self.search_matches.len(),
            None => 0,
        };
        self.goto_match_index(next_index);
    }

    pub fn prev_match(&mut self) {
        if self.search_matches.is_empty() {
            return;
        }
        let prev_index = match self.current_match_index {
            Some(0) | None => self.search_matches.len().saturating_sub(1),
            Some(idx) => idx - 1,
        };
        self.goto_match_index(prev_index);
    }

    fn goto_match_index(&mut self, index: usize) {
        if let Some((line, start, _)) = self.search_matches.get(index).cloned() {
            self.current_line = line;
            self.current_column = start;
            self.ensure_cursor_visible();
            self.current_match_index = Some(index);
        }
    }

    fn jump_to_first_match_if_any(&mut self) {
        if !self.search_matches.is_empty() {
            self.goto_match_index(0);
        } else {
            self.current_match_index = None;
        }
    }

    fn update_search_matches(&mut self) {
        self.search_matches.clear();
        self.current_match_index = None;
        if self.search_query.is_empty() {
            return;
        }
        for (li, line) in self.content.iter().enumerate() {
            let mut start = 0usize;
            while let Some(pos) = line[start..].find(&self.search_query) {
                let s = start + pos;
                let e = s + self.search_query.len();
                self.search_matches.push((li, s, e));
                start = e.max(s + 1);
            }
        }
        if !self.search_matches.is_empty() {
            // Prefer first match at or after current cursor
            let mut selected = 0usize;
            for (idx, (li, col_s, _)) in self.search_matches.iter().enumerate() {
                if *li > self.current_line
                    || (*li == self.current_line && *col_s >= self.current_column)
                {
                    selected = idx;
                    break;
                }
            }
            self.current_match_index = Some(selected);
        }
    }

    fn search_styles(&self) -> (Style, Style, Style) {
        // Fixed scheme per user request:
        // '/' purple (magenta), query cyan, highlight: bright pink fg, no bg
        let slash_style = Style::default().fg(Color::Magenta);
        let query_style = Style::default().fg(Color::Cyan);
        let overlay_style = Style::default().fg(Color::LightMagenta);
        (slash_style, query_style, overlay_style)
    }

    // ===== File Search (quick-open) =====
    pub fn enter_file_search_mode(&mut self) {
        self.mode = SourcePanelMode::FileSearch;
        self.file_search_query.clear();
        self.file_search_filtered_indices.clear();
        self.file_search_selected = 0;
        self.file_search_message = Some("Loading files…".to_string());
        self.file_search_scroll = 0;
    }

    pub fn is_in_text_search_mode(&self) -> bool {
        self.mode == SourcePanelMode::TextSearch
    }
    pub fn is_in_file_search_mode(&self) -> bool {
        self.mode == SourcePanelMode::FileSearch
    }

    pub fn set_file_search_files(&mut self, files: Vec<String>) {
        self.file_search_files = files;
        self.file_search_message = None;
        self.update_file_search_filter();
    }

    /// Ingest grouped SourceFileInfo and build a deduplicated full-path list for quick-open
    pub fn ingest_file_info_groups(&mut self, groups: &[crate::events::SourceFileGroup]) {
        let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for g in groups {
            for f in &g.files {
                let full = std::path::Path::new(&f.directory)
                    .join(&f.path)
                    .to_string_lossy()
                    .to_string();
                set.insert(full);
            }
        }
        self.set_file_search_files(set.into_iter().collect());
    }

    pub fn set_file_search_error(&mut self, error: String) {
        self.file_search_message = Some(format!("✗ {}", error));
    }

    pub fn push_file_search_char(&mut self, ch: char) {
        self.file_search_query.push(ch);
        self.update_file_search_filter();
        self.file_search_selected = 0;
        self.ensure_file_search_cursor_visible();
    }

    pub fn backspace_file_search(&mut self) {
        self.file_search_query.pop();
        self.update_file_search_filter();
        self.file_search_selected = 0;
        self.ensure_file_search_cursor_visible();
    }

    pub fn move_file_search_up(&mut self) {
        if self.file_search_filtered_indices.is_empty() {
            return;
        }
        if self.file_search_selected > 0 {
            self.file_search_selected -= 1;
        } else {
            // At top, wrap to bottom
            self.file_search_selected = self.file_search_filtered_indices.len() - 1;
        }
        self.ensure_file_search_cursor_visible();
    }

    pub fn move_file_search_down(&mut self) {
        if self.file_search_filtered_indices.is_empty() {
            return;
        }
        if self.file_search_selected + 1 < self.file_search_filtered_indices.len() {
            self.file_search_selected += 1;
        } else {
            // At bottom, wrap to top
            self.file_search_selected = 0;
        }
        self.ensure_file_search_cursor_visible();
    }

    pub fn confirm_file_search(&mut self) -> Option<String> {
        if self.file_search_filtered_indices.is_empty() {
            return None;
        }
        let idx = self.file_search_filtered_indices[self.file_search_selected];
        self.file_search_files.get(idx).cloned()
    }

    pub fn exit_file_search_mode(&mut self) {
        if self.mode == SourcePanelMode::FileSearch {
            self.mode = SourcePanelMode::Normal;
        }
        self.file_search_query.clear();
        self.file_search_filtered_indices.clear();
        self.file_search_selected = 0;
        self.file_search_message = None;
        self.file_search_scroll = 0;
        // Also clear the file list to ensure no residual data
        self.file_search_files.clear();
    }

    fn update_file_search_filter(&mut self) {
        self.file_search_filtered_indices.clear();
        let q = self.file_search_query.to_lowercase();
        let mut indexed: Vec<(usize, i32, usize)> = Vec::new();
        for (i, path) in self.file_search_files.iter().enumerate() {
            let path_lower = path.to_lowercase();
            if q.is_empty() {
                // When no query, default to alphabetical by full path
                indexed.push((i, 0, 0));
            } else if let Some(pos) = path_lower.find(&q) {
                let file_name = std::path::Path::new(path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or(path);
                let file_lower = file_name.to_lowercase();
                let name_hit = file_lower.find(&q).is_some();
                let name_len = file_name.len();
                let score_primary = if name_hit { 0 } else { 1 };
                indexed.push((i, score_primary * 1_000_000 + pos as i32, name_len));
            }
        }
        indexed.sort_by(|a, b| {
            a.1.cmp(&b.1)
                .then(a.2.cmp(&b.2))
                .then(self.file_search_files[a.0].cmp(&self.file_search_files[b.0]))
        });
        for (i, _, _) in indexed.into_iter() {
            self.file_search_filtered_indices.push(i);
        }
        if self.file_search_selected >= self.file_search_filtered_indices.len() {
            self.file_search_selected = self.file_search_filtered_indices.len().saturating_sub(1);
        }
        self.ensure_file_search_cursor_visible();
    }

    fn ensure_file_search_cursor_visible(&mut self) {
        let window = 10usize;
        if self.file_search_selected < self.file_search_scroll {
            self.file_search_scroll = self.file_search_selected;
        } else if self.file_search_selected >= self.file_search_scroll + window {
            self.file_search_scroll = self.file_search_selected + 1 - window;
        }
    }

    /// Handle number input for vim-style number + g navigation
    pub fn handle_number_input(&mut self, digit: char) {
        if digit.is_ascii_digit() {
            self.number_buffer.push(digit);
            self.expecting_g = true;
        }
    }

    /// Handle 'g' key for vim-style navigation
    pub fn handle_g_key(&mut self) -> bool {
        if self.g_pressed {
            // Second 'g' - 'gg' combination, go to top
            self.clear_number_buffer();
            self.move_to_top();
            self.g_pressed = false;
            return true;
        } else {
            // First 'g' - set flag and wait for second 'g'
            self.g_pressed = true;
            return true;
        }
    }

    /// Handle 'G' key for vim-style navigation
    pub fn handle_uppercase_g_key(&mut self) -> bool {
        if self.expecting_g {
            if self.number_buffer.is_empty() {
                // Just 'G' - go to bottom (like vim)
                self.move_to_bottom();
            } else {
                // Number + 'G' - go to specific line
                if let Ok(line_num) = self.number_buffer.parse::<usize>() {
                    self.goto_line(line_num);
                }
            }
            self.clear_number_buffer();
            return true;
        } else {
            // Just 'G' - go to bottom
            self.move_to_bottom();
            return true;
        }
    }

    /// Clear the number buffer and reset expecting_g state
    pub fn clear_number_buffer(&mut self) {
        self.number_buffer.clear();
        self.expecting_g = false;
        self.g_pressed = false;
    }

    /// Go to a specific line number (1-based, like vim)
    pub fn goto_line(&mut self, line_number: usize) {
        if self.content.is_empty() {
            return;
        }

        // Convert 1-based line number to 0-based index
        let target_line = if line_number == 0 { 0 } else { line_number - 1 };

        // If line number is greater than total lines, go to the last line
        let max_line = self.content.len() - 1;
        self.current_line = target_line.min(max_line);
        self.current_column = 0;
        self.horizontal_scroll_offset = 0;
        self.ensure_cursor_visible();
    }

    pub fn move_right(&mut self) {
        if let Some(current_line_content) = self.content.get(self.current_line) {
            if self.current_column < current_line_content.len() {
                self.current_column += 1;
                // If we just moved to the end of the line, immediately jump to next line
                if self.current_column == current_line_content.len()
                    && self.current_line + 1 < self.content.len()
                {
                    self.current_line += 1;
                    self.current_column = 0;
                    self.ensure_cursor_visible();
                }
            } else if self.current_line + 1 < self.content.len() {
                // Already at end of line, jump to next line
                self.current_line += 1;
                self.current_column = 0;
                self.ensure_cursor_visible();
            }
            // If we're at the end of the last line, stay there (don't move)
        }
        self.ensure_column_bounds();
    }

    pub fn move_left(&mut self) {
        if self.current_column > 0 {
            self.current_column -= 1;
            // If we just moved to the beginning of the line, immediately jump to previous line end
            if self.current_column == 0 && self.current_line > 0 {
                self.current_line -= 1;
                if let Some(prev_line_content) = self.content.get(self.current_line) {
                    // Jump to the last character of the previous line, not the newline position
                    self.current_column = if prev_line_content.is_empty() {
                        0
                    } else {
                        prev_line_content.len() - 1
                    };
                }
                self.ensure_cursor_visible();
            }
        } else if self.current_line > 0 {
            // Already at beginning of line, jump to end of previous line
            self.current_line -= 1;
            if let Some(prev_line_content) = self.content.get(self.current_line) {
                // Jump to the last character of the previous line, not the newline position
                self.current_column = if prev_line_content.is_empty() {
                    0
                } else {
                    prev_line_content.len() - 1
                };
            }
            self.ensure_cursor_visible();
        }
        // If we're at the beginning of the first line, stay there (don't move)
        self.ensure_column_bounds();
    }

    fn adjust_column_for_new_line(&mut self, old_column: usize) {
        if let Some(current_line_content) = self.content.get(self.current_line) {
            if current_line_content.is_empty() {
                // Empty line, stay at column 0
                self.current_column = 0;
            } else {
                // Adjust column to stay within the line, but prefer last character over newline position
                let max_column = current_line_content.len() - 1; // Last character position
                self.current_column = old_column.min(max_column);
            }
        }
    }

    fn ensure_column_bounds(&mut self) {
        if let Some(current_line_content) = self.content.get(self.current_line) {
            if current_line_content.is_empty() {
                // Empty line, stay at column 0
                self.current_column = 0;
            } else {
                // Ensure column is within bounds, but prefer last character over newline position
                let max_column = current_line_content.len() - 1; // Last character position
                self.current_column = self.current_column.min(max_column);
            }
        }
    }

    fn ensure_cursor_visible(&mut self) {
        if self.content.is_empty() {
            return;
        }

        // Vertical scrolling logic
        let visible_lines = (self.area_height.saturating_sub(2)) as usize;

        if self.content.len() <= visible_lines {
            self.scroll_offset = 0;
        } else {
            let scrolloff = visible_lines / 3;
            let ideal_scroll = self.current_line.saturating_sub(scrolloff);
            let max_scroll = self.content.len().saturating_sub(visible_lines);
            let near_end = self.current_line >= max_scroll.saturating_add(scrolloff);

            if near_end {
                self.scroll_offset = max_scroll;
            } else {
                self.scroll_offset = ideal_scroll.min(max_scroll);
            }
        }

        // Horizontal scrolling logic
        self.ensure_horizontal_cursor_visible();
    }

    fn ensure_horizontal_cursor_visible(&mut self) {
        if let Some(current_line_content) = self.content.get(self.current_line) {
            // Calculate available width for content (subtract line numbers and borders)
            let line_number_width = 5; // "1234 " format
            let border_width = 2; // left and right borders
            let available_width = (self
                .area_width
                .saturating_sub(line_number_width + border_width))
                as usize;

            if current_line_content.len() <= available_width {
                // Line fits entirely, no horizontal scrolling needed
                self.horizontal_scroll_offset = 0;
            } else {
                // Line is longer than available width, need horizontal scrolling
                let scrolloff = available_width / 3; // Keep some context around cursor

                // Calculate ideal horizontal scroll position
                let ideal_scroll = self.current_column.saturating_sub(scrolloff);

                // Calculate maximum possible scroll
                let max_scroll = current_line_content.len().saturating_sub(available_width);

                // Check if we're near the end of the line
                let near_end = self.current_column >= max_scroll.saturating_add(scrolloff);

                if near_end {
                    // Near the end, scroll to show the end
                    self.horizontal_scroll_offset = max_scroll;
                } else {
                    // Normal case, scroll to keep cursor visible with context
                    self.horizontal_scroll_offset = ideal_scroll.min(max_scroll);
                }
            }
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, is_focused: bool) {
        self.area_height = area.height;
        self.area_width = area.width;

        if is_focused {
            self.ensure_cursor_visible();
        }

        // If in file search mode, render only the overlay (mask entire area), then return
        if self.mode == SourcePanelMode::FileSearch {
            // Clear the entire source panel area to prevent any interference with other controls
            frame.render_widget(ratatui::widgets::Clear, area);

            // Render a conservative background that stays within bounds
            let background = Block::default()
                .style(Style::default().bg(Color::Rgb(16, 16, 16)))
                .borders(Borders::NONE); // Remove borders to prevent overflow
            frame.render_widget(background, area);

            // Centered overlay container
            let overlay_height = 1u16 + 10u16 + 2u16;
            let overlay_width = area.width.saturating_sub(10).max(40);
            let overlay_area = Rect::new(
                area.x + (area.width.saturating_sub(overlay_width)) / 2,
                area.y + (area.height.saturating_sub(overlay_height)) / 2,
                overlay_width,
                overlay_height.min(area.height),
            );

            // Clear overlay area to ensure clean drawing
            frame.render_widget(ratatui::widgets::Clear, overlay_area);

            // Outer block
            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Thick)
                .title("Open File")
                .border_style(Style::default().fg(Color::Cyan))
                .style(Style::default().bg(Color::Rgb(20, 20, 20)));
            frame.render_widget(block, overlay_area);

            if overlay_area.width <= 2 || overlay_area.height <= 2 {
                return;
            }
            let inner = Rect {
                x: overlay_area.x + 1,
                y: overlay_area.y + 1,
                width: overlay_area.width - 2,
                height: overlay_area.height - 2,
            };

            // Input line with safe UTF-8 width calculation
            let prefix = "🔎 ";
            let prompt = format!("{}{}", prefix, self.file_search_query);
            let input_para = ratatui::widgets::Paragraph::new(prompt.clone())
                .style(Style::default().fg(Color::Cyan).bg(Color::Rgb(30, 30, 30)));
            frame.render_widget(input_para, Rect::new(inner.x, inner.y, inner.width, 1));

            // Calculate cursor position using Unicode width
            let prefix_width = prefix.width() as u16;
            let query_width = self.file_search_query.width() as u16;
            let total_width = prefix_width + query_width;

            // Ensure cursor doesn't go out of bounds
            if total_width < inner.width {
                let caret_x = inner.x + total_width;
                frame.render_widget(
                    Block::default().style(Style::default().bg(Color::Cyan)),
                    Rect::new(caret_x, inner.y, 1, 1),
                );
            }

            // Body: message or list
            if let Some(msg) = &self.file_search_message {
                let msg_para = ratatui::widgets::Paragraph::new(msg.clone()).style(
                    Style::default()
                        .fg(if msg.starts_with('✗') {
                            Color::Red
                        } else {
                            Color::DarkGray
                        })
                        .bg(Color::Rgb(30, 30, 30)),
                );
                if inner.height > 2 {
                    frame.render_widget(
                        msg_para,
                        Rect::new(inner.x, inner.y + 1, inner.width, inner.height - 1),
                    );
                }
            } else {
                let mut items: Vec<ListItem> = Vec::new();
                let start = self.file_search_scroll;
                let end = (start + 10).min(self.file_search_filtered_indices.len());
                for idx in start..end {
                    let real_idx = self.file_search_filtered_indices[idx];
                    let path = &self.file_search_files[real_idx];
                    let icon = match std::path::Path::new(path)
                        .extension()
                        .and_then(|s| s.to_str())
                        .map(|s| s.to_ascii_lowercase())
                    {
                        Some(ref e) if ["h", "hpp", "hh", "hxx"].contains(&e.as_str()) => "📑",
                        Some(ref e) if ["c", "cc", "cpp", "cxx"].contains(&e.as_str()) => "📝",
                        Some(ref e) if e == "rs" => "🦀",
                        Some(ref e) if ["s", "asm"].contains(&e.as_str()) => "🛠️",
                        _ => "📄",
                    };
                    // Use pink color for selected file, white for others
                    let is_selected = idx == self.file_search_selected;
                    let text_color = if is_selected {
                        Color::LightMagenta
                    } else {
                        Color::White
                    };

                    // Create text with safe UTF-8 truncation instead of wrapping
                    let full_text = format!("{} {}", icon, path);
                    let max_width = (inner.width.saturating_sub(4)) as usize; // More conservative margin

                    // Safely truncate text to fit in one line to avoid layout issues
                    let display_text = if full_text.width() > max_width {
                        let mut truncated = String::new();
                        let mut current_width = 0;

                        for ch in full_text.chars() {
                            let char_width = ch.width().unwrap_or(1);
                            // Reserve space for "..." ellipsis
                            if current_width + char_width + 3 > max_width {
                                break;
                            }
                            truncated.push(ch);
                            current_width += char_width;
                        }

                        if truncated.len() < full_text.len() {
                            truncated.push_str("...");
                        }
                        truncated
                    } else {
                        full_text
                    };

                    // Create single-line item to prevent overflow into other controls
                    let line = Line::from(vec![Span::styled(
                        display_text,
                        Style::default().fg(text_color),
                    )]);
                    items.push(ListItem::new(line));
                }

                let list = List::new(items)
                    .block(Block::default().style(Style::default().bg(Color::Rgb(30, 30, 30))));
                let list_area = Rect::new(
                    inner.x,
                    inner.y + 1,
                    inner.width,
                    inner.height.saturating_sub(1),
                );
                frame.render_widget(list, list_area);
            }

            return;
        }

        let items: Vec<ListItem> = self
            .content
            .iter()
            .enumerate()
            .skip(self.scroll_offset)
            .map(|(i, line)| {
                let line_num = i + 1;
                let is_current_line = i == self.current_line;

                let line_number_style = if is_current_line {
                    Style::default().fg(Color::LightYellow).bg(Color::DarkGray)
                } else {
                    Style::default().fg(Color::DarkGray)
                };

                // Apply horizontal scrolling to the line content - use character-safe slicing
                let mut visible_line = if self.horizontal_scroll_offset > 0 {
                    // Use char indices to avoid splitting UTF-8 characters
                    let chars: Vec<char> = line.chars().collect();
                    if self.horizontal_scroll_offset < chars.len() {
                        chars[self.horizontal_scroll_offset..].iter().collect()
                    } else {
                        String::new()
                    }
                } else {
                    line.to_string()
                };

                // Ensure we don't exceed available width to prevent overflow
                // Be very conservative with the margin to prevent any overflow
                let max_visible_width = (self.area_width.saturating_sub(15)) as usize; // Very conservative margin
                let original_width = visible_line.width();
                if original_width > max_visible_width {
                    // Truncate to prevent overflow using unicode width
                    let mut truncated = String::new();
                    let mut current_width = 0;
                    for ch in visible_line.chars() {
                        let char_width = ch.width().unwrap_or(1);
                        if current_width + char_width > max_visible_width {
                            break;
                        }
                        truncated.push(ch);
                        current_width += char_width;
                    }
                    visible_line = truncated;
                }

                // Apply syntax highlighting to the visible portion
                let highlighted_spans = self.highlight_line(&visible_line);

                // Overlay search highlights on top of syntax highlighting
                let highlighted_spans =
                    self.apply_search_overlay(&visible_line, highlighted_spans, i);

                let mut spans = vec![Span::styled(format!("{:4} ", line_num), line_number_style)];
                spans.extend(highlighted_spans);

                ListItem::new(Line::from(spans))
            })
            .collect();

        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let title = match &self.file_path {
            Some(path) => format!("Source Code - {}", path),
            None => "Source Code".to_string(),
        };

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(if is_focused {
                    BorderType::Thick
                } else {
                    BorderType::Plain
                })
                .title(title)
                .border_style(border_style),
        );

        frame.render_widget(list, area);

        // Display input buffer in bottom right corner
        if is_focused && (!self.number_buffer.is_empty() || self.g_pressed) {
            let mut display_text = String::new();

            if !self.number_buffer.is_empty() {
                display_text.push_str(&self.number_buffer);
            }

            if self.g_pressed {
                display_text.push('g');
            }

            if !display_text.is_empty() {
                // Create a nice display with hint text
                let hint_text = if self.g_pressed && self.number_buffer.is_empty() {
                    "Press 'g' again for top"
                } else if !self.number_buffer.is_empty() && !self.g_pressed {
                    "Press 'G' to jump to line"
                } else if !self.number_buffer.is_empty() && self.g_pressed {
                    "Press 'G' to jump to line"
                } else {
                    ""
                };

                // Create styled spans with different colors for numbers and hints
                let mut spans = Vec::new();

                // Add the input text (numbers + g) with green color
                spans.push(Span::styled(
                    display_text.clone(),
                    Style::default()
                        .fg(Color::Green) // Green for input
                        .bg(Color::Rgb(30, 30, 30)), // Dark gray background
                ));

                // Add hint text with border color if present
                if !hint_text.is_empty() {
                    spans.push(Span::styled(
                        format!(" ({})", hint_text),
                        Style::default()
                            .fg(border_style.fg.unwrap_or(Color::White)) // Same as border color
                            .bg(Color::Rgb(30, 30, 30)), // Dark gray background
                    ));
                }

                let text = ratatui::text::Text::from(ratatui::text::Line::from(spans));

                // Calculate total text width for positioning
                let full_text = if !hint_text.is_empty() {
                    format!("{} ({})", display_text, hint_text)
                } else {
                    display_text
                };

                // Position in bottom right corner with some padding
                let text_width = full_text.len() as u16;
                let display_x = area.x + area.width.saturating_sub(text_width + 2);
                let display_y = area.y + area.height.saturating_sub(1);

                // Render the text
                frame.render_widget(
                    ratatui::widgets::Paragraph::new(text)
                        .alignment(ratatui::layout::Alignment::Right),
                    Rect::new(display_x, display_y, text_width + 2, 1),
                );
            }
        }

        // Render search prompt at bottom-left when in text search mode
        if is_focused && self.mode == SourcePanelMode::TextSearch {
            let (slash_style, query_style, _overlay_style) = self.search_styles();
            let prompt_slash = "/";
            let prompt_query = &self.search_query;
            let text = ratatui::text::Text::from(ratatui::text::Line::from(vec![
                Span::styled(prompt_slash.to_string(), slash_style),
                Span::styled(prompt_query.to_string(), query_style),
            ]));
            let display_x = area.x + 1;
            let display_y = area.y + area.height.saturating_sub(1);
            let text_width = (1 + self.search_query.len()) as u16 + 1;
            frame.render_widget(
                ratatui::widgets::Paragraph::new(text),
                Rect::new(display_x, display_y, text_width, 1),
            );
        }

        // Render cursor in normal mode
        if is_focused && !self.content.is_empty() && self.mode == SourcePanelMode::Normal {
            self.ensure_column_bounds();

            let cursor_y =
                area.y + 1 + (self.current_line.saturating_sub(self.scroll_offset)) as u16;
            let line_number_width = 5u16;

            // Calculate cursor X position considering horizontal scroll
            let visible_cursor_column = if self.current_column >= self.horizontal_scroll_offset {
                self.current_column - self.horizontal_scroll_offset
            } else {
                0 // Cursor is to the left of visible area
            };

            let cursor_x = area.x + 1 + line_number_width + visible_cursor_column as u16;

            // Only render cursor if it's within the visible area
            if cursor_y < area.y + area.height - 1
                && cursor_x < area.x + area.width - 1
                && cursor_x >= area.x + 1 + line_number_width
            {
                frame.render_widget(
                    Block::default().style(Style::default().bg(Color::Cyan)),
                    Rect::new(cursor_x, cursor_y, 1, 1),
                );
            }
        }
    }
}

impl SourceCodePanel {
    // Post-process a line's spans to overlay search highlights for the visible portion
    fn apply_search_overlay(
        &self,
        visible_line_full: &str,
        spans: Vec<Span>,
        line_index: usize,
    ) -> Vec<Span> {
        if self.search_query.is_empty() || self.search_matches.is_empty() {
            // Return an owned copy to avoid lifetime issues
            return spans
                .into_iter()
                .map(|s| Span::styled(s.content.to_string(), s.style))
                .collect();
        }

        // Collect match ranges for this line in visible coordinates
        let h_off = self.horizontal_scroll_offset;
        let ranges: Vec<(usize, usize)> = self
            .search_matches
            .iter()
            .filter_map(|(li, s, e)| {
                if *li != line_index {
                    return None;
                }
                if *e <= h_off || *s >= h_off + visible_line_full.len() {
                    return None; // out of visible area
                }
                let vis_start = s.saturating_sub(h_off);
                let vis_end = e.saturating_sub(h_off);
                Some((vis_start, vis_end))
            })
            .collect();

        if ranges.is_empty() {
            return spans
                .into_iter()
                .map(|s| Span::styled(s.content.to_string(), s.style))
                .collect();
        }

        // Build a flat string from spans to map positions, then rebuild with background overlay
        let mut result: Vec<Span> = Vec::new();
        let mut pos = 0usize;
        for span in spans {
            let text = span.content.clone();
            let base_style = span.style;
            let mut cursor = 0usize;
            while cursor < text.len() {
                // Determine next split point and whether current slice is highlighted
                let mut next_break = text.len() - cursor;
                let mut highlight_now = false;
                for (rs, re) in &ranges {
                    if pos >= *re || pos + next_break <= *rs {
                        continue;
                    }
                    if pos < *rs {
                        next_break = (*rs - pos).min(next_break);
                        highlight_now = false;
                    } else {
                        next_break = (*re - pos).min(next_break);
                        highlight_now = true;
                    }
                }
                let end_cursor = cursor + next_break;
                let slice = &text[cursor..end_cursor];
                let style = if highlight_now {
                    let (_slash_style, _query_style, overlay_style) = self.search_styles();
                    let mut style = base_style;
                    style.bg = None; // No background
                    style.fg = overlay_style.fg; // Bright pink
                    style
                } else {
                    base_style
                };
                result.push(Span::styled(slice.to_string(), style));
                pos += next_break;
                cursor = end_cursor;
            }
        }

        result
    }
}

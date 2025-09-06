use crate::syntax_highlight::{SyntaxHighlighter, Token, TokenType};
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem},
    Frame,
};

pub struct SourceCodePanel {
    pub content: Vec<String>,
    pub current_line: usize,
    pub current_column: usize, // Add horizontal cursor position
    pub scroll_offset: usize,
    pub file_path: Option<String>,
    pub area_height: u16, // Store the current area height for scroll calculations
    pub language: String, // Programming language for syntax highlighting
    pub syntax_highlighter: SyntaxHighlighter,

    pub number_buffer: String, // Buffer for collecting numbers before 'g'
    pub expecting_g: bool,     // Whether we're expecting a 'g' after numbers
    pub g_pressed: bool,       // Whether 'g' was pressed (for 'gg' combination)
}

impl SourceCodePanel {
    pub fn new() -> Self {
        Self {
            content: vec!["// No source code loaded".to_string()],
            current_line: 0,
            current_column: 0,
            scroll_offset: 0,
            file_path: None,
            area_height: 10,           // Default height
            language: "c".to_string(), // Default to C
            syntax_highlighter: SyntaxHighlighter::new(),
            number_buffer: String::new(),
            expecting_g: false,
            g_pressed: false,
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
    }

    pub fn show_error(&mut self, error_message: String) {
        self.content = vec![
            "// Source code loading failed".to_string(),
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
    }

    pub fn move_to_bottom(&mut self) {
        if !self.content.is_empty() {
            self.current_line = self.content.len() - 1;
            self.current_column = 0;
            self.ensure_cursor_visible();
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
        self.ensure_cursor_visible();
    }

    pub fn move_right(&mut self) {
        if let Some(current_line_content) = self.content.get(self.current_line) {
            if self.current_column < current_line_content.len() {
                self.current_column += 1;
            } else if self.current_line + 1 < self.content.len() {
                self.current_line += 1;
                self.current_column = 0;
                self.ensure_cursor_visible();
            }
        }
        self.ensure_column_bounds();
    }

    pub fn move_left(&mut self) {
        if self.current_column > 0 {
            self.current_column -= 1;
        } else if self.current_line > 0 {
            self.current_line -= 1;
            if let Some(prev_line_content) = self.content.get(self.current_line) {
                self.current_column = prev_line_content.len();
            }
            self.ensure_cursor_visible();
        }
        self.ensure_column_bounds();
    }

    fn adjust_column_for_new_line(&mut self, old_column: usize) {
        if let Some(current_line_content) = self.content.get(self.current_line) {
            self.current_column = old_column.min(current_line_content.len());
        }
    }

    fn ensure_column_bounds(&mut self) {
        if let Some(current_line_content) = self.content.get(self.current_line) {
            self.current_column = self.current_column.min(current_line_content.len());
        }
    }

    fn ensure_cursor_visible(&mut self) {
        if self.content.is_empty() {
            return;
        }

        let visible_lines = (self.area_height.saturating_sub(2)) as usize;

        if self.content.len() <= visible_lines {
            self.scroll_offset = 0;
            return;
        }

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

    pub fn render(&mut self, frame: &mut Frame, area: Rect, is_focused: bool) {
        self.area_height = area.height;

        if is_focused {
            self.ensure_cursor_visible();
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

                // Apply syntax highlighting
                let highlighted_spans = self.highlight_line(line);

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

        if is_focused && !self.content.is_empty() {
            self.ensure_column_bounds();

            let cursor_y =
                area.y + 1 + (self.current_line.saturating_sub(self.scroll_offset)) as u16;
            let line_number_width = 5u16;
            let cursor_x = area.x + 1 + line_number_width + self.current_column as u16;

            if cursor_y < area.y + area.height - 1 && cursor_x < area.x + area.width - 1 {
                frame.render_widget(
                    Block::default().style(Style::default().bg(Color::Cyan)),
                    Rect::new(cursor_x, cursor_y, 1, 1),
                );
            }
        }
    }
}

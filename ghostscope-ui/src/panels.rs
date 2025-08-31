use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, BorderType, List, ListItem, Paragraph},
    Frame,
};
use std::collections::VecDeque;

use crate::events::{RingbufEvent, RuntimeStatus};

pub struct SourceCodePanel {
    pub content: Vec<String>,
    pub current_line: usize,
    pub current_column: usize, // Add horizontal cursor position
    pub scroll_offset: usize,
    pub file_path: Option<String>,
    pub area_height: u16, // Store the current area height for scroll calculations
}

impl SourceCodePanel {

    pub fn new() -> Self {
        Self {
            content: vec!["// No source code loaded".to_string()],
            current_line: 0,
            current_column: 0,
            scroll_offset: 0,
            file_path: None,
            area_height: 10, // Default height
        }
    }

    pub fn load_source(
        &mut self,
        file_path: String,
        content: Vec<String>,
        highlight_line: Option<usize>,
    ) {
        self.file_path = Some(file_path);
        self.content = content;

        if let Some(line) = highlight_line {
            if line > 0 && line <= self.content.len() {
                self.current_line = line - 1;
                self.current_column = 0;
            } else {
                self.current_line = 0;
                self.current_column = 0;
            }
        } else {
            self.current_line = 0;
            self.current_column = 0;
        }
        
        self.scroll_offset = 0;
    }

    pub fn clear_source(&mut self) {
        self.content = vec!["// No source code loaded".to_string()];
        self.file_path = None;
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

                let style = Style::default();

                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{:4} ", line_num),
                        line_number_style,
                    ),
                    Span::styled(line.clone(), style),
                ]))
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
                .border_type(if is_focused { BorderType::Thick } else { BorderType::Plain })
                .title(title)
                .border_style(border_style),
        );

        frame.render_widget(list, area);

        if is_focused && !self.content.is_empty() {
            self.ensure_column_bounds();
            
            let cursor_y = area.y + 1 + (self.current_line.saturating_sub(self.scroll_offset)) as u16;
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

pub struct OutputPanel {
    pub messages: VecDeque<RingbufEvent>,
    pub status_messages: VecDeque<RuntimeStatus>,
    pub scroll_offset: usize,
    pub max_messages: usize,
    pub auto_scroll: bool,
}

impl OutputPanel {
    pub fn new() -> Self {
        Self {
            messages: VecDeque::new(),
            status_messages: VecDeque::new(),
            scroll_offset: 0,
            max_messages: 1000,
            auto_scroll: true,
        }
    }

    pub fn add_ringbuf_event(&mut self, event: RingbufEvent) {
        self.messages.push_back(event);
        if self.messages.len() > self.max_messages {
            self.messages.pop_front();
        }

        if self.auto_scroll {
            self.scroll_to_bottom();
        }
    }

    pub fn add_status_message(&mut self, status: RuntimeStatus) {
        self.status_messages.push_back(status);
        if self.status_messages.len() > 100 {
            // Keep fewer status messages
            self.status_messages.pop_front();
        }
    }

    pub fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
            self.auto_scroll = false;
        }
    }

    pub fn scroll_down(&mut self) {
        let total_lines = self.messages.len() + self.status_messages.len();
        if self.scroll_offset + 1 < total_lines {
            self.scroll_offset += 1;
        } else {
            self.auto_scroll = true;
        }
    }

    pub fn scroll_to_bottom(&mut self) {
        let total_lines = self.messages.len() + self.status_messages.len();
        self.scroll_offset = total_lines.saturating_sub(1);
        self.auto_scroll = true;
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let mut all_items = Vec::new();

        // Calculate content width for text wrapping (subtract borders and prefix)
        let content_width = area.width.saturating_sub(4); // 2 for borders + 2 for padding

        // Add status messages first (in chronological order)
        for status in &self.status_messages {
            let (style, text) = match status {
                RuntimeStatus::DwarfLoadingStarted => (
                    Style::default().fg(Color::Yellow),
                    "Loading DWARF information...".to_string(),
                ),
                RuntimeStatus::DwarfLoadingCompleted { symbols_count } => (
                    Style::default().fg(Color::Green),
                    format!("DWARF loaded successfully ({} symbols)", symbols_count),
                ),
                RuntimeStatus::DwarfLoadingFailed(err) => (
                    Style::default().fg(Color::Red),
                    format!("DWARF loading failed: {}", err),
                ),
                RuntimeStatus::ScriptCompilationStarted => (
                    Style::default().fg(Color::Yellow),
                    "Compiling script...".to_string(),
                ),
                RuntimeStatus::ScriptCompilationCompleted => (
                    Style::default().fg(Color::Green),
                    "Script compiled successfully".to_string(),
                ),
                RuntimeStatus::ScriptCompilationFailed(err) => (
                    Style::default().fg(Color::Red),
                    format!("Script compilation failed: {}", err),
                ),
                RuntimeStatus::UprobeAttached { function, address } => (
                    Style::default().fg(Color::Green),
                    format!("Uprobe attached: {} @ 0x{:x}", function, address),
                ),
                RuntimeStatus::UprobeDetached { function } => (
                    Style::default().fg(Color::Yellow),
                    format!("Uprobe detached: {}", function),
                ),
                RuntimeStatus::ProcessAttached(pid) => (
                    Style::default().fg(Color::Green),
                    format!("Attached to process {}", pid),
                ),
                RuntimeStatus::ProcessDetached => (
                    Style::default().fg(Color::Yellow),
                    "Detached from process".to_string(),
                ),
                RuntimeStatus::SourceCodeLoaded(source_info) => (
                    Style::default().fg(Color::Green),
                    format!("Source code loaded: {}", source_info.file_path),
                ),
                RuntimeStatus::SourceCodeLoadFailed(err) => (
                    Style::default().fg(Color::Red),
                    format!("Source code load failed: {}", err),
                ),
                RuntimeStatus::Error(err) => {
                    (Style::default().fg(Color::Red), format!("Error: {}", err))
                }
            };

            // Wrap long messages
            let status_prefix = "[STATUS] ";
            let full_text = format!("{}{}", status_prefix, text);
            let wrapped_lines = self.wrap_text(&full_text, content_width as usize);
            
            for (i, line) in wrapped_lines.iter().enumerate() {
                if i == 0 {
                    // First line includes the [STATUS] prefix
                    all_items.push(ListItem::new(Line::from(vec![Span::styled(
                        line.clone(),
                        style,
                    )])));
                } else {
                    // Continuation lines are indented to align with content after prefix
                    let indent = " ".repeat(status_prefix.len());
                    all_items.push(ListItem::new(Line::from(vec![
                        Span::styled(format!("{}{}", indent, line), style),
                    ])));
                }
            }
        }

        // Add ringbuf messages
        for event in &self.messages {
            let timestamp_text = format!("[{:>12}] ", event.timestamp);
            let message_text =
                format!("Type: {:?}, {} bytes", event.message_type, event.data.len());
            let full_line = format!("{}{}", timestamp_text, message_text);

            let wrapped_lines = self.wrap_text(&full_line, content_width as usize);
            for (i, line) in wrapped_lines.iter().enumerate() {
                if i == 0 {
                    // First line with proper coloring
                    let prefix_len = timestamp_text.len();
                    let prefix = &line[..prefix_len.min(line.len())];
                    let content = if line.len() > prefix_len {
                        &line[prefix_len..]
                    } else {
                        ""
                    };

                    all_items.push(ListItem::new(Line::from(vec![
                        Span::styled(prefix.to_string(), Style::default().fg(Color::DarkGray)),
                        Span::styled(content.to_string(), Style::default()),
                    ])));
                } else {
                    // Continuation lines - indent to align with content after timestamp
                    let indent = " ".repeat(timestamp_text.len());
                    all_items.push(ListItem::new(Line::from(vec![
                        Span::styled(format!("{}{}", indent, line), Style::default()),
                    ])));
                }
            }
        }

        // Apply scrolling
        let visible_items: Vec<_> = all_items.into_iter().skip(self.scroll_offset).collect();

        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let list = List::new(visible_items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(if is_focused { BorderType::Thick } else { BorderType::Plain })
                .title(format!("Output ({} messages)", self.messages.len()))
                .border_style(border_style),
        );

        frame.render_widget(list, area);
    }

    /// Wrap text to fit within the specified width
    /// This improved version handles long words and special characters better
    fn wrap_text(&self, text: &str, width: usize) -> Vec<String> {
        if width == 0 {
            return vec![text.to_string()];
        }

        let mut lines = Vec::new();
        let mut current_line = String::new();

        for word in text.split_whitespace() {
            // If the word itself is longer than the width, we need to break it
            if word.len() > width {
                // If we have content on the current line, push it first
                if !current_line.is_empty() {
                    lines.push(current_line);
                    current_line = String::new();
                }
                
                // For long words (like file paths), try to break at more sensible points
                if word.contains('/') {
                    // Try to break at path separators for file paths
                    let mut remaining = word;
                    while !remaining.is_empty() {
                        let mut chunk_size = (width - 3).min(remaining.len()); // 更保守的边距
                        
                        // If we're not at the end, try to find a good break point
                        if chunk_size < remaining.len() {
                            // Look for a path separator near the end of the chunk
                            let chunk = &remaining[..chunk_size];
                            if let Some(last_slash) = chunk.rfind('/') {
                                // Break after the last slash in the chunk
                                chunk_size = last_slash + 1;
                            }
                        }
                        
                        let chunk = &remaining[..chunk_size];
                        lines.push(chunk.to_string());
                        remaining = &remaining[chunk_size..];
                    }
                } else {
                    // For other long words, break at character boundaries
                    let mut remaining = word;
                    while !remaining.is_empty() {
                        let chunk_size = (width - 3).min(remaining.len()); // 更保守的边距
                        let chunk = &remaining[..chunk_size];
                        lines.push(chunk.to_string());
                        remaining = &remaining[chunk_size..];
                    }
                }
            } else if current_line.is_empty() {
                // First word on the line
                current_line = word.to_string();
            } else if current_line.len() + 1 + word.len() <= width {
                // Word fits on current line
                current_line.push(' ');
                current_line.push_str(word);
            } else {
                // Word doesn't fit, start new line
                lines.push(current_line);
                current_line = word.to_string();
            }
        }

        // Add the last line if it's not empty
        if !current_line.is_empty() {
            lines.push(current_line);
        }

        // If no lines were created, return the original text
        if lines.is_empty() {
            vec![text.to_string()]
        } else {
            lines
        }
    }
}

pub struct InputPanel {
    pub input_text: String,
    pub cursor_position: usize,
    pub command_history: Vec<String>,
    pub history_index: Option<usize>,
    pub prompt: String,
}

impl InputPanel {
    pub fn new() -> Self {
        Self {
            input_text: String::new(),
            cursor_position: 0,
            command_history: Vec::new(),
            history_index: None,
            prompt: "(ghostscope) ".to_string(),
        }
    }

    pub fn insert_char(&mut self, c: char) {
        self.input_text.insert(self.cursor_position, c);
        self.cursor_position += 1;
    }

    pub fn delete_char(&mut self) {
        if self.cursor_position > 0 {
            self.input_text.remove(self.cursor_position - 1);
            self.cursor_position -= 1;
        }
    }

    pub fn move_cursor_left(&mut self) {
        if self.cursor_position > 0 {
            self.cursor_position -= 1;
        }
    }

    pub fn move_cursor_right(&mut self) {
        if self.cursor_position < self.input_text.len() {
            self.cursor_position += 1;
        }
    }

    pub fn submit_command(&mut self) -> Option<String> {
        if !self.input_text.trim().is_empty() {
            let command = self.input_text.clone();
            self.command_history.push(command.clone());
            self.input_text.clear();
            self.cursor_position = 0;
            self.history_index = None;
            Some(command)
        } else {
            None
        }
    }

    pub fn history_up(&mut self) {
        if self.command_history.is_empty() {
            return;
        }

        let new_index = match self.history_index {
            None => self.command_history.len() - 1,
            Some(i) if i > 0 => i - 1,
            Some(_) => return, // Already at the top
        };

        self.history_index = Some(new_index);
        self.input_text = self.command_history[new_index].clone();
        self.cursor_position = self.input_text.len();
    }

    pub fn history_down(&mut self) {
        match self.history_index {
            None => return,
            Some(i) if i < self.command_history.len() - 1 => {
                let new_index = i + 1;
                self.history_index = Some(new_index);
                self.input_text = self.command_history[new_index].clone();
                self.cursor_position = self.input_text.len();
            }
            Some(_) => {
                // At the bottom, clear input
                self.history_index = None;
                self.input_text.clear();
                self.cursor_position = 0;
            }
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let input_line = format!("{}{}", self.prompt, self.input_text);

        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let paragraph = Paragraph::new(input_line).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(if is_focused { BorderType::Thick } else { BorderType::Plain })
                .border_style(border_style),
        );

        frame.render_widget(paragraph, area);

        // Render cursor
        let cursor_x = area.x + self.prompt.len() as u16 + self.cursor_position as u16 + 1;
        let cursor_y = area.y + 1;

        if cursor_x < area.x + area.width - 1 && cursor_y < area.y + area.height - 1 {
            frame.render_widget(
                Block::default().style(Style::default().bg(Color::White)),
                Rect::new(cursor_x, cursor_y, 1, 1),
            );
        }
    }
}



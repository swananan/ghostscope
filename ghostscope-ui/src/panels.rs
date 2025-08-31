use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph},
    Frame,
};
use std::collections::VecDeque;

use crate::events::{RingbufEvent, RuntimeStatus};

pub struct SourceCodePanel {
    pub content: Vec<String>,
    pub current_line: usize,
    pub scroll_offset: usize,
}

impl SourceCodePanel {
    pub fn new() -> Self {
        Self {
            content: vec!["// No source code loaded".to_string()],
            current_line: 0,
            scroll_offset: 0,
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let items: Vec<ListItem> = self
            .content
            .iter()
            .enumerate()
            .skip(self.scroll_offset)
            .map(|(i, line)| {
                let line_num = i + 1;
                let style = if i == self.current_line {
                    Style::default().bg(Color::Blue).fg(Color::White)
                } else {
                    Style::default()
                };

                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{:4} ", line_num),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(line.clone(), style),
                ]))
            })
            .collect();

        let border_style = if is_focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .title("Source Code")
                .border_style(border_style),
        );

        frame.render_widget(list, area);
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
                RuntimeStatus::Error(err) => {
                    (Style::default().fg(Color::Red), format!("Error: {}", err))
                }
            };

            all_items.push(ListItem::new(Line::from(vec![
                Span::styled("[STATUS] ", Style::default().fg(Color::Cyan)),
                Span::styled(text, style),
            ])));
        }

        // Add ringbuf messages
        for event in &self.messages {
            let timestamp_text = format!("[{:>12}] ", event.timestamp);
            let message_text =
                format!("Type: {:?}, {} bytes", event.message_type, event.data.len());

            all_items.push(ListItem::new(Line::from(vec![
                Span::styled(timestamp_text, Style::default().fg(Color::DarkGray)),
                Span::styled(message_text, Style::default()),
            ])));
        }

        // Apply scrolling
        let visible_items: Vec<_> = all_items.into_iter().skip(self.scroll_offset).collect();

        let border_style = if is_focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let list = List::new(visible_items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!("Output ({} messages)", self.messages.len()))
                .border_style(border_style),
        );

        frame.render_widget(list, area);
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
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let paragraph = Paragraph::new(input_line).block(
            Block::default()
                .borders(Borders::ALL)
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

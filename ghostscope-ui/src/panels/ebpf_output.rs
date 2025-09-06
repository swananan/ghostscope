// Removed unused chrono imports
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem},
    Frame,
};
use std::collections::VecDeque;

use ghostscope_protocol::EventData;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DisplayMode {
    AutoRefresh,  // Default mode: always show latest trace, auto-scroll
    Scroll,       // Manual mode: show cursor, manual navigation
}

pub struct EbpfInfoPanel {
    pub trace_events: VecDeque<EventData>,
    pub scroll_offset: usize,
    pub max_messages: usize,
    pub auto_scroll: bool,
    pub cursor_trace_index: usize,  // Index of the selected trace (not line)
    pub show_cursor: bool,          // Whether to show cursor highlighting
    pub display_mode: DisplayMode,  // Current display mode
}

impl EbpfInfoPanel {
    pub fn new() -> Self {
        Self {
            trace_events: VecDeque::new(),
            scroll_offset: 0,
            max_messages: 2000, // TODO: Make this configurable in the future
            auto_scroll: true,
            cursor_trace_index: 0,
            show_cursor: false,
            display_mode: DisplayMode::AutoRefresh,
        }
    }

    pub fn add_trace_event(&mut self, trace_event: EventData) {
        self.trace_events.push_back(trace_event);
        if self.trace_events.len() > self.max_messages {
            self.trace_events.pop_front();
        }

        // Only auto-scroll in auto-refresh mode
        if self.display_mode == DisplayMode::AutoRefresh {
            self.scroll_to_bottom();
        }
    }

    pub fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
            self.auto_scroll = false;
        }
    }

    pub fn scroll_down(&mut self) {
        let total_lines = self.trace_events.len();
        if self.scroll_offset + 1 < total_lines {
            self.scroll_offset += 1;
        } else {
            self.auto_scroll = true;
        }
    }

    pub fn scroll_to_bottom(&mut self) {
        // For now, just set scroll offset to 0 to show all messages
        self.scroll_offset = 0;
        self.auto_scroll = true;
        self.show_cursor = false;
    }

    pub fn move_cursor_up(&mut self) {
        self.enter_scroll_mode();
        if self.cursor_trace_index > 0 {
            self.cursor_trace_index -= 1;
        }
    }

    pub fn move_cursor_down(&mut self) {
        self.enter_scroll_mode();
        if self.cursor_trace_index + 1 < self.trace_events.len() {
            self.cursor_trace_index += 1;
        }
    }

    pub fn move_cursor_up_10(&mut self) {
        self.enter_scroll_mode();
        self.cursor_trace_index = self.cursor_trace_index.saturating_sub(10);
    }

    pub fn move_cursor_down_10(&mut self) {
        self.enter_scroll_mode();
        let max_index = self.trace_events.len().saturating_sub(1);
        self.cursor_trace_index = (self.cursor_trace_index + 10).min(max_index);
    }

    /// Enter scroll mode and set cursor to the last trace
    fn enter_scroll_mode(&mut self) {
        if self.display_mode != DisplayMode::Scroll {
            self.display_mode = DisplayMode::Scroll;
            self.show_cursor = true;
            self.auto_scroll = false;
            // Set cursor to the last trace when entering scroll mode
            self.cursor_trace_index = self.trace_events.len().saturating_sub(1);
        }
    }

    pub fn hide_cursor(&mut self) {
        self.display_mode = DisplayMode::AutoRefresh;
        self.show_cursor = false;
        self.auto_scroll = true;
    }

    /// Ensure the cursor trace is visible by adjusting scroll offset
    fn ensure_cursor_visible(&mut self, total_items: usize, available_height: usize, content_width: usize) {
        if total_items <= available_height {
            // All items fit, no scrolling needed
            self.scroll_offset = 0;
            return;
        }

        // Calculate the line index of the cursor trace by counting actual lines
        let mut cursor_line_index = 0;
        for (trace_index, trace) in self.trace_events.iter().enumerate() {
            if trace_index == self.cursor_trace_index {
                break;
            }
            
            // Count actual lines for this trace (including wrapped lines)
            // Use the same content width calculation as in render method
            let mut message_line = format!(
                "{} [TraceID:{}] PID:{} TID:{} [{:?}]",
                trace.readable_timestamp, trace.trace_id, trace.pid, trace.tid, trace.message_type
            );

            // Add variable information if available
            if !trace.variables.is_empty() {
                let variables_info = trace.variables.iter()
                    .map(|var| format!("{}: {}", var.name, var.formatted_value))
                    .collect::<Vec<_>>()
                    .join(", ");
                message_line.push_str(&format!(" | Variables: [{}]", variables_info));
            }

            // Add log message if available
            if let Some(log_msg) = &trace.log_message {
                message_line.push_str(&format!(" | Log: {}", log_msg));
            }

            // Add failure message if available
            if let Some(failure_msg) = &trace.failure_message {
                message_line.push_str(&format!(" | Failure: {}", failure_msg));
            }

            let wrapped_lines = self.wrap_text(&message_line, content_width);
            cursor_line_index += wrapped_lines.len();
        }

        // Ensure cursor is visible
        if cursor_line_index < self.scroll_offset {
            // Cursor is above visible area, scroll up to show it at the top
            self.scroll_offset = cursor_line_index;
        } else if cursor_line_index >= self.scroll_offset + available_height {
            // Cursor is below visible area, scroll down to show it at the bottom
            self.scroll_offset = cursor_line_index.saturating_sub(available_height - 1);
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let mut all_items = Vec::new();

        // Calculate content width for text wrapping (subtract borders and padding)
        let content_width = area.width.saturating_sub(6); // 2 for borders + 4 for padding

        // Add trace events with clean, simple formatting
        let total_traces = self.trace_events.len();
        
        for (trace_index, trace) in self.trace_events.iter().enumerate() {
            let is_latest = trace_index == total_traces - 1;
            let is_cursor_trace = self.show_cursor && trace_index == self.cursor_trace_index;

            // Create the main message line with enhanced information
            let mut message_line = format!(
                "{} [TraceID:{}] PID:{} TID:{} [{:?}]",
                trace.readable_timestamp, trace.trace_id, trace.pid, trace.tid, trace.message_type
            );

            // Add variable information if available
            if !trace.variables.is_empty() {
                let variables_info = trace.variables.iter()
                    .map(|var| format!("{}: {}", var.name, var.formatted_value))
                    .collect::<Vec<_>>()
                    .join(", ");
                message_line.push_str(&format!(" | Variables: [{}]", variables_info));
            }

            // Add log message if available
            if let Some(log_msg) = &trace.log_message {
                message_line.push_str(&format!(" | Log: {}", log_msg));
            }

            // Add failure message if available
            if let Some(failure_msg) = &trace.failure_message {
                message_line.push_str(&format!(" | Failure: {}", failure_msg));
            }

            // Wrap the message if needed
            let wrapped_lines = self.wrap_text(&message_line, content_width as usize);

            // Determine the style based on latest message and cursor position
            let final_style = if is_cursor_trace {
                // Cursor highlighting - use pink/magenta with bold and reverse for better terminal visibility
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(ratatui::style::Modifier::BOLD | ratatui::style::Modifier::REVERSED)
            } else if is_latest {
                // Latest message highlighting
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(ratatui::style::Modifier::BOLD)
            } else {
                // Normal style
                Style::default().fg(Color::White)
            };

            // Add each line of the trace
            for (line_index, line) in wrapped_lines.iter().enumerate() {
                if line_index == 0 {
                    // First line - use the full styled message
                    all_items.push(ListItem::new(Line::from(vec![Span::styled(
                        line.clone(),
                        final_style,
                    )])));
                } else {
                    // Continuation lines - indent and use same style
                    let indent = " ".repeat(4); // Simple 4-space indent
                    all_items.push(ListItem::new(Line::from(vec![Span::styled(
                        format!("{}{}", indent, line),
                        final_style,
                    )])));
                }
            }
        }

        // Apply scrolling based on display mode
        let available_height = area.height.saturating_sub(2); // Subtract borders

        match self.display_mode {
            DisplayMode::AutoRefresh => {
                // Auto-refresh mode: always show latest events
                if all_items.len() > available_height as usize {
                    self.scroll_offset = all_items.len().saturating_sub(available_height as usize);
                }
            }
            DisplayMode::Scroll => {
                // Scroll mode: ensure cursor trace is visible
                self.ensure_cursor_visible(all_items.len(), available_height as usize, content_width as usize);
            }
        }

        // Ensure cursor trace index is within bounds
        if self.cursor_trace_index >= self.trace_events.len() {
            self.cursor_trace_index = self.trace_events.len().saturating_sub(1);
        }

        let visible_items: Vec<_> = all_items.into_iter().skip(self.scroll_offset).collect();

        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let list = List::new(visible_items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(if is_focused {
                    BorderType::Thick
                } else {
                    BorderType::Plain
                })
                .title(format!(
                    "eBPF Trace Output ({} events)",
                    self.trace_events.len()
                ))
                .border_style(border_style),
        );

        frame.render_widget(list, area);
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
}

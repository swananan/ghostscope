use chrono::{DateTime, Local, TimeZone, Timelike, Utc};
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem},
    Frame,
};
use std::collections::VecDeque;

use ghostscope_protocol::EventData;

pub struct EbpfInfoPanel {
    pub trace_events: VecDeque<EventData>,
    pub scroll_offset: usize,
    pub max_messages: usize,
    pub auto_scroll: bool,
}

impl EbpfInfoPanel {
    pub fn new() -> Self {
        Self {
            trace_events: VecDeque::new(),
            scroll_offset: 0,
            max_messages: 2000, // TODO: Make this configurable in the future
            auto_scroll: true,
        }
    }

    pub fn add_trace_event(&mut self, trace_event: EventData) {
        self.trace_events.push_back(trace_event);
        if self.trace_events.len() > self.max_messages {
            self.trace_events.pop_front();
        }

        if self.auto_scroll {
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
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let mut all_items = Vec::new();

        // Calculate content width for text wrapping (subtract borders and padding)
        let content_width = area.width.saturating_sub(6); // 2 for borders + 4 for padding

        // Add trace events with clean, simple formatting
        let total_traces = self.trace_events.len();
        for (trace_index, trace) in self.trace_events.iter().enumerate() {
            let is_latest = trace_index == total_traces - 1;

            // Create the main message line with enhanced information
            let mut message_line = format!(
                "{} [TraceID:{}] PID:{} TID:{} [{:?}]",
                trace.readable_timestamp, trace.trace_id, trace.pid, trace.tid, trace.message_type
            );

            // Add variable information if available
            if !trace.variables.is_empty() {
                let variables_info = trace
                    .variables
                    .iter()
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

            // Apply highlighting for latest message, use white for non-latest messages
            let final_style = if is_latest {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(ratatui::style::Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            // Add each line
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

        // Apply scrolling with auto-scroll to latest events when area is full
        let available_height = area.height.saturating_sub(2); // Subtract borders

        // If auto-scroll is enabled and we have more items than can fit,
        // adjust scroll offset to show the latest events
        if self.auto_scroll && all_items.len() > available_height as usize {
            self.scroll_offset = all_items.len().saturating_sub(available_height as usize);
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

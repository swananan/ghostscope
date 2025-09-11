// Removed unused chrono imports
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};
use std::collections::VecDeque;

use ghostscope_protocol::EventData;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DisplayMode {
    AutoRefresh, // Default mode: always show latest trace, auto-scroll
    Scroll,      // Manual mode: show cursor, manual navigation
}

pub struct EbpfInfoPanel {
    pub trace_events: VecDeque<EventData>,
    pub scroll_offset: usize,
    pub max_messages: usize,
    pub auto_scroll: bool,
    pub cursor_trace_index: usize, // Index of the selected trace (not line)
    pub show_cursor: bool,         // Whether to show cursor highlighting
    pub display_mode: DisplayMode, // Current display mode
    pub next_message_number: u64,  // Next message number to assign
    // Numeric jump input for N+G
    pub numeric_prefix: Option<String>,
    pub g_pressed: bool, // whether first 'g' was pressed (for 'gg')
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
            next_message_number: 1, // Start from 1
            numeric_prefix: None,
            g_pressed: false,
        }
    }

    pub fn add_trace_event(&mut self, mut trace_event: EventData) {
        // Assign message number
        trace_event.message_number = self.next_message_number;
        self.next_message_number += 1;

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

    // Jump to first trace (gg)
    pub fn jump_to_first(&mut self) {
        self.enter_scroll_mode();
        self.cursor_trace_index = 0;
    }

    // Jump to last trace (G without prefix)
    pub fn jump_to_last(&mut self) {
        self.enter_scroll_mode();
        self.cursor_trace_index = self.trace_events.len().saturating_sub(1);
    }

    // Start or append numeric prefix for N G
    pub fn push_numeric_digit(&mut self, ch: char) {
        if ch.is_ascii_digit() {
            self.enter_scroll_mode();
            let s = self.numeric_prefix.get_or_insert_with(String::new);
            if s.len() < 9 {
                s.push(ch);
            }
            // typing number cancels pending 'g'
            self.g_pressed = false;
        }
    }

    // Confirm 'G' action: if numeric prefix present, jump to that message number; else jump to last
    pub fn confirm_goto(&mut self) {
        if let Some(s) = self.numeric_prefix.take() {
            if let Ok(num) = s.parse::<u64>() {
                self.jump_to_message_number(num);
                return;
            }
        }
        self.jump_to_last();
    }

    // Jump to specific message number (1-based). Clamp to [first,last]
    pub fn jump_to_message_number(&mut self, message_number: u64) {
        self.enter_scroll_mode();
        if self.trace_events.is_empty() {
            self.cursor_trace_index = 0;
            return;
        }
        let mut target_idx = None;
        for (idx, ev) in self.trace_events.iter().enumerate() {
            if ev.message_number >= message_number {
                target_idx = Some(idx);
                break;
            }
        }
        let idx = target_idx.unwrap_or_else(|| self.trace_events.len().saturating_sub(1));
        self.cursor_trace_index = idx;
    }

    // Exit to auto-refresh (ESC)
    pub fn exit_to_auto_refresh(&mut self) {
        self.numeric_prefix = None;
        self.g_pressed = false;
        self.hide_cursor();
        self.scroll_to_bottom();
    }

    // Handle 'g' key (support 'gg')
    pub fn handle_g_key(&mut self) {
        self.enter_scroll_mode();
        if self.g_pressed {
            self.g_pressed = false;
            self.jump_to_first();
        } else {
            self.g_pressed = true;
        }
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
    fn ensure_cursor_visible(
        &mut self,
        total_items: usize,
        available_height: usize,
        content_width: usize,
    ) {
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
            let message_type_short = match trace.message_type {
                ghostscope_protocol::EventMessageType::VariableData => "VAR",
                ghostscope_protocol::EventMessageType::Log => "LOG",
                ghostscope_protocol::EventMessageType::ExecutionFailure => "ERR",
                ghostscope_protocol::EventMessageType::Unknown => "UNK",
            };

            let mut message_line = format!(
                "{} [No:{}] TraceID:{} PID:{} TID:{} [{}]",
                trace.readable_timestamp,
                trace.message_number,
                trace.trace_id,
                trace.pid,
                trace.tid,
                message_type_short
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
        // Outer panel block
        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };
        let panel_block = Block::default()
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
            .border_style(border_style);
        frame.render_widget(panel_block, area);

        // Content area inside outer border
        if area.width <= 2 || area.height <= 2 {
            return;
        }
        let content_area = Rect {
            x: area.x + 1,
            y: area.y + 1,
            width: area.width - 2,
            height: area.height - 2,
        };
        let content_width = content_area.width as usize;

        // Pre-compute card heights and bodies
        struct Card {
            header_no_bold: String,
            header_number: String,
            header_rest: String,
            body_lines: Vec<Line<'static>>,
            total_height: u16,
            is_error: bool,
            is_latest: bool,
        }
        let mut cards: Vec<Card> = Vec::new();

        let total_traces = self.trace_events.len();
        for (trace_index, trace) in self.trace_events.iter().enumerate() {
            let is_latest = trace_index == total_traces - 1;
            let is_error = matches!(
                trace.message_type,
                ghostscope_protocol::EventMessageType::ExecutionFailure
            );

            // Header: remove type tag per request
            // Header parts: only number should be bold -> split into two strings
            let header_no_bold = String::from("[No:");
            let header_number = format!("{}", trace.message_number);
            let header_rest = format!(
                "] {} TraceID:{} PID:{} TID:{}",
                trace.readable_timestamp, trace.trace_id, trace.pid, trace.tid
            );

            let mut body_lines: Vec<Line> = Vec::new();
            // Variables: show as key-value pairs, no "vars:" label; values bold
            if !trace.variables.is_empty() {
                let indent = "  ";
                for var in &trace.variables {
                    let name = &var.name;
                    let value = &var.formatted_value;
                    let name_prefix = format!("{}{}: ", indent, name);
                    let name_prefix_width = name_prefix.len();
                    let wrap_width = content_width.saturating_sub(name_prefix_width);
                    let wrapped_vals = self.wrap_text(value, wrap_width);
                    for (i, seg) in wrapped_vals.into_iter().enumerate() {
                        if i == 0 {
                            body_lines.push(Line::from(vec![
                                Span::styled(
                                    name_prefix.clone(),
                                    Style::default().fg(Color::DarkGray),
                                ),
                                Span::styled(
                                    seg,
                                    Style::default()
                                        .fg(Color::White)
                                        .add_modifier(Modifier::BOLD),
                                ),
                            ]));
                        } else {
                            body_lines.push(Line::from(vec![
                                Span::styled(
                                    " ".repeat(name_prefix_width),
                                    Style::default().fg(Color::DarkGray),
                                ),
                                Span::styled(
                                    seg,
                                    Style::default()
                                        .fg(Color::White)
                                        .add_modifier(Modifier::BOLD),
                                ),
                            ]));
                        }
                    }
                }
            }
            // Log
            if let Some(log_msg) = &trace.log_message {
                let prefix = "log: ";
                let wrapped =
                    self.wrap_text(log_msg, content_width.saturating_sub(2 + prefix.len()));
                for (i, seg) in wrapped.into_iter().enumerate() {
                    let indent = "  ";
                    if i == 0 {
                        body_lines.push(Line::from(vec![
                            Span::raw(indent),
                            Span::styled(prefix, Style::default().fg(Color::DarkGray)),
                            Span::styled(
                                seg,
                                Style::default()
                                    .fg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            ),
                        ]));
                    } else {
                        body_lines.push(Line::from(vec![
                            Span::raw(indent),
                            Span::styled(
                                " ".repeat(prefix.len()),
                                Style::default().fg(Color::DarkGray),
                            ),
                            Span::styled(
                                seg,
                                Style::default()
                                    .fg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            ),
                        ]));
                    }
                }
            }
            // Failure
            if let Some(failure_msg) = &trace.failure_message {
                let prefix = "failure: ";
                let wrapped =
                    self.wrap_text(failure_msg, content_width.saturating_sub(2 + prefix.len()));
                for (i, seg) in wrapped.into_iter().enumerate() {
                    let indent = "  ";
                    if i == 0 {
                        body_lines.push(Line::from(vec![
                            Span::raw(indent),
                            Span::styled(prefix, Style::default().fg(Color::DarkGray)),
                            Span::styled(
                                seg,
                                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                            ),
                        ]));
                    } else {
                        body_lines.push(Line::from(vec![
                            Span::raw(indent),
                            Span::styled(
                                " ".repeat(prefix.len()),
                                Style::default().fg(Color::DarkGray),
                            ),
                            Span::styled(
                                seg,
                                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                            ),
                        ]));
                    }
                }
            }

            // Minimum inner height is at least 1 line body (even if empty)
            let inner_height = u16::max(1, body_lines.len() as u16);
            // Card total height includes borders
            let total_height = inner_height + 2;
            cards.push(Card {
                header_no_bold,
                header_number,
                header_rest,
                body_lines,
                total_height,
                is_error,
                is_latest,
            });
        }

        // Determine starting card index based on mode and cursor visibility
        let mut start_index = 0usize;
        let viewport_height = content_area.height;
        match self.display_mode {
            DisplayMode::AutoRefresh => {
                // Fit as many cards from the end as possible
                let mut h: u16 = 0;
                start_index = cards.len();
                while start_index > 0 {
                    let next_h = h.saturating_add(cards[start_index - 1].total_height);
                    if next_h > viewport_height {
                        break;
                    }
                    h = next_h;
                    start_index -= 1;
                }
            }
            DisplayMode::Scroll => {
                // Ensure cursor card is fully visible
                let cursor = self.cursor_trace_index.min(cards.len().saturating_sub(1));
                // Try to place cursor card slightly below center if possible
                let mut h_below: u16 = 0;
                let mut end = cursor;
                while end < cards.len() {
                    let ch = cards[end].total_height;
                    if h_below + ch > viewport_height {
                        break;
                    }
                    h_below += ch;
                    end += 1;
                }
                let mut h_above: u16 = 0;
                let mut i = cursor;
                while i > 0 {
                    let ch = cards[i - 1].total_height;
                    if h_above + h_below + ch > viewport_height {
                        break;
                    }
                    h_above += ch;
                    i -= 1;
                }
                start_index = i;
            }
        }

        // Render visible cards
        let mut y = content_area.y;
        for (idx, card) in cards.iter().enumerate().skip(start_index) {
            if y >= content_area.y + content_area.height {
                break;
            }
            let height = card
                .total_height
                .min(content_area.y + content_area.height - y);
            if height < 2 {
                break;
            }

            let is_cursor = self.show_cursor && idx == self.cursor_trace_index;
            let title_style = Style::default().add_modifier(Modifier::BOLD);

            let mut border_style = Style::default();
            let mut border_type = BorderType::Plain;
            if is_cursor {
                border_style = Style::default().fg(Color::Yellow);
                border_type = BorderType::Thick;
            } else if card.is_latest {
                border_style = Style::default().fg(Color::Green);
                border_type = BorderType::Thick;
            } else if card.is_error {
                border_style = Style::default().fg(Color::Red);
            }

            // Title text color follows border color for latest or focused cards; otherwise gray
            let title_color = if is_cursor {
                Color::Yellow
            } else if card.is_latest {
                Color::Green
            } else {
                Color::Gray
            };

            let card_block = Block::default()
                .borders(Borders::ALL)
                .border_type(border_type)
                .border_style(border_style)
                .title(Line::from(vec![
                    Span::styled(
                        card.header_no_bold.clone(),
                        Style::default().fg(title_color),
                    ),
                    Span::styled(
                        card.header_number.clone(),
                        Style::default()
                            .fg(Color::LightMagenta)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(card.header_rest.clone(), Style::default().fg(title_color)),
                ]));

            let card_area = Rect {
                x: content_area.x,
                y,
                width: content_area.width,
                height,
            };
            frame.render_widget(card_block, card_area);

            // Inner area
            if card_area.width > 2 && card_area.height > 2 {
                let inner = Rect {
                    x: card_area.x + 1,
                    y: card_area.y + 1,
                    width: card_area.width - 2,
                    height: card_area.height - 2,
                };
                // Build Paragraph from visible body lines
                let max_body_lines = inner.height as usize;
                let body = if card.body_lines.is_empty() {
                    vec![Line::from("")]
                } else {
                    card.body_lines.clone()
                };
                let lines = body.into_iter().take(max_body_lines).collect::<Vec<_>>();
                let para = Paragraph::new(lines);
                frame.render_widget(para, inner);
            }

            y = y.saturating_add(height);
        }

        // Render numeric prefix or 'g' hint (style consistent with SourceCode panel)
        if self.g_pressed || self.numeric_prefix.is_some() {
            let input_text = if let Some(ref s) = self.numeric_prefix {
                format!("{}G", s)
            } else {
                "g".to_string()
            };
            let hint_text = if self.g_pressed && self.numeric_prefix.is_none() {
                " Press 'g' again for top"
            } else if self.numeric_prefix.is_some() {
                " Press 'G' to jump to message"
            } else {
                ""
            };
            let full_text = if hint_text.is_empty() {
                input_text.clone()
            } else {
                format!("{} ({})", input_text, &hint_text[1..])
            };

            let text_width = full_text.len() as u16;
            let display_x = content_area.x + content_area.width.saturating_sub(text_width + 2);
            let display_y = content_area.y + content_area.height.saturating_sub(1);

            let mut spans = vec![Span::styled(
                input_text,
                Style::default().fg(Color::Green).bg(Color::Rgb(30, 30, 30)),
            )];
            if !hint_text.is_empty() {
                spans.push(Span::styled(
                    format!(" ({})", &hint_text[1..]),
                    Style::default()
                        .fg(border_style.fg.unwrap_or(Color::White))
                        .bg(Color::Rgb(30, 30, 30)),
                ));
            }

            let text = ratatui::text::Text::from(ratatui::text::Line::from(spans));
            frame.render_widget(
                ratatui::widgets::Paragraph::new(text).alignment(ratatui::layout::Alignment::Right),
                Rect::new(display_x, display_y, text_width + 2, 1),
            );
        }
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

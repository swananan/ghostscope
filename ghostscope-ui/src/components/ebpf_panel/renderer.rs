use crate::model::panel_state::{DisplayMode, EbpfPanelState};
use crate::ui::themes::UIThemes;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};

/// Renders the eBPF output panel
#[derive(Debug)]
pub struct EbpfPanelRenderer;

impl EbpfPanelRenderer {
    pub fn new() -> Self {
        Self
    }

    /// Render the eBPF panel
    pub fn render(
        &mut self,
        state: &mut EbpfPanelState,
        frame: &mut Frame,
        area: Rect,
        is_focused: bool,
    ) {
        // Outer panel block
        let border_style = if is_focused {
            UIThemes::panel_focused()
        } else {
            UIThemes::panel_unfocused()
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
                state.trace_events.len()
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

        let total_traces = state.trace_events.len();
        for (trace_index, cached_trace) in state.trace_events.iter().enumerate() {
            let trace = &cached_trace.event;
            let is_latest = trace_index == total_traces - 1;
            // Check execution status from EndInstruction
            let is_error = trace.instructions.last().is_some_and(|inst| {
                if let ghostscope_protocol::ParsedInstruction::EndInstruction {
                    execution_status,
                    ..
                } = inst
                {
                    *execution_status == 1 || *execution_status == 2
                } else {
                    false
                }
            });

            // Header: remove type tag per request
            // Header parts: only number should be bold -> split into two strings
            let header_no_bold = String::from("[No:");
            let message_id = (trace_index + 1) as u64; // Simple sequential numbering
            let formatted_timestamp = &cached_trace.formatted_timestamp; // Use cached timestamp
            let header_number = message_id.to_string();
            let header_rest = format!(
                "] {} TraceID:{} PID:{} TID:{}",
                formatted_timestamp, trace.trace_id, trace.pid, trace.tid
            );

            let mut body_lines: Vec<Line> = Vec::new();

            // Use formatted output for better display (same as CLI)
            let formatted_output = trace.to_formatted_output();
            let indent = "  ";

            // Display formatted output lines using to_formatted_output()
            for output_line in formatted_output {
                let color = if output_line.contains("ERROR") || output_line.contains("Error") {
                    Color::Red
                } else if output_line.contains("WARN") || output_line.contains("Warning") {
                    Color::Yellow
                } else {
                    Color::Cyan
                };

                // Wrap long output lines
                let wrap_width = content_width.saturating_sub(indent.len());
                let wrapped_lines = Self::wrap_text(&output_line, wrap_width);

                for (i, seg) in wrapped_lines.into_iter().enumerate() {
                    let line_indent = if i == 0 { indent } else { "    " }; // Extra indent for continuation
                    body_lines.push(Line::from(vec![
                        Span::raw(line_indent),
                        Span::styled(
                            seg,
                            Style::default().fg(color).add_modifier(Modifier::empty()),
                        ),
                    ]));
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
        let viewport_height = content_area.height;
        let start_index = match state.display_mode {
            DisplayMode::AutoRefresh => {
                let mut accumulated: u16 = 0;
                let mut idx = cards.len();
                while idx > 0 {
                    let next_height = accumulated.saturating_add(cards[idx - 1].total_height);
                    if next_height > viewport_height {
                        break;
                    }
                    accumulated = next_height;
                    idx -= 1;
                }
                idx
            }
            DisplayMode::Scroll => {
                let cursor = state.cursor_trace_index.min(cards.len().saturating_sub(1));
                let mut height_below: u16 = 0;
                let mut end = cursor;
                while end < cards.len() {
                    let card_height = cards[end].total_height;
                    if height_below + card_height > viewport_height {
                        break;
                    }
                    height_below += card_height;
                    end += 1;
                }

                let mut height_above: u16 = 0;
                let mut idx = cursor;
                while idx > 0 {
                    let card_height = cards[idx - 1].total_height;
                    if height_above + height_below + card_height > viewport_height {
                        break;
                    }
                    height_above += card_height;
                    idx -= 1;
                }
                idx
            }
        };

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

            let is_cursor = state.show_cursor && idx == state.cursor_trace_index;

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
        if state.g_pressed || state.numeric_prefix.is_some() {
            let input_text = if let Some(ref s) = state.numeric_prefix {
                s.clone()
            } else {
                "g".to_string()
            };
            let hint_text = if state.g_pressed && state.numeric_prefix.is_none() {
                " Press 'g' again for top"
            } else if state.numeric_prefix.is_some() {
                " Press 'G' to jump to message"
            } else {
                ""
            };
            let full_text = if hint_text.is_empty() {
                input_text.clone()
            } else {
                let hint_body = &hint_text[1..];
                format!("{input_text} ({hint_body})")
            };

            let text_width = full_text.len() as u16;
            let display_x = content_area.x + content_area.width.saturating_sub(text_width + 2);
            let display_y = content_area.y + content_area.height.saturating_sub(1);

            let mut spans = vec![Span::styled(
                input_text,
                Style::default().fg(Color::Green).bg(Color::Rgb(30, 30, 30)),
            )];
            if !hint_text.is_empty() {
                let hint_body = &hint_text[1..];
                spans.push(Span::styled(
                    format!(" ({hint_body})"),
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
    fn wrap_text(text: &str, width: usize) -> Vec<String> {
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

impl Default for EbpfPanelRenderer {
    fn default() -> Self {
        Self::new()
    }
}

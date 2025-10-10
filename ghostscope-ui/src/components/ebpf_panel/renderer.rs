use crate::model::panel_state::{DisplayMode, EbpfPanelState, EbpfViewMode};
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

        // Build cards
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

            let header_no_bold = String::from("[No:");
            let message_id = (trace_index + 1) as u64;
            let formatted_timestamp = &cached_trace.formatted_timestamp;
            let header_number = message_id.to_string();
            let header_rest = format!(
                "] {} TraceID:{} PID:{} TID:{}",
                formatted_timestamp, trace.trace_id, trace.pid, trace.tid
            );

            let mut body_lines: Vec<Line> = Vec::new();
            for output_line in trace.to_formatted_output() {
                let color = if output_line.contains("ERROR") || output_line.contains("Error") {
                    Color::Red
                } else if output_line.contains("WARN") || output_line.contains("Warning") {
                    Color::Yellow
                } else {
                    Color::Cyan
                };
                // Compute wrapping widths based on card inner width and indent per line
                let inner_width = content_width.saturating_sub(2);
                let first_width = inner_width.saturating_sub(2); // first line indent "  "
                let cont_width = inner_width.saturating_sub(4); // continuation indent "    "
                let wrapped_lines =
                    Self::wrap_text_with_widths(&output_line, first_width, cont_width);
                for (i, seg) in wrapped_lines.into_iter().enumerate() {
                    let line_indent = if i == 0 { "  " } else { "    " };
                    body_lines.push(Line::from(vec![
                        Span::raw(line_indent),
                        Span::styled(
                            seg,
                            Style::default().fg(color).add_modifier(Modifier::empty()),
                        ),
                    ]));
                }
            }

            // In list view: truncate to 3 body lines (with ellipsis) to keep card compact
            let (body_for_display, inner_height): (Vec<Line>, u16) = match state.view_mode {
                EbpfViewMode::List => {
                    let mut b = Vec::new();
                    if body_lines.is_empty() {
                        b.push(Line::from(""));
                    } else {
                        let max_body = 3usize;
                        let truncated = body_lines.len() > max_body;
                        let take_n = body_lines.len().min(max_body);
                        b.extend(body_lines.iter().take(take_n).cloned());
                        if truncated {
                            if let Some(last) = b.last_mut() {
                                // Make ellipsis more eye-catching and prevent wrap from hiding it
                                let ellipsis = Span::styled(
                                    " …",
                                    Style::default()
                                        .fg(Color::Yellow)
                                        .add_modifier(Modifier::BOLD),
                                );
                                if last.spans.len() >= 2 {
                                    let indent = last.spans[0].content.clone();
                                    let style = last.spans[1].style;
                                    let original = last.spans[1].content.to_string();
                                    // Reserve 2 characters (space + ellipsis) using char-safe trimming
                                    let trimmed = Self::trim_chars_from_end(&original, 2);
                                    last.spans.clear();
                                    last.spans.push(Span::raw(indent));
                                    last.spans.push(Span::styled(trimmed, style));
                                    last.spans.push(ellipsis);
                                } else {
                                    last.spans.push(ellipsis);
                                }
                            }
                        }
                    }
                    (b.clone(), u16::max(1, b.len() as u16))
                }
                EbpfViewMode::Expanded { .. } => {
                    (body_lines.clone(), u16::max(1, body_lines.len() as u16))
                }
            };
            let total_height = inner_height + 2;
            cards.push(Card {
                header_no_bold,
                header_number,
                header_rest,
                body_lines: body_for_display,
                total_height,
                is_error,
                is_latest,
            });
        }

        // Expanded view: render only selected card full-screen with scroll
        if let EbpfViewMode::Expanded { index, scroll } = state.view_mode {
            if let Some(card) = cards.get(index) {
                let border_style_l = Style::default().fg(Color::Green);
                let title_color = Color::Green;
                let card_block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Thick)
                    .border_style(border_style_l)
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
                frame.render_widget(card_block, content_area);

                if content_area.width > 2 && content_area.height > 2 {
                    // reserve 1 line for hint at bottom
                    let hint_h: u16 = 1;
                    let inner_h = content_area.height.saturating_sub(2 + hint_h);
                    let inner = Rect {
                        x: content_area.x + 1,
                        y: content_area.y + 1,
                        width: content_area.width - 2,
                        height: inner_h,
                    };
                    // update last_inner_height for half-page scroll
                    state.last_inner_height = inner.height as usize;
                    let max_body_lines = inner.height as usize;
                    let total = card.body_lines.len();
                    let max_scroll = total.saturating_sub(max_body_lines);
                    let start = scroll.min(max_scroll);
                    let end = (start + max_body_lines).min(total);
                    // Normalize scroll state to avoid accumulating beyond bounds
                    if start != scroll {
                        state.set_expanded_scroll(start);
                    }
                    let lines = card.body_lines[start..end].to_vec();
                    let para = Paragraph::new(lines);
                    frame.render_widget(para, inner);
                    // hint
                    let hint_rect = Rect {
                        x: content_area.x + 1,
                        y: content_area.y + content_area.height.saturating_sub(1),
                        width: content_area.width.saturating_sub(2),
                        height: 1,
                    };
                    let hint = "Esc/Ctrl+C to exit  •  j/k/↑/↓ scroll  •  Ctrl+U/D half-page  •  PgUp/PgDn page";
                    let hint_line =
                        Line::from(Span::styled(hint, Style::default().fg(Color::Gray)));
                    let hint_para = Paragraph::new(vec![hint_line]);
                    frame.render_widget(hint_para, hint_rect);
                }
            }
            return;
        }

        // Determine start index based on mode (keep previous behavior)
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

        // Render cards: clamp within viewport and keep order
        let mut y = content_area.y;
        for (idx, card) in cards.iter().enumerate().skip(start_index) {
            if y >= content_area.y + content_area.height {
                break;
            }
            // Clamp card height to remaining viewport to avoid rendering outside buffer
            let remaining = (content_area.y + content_area.height).saturating_sub(y);
            let height = card.total_height.min(remaining);
            if height < 2 {
                break;
            }

            let is_cursor = state.show_cursor && idx == state.cursor_trace_index;
            let mut border_style_l = Style::default();
            let mut border_type = BorderType::Plain;
            if is_cursor {
                border_style_l = Style::default().fg(Color::Yellow);
                border_type = BorderType::Thick;
            } else if card.is_latest {
                border_style_l = Style::default().fg(Color::Green);
                border_type = BorderType::Thick;
            } else if card.is_error {
                border_style_l = Style::default().fg(Color::Red);
            }
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
                .border_style(border_style_l)
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

            if card_area.width > 2 && card_area.height > 2 {
                let inner = Rect {
                    x: card_area.x + 1,
                    y: card_area.y + 1,
                    width: card_area.width - 2,
                    height: card_area.height - 2,
                };
                let body = if card.body_lines.is_empty() {
                    vec![Line::from("")]
                } else {
                    card.body_lines.clone()
                };
                let para = Paragraph::new(body);
                frame.render_widget(para, inner);
            }

            y = y.saturating_add(height);
        }

        // Auxiliary hint (keep original behavior)
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

    /// Wrap text with different widths for first and continuation lines
    fn wrap_text_with_widths(text: &str, first_width: usize, cont_width: usize) -> Vec<String> {
        if text.is_empty() {
            return vec![String::new()];
        }

        let fw = first_width.max(1);
        let cw = cont_width.max(1);
        let mut width = fw;
        let mut lines = Vec::new();
        let mut current_line = String::new();

        for ch in text.chars() {
            if ch == '\n' {
                lines.push(current_line);
                current_line = String::new();
                width = cw; // after first explicit break, use continuation width
                continue;
            }
            if current_line.len() >= width {
                lines.push(std::mem::take(&mut current_line));
                width = cw; // subsequent lines use continuation width
            }
            current_line.push(ch);
        }

        lines.push(current_line);
        lines
    }

    /// Trim the last `n` characters from a UTF-8 string safely (by char boundary)
    fn trim_chars_from_end(s: &str, n: usize) -> String {
        if n == 0 || s.is_empty() {
            return s.to_string();
        }
        let mut end = s.len();
        let mut iter = s.char_indices().rev();
        for _ in 0..n {
            if let Some((idx, _)) = iter.next() {
                end = idx;
            } else {
                end = 0;
                break;
            }
        }
        s[..end].to_string()
    }
}

impl Default for EbpfPanelRenderer {
    fn default() -> Self {
        Self::new()
    }
}

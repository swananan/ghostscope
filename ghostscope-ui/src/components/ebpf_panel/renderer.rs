use crate::events::{BacktraceDisplay, BacktraceDisplayFrame, TraceDisplayItem};
use crate::model::panel_state::{DisplayMode, EbpfPanelState, EbpfViewMode};
use crate::ui::themes::UIThemes;
use ghostscope_protocol::trace_event::BacktraceStatus;
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
            let is_error = trace.is_error();

            let header_no_bold = String::from("[No:");
            let message_id = (trace_index + 1) as u64;
            let formatted_timestamp = &cached_trace.formatted_timestamp;
            let header_number = message_id.to_string();
            let header_rest = format!(
                "] {} TraceID:{} PID:{} TID:{}",
                formatted_timestamp, trace.trace_id, trace.pid, trace.tid
            );

            let mut body_lines: Vec<Line> = Vec::new();
            for item in &trace.items {
                body_lines.extend(Self::render_trace_item(
                    item,
                    content_width,
                    state.view_mode,
                ));
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

    fn render_trace_item(
        item: &TraceDisplayItem,
        content_width: usize,
        view_mode: EbpfViewMode,
    ) -> Vec<Line<'static>> {
        match item {
            TraceDisplayItem::Text { content } => Self::render_text_item(content, content_width),
            TraceDisplayItem::FormattedText { content } => {
                Self::render_text_item(content, content_width)
            }
            TraceDisplayItem::Variable(variable) => {
                Self::render_text_item(&variable.to_formatted_output(), content_width)
            }
            TraceDisplayItem::ComplexVariable(variable) => {
                Self::render_text_item(&variable.to_formatted_output(), content_width)
            }
            TraceDisplayItem::ExprError(error) => {
                Self::render_text_item(&error.to_formatted_output(), content_width)
            }
            TraceDisplayItem::Backtrace(backtrace) => Self::render_backtrace_item(
                backtrace,
                matches!(view_mode, EbpfViewMode::Expanded { .. }),
                content_width,
            ),
        }
    }

    fn render_text_item(content: &str, content_width: usize) -> Vec<Line<'static>> {
        let color = if content.contains("ERROR") || content.contains("Error") {
            Color::Red
        } else if content.contains("WARN") || content.contains("Warning") {
            Color::Yellow
        } else {
            Color::Cyan
        };
        let inner_width = content_width.saturating_sub(2);
        let first_width = inner_width.saturating_sub(2);
        let cont_width = inner_width.saturating_sub(4);
        Self::wrap_text_with_widths(content, first_width, cont_width)
            .into_iter()
            .enumerate()
            .map(|(i, seg)| {
                let line_indent = if i == 0 { "  " } else { "    " };
                Line::from(vec![
                    Span::raw(line_indent),
                    Span::styled(seg, Style::default().fg(color)),
                ])
            })
            .collect()
    }

    fn render_backtrace_item(
        backtrace: &BacktraceDisplay,
        expanded: bool,
        content_width: usize,
    ) -> Vec<Line<'static>> {
        let line_width = content_width.saturating_sub(2).max(1);
        let mut lines = Vec::new();
        lines.push(Self::render_backtrace_header(backtrace));

        if expanded {
            lines.extend(backtrace.frames.iter().map(Self::render_backtrace_frame));
            if let Some(stopped) = backtrace.stopped_text() {
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(stopped, Self::status_style(backtrace.status)),
                ]));
            }
            return lines
                .into_iter()
                .flat_map(|line| Self::wrap_styled_line(line, line_width, "    "))
                .collect();
        } else if backtrace.frames.len() > 2 {
            if let Some(first) = backtrace.frames.first() {
                let first_frame =
                    Self::wrap_styled_line(Self::render_backtrace_frame(first), line_width, "    ");
                if let Some(first_line) = first_frame.into_iter().next() {
                    lines.push(first_line);
                }
            }
            lines.push(Self::render_backtrace_more_line(
                backtrace.frames.len().saturating_sub(1),
            ));
            return lines;
        } else {
            lines.extend(backtrace.frames.iter().map(Self::render_backtrace_frame));
            if lines.len() < 3 {
                if let Some(stopped) = backtrace.stopped_text() {
                    lines.push(Line::from(vec![
                        Span::raw("  "),
                        Span::styled(stopped, Self::status_style(backtrace.status)),
                    ]));
                }
            }
        }

        lines
            .into_iter()
            .flat_map(|line| Self::wrap_styled_line(line, line_width, "    "))
            .collect()
    }

    fn wrap_styled_line(
        line: Line<'static>,
        width: usize,
        continuation_indent: &'static str,
    ) -> Vec<Line<'static>> {
        let width = width.max(1);
        let indent_width = continuation_indent.chars().count();
        if width <= indent_width {
            return vec![line];
        }

        let mut wrapped = Vec::new();
        let mut current = Vec::new();
        let mut current_len = 0usize;
        let mut continuation = false;

        for span in line.spans {
            let style = span.style;
            let mut remaining = span.content.into_owned();
            while !remaining.is_empty() {
                if current_len >= width {
                    wrapped.push(Line::from(current));
                    current = vec![Span::raw(continuation_indent)];
                    current_len = indent_width;
                    continuation = true;
                }

                let available = width.saturating_sub(current_len);
                if available == 0 {
                    wrapped.push(Line::from(current));
                    current = vec![Span::raw(continuation_indent)];
                    current_len = indent_width;
                    continuation = true;
                    continue;
                }

                let (segment, rest) = Self::split_prefix_chars(&remaining, available);
                current_len += segment.chars().count();
                current.push(Span::styled(segment, style));
                remaining = rest;
            }
        }

        if current.is_empty() {
            if continuation {
                wrapped.push(Line::from(vec![Span::raw(continuation_indent)]));
            }
        } else {
            wrapped.push(Line::from(current));
        }
        wrapped
    }

    fn split_prefix_chars(text: &str, max_chars: usize) -> (String, String) {
        if max_chars == 0 {
            return (String::new(), text.to_string());
        }

        let mut split = text.len();
        for (count, (idx, _)) in text.char_indices().enumerate() {
            if count == max_chars {
                split = idx;
                break;
            }
        }
        (text[..split].to_string(), text[split..].to_string())
    }

    fn render_backtrace_header(backtrace: &BacktraceDisplay) -> Line<'static> {
        let frame_word = if backtrace.physical_frame_count == 1 {
            "frame"
        } else {
            "frames"
        };
        let mut spans = vec![
            Span::raw("  "),
            Span::styled(
                "backtrace",
                Style::default()
                    .fg(Color::LightBlue)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(": ", Style::default().fg(Color::Gray)),
            Span::styled(
                backtrace.status.label().to_string(),
                Self::status_style(backtrace.status),
            ),
            Span::styled(", ", Style::default().fg(Color::Gray)),
            Span::styled(
                backtrace.physical_frame_count.to_string(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" {frame_word}"), Style::default().fg(Color::Gray)),
            Span::styled(
                format!(" (max {})", backtrace.requested_depth),
                Style::default().fg(Color::DarkGray),
            ),
        ];
        if backtrace.raw {
            spans.push(Span::styled(" raw", Style::default().fg(Color::Yellow)));
        }
        Line::from(spans)
    }

    fn render_backtrace_frame(frame: &BacktraceDisplayFrame) -> Line<'static> {
        let mut spans = vec![
            Span::raw("  "),
            Span::styled(
                format!("#{}", frame.index),
                Style::default()
                    .fg(Color::LightBlue)
                    .add_modifier(Modifier::BOLD),
            ),
        ];
        if frame.inline {
            spans.push(Span::styled(
                ".inline",
                Style::default().fg(Color::LightBlue),
            ));
        }
        spans.push(Span::raw(" "));

        if let Some(function) = &frame.function {
            spans.push(Span::styled(
                function.clone(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ));
            if !frame.parameters.is_empty() {
                spans.push(Span::styled("(", Style::default().fg(Color::Gray)));
                for (idx, parameter) in frame.parameters.iter().enumerate() {
                    if idx > 0 {
                        spans.push(Span::styled(", ", Style::default().fg(Color::Gray)));
                    }
                    spans.extend(Self::render_parameter_spans(parameter));
                }
                spans.push(Span::styled(")", Style::default().fg(Color::Gray)));
            }
        } else {
            spans.push(Span::styled(
                frame
                    .address
                    .clone()
                    .unwrap_or_else(|| "<unknown function>".to_string()),
                Style::default().fg(Color::Yellow),
            ));
        }

        if let Some(location) = &frame.location {
            spans.push(Span::styled(" at ", Style::default().fg(Color::Gray)));
            spans.push(Span::styled(
                location.clone(),
                Style::default().fg(Color::Cyan),
            ));
        } else if frame.function.is_some() {
            spans.push(Span::styled(" at ??", Style::default().fg(Color::DarkGray)));
        }
        spans.push(Span::styled(" [", Style::default().fg(Color::Gray)));
        spans.push(Span::styled(
            frame.module.clone(),
            Style::default().fg(Color::LightYellow),
        ));
        spans.push(Span::styled("]", Style::default().fg(Color::Gray)));

        if let Some(raw_ip) = frame.raw_ip {
            spans.push(Span::styled(
                format!(" raw=0x{raw_ip:x}"),
                Style::default().fg(Color::DarkGray),
            ));
        }
        if let Some(cookie) = frame.cookie {
            spans.push(Span::styled(
                format!(" cookie=0x{cookie:016x}"),
                Style::default().fg(Color::DarkGray),
            ));
        }
        if let Some(flags) = frame.flags {
            spans.push(Span::styled(
                format!(" flags=0x{flags:x}"),
                Style::default().fg(Color::DarkGray),
            ));
        }

        Line::from(spans)
    }

    fn render_backtrace_more_line(hidden_frames: usize) -> Line<'static> {
        let frame_word = if hidden_frames == 1 {
            "frame"
        } else {
            "frames"
        };
        Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("... {hidden_frames} more {frame_word}"),
                Style::default().fg(Color::DarkGray),
            ),
        ])
    }

    fn render_parameter_spans(parameter: &str) -> Vec<Span<'static>> {
        let parameter = parameter.trim();
        if parameter.is_empty() {
            return Vec::new();
        }

        if let Some((type_name, name)) = parameter.rsplit_once(' ') {
            if !type_name.trim().is_empty() && !name.trim().is_empty() {
                return vec![
                    Span::styled(
                        type_name.trim().to_string(),
                        Style::default().fg(Color::LightMagenta),
                    ),
                    Span::raw(" "),
                    Span::styled(
                        name.trim().to_string(),
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                ];
            }
        }

        vec![Span::styled(
            parameter.to_string(),
            Style::default().fg(Color::LightMagenta),
        )]
    }

    fn status_style(status: BacktraceStatus) -> Style {
        match status {
            BacktraceStatus::Complete => Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
            BacktraceStatus::Truncated
            | BacktraceStatus::DwarfUnavailable
            | BacktraceStatus::UnsupportedCfi
            | BacktraceStatus::NoUnwindRowsForPc
            | BacktraceStatus::OffsetsUnavailable => Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            BacktraceStatus::ReadError
            | BacktraceStatus::InternalError
            | BacktraceStatus::InvalidFrame => {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            }
        }
    }
}

impl Default for EbpfPanelRenderer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    fn sample_backtrace(frame_count: usize) -> BacktraceDisplay {
        BacktraceDisplay {
            requested_depth: 128,
            physical_frame_count: frame_count,
            status: BacktraceStatus::Complete,
            error_code: 0,
            raw: false,
            frames: (0..frame_count)
                .map(|index| BacktraceDisplayFrame {
                    index,
                    inline: false,
                    function: Some(format!("function_{index}")),
                    parameters: vec!["ngx_http_request_s* r".to_string()],
                    address: None,
                    location: Some(format!("request.c:{}", 100 + index)),
                    module: format!("nginx+0x{:x}", 0x1000 + index),
                    raw_ip: None,
                    cookie: None,
                    flags: None,
                })
                .collect(),
        }
    }

    #[test]
    fn list_mode_renders_backtrace_as_compact_structured_item() {
        let item = TraceDisplayItem::Backtrace(sample_backtrace(4));
        let lines = EbpfPanelRenderer::render_trace_item(&item, 120, EbpfViewMode::List);

        assert_eq!(lines.len(), 3);
        assert!(line_text(&lines[0]).contains("backtrace: complete, 4 frames"));
        assert!(line_text(&lines[1]).contains("#0 function_0"));
        assert!(line_text(&lines[2]).contains("... 3 more frames"));
    }

    #[test]
    fn list_mode_keeps_backtrace_summary_when_first_frame_wraps() {
        let mut backtrace = sample_backtrace(4);
        backtrace.frames[0].function =
            Some("ngx_http_process_request_headers_with_a_long_suffix".to_string());
        backtrace.frames[0].parameters = vec!["ngx_http_request_s* request".to_string()];
        backtrace.frames[0].location = Some(
            "/mnt/500g/code/openresty/openresty-1.27.1.1/build/nginx/src/http/ngx_http_request.c:1529:13"
                .to_string(),
        );

        let item = TraceDisplayItem::Backtrace(backtrace);
        let lines = EbpfPanelRenderer::render_trace_item(&item, 48, EbpfViewMode::List);

        assert_eq!(lines.len(), 3);
        assert!(line_text(&lines[0]).contains("backtrace: complete, 4 frames"));
        assert!(line_text(&lines[1]).contains("#0 ngx_http_process"));
        assert!(line_text(&lines[2]).contains("... 3 more frames"));
    }

    #[test]
    fn expanded_mode_keeps_backtrace_status_and_parameters_structured() {
        let item = TraceDisplayItem::Backtrace(sample_backtrace(1));
        let lines = EbpfPanelRenderer::render_trace_item(
            &item,
            120,
            EbpfViewMode::Expanded {
                index: 0,
                scroll: 0,
            },
        );

        let frame = line_text(&lines[1]);
        assert!(frame.contains("function_0("));
        assert!(frame.contains("ngx_http_request_s* r"));
        assert!(frame.contains("request.c:100"));
        assert!(frame.contains("[nginx+0x1000]"));
    }

    #[test]
    fn expanded_backtrace_lines_wrap_to_panel_width() {
        let mut backtrace = sample_backtrace(1);
        backtrace.frames[0].function =
            Some("ngx_http_process_request_headers_with_a_long_suffix".to_string());
        backtrace.frames[0].parameters = vec![
            "ngx_http_request_s* request".to_string(),
            "long unsigned int flags".to_string(),
        ];
        backtrace.frames[0].location = Some(
            "/mnt/500g/code/openresty/openresty-1.27.1.1/build/nginx/src/http/ngx_http_request.c:1529:13"
                .to_string(),
        );

        let item = TraceDisplayItem::Backtrace(backtrace);
        let lines = EbpfPanelRenderer::render_trace_item(
            &item,
            48,
            EbpfViewMode::Expanded {
                index: 0,
                scroll: 0,
            },
        );

        assert!(
            lines.len() > 2,
            "narrow backtrace output should wrap long frame lines"
        );
        assert!(line_text(&lines[1]).contains("#0 ngx_http_process"));
        assert!(
            lines
                .iter()
                .skip(2)
                .map(line_text)
                .any(|line| line.starts_with("    ") && line.contains("request")),
            "wrapped continuation should keep parameter text with indentation"
        );
        assert!(
            lines
                .iter()
                .map(line_text)
                .any(|line| line.contains("ngx_http_request.c:1529:13")),
            "wrapped continuation should retain the source location"
        );
    }

    #[test]
    fn header_uses_physical_frame_count_for_inline_backtraces() {
        let mut backtrace = sample_backtrace(1);
        let mut inline_frame = backtrace.frames[0].clone();
        inline_frame.inline = true;
        inline_frame.function = Some("inlined_add".to_string());
        backtrace.frames.insert(0, inline_frame);

        let item = TraceDisplayItem::Backtrace(backtrace);
        let lines = EbpfPanelRenderer::render_trace_item(
            &item,
            120,
            EbpfViewMode::Expanded {
                index: 0,
                scroll: 0,
            },
        );

        let header = line_text(&lines[0]);
        assert!(header.contains("backtrace: complete, 1 frame (max 128)"));
        assert!(!header.contains("2 frames"));
        assert!(line_text(&lines[1]).contains("#0.inline inlined_add"));
        assert!(line_text(&lines[2]).contains("#0 function_0"));
    }
}

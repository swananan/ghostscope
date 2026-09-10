use crate::events::{BacktraceDisplay, BacktraceDisplayFrame, TraceDisplayItem};
use crate::model::panel_state::{CachedTraceEvent, DisplayMode, EbpfPanelState, EbpfViewMode};
use crate::ui::themes::UIThemes;
use ghostscope_protocol::trace_event::BacktraceStatus;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};
use std::collections::VecDeque;

/// Renders the eBPF output panel
#[derive(Debug)]
pub struct EbpfPanelRenderer;

struct Card {
    trace_index: usize,
    header_no_bold: String,
    header_number: String,
    header_rest: String,
    body_lines: Vec<Line<'static>>,
    total_height: usize,
    is_error: bool,
    is_latest: bool,
}

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

        let total_traces = state.trace_events.len();
        let cards = Self::visible_cards(state, content_area.height, |index| {
            Self::build_card(
                &state.trace_events[index],
                index,
                total_traces,
                content_width,
                state.view_mode,
            )
        });

        // Expanded view: render only selected card full-screen with scroll
        if let EbpfViewMode::Expanded { scroll, .. } = state.view_mode {
            if let Some(card) = cards.front() {
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

        // Render cards: clamp within viewport and keep order
        let mut y = content_area.y;
        for card in cards {
            if y >= content_area.y + content_area.height {
                break;
            }
            // Clamp card height to remaining viewport to avoid rendering outside buffer
            let remaining = (content_area.y + content_area.height).saturating_sub(y);
            let height = card.total_height.min(remaining as usize) as u16;
            if height < 2 {
                break;
            }

            let is_cursor = state.show_cursor && card.trace_index == state.cursor_trace_index;
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
                    card.body_lines
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

    /// Walk outward from the latest event or cursor, formatting only cards near
    /// the viewport. Variable heights require at most one lookahead on each side.
    fn visible_cards(
        state: &EbpfPanelState,
        viewport_height: u16,
        mut build_card: impl FnMut(usize) -> Card,
    ) -> VecDeque<Card> {
        let mut cards = VecDeque::new();
        if let EbpfViewMode::Expanded { index, .. } = state.view_mode {
            if index < state.trace_events.len() {
                cards.push_back(build_card(index));
            }
            return cards;
        }

        let mut remaining = viewport_height as usize;
        if remaining < 2 || state.trace_events.is_empty() {
            return cards;
        }

        match state.display_mode {
            DisplayMode::AutoRefresh => {
                for index in (0..state.trace_events.len()).rev() {
                    let card = build_card(index);
                    if card.total_height > remaining {
                        // Keep the latest event visible even in a short panel.
                        if cards.is_empty() {
                            cards.push_front(card);
                        }
                        break;
                    }
                    remaining -= card.total_height;
                    cards.push_front(card);
                    if remaining < 3 {
                        break;
                    }
                }
            }
            DisplayMode::Scroll => {
                let cursor = state.cursor_trace_index.min(state.trace_events.len() - 1);
                let mut partial_card = None;
                for index in cursor..state.trace_events.len() {
                    if remaining < 2 {
                        break;
                    }
                    let card = build_card(index);
                    if card.total_height > remaining {
                        if cards.is_empty() {
                            // A short panel must still show the selected card.
                            cards.push_back(card);
                            return cards;
                        }
                        partial_card = Some(card);
                        break;
                    }
                    remaining -= card.total_height;
                    cards.push_back(card);
                }

                // Fill spare space above the cursor with whole cards, preserving
                // the existing preference for showing newer events below it.
                for index in (0..cursor).rev() {
                    if remaining < 3 {
                        break;
                    }
                    let card = build_card(index);
                    if card.total_height > remaining {
                        break;
                    }
                    remaining -= card.total_height;
                    cards.push_front(card);
                }
                if remaining >= 2 {
                    cards.extend(partial_card);
                }
            }
        }
        cards
    }

    fn build_card(
        cached_trace: &CachedTraceEvent,
        trace_index: usize,
        total_traces: usize,
        content_width: usize,
        view_mode: EbpfViewMode,
    ) -> Card {
        let trace = &cached_trace.event;
        const MAX_LIST_BODY_LINES: usize = 3;
        let line_limit = match view_mode {
            EbpfViewMode::List => MAX_LIST_BODY_LINES + 1,
            EbpfViewMode::Expanded { .. } => usize::MAX,
        };
        let mut body_lines: Vec<_> = trace
            .items
            .iter()
            .flat_map(|item| Self::render_trace_item(item, content_width, view_mode))
            .take(line_limit)
            .collect();

        if view_mode == EbpfViewMode::List {
            let truncated = body_lines.len() > MAX_LIST_BODY_LINES;
            body_lines.truncate(MAX_LIST_BODY_LINES);
            if body_lines.is_empty() {
                body_lines.push(Line::from(""));
            }
            if truncated {
                if let Some(last) = body_lines.last_mut() {
                    let ellipsis = Span::styled(
                        " …",
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    );
                    if last.spans.len() >= 2 {
                        let indent = last.spans[0].content.clone();
                        let style = last.spans[1].style;
                        // Reserve space for the ellipsis without splitting UTF-8.
                        let trimmed = Self::trim_chars_from_end(&last.spans[1].content, 2);
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

        Card {
            trace_index,
            header_no_bold: String::from("[No:"),
            header_number: (trace_index + 1).to_string(),
            header_rest: format!(
                "] {} TraceID:{} PID:{} TID:{}",
                cached_trace.formatted_timestamp, trace.trace_id, trace.pid, trace.tid
            ),
            total_height: body_lines.len().max(1) + 2,
            body_lines,
            is_error: trace.is_error(),
            is_latest: trace_index + 1 == total_traces,
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
    use crate::events::UiTraceEvent;
    use ratatui::{backend::TestBackend, buffer::Buffer, Terminal};

    fn panel_with_messages(messages: &[&str]) -> EbpfPanelState {
        let mut state = EbpfPanelState::new();
        for (index, message) in messages.iter().enumerate() {
            state.add_trace_event(UiTraceEvent::text_event(
                index as u64,
                1_000_000_000,
                123,
                456,
                (*message).to_string(),
                Some(0),
            ));
        }
        state
    }

    fn render_panel(state: &mut EbpfPanelState, width: u16, height: u16) -> Buffer {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        let mut renderer = EbpfPanelRenderer::new();
        terminal
            .draw(|frame| renderer.render(state, frame, frame.area(), true))
            .unwrap();
        terminal.backend().buffer().clone()
    }

    fn row_text(buffer: &Buffer, y: u16) -> String {
        (0..buffer.area.width)
            .map(|x| buffer[(x, y)].symbol())
            .collect()
    }

    #[test]
    fn formatting_work_is_bounded_by_viewport_in_all_modes() {
        for count in [20, 2000] {
            let mut state = panel_with_messages(&vec!["one\ntwo\nthree"; count]);
            for cursor in [0, count / 2, count - 1] {
                state.cursor_trace_index = cursor;
                for mode in [DisplayMode::AutoRefresh, DisplayMode::Scroll] {
                    state.display_mode = mode;
                    for view in [
                        EbpfViewMode::List,
                        EbpfViewMode::Expanded {
                            index: cursor,
                            scroll: 0,
                        },
                    ] {
                        state.view_mode = view;
                        let mut formatted = Vec::new();
                        let cards = EbpfPanelRenderer::visible_cards(&state, 18, |index| {
                            formatted.push(index);
                            EbpfPanelRenderer::build_card(
                                &state.trace_events[index],
                                index,
                                count,
                                78,
                                view,
                            )
                        });
                        if matches!(view, EbpfViewMode::Expanded { .. }) {
                            assert_eq!(formatted, [cursor]);
                            assert_eq!(cards.len(), 1);
                        } else {
                            // Three full cards, a possible partial card, and
                            // at most one height lookahead in either direction.
                            assert!(formatted.len() <= 5, "{formatted:?}");
                            let anchor = match mode {
                                DisplayMode::AutoRefresh => count - 1,
                                DisplayMode::Scroll => cursor,
                            };
                            assert!(cards.iter().any(|card| card.trace_index == anchor));
                            assert!(formatted.iter().all(|index| index.abs_diff(anchor) <= 4));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn auto_refresh_reflows_visible_cards_after_width_changes() {
        let mut state = panel_with_messages(&["abcdefghijklmnopqrstuvwxyz"; 2]);
        let wide = render_panel(&mut state, 60, 8);
        assert!(row_text(&wide, 1).contains("[No:1]"));
        assert!(row_text(&wide, 4).contains("[No:2]"));
        assert_eq!(wide[(1, 4)].fg, Color::Green);

        let narrow = render_panel(&mut state, 15, 8);
        assert!(row_text(&narrow, 1).contains("[No:2]"));
        assert!(row_text(&narrow, 4).contains('…'));

        assert_eq!(render_panel(&mut state, 60, 8), wide);
    }

    #[test]
    fn scroll_view_preserves_variable_heights_and_partial_bottom_card() {
        let mut state = panel_with_messages(&["one", "one\ntwo", "one\ntwo\nthree", "last"]);
        state.display_mode = DisplayMode::Scroll;
        state.cursor_trace_index = 1;
        state.show_cursor = true;

        let filled_above = render_panel(&mut state, 80, 10);
        assert!(row_text(&filled_above, 1).contains("[No:1]"));
        assert!(row_text(&filled_above, 4).contains("[No:2]"));
        assert_eq!(filled_above[(1, 4)].fg, Color::Yellow);

        let partial_below = render_panel(&mut state, 80, 13);
        assert!(row_text(&partial_below, 1).contains("[No:2]"));
        assert!(row_text(&partial_below, 5).contains("[No:3]"));
        assert!(row_text(&partial_below, 10).contains("[No:4]"));
    }

    #[test]
    fn short_viewport_keeps_latest_or_selected_card_visible() {
        let mut state = panel_with_messages(&["short", "one\ntwo\nthree", "last"]);
        let latest = render_panel(&mut state, 80, 4);
        assert!(row_text(&latest, 1).contains("[No:3]"));

        state.display_mode = DisplayMode::Scroll;
        state.cursor_trace_index = 1;
        let selected = render_panel(&mut state, 80, 5);
        assert!(row_text(&selected, 1).contains("[No:2]"));
        assert!(row_text(&selected, 2).contains("one"));
    }

    #[test]
    fn expanded_view_clamps_scroll_and_keeps_selected_header() {
        let mut state = panel_with_messages(&[
            "hidden before",
            "line 0\nline 1\nline 2\nline 3\nline 4\nline 5\nline 6\nline 7\nline 8",
            "hidden after",
        ]);
        state.view_mode = EbpfViewMode::Expanded {
            index: 1,
            scroll: usize::MAX,
        };
        let buffer = render_panel(&mut state, 100, 12);
        assert!(row_text(&buffer, 1).contains("[No:2]"));
        assert!(row_text(&buffer, 2).contains("line 2"));
        assert!(row_text(&buffer, 8).contains("line 8"));
        assert!(row_text(&buffer, 10).contains("Esc/Ctrl+C to exit"));
        assert_eq!(state.expanded_scroll, 2);
        assert_eq!(state.last_inner_height, 7);
    }

    #[test]
    fn list_preview_truncates_across_items_and_expanded_keeps_all_items() {
        let mut state = panel_with_messages(&["unused"]);
        state.trace_events[0].event.items = ["first", "second", "third", "fourth"]
            .into_iter()
            .map(|content| TraceDisplayItem::Text {
                content: content.to_string(),
            })
            .collect();
        let list = render_panel(&mut state, 80, 12);
        assert!(row_text(&list, 4).contains("thi …"));
        state.view_mode = EbpfViewMode::Expanded {
            index: 0,
            scroll: 0,
        };
        let expanded = render_panel(&mut state, 80, 12);
        assert!(row_text(&expanded, 4).contains("third"));
        assert!(row_text(&expanded, 5).contains("fourth"));
    }

    #[test]
    fn empty_and_minimal_viewports_are_safe_in_all_modes() {
        for mut state in [EbpfPanelState::new(), panel_with_messages(&["message"])] {
            for width in [0, 1, 2, 3, 5, 80] {
                for height in [0, 1, 2, 3, 4, 24] {
                    for mode in [DisplayMode::AutoRefresh, DisplayMode::Scroll] {
                        state.display_mode = mode;
                        for view in [
                            EbpfViewMode::List,
                            EbpfViewMode::Expanded {
                                index: 0,
                                scroll: 0,
                            },
                            EbpfViewMode::Expanded {
                                index: 10,
                                scroll: 0,
                            },
                        ] {
                            state.view_mode = view;
                            render_panel(&mut state, width, height);
                        }
                    }
                }
            }
        }
    }

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

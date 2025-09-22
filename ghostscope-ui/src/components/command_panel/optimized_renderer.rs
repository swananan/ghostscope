use crate::action::ResponseType;
use crate::model::panel_state::{CommandPanelState, InteractionMode, LineType};
use crate::ui::themes::UIThemes;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Paragraph},
    Frame,
};
use unicode_width::UnicodeWidthChar;

/// Direct renderer for command panel (no caching)
#[derive(Debug)]
pub struct OptimizedRenderer {
    // Viewport management only
    scroll_offset: usize,
    visible_lines: usize,
}

impl OptimizedRenderer {
    pub fn new() -> Self {
        Self {
            scroll_offset: 0,
            visible_lines: 0,
        }
    }

    /// Mark that updates are pending (placeholder for API compatibility)
    pub fn mark_pending_updates(&mut self) {
        // No-op: direct rendering doesn't need pending flags
    }

    /// Main render function with direct rendering
    pub fn render(
        &mut self,
        f: &mut Frame,
        area: Rect,
        state: &CommandPanelState,
        is_focused: bool,
    ) {
        // Update viewport
        self.update_viewport(area);

        // Always render directly - no caching
        self.render_border(f, area, is_focused, state);
        self.render_content(f, area, state);
    }

    /// Update viewport information
    fn update_viewport(&mut self, area: Rect) {
        let height = area.height.saturating_sub(2);
        self.visible_lines = height as usize;
    }

    /// Render border with mode status
    fn render_border(
        &self,
        f: &mut Frame,
        area: Rect,
        is_focused: bool,
        state: &CommandPanelState,
    ) {
        let border_style = if !is_focused {
            Style::default().fg(Color::White)
        } else {
            match state.input_state {
                crate::model::panel_state::InputState::WaitingResponse { .. } => {
                    Style::default().fg(Color::Yellow)
                }
                _ => match state.mode {
                    InteractionMode::Input => Style::default().fg(Color::Green),
                    InteractionMode::Command => Style::default().fg(Color::Cyan),
                    InteractionMode::ScriptEditor => Style::default().fg(Color::Green),
                },
            }
        };

        let title = match state.input_state {
            crate::model::panel_state::InputState::WaitingResponse { .. } => {
                "Interactive Command (waiting for response...)".to_string()
            }
            _ => match state.mode {
                InteractionMode::Input => "Interactive Command (input mode)".to_string(),
                InteractionMode::Command => "Interactive Command (command mode)".to_string(),
                InteractionMode::ScriptEditor => "Interactive Command (script mode)".to_string(),
            },
        };

        let block = Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_type(if is_focused {
                BorderType::Thick
            } else {
                BorderType::Plain
            })
            .border_style(border_style);

        f.render_widget(block, area);
    }

    /// Render content directly
    fn render_content(&self, f: &mut Frame, area: Rect, state: &CommandPanelState) {
        let inner_area = Rect::new(
            area.x + 1,
            area.y + 1,
            area.width.saturating_sub(2),
            area.height.saturating_sub(2),
        );

        let width = inner_area.width;
        let mut lines = Vec::new();

        // Render static lines (welcome messages, etc.)
        for static_line in &state.static_lines {
            match static_line.line_type {
                LineType::Welcome => {
                    if let Some(ref styled_content) = static_line.styled_content {
                        let wrapped_lines = self.wrap_styled_line(styled_content, width as usize);
                        lines.extend(wrapped_lines);
                    } else {
                        let wrapped_lines = self.wrap_text(&static_line.content, width);
                        for wrapped_line in wrapped_lines {
                            lines.push(self.create_fallback_welcome_line(&wrapped_line));
                        }
                    }
                }
                _ => {
                    let wrapped_lines = self.wrap_text(&static_line.content, width);
                    for wrapped_line in wrapped_lines {
                        let styled_line = match static_line.line_type {
                            LineType::Response => {
                                self.create_response_line(&wrapped_line, static_line.response_type)
                            }
                            LineType::Command => self.create_command_line(&wrapped_line),
                            LineType::CurrentInput => Line::from(Span::styled(
                                wrapped_line,
                                Style::default().fg(Color::White),
                            )),
                            _ => unreachable!(),
                        };
                        lines.push(styled_line);
                    }
                }
            }
        }

        // Render command history
        for item in &state.command_history {
            // Command line
            let command_content = format!("(ghostscope) {}", item.command);
            let wrapped_commands = self.wrap_text(&command_content, width);
            for (line_idx, wrapped_line) in wrapped_commands.iter().enumerate() {
                let command_line = if line_idx == 0 {
                    self.create_command_line(wrapped_line)
                } else {
                    Line::from(Span::styled(
                        wrapped_line.clone(),
                        Style::default().fg(Color::White),
                    ))
                };
                lines.push(command_line);
            }

            // Response lines
            if let Some(ref response) = item.response {
                let response_lines = self.split_response_lines(response);
                for response_line in response_lines {
                    let wrapped_responses = self.wrap_text(&response_line, width);
                    for wrapped_response in wrapped_responses {
                        let styled_line =
                            self.create_response_line(&wrapped_response, item.response_type);
                        lines.push(styled_line);
                    }
                }
            }
        }

        // Render current input
        match state.mode {
            InteractionMode::ScriptEditor => {
                if let Some(ref script_cache) = state.script_cache {
                    self.render_script_editor(script_cache, width, &mut lines);
                }
            }
            _ => {
                if matches!(
                    state.input_state,
                    crate::model::panel_state::InputState::Ready
                ) {
                    if state.is_in_history_search() {
                        self.render_history_search(state, width, &mut lines);
                    } else {
                        self.render_normal_input(state, width, &mut lines);
                    }
                }
            }
        }

        // Apply viewport
        let total_lines = lines.len();
        let visible_count = inner_area.height as usize;

        let (start_line, cursor_line_in_viewport) =
            if matches!(state.mode, InteractionMode::Command) || state.is_in_history_search() {
                let cursor_line = if state.is_in_history_search() {
                    total_lines.saturating_sub(1)
                } else {
                    state.command_cursor_line
                };

                let mut start = if total_lines > visible_count {
                    total_lines - visible_count
                } else {
                    0
                };

                if cursor_line < start {
                    start = cursor_line;
                } else if cursor_line >= start + visible_count {
                    start = cursor_line.saturating_sub(visible_count - 1);
                }

                (start, Some(cursor_line.saturating_sub(start)))
            } else {
                let start = if total_lines > visible_count {
                    total_lines - visible_count
                } else {
                    0
                };
                (start, None)
            };

        let mut visible_lines: Vec<Line> = lines
            .into_iter()
            .skip(start_line)
            .take(visible_count)
            .collect();

        // Add command mode cursor if needed
        if let Some(cursor_line_idx) = cursor_line_in_viewport {
            if cursor_line_idx < visible_lines.len()
                && matches!(state.mode, InteractionMode::Command)
            {
                self.add_command_cursor(
                    &mut visible_lines[cursor_line_idx],
                    state.command_cursor_column,
                );
            }
        }

        let paragraph = Paragraph::new(visible_lines);
        f.render_widget(paragraph, inner_area);
    }

    /// Render script editor content
    fn render_script_editor(
        &self,
        script_cache: &crate::model::panel_state::ScriptCache,
        width: u16,
        lines: &mut Vec<Line<'static>>,
    ) {
        // Header
        let header = format!(
            "🔨 Entering script mode for target: {}",
            script_cache.target
        );
        lines.push(Line::from(Span::styled(
            header,
            Style::default().fg(Color::Cyan),
        )));

        // Separator
        let separator = "─".repeat(50);
        lines.push(Line::from(Span::styled(
            separator,
            Style::default().fg(Color::Cyan),
        )));

        // Prompt
        lines.push(Line::from(Span::styled(
            "Script Editor (Ctrl+s to submit, Esc to cancel):",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));

        // Script lines
        for (line_idx, line_content) in script_cache.lines.iter().enumerate() {
            let line_number = format!("{:3} │ ", line_idx + 1);
            let is_cursor_line = line_idx == script_cache.cursor_line;

            if is_cursor_line {
                lines.push(self.create_script_line_with_cursor(
                    &line_number,
                    line_content,
                    script_cache.cursor_col,
                ));
            } else {
                lines.push(Line::from(vec![
                    Span::styled(line_number, Style::default().fg(Color::DarkGray)),
                    Span::styled(line_content.clone(), Style::default().fg(Color::White)),
                ]));
            }
        }
    }

    /// Render history search input
    fn render_history_search(
        &self,
        state: &CommandPanelState,
        width: u16,
        lines: &mut Vec<Line<'static>>,
    ) {
        let search_query = state.get_history_search_query();

        if let Some(matched_command) = state
            .history_search
            .current_match(&state.command_history_manager)
        {
            // Success case
            let prompt_text = format!("(reverse-i-search)`{}': ", search_query);
            let full_content = format!("{}{}", prompt_text, matched_command);

            if full_content.chars().count() > width as usize {
                // Wrapped case
                let wrapped_lines = self.wrap_text(&full_content, width);
                let cursor_pos = prompt_text.chars().count() + search_query.len();

                let mut char_count = 0;
                for (line_idx, line) in wrapped_lines.iter().enumerate() {
                    let line_char_count = line.chars().count();
                    let line_end = char_count + line_char_count;

                    if cursor_pos >= char_count && cursor_pos < line_end {
                        // This line contains the cursor
                        let cursor_in_line = cursor_pos - char_count;
                        lines.push(self.create_history_search_line_with_cursor(
                            line,
                            &prompt_text,
                            cursor_in_line,
                        ));
                    } else {
                        lines.push(
                            self.create_history_search_line_without_cursor(line, &prompt_text),
                        );
                    }
                    char_count = line_end;
                }
            } else {
                // Single line case
                let cursor_pos = search_query.len();
                lines.push(self.create_simple_history_search_line(
                    &prompt_text,
                    matched_command,
                    cursor_pos,
                    true,
                ));
            }
        } else if search_query.is_empty() {
            // Empty search
            let prompt_text = "(reverse-i-search)`': ";

            if prompt_text.chars().count() > width as usize {
                // Wrapped empty search
                let wrapped_lines = self.wrap_text(prompt_text, width);
                for wrapped_line in wrapped_lines {
                    lines.push(Line::from(Span::styled(
                        wrapped_line,
                        Style::default().fg(Color::Cyan),
                    )));
                }
            } else {
                // Single line empty search
                lines.push(Line::from(Span::styled(
                    prompt_text,
                    Style::default().fg(Color::Cyan),
                )));
            }
        } else {
            // Failed search
            let failed_prompt = format!("(failed reverse-i-search)`{}': ", search_query);

            if failed_prompt.chars().count() > width as usize {
                // Wrapped failed search
                let wrapped_lines = self.wrap_text(&failed_prompt, width);
                for wrapped_line in wrapped_lines {
                    lines.push(Line::from(Span::styled(
                        wrapped_line,
                        Style::default().fg(Color::Red),
                    )));
                }
            } else {
                // Single line failed search
                lines.push(Line::from(Span::styled(
                    failed_prompt,
                    Style::default().fg(Color::Red),
                )));
            }
        }
    }

    /// Render normal input
    fn render_normal_input(
        &self,
        state: &CommandPanelState,
        width: u16,
        lines: &mut Vec<Line<'static>>,
    ) {
        let prompt = "(ghostscope) ";
        let input_text = state.get_display_text();
        let cursor_pos = state.get_display_cursor_position();
        let full_content = format!("{}{}", prompt, input_text);

        if full_content.chars().count() > width as usize {
            // Handle wrapped input
            let wrapped_lines = self.wrap_text(&full_content, width);
            let cursor_pos_with_prompt = cursor_pos + prompt.chars().count();

            let mut char_count = 0;
            for (line_idx, line) in wrapped_lines.iter().enumerate() {
                let line_char_count = line.chars().count();
                let line_end = char_count + line_char_count;

                if cursor_pos_with_prompt >= char_count && cursor_pos_with_prompt < line_end {
                    let cursor_in_line = cursor_pos_with_prompt - char_count;
                    lines.push(self.create_input_line_with_cursor(
                        line,
                        prompt,
                        cursor_in_line,
                        line_idx == 0,
                    ));
                } else {
                    lines.push(self.create_input_line_without_cursor(line, prompt, line_idx == 0));
                }
                char_count = line_end;
            }
        } else {
            // Single line input
            lines.push(self.create_input_line(prompt, input_text, cursor_pos, state));
        }
    }

    /// Create simple history search line
    fn create_simple_history_search_line(
        &self,
        prompt_text: &str,
        matched_command: &str,
        cursor_pos: usize,
        show_cursor: bool,
    ) -> Line<'static> {
        let mut spans = vec![Span::styled(
            prompt_text.to_string(),
            Style::default().fg(Color::Cyan),
        )];

        if show_cursor {
            self.add_text_with_cursor(&mut spans, matched_command, cursor_pos);
        } else {
            spans.push(Span::styled(matched_command.to_string(), Style::default()));
        }

        Line::from(spans)
    }

    /// Create history search line with cursor (wrapped)
    fn create_history_search_line_with_cursor(
        &self,
        line: &str,
        prompt_text: &str,
        cursor_pos: usize,
    ) -> Line<'static> {
        let chars: Vec<char> = line.chars().collect();
        let mut spans = Vec::new();
        let prompt_len = prompt_text.chars().count();

        if prompt_len > 0 && prompt_len <= chars.len() {
            // Line contains prompt
            let prompt_part: String = chars[..prompt_len].iter().collect();
            spans.push(Span::styled(prompt_part, Style::default().fg(Color::Cyan)));

            let text_part: String = chars[prompt_len..].iter().collect();
            let cursor_in_text = cursor_pos.saturating_sub(prompt_len);
            self.add_text_with_cursor(&mut spans, &text_part, cursor_in_text);
        } else {
            // Continuation line
            self.add_text_with_cursor(&mut spans, line, cursor_pos);
        }

        Line::from(spans)
    }

    /// Create history search line without cursor (wrapped)
    fn create_history_search_line_without_cursor(
        &self,
        line: &str,
        prompt_text: &str,
    ) -> Line<'static> {
        let chars: Vec<char> = line.chars().collect();
        let mut spans = Vec::new();
        let prompt_len = prompt_text.chars().count();

        if prompt_len > 0 && prompt_len <= chars.len() {
            let prompt_part: String = chars[..prompt_len].iter().collect();
            spans.push(Span::styled(prompt_part, Style::default().fg(Color::Cyan)));

            let text_part: String = chars[prompt_len..].iter().collect();
            spans.push(Span::styled(text_part, Style::default()));
        } else {
            spans.push(Span::styled(line.to_string(), Style::default()));
        }

        Line::from(spans)
    }

    /// Create input line with cursor
    fn create_input_line_with_cursor(
        &self,
        line: &str,
        prompt: &str,
        cursor_pos: usize,
        is_first_line: bool,
    ) -> Line<'static> {
        let chars: Vec<char> = line.chars().collect();
        let mut spans = Vec::new();
        let prompt_len = if is_first_line {
            prompt.chars().count()
        } else {
            0
        };

        if is_first_line && prompt_len <= chars.len() {
            let prompt_part: String = chars[..prompt_len].iter().collect();
            spans.push(Span::styled(
                prompt_part,
                Style::default().fg(Color::Magenta),
            ));

            let text_part: String = chars[prompt_len..].iter().collect();
            let cursor_in_text = cursor_pos.saturating_sub(prompt_len);
            self.add_text_with_cursor(&mut spans, &text_part, cursor_in_text);
        } else {
            self.add_text_with_cursor(&mut spans, line, cursor_pos);
        }

        Line::from(spans)
    }

    /// Create input line without cursor
    fn create_input_line_without_cursor(
        &self,
        line: &str,
        prompt: &str,
        is_first_line: bool,
    ) -> Line<'static> {
        let chars: Vec<char> = line.chars().collect();
        let mut spans = Vec::new();
        let prompt_len = if is_first_line {
            prompt.chars().count()
        } else {
            0
        };

        if is_first_line && prompt_len <= chars.len() {
            let prompt_part: String = chars[..prompt_len].iter().collect();
            spans.push(Span::styled(
                prompt_part,
                Style::default().fg(Color::Magenta),
            ));

            let text_part: String = chars[prompt_len..].iter().collect();
            spans.push(Span::styled(text_part, Style::default()));
        } else {
            spans.push(Span::styled(line.to_string(), Style::default()));
        }

        Line::from(spans)
    }

    /// Add command cursor to existing line
    fn add_command_cursor(&self, line: &mut Line<'static>, cursor_col: usize) {
        let mut new_spans = Vec::new();
        let mut current_pos = 0;

        for span in &line.spans {
            let span_len = span.content.chars().count();
            let span_end = current_pos + span_len;

            if cursor_col >= current_pos && cursor_col < span_end {
                let chars: Vec<char> = span.content.chars().collect();
                let cursor_pos_in_span = cursor_col - current_pos;

                if cursor_pos_in_span > 0 {
                    let before: String = chars[..cursor_pos_in_span].iter().collect();
                    new_spans.push(Span::styled(before, span.style));
                }

                if cursor_pos_in_span < chars.len() {
                    let cursor_char = chars[cursor_pos_in_span];
                    new_spans.push(Span::styled(
                        cursor_char.to_string(),
                        UIThemes::cursor_style(),
                    ));

                    if cursor_pos_in_span + 1 < chars.len() {
                        let after: String = chars[cursor_pos_in_span + 1..].iter().collect();
                        new_spans.push(Span::styled(after, span.style));
                    }
                } else {
                    new_spans.push(Span::styled(" ".to_string(), UIThemes::cursor_style()));
                }
            } else {
                new_spans.push(span.clone());
            }

            current_pos = span_end;
        }

        if cursor_col >= current_pos {
            new_spans.push(Span::styled(" ".to_string(), UIThemes::cursor_style()));
        }

        line.spans = new_spans;
    }

    /// Create a styled input line with cursor
    fn create_input_line(
        &self,
        prompt: &str,
        input_text: &str,
        cursor_pos: usize,
        state: &CommandPanelState,
    ) -> Line<'static> {
        let chars: Vec<char> = input_text.chars().collect();
        let mut spans = vec![Span::styled(
            prompt.to_string(),
            Style::default().fg(Color::Magenta),
        )];

        let show_cursor = matches!(state.mode, InteractionMode::Input);

        if chars.is_empty() {
            if let Some(suggestion_text) = state.get_suggestion_text() {
                let suggestion_chars: Vec<char> = suggestion_text.chars().collect();
                if !suggestion_chars.is_empty() {
                    spans.push(Span::styled(
                        suggestion_chars[0].to_string(),
                        if show_cursor {
                            UIThemes::cursor_style()
                        } else {
                            Style::default().fg(Color::DarkGray)
                        },
                    ));
                    if suggestion_chars.len() > 1 {
                        let remaining: String = suggestion_chars[1..].iter().collect();
                        spans.push(Span::styled(
                            remaining,
                            Style::default().fg(Color::DarkGray),
                        ));
                    }
                }
            } else {
                spans.push(Span::styled(
                    " ".to_string(),
                    if show_cursor {
                        UIThemes::cursor_style()
                    } else {
                        Style::default()
                    },
                ));
            }
        } else if cursor_pos >= chars.len() {
            // Cursor at end - check if we have auto-suggestion to merge
            if let Some(suggestion_text) = state.get_suggestion_text() {
                // We have auto-suggestion, show merged text with cursor at boundary
                let full_text = format!("{}{}", input_text, suggestion_text);
                let full_chars: Vec<char> = full_text.chars().collect();

                // Show input part in normal color
                if !input_text.is_empty() {
                    spans.push(Span::styled(input_text.to_string(), Style::default()));
                }

                // Show the character at cursor position as block cursor
                if cursor_pos < full_chars.len() {
                    let cursor_char = full_chars[cursor_pos];
                    spans.push(Span::styled(
                        cursor_char.to_string(),
                        if show_cursor {
                            UIThemes::cursor_style()
                        } else {
                            Style::default().fg(Color::DarkGray)
                        },
                    ));

                    // Show remaining characters in dark gray
                    if cursor_pos + 1 < full_chars.len() {
                        let remaining: String = full_chars[cursor_pos + 1..].iter().collect();
                        spans.push(Span::styled(
                            remaining,
                            Style::default().fg(Color::DarkGray),
                        ));
                    }
                } else {
                    // Fallback - show space as block cursor
                    spans.push(Span::styled(
                        " ".to_string(),
                        if show_cursor {
                            UIThemes::cursor_style()
                        } else {
                            Style::default()
                        },
                    ));
                }
            } else {
                // No auto-suggestion, show block cursor at end
                spans.push(Span::styled(input_text.to_string(), Style::default()));
                spans.push(Span::styled(
                    " ".to_string(),
                    if show_cursor {
                        UIThemes::cursor_style()
                    } else {
                        Style::default()
                    },
                ));
            }
        } else {
            // Cursor in middle of text - show character as block cursor
            let before_cursor: String = chars[..cursor_pos].iter().collect();
            let at_cursor = chars[cursor_pos];
            let after_cursor: String = chars[cursor_pos + 1..].iter().collect();

            // Text before cursor
            if !before_cursor.is_empty() {
                spans.push(Span::styled(before_cursor, Style::default()));
            }

            // Character at cursor position as block cursor
            spans.push(Span::styled(
                at_cursor.to_string(),
                if show_cursor {
                    UIThemes::cursor_style()
                } else {
                    Style::default()
                },
            ));

            // Text after cursor
            if !after_cursor.is_empty() {
                spans.push(Span::styled(after_cursor, Style::default()));
            }

            // Add auto-suggestion at the end if cursor is at the end of meaningful text
            if cursor_pos + 1 >= chars.len() {
                if let Some(suggestion_text) = state.get_suggestion_text() {
                    spans.push(Span::styled(
                        suggestion_text.to_string(),
                        Style::default().fg(Color::DarkGray),
                    ));
                }
            }
        }

        Line::from(spans)
    }

    /// Create a script line with cursor
    fn create_script_line_with_cursor(
        &self,
        line_number: &str,
        content: &str,
        cursor_pos: usize,
    ) -> Line<'static> {
        let chars: Vec<char> = content.chars().collect();
        let mut spans = vec![Span::styled(
            line_number.to_string(),
            Style::default().fg(Color::DarkGray),
        )];

        if chars.is_empty() {
            spans.push(Span::styled(" ".to_string(), UIThemes::cursor_style()));
        } else if cursor_pos >= chars.len() {
            spans.push(Span::styled(
                content.to_string(),
                Style::default().fg(Color::White),
            ));
            spans.push(Span::styled(" ".to_string(), UIThemes::cursor_style()));
        } else {
            let before_cursor: String = chars[..cursor_pos].iter().collect();
            let at_cursor = chars[cursor_pos];
            let after_cursor: String = chars[cursor_pos + 1..].iter().collect();

            if !before_cursor.is_empty() {
                spans.push(Span::styled(
                    before_cursor,
                    Style::default().fg(Color::White),
                ));
            }
            spans.push(Span::styled(
                at_cursor.to_string(),
                UIThemes::cursor_style(),
            ));
            if !after_cursor.is_empty() {
                spans.push(Span::styled(
                    after_cursor,
                    Style::default().fg(Color::White),
                ));
            }
        }

        Line::from(spans)
    }

    /// Create a styled command line
    fn create_command_line(&self, content: &str) -> Line<'static> {
        if content.starts_with("(ghostscope) ") {
            let prompt_part = "(ghostscope) ";
            let command_part = &content[prompt_part.len()..];

            Line::from(vec![
                Span::styled(
                    prompt_part.to_string(),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(command_part.to_string(), Style::default().fg(Color::Gray)),
            ])
        } else {
            Line::from(Span::styled(
                content.to_string(),
                Style::default().fg(Color::Gray),
            ))
        }
    }

    /// Create a styled response line
    fn create_response_line(
        &self,
        content: &str,
        response_type: Option<ResponseType>,
    ) -> Line<'static> {
        let style = match response_type {
            Some(ResponseType::Success) => Style::default().fg(Color::Green),
            Some(ResponseType::Error) => Style::default().fg(Color::Red),
            Some(ResponseType::Warning) => Style::default().fg(Color::Yellow),
            Some(ResponseType::Info) => Style::default().fg(Color::Cyan),
            Some(ResponseType::Progress) => Style::default().fg(Color::Blue),
            Some(ResponseType::ScriptDisplay) => Style::default().fg(Color::Magenta),
            None => Style::default().fg(Color::Gray),
        };
        Line::from(Span::styled(content.to_string(), style))
    }

    /// Create fallback welcome line
    fn create_fallback_welcome_line(&self, content: &str) -> Line<'static> {
        if content.contains("GhostScope") {
            Line::from(Span::styled(
                content.to_string(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ))
        } else if content.starts_with("•") || content.starts_with("Loading completed in") {
            Line::from(Span::styled(
                content.to_string(),
                Style::default().fg(Color::Cyan),
            ))
        } else if content.starts_with("Attached to process") {
            Line::from(Span::styled(
                content.to_string(),
                Style::default().fg(Color::White),
            ))
        } else if content.trim().is_empty() {
            Line::from("")
        } else {
            Line::from(Span::styled(
                content.to_string(),
                Style::default().fg(Color::White),
            ))
        }
    }

    /// Add text with cursor to spans vector
    fn add_text_with_cursor(&self, spans: &mut Vec<Span<'static>>, text: &str, cursor_pos: usize) {
        let chars: Vec<char> = text.chars().collect();

        if chars.is_empty() {
            spans.push(Span::styled(" ".to_string(), UIThemes::cursor_style()));
        } else if cursor_pos == 0 {
            let first_char = chars[0];
            spans.push(Span::styled(
                first_char.to_string(),
                UIThemes::cursor_style(),
            ));
            if chars.len() > 1 {
                let remaining: String = chars[1..].iter().collect();
                spans.push(Span::styled(remaining, Style::default()));
            }
        } else if cursor_pos >= chars.len() {
            spans.push(Span::styled(text.to_string(), Style::default()));
            spans.push(Span::styled(" ".to_string(), UIThemes::cursor_style()));
        } else {
            let before_cursor: String = chars[..cursor_pos].iter().collect();
            let at_cursor = chars[cursor_pos];
            let after_cursor: String = chars[cursor_pos + 1..].iter().collect();

            if !before_cursor.is_empty() {
                spans.push(Span::styled(before_cursor, Style::default()));
            }

            spans.push(Span::styled(
                at_cursor.to_string(),
                UIThemes::cursor_style(),
            ));

            if !after_cursor.is_empty() {
                spans.push(Span::styled(after_cursor, Style::default()));
            }
        }
    }

    /// Wrap text to fit within the specified width
    fn wrap_text(&self, text: &str, width: u16) -> Vec<String> {
        if width <= 2 {
            return vec![text.to_string()];
        }

        let max_width = width as usize;
        let mut lines = Vec::new();

        for line in text.lines() {
            let line_width: usize = line
                .chars()
                .map(|c| UnicodeWidthChar::width(c).unwrap_or(0))
                .sum();

            if line_width <= max_width {
                lines.push(line.to_string());
            } else {
                let mut current_line = String::new();
                let mut current_width = 0;

                for ch in line.chars() {
                    let char_width = UnicodeWidthChar::width(ch).unwrap_or(0);

                    if current_width + char_width > max_width && !current_line.is_empty() {
                        lines.push(current_line);
                        current_line = ch.to_string();
                        current_width = char_width;
                    } else {
                        current_line.push(ch);
                        current_width += char_width;
                    }
                }

                if !current_line.is_empty() {
                    lines.push(current_line);
                }
            }
        }

        if lines.is_empty() {
            lines.push(String::new());
        }

        lines
    }

    /// Wrap styled line preserving spans
    fn wrap_styled_line(&self, styled_line: &Line<'static>, width: usize) -> Vec<Line<'static>> {
        let full_text: String = styled_line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();

        if full_text.len() <= width {
            return vec![styled_line.clone()];
        }

        let mut result_lines = Vec::new();
        let mut current_line_spans = Vec::new();
        let mut current_line_length = 0;

        for span in &styled_line.spans {
            let span_text = span.content.as_ref();
            let span_style = span.style;

            if current_line_length + span_text.len() <= width {
                current_line_spans.push(span.clone());
                current_line_length += span_text.len();
            } else {
                let remaining_width = width - current_line_length;

                if remaining_width > 0 {
                    let (first_part, remaining_part) =
                        span_text.split_at(remaining_width.min(span_text.len()));
                    if !first_part.is_empty() {
                        current_line_spans.push(Span::styled(first_part.to_string(), span_style));
                    }

                    if !current_line_spans.is_empty() {
                        result_lines.push(Line::from(current_line_spans));
                        current_line_spans = Vec::new();
                        current_line_length = 0;
                    }

                    let mut remaining = remaining_part;
                    while !remaining.is_empty() {
                        let chunk_size = width.min(remaining.len());
                        let (chunk, rest) = remaining.split_at(chunk_size);
                        result_lines.push(Line::from(vec![Span::styled(
                            chunk.to_string(),
                            span_style,
                        )]));
                        remaining = rest;
                    }
                } else {
                    if !current_line_spans.is_empty() {
                        result_lines.push(Line::from(current_line_spans));
                        current_line_spans = Vec::new();
                        current_line_length = 0;
                    }

                    let mut remaining = span_text;
                    while !remaining.is_empty() {
                        let chunk_size = width.min(remaining.len());
                        let (chunk, rest) = remaining.split_at(chunk_size);
                        result_lines.push(Line::from(vec![Span::styled(
                            chunk.to_string(),
                            span_style,
                        )]));
                        remaining = rest;
                    }
                }
            }
        }

        if !current_line_spans.is_empty() {
            result_lines.push(Line::from(current_line_spans));
        }

        result_lines
    }

    /// Split response into lines
    fn split_response_lines(&self, response: &str) -> Vec<String> {
        response.lines().map(String::from).collect()
    }

    /// Scroll methods for API compatibility
    pub fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
        }
    }

    pub fn scroll_down(&mut self) {
        self.scroll_offset += 1;
    }
}

impl Default for OptimizedRenderer {
    fn default() -> Self {
        Self::new()
    }
}

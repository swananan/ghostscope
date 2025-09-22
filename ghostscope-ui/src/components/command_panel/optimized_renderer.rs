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
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
// Removed Duration, Instant - no longer needed for immediate rendering
use unicode_width::UnicodeWidthChar;

/// Frame-based optimized renderer for command panel
#[derive(Debug)]
pub struct OptimizedRenderer {
    // Line-based cache
    cached_lines: Vec<CachedLine>,
    cache_version: u64,
    last_width: u16,
    last_height: u16,

    // Frame-based rendering
    // Removed 60fps optimization - immediate rendering is better for TUI

    // Viewport management
    scroll_offset: usize,
    visible_lines: usize,

    // Welcome message styling cache
    welcome_lines_mapping: std::collections::HashMap<String, Line<'static>>,
}

#[derive(Clone, Debug)]
struct CachedLine {
    content_hash: u64,
    rendered_line: Line<'static>,
    line_type: LineType,
    response_type: Option<ResponseType>,
    original_content: String, // Keep for rehashing when width changes
}

impl OptimizedRenderer {
    pub fn new() -> Self {
        Self {
            cached_lines: Vec::new(),
            cache_version: 0,
            last_width: 0,
            last_height: 0,
            scroll_offset: 0,
            visible_lines: 0,
            welcome_lines_mapping: std::collections::HashMap::new(),
        }
    }

    /// Mark that updates are pending (called on input changes)
    /// Note: With immediate rendering, this is just a placeholder for API compatibility
    pub fn mark_pending_updates(&mut self) {
        // No-op: immediate rendering doesn't need pending flags
    }

    /// Set the welcome lines mapping for styled rendering
    pub fn set_welcome_lines_mapping(&mut self, styled_lines: Vec<Line<'static>>) {
        self.welcome_lines_mapping.clear();
        for line in styled_lines {
            // Convert line to plain text for mapping key
            let text_key: String = line
                .spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect();
            self.welcome_lines_mapping.insert(text_key, line);
        }
        // Force cache rebuild to apply new mapping immediately
        self.cache_version += 1;
    }

    /// Main render function with smart caching (immediate rendering)
    pub fn render(
        &mut self,
        f: &mut Frame,
        area: Rect,
        state: &CommandPanelState,
        is_focused: bool,
    ) {
        // Update viewport if area changed
        let area_changed = self.update_viewport(area);

        // Rebuild cache if needed (only when content actually changes)
        if area_changed || self.cache_needs_rebuild(state) {
            self.rebuild_cache(state, area.width.saturating_sub(2));
        }

        // Always render - immediate feedback is better for TUI
        self.render_border(f, area, is_focused, state);
        self.render_content(f, area, state);
    }

    /// Check if cache needs to be rebuilt
    fn cache_needs_rebuild(&self, state: &CommandPanelState) -> bool {
        // Simple heuristic: rebuild if command history count changed or input changed
        // This is conservative but ensures we never miss updates
        let current_history_len = state.command_history.len();
        let current_input_len = state.input_text.len();
        let current_cursor = state.cursor_position;

        // For now, always rebuild - it's simple and TUI rendering is fast
        // TODO: We could cache a hash of the current state if performance becomes an issue
        true
    }

    /// Update viewport information
    fn update_viewport(&mut self, area: Rect) -> bool {
        let width = area.width.saturating_sub(2);
        let height = area.height.saturating_sub(2);
        let visible_lines = height as usize;

        let changed = self.last_width != width
            || self.last_height != height
            || self.visible_lines != visible_lines;

        if changed {
            self.last_width = width;
            self.last_height = height;
            self.visible_lines = visible_lines;
        }

        changed
    }

    /// Rebuild the line cache
    fn rebuild_cache(&mut self, state: &CommandPanelState, width: u16) {
        self.cached_lines.clear();

        // Debug: Log command history state
        tracing::debug!("rebuild_cache: command_history.len()={}, static_lines.len()={}, is_in_history_search={}",
            state.command_history.len(), state.static_lines.len(), state.is_in_history_search());

        // First, cache static lines (including welcome messages)
        for static_line in &state.static_lines {
            let wrapped_lines = self.wrap_text(&static_line.content, width);
            for wrapped_line in wrapped_lines {
                let line_hash = self.calculate_hash(&wrapped_line);
                let styled_line = match static_line.line_type {
                    LineType::Welcome => {
                        // Format welcome messages with special styling based on content
                        self.create_welcome_line(&wrapped_line)
                    }
                    LineType::Response => {
                        self.create_response_line(&wrapped_line, static_line.response_type)
                    }
                    LineType::Command => self.create_command_line(&wrapped_line),
                    LineType::CurrentInput => Line::from(Span::styled(
                        wrapped_line.clone(),
                        Style::default().fg(Color::White),
                    )),
                };

                self.cached_lines.push(CachedLine {
                    content_hash: line_hash,
                    rendered_line: styled_line,
                    line_type: static_line.line_type,
                    response_type: static_line.response_type,
                    original_content: wrapped_line,
                });
            }
        }

        // Then, cache command history
        for (_index, item) in state.command_history.iter().enumerate() {
            // Command line - use (ghostscope) prompt for consistency
            let command_content = format!("(ghostscope) {}", item.command);

            // Wrap command line if it's too long
            let wrapped_command_lines = self.wrap_text(&command_content, width);
            for (line_idx, wrapped_line) in wrapped_command_lines.iter().enumerate() {
                let command_hash = self.calculate_hash(wrapped_line);
                let command_line = if line_idx == 0 {
                    // First line with full styling
                    self.create_command_line(wrapped_line)
                } else {
                    // Continuation lines with simpler styling
                    Line::from(Span::styled(
                        wrapped_line.clone(),
                        Style::default().fg(Color::White),
                    ))
                };

                self.cached_lines.push(CachedLine {
                    content_hash: command_hash,
                    rendered_line: command_line,
                    line_type: LineType::Command,
                    response_type: None,
                    original_content: wrapped_line.clone(),
                });
            }

            // Response lines (if any)
            if let Some(ref response) = item.response {
                let response_lines = self.split_response_lines(response);
                for response_line in response_lines {
                    // Wrap each response line if it's too long
                    let wrapped_response_lines = self.wrap_text(&response_line, width);
                    for wrapped_response in wrapped_response_lines {
                        let response_hash = self.calculate_hash(&wrapped_response);
                        let styled_line =
                            self.create_response_line(&wrapped_response, item.response_type);

                        self.cached_lines.push(CachedLine {
                            content_hash: response_hash,
                            rendered_line: styled_line,
                            line_type: LineType::Response,
                            response_type: item.response_type,
                            original_content: wrapped_response,
                        });
                    }
                }
            }
        }

        // Current input line or script editor content
        match state.mode {
            crate::model::panel_state::InteractionMode::ScriptEditor => {
                // Render script editor content
                if let Some(ref script_cache) = state.script_cache {
                    // Script header
                    let header = format!(
                        "🔨 Entering script mode for target: {}",
                        script_cache.target
                    );
                    let header_hash = self.calculate_hash(&header);
                    let header_line = Line::from(Span::styled(
                        header.clone(),
                        Style::default().fg(Color::Cyan),
                    ));
                    self.cached_lines.push(CachedLine {
                        content_hash: header_hash,
                        rendered_line: header_line,
                        line_type: LineType::CurrentInput,
                        response_type: None,
                        original_content: header,
                    });

                    // Separator line
                    let separator = "─".repeat(50);
                    let separator_hash = self.calculate_hash(&separator);
                    let separator_line = Line::from(Span::styled(
                        separator.clone(),
                        Style::default().fg(Color::Cyan),
                    ));
                    self.cached_lines.push(CachedLine {
                        content_hash: separator_hash,
                        rendered_line: separator_line,
                        line_type: LineType::CurrentInput,
                        response_type: None,
                        original_content: separator,
                    });

                    // Script editor prompt
                    let script_prompt = "Script Editor (Ctrl+s to submit, Esc to cancel):";
                    let prompt_hash = self.calculate_hash(script_prompt);
                    let prompt_line = Line::from(Span::styled(
                        script_prompt.to_string(),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(ratatui::style::Modifier::BOLD),
                    ));
                    self.cached_lines.push(CachedLine {
                        content_hash: prompt_hash,
                        rendered_line: prompt_line,
                        line_type: LineType::CurrentInput,
                        response_type: None,
                        original_content: script_prompt.to_string(),
                    });

                    // Script lines with automatic wrapping
                    for (line_idx, line_content) in script_cache.lines.iter().enumerate() {
                        let line_number = format!("{:3} │ ", line_idx + 1);

                        // Check if this line needs wrapping
                        let line_number_width = line_number.chars().count();
                        let available_width = (width as usize).saturating_sub(line_number_width);

                        if line_content.chars().count() > available_width && available_width > 0 {
                            // Line needs wrapping
                            let wrapped_lines =
                                self.wrap_text(line_content, available_width as u16);

                            for (wrap_idx, wrapped_line) in wrapped_lines.iter().enumerate() {
                                let is_current_line = line_idx == script_cache.cursor_line;
                                let cursor_pos_in_wrap = if is_current_line {
                                    // Calculate which wrapped line contains the cursor
                                    let mut char_count = 0;
                                    let mut found_wrap = false;
                                    for (idx, wrap) in wrapped_lines.iter().enumerate() {
                                        let wrap_char_count = wrap.chars().count();
                                        if script_cache.cursor_col >= char_count
                                            && script_cache.cursor_col
                                                < char_count + wrap_char_count
                                        {
                                            if idx == wrap_idx {
                                                found_wrap = true;
                                                break;
                                            }
                                        }
                                        char_count += wrap_char_count;
                                    }
                                    if found_wrap {
                                        script_cache.cursor_col.saturating_sub(char_count)
                                    } else {
                                        usize::MAX // No cursor on this wrap line
                                    }
                                } else {
                                    usize::MAX // No cursor on this line
                                };

                                let full_line = format!(
                                    "{}{}",
                                    if wrap_idx == 0 {
                                        line_number.clone()
                                    } else {
                                        "    │ ".to_string()
                                    },
                                    wrapped_line
                                );
                                let line_hash = self.calculate_hash(&full_line);

                                // Create line with cursor if needed
                                let styled_line = if cursor_pos_in_wrap != usize::MAX {
                                    self.create_script_line_with_cursor(
                                        &if wrap_idx == 0 {
                                            line_number.clone()
                                        } else {
                                            "    │ ".to_string()
                                        },
                                        wrapped_line,
                                        cursor_pos_in_wrap,
                                    )
                                } else {
                                    Line::from(vec![
                                        Span::styled(
                                            if wrap_idx == 0 {
                                                line_number.clone()
                                            } else {
                                                "    │ ".to_string()
                                            },
                                            Style::default().fg(Color::DarkGray),
                                        ),
                                        Span::styled(
                                            wrapped_line.clone(),
                                            Style::default().fg(Color::White),
                                        ),
                                    ])
                                };

                                self.cached_lines.push(CachedLine {
                                    content_hash: line_hash,
                                    rendered_line: styled_line,
                                    line_type: LineType::CurrentInput,
                                    response_type: None,
                                    original_content: full_line,
                                });
                            }
                        } else {
                            // Line doesn't need wrapping, use original logic
                            let full_line = format!("{}{}", line_number, line_content);
                            let line_hash = self.calculate_hash(&full_line);

                            let styled_line = if line_idx == script_cache.cursor_line {
                                self.create_script_line_with_cursor(
                                    &line_number,
                                    line_content,
                                    script_cache.cursor_col,
                                )
                            } else {
                                Line::from(vec![
                                    Span::styled(line_number, Style::default().fg(Color::DarkGray)),
                                    Span::styled(
                                        line_content.clone(),
                                        Style::default().fg(Color::White),
                                    ),
                                ])
                            };

                            self.cached_lines.push(CachedLine {
                                content_hash: line_hash,
                                rendered_line: styled_line,
                                line_type: LineType::CurrentInput,
                                response_type: None,
                                original_content: full_line,
                            });
                        }
                    }
                }
            }
            _ => {
                // Normal input mode
                if matches!(
                    state.input_state,
                    crate::model::panel_state::InputState::Ready
                ) {
                    let prompt = "(ghostscope) ";

                    // Calculate the actual display content including history search prompt
                    let display_prompt = if state.is_in_history_search() {
                        format!("(reverse-i-search)`{}': ", state.get_history_search_query())
                    } else {
                        prompt.to_string()
                    };
                    let display_text = state.get_display_text();
                    let input_content = format!("{}{}", display_prompt, display_text);

                    // Handle long input that needs wrapping
                    if input_content.chars().count() > width as usize {
                        self.handle_wrapped_input(state, prompt, width);
                    } else {
                        // Normal single-line input
                        let input_hash = self.calculate_hash(&input_content);
                        let input_line = if state.is_in_history_search() {
                            // In history search mode, handle specially
                            self.create_history_search_input_line(state)
                        } else {
                            self.create_input_line(
                                prompt,
                                state.get_display_text(),
                                state.get_display_cursor_position(),
                                state,
                            )
                        };
                        self.cached_lines.push(CachedLine {
                            content_hash: input_hash,
                            rendered_line: input_line,
                            line_type: LineType::CurrentInput,
                            response_type: None,
                            original_content: input_content,
                        });
                    }
                }
            }
        }

        self.cache_version += 1;
    }

    /// Create a styled command line
    fn create_command_line(&self, content: &str) -> Line<'static> {
        // Handle (ghostscope) prompt specifically
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
        let style = self.get_response_style(response_type);
        Line::from(Span::styled(content.to_string(), style))
    }

    /// Create a welcome line with content-based styling
    fn create_welcome_line(&self, content: &str) -> Line<'static> {
        // Check if we have a pre-styled version in the mapping
        if let Some(styled_line) = self.welcome_lines_mapping.get(content) {
            return styled_line.clone();
        }

        // Fallback to content-based styling if not found in mapping
        use ratatui::style::{Color, Modifier, Style};
        use ratatui::text::Span;

        // Apply content-based styling for welcome messages
        if content.contains("GhostScope") {
            // Title line
            Line::from(Span::styled(
                content.to_string(),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ))
        } else if content.starts_with("•") || content.starts_with("Loading completed in") {
            // Bullet points and timing info
            Line::from(Span::styled(
                content.to_string(),
                Style::default().fg(Color::Cyan),
            ))
        } else if content.starts_with("Attached to process") {
            // Process info
            Line::from(Span::styled(
                content.to_string(),
                Style::default().fg(Color::White),
            ))
        } else if content.trim().is_empty() {
            // Empty lines
            Line::from("")
        } else {
            // Default welcome text styling
            Line::from(Span::styled(
                content.to_string(),
                Style::default().fg(Color::White),
            ))
        }
    }

    /// Create a history search input line with proper cursor positioning
    fn create_history_search_input_line(&self, state: &CommandPanelState) -> Line<'static> {
        let mut spans = Vec::new();

        // History search prompt
        let search_query = state.get_history_search_query();
        let prompt_text = format!("(reverse-i-search)`{}': ", search_query);

        tracing::debug!(
            "create_history_search_input_line: search_query='{}', prompt_text='{}'",
            search_query,
            prompt_text
        );

        spans.push(Span::styled(prompt_text, Style::default().fg(Color::Cyan)));

        // Display matched command or search query
        if let Some(matched_command) = state
            .history_search
            .current_match(&state.command_history_manager)
        {
            // Show matched command
            let cursor_pos = search_query.len();
            let chars: Vec<char> = matched_command.chars().collect();

            tracing::debug!("create_history_search_input_line: matched_command='{}', cursor_pos={}, chars.len()={}",
                matched_command, cursor_pos, chars.len());

            if cursor_pos < chars.len() {
                // Show text before cursor position (should be the matching part)
                if cursor_pos > 0 {
                    let before: String = chars[..cursor_pos].iter().collect();
                    tracing::debug!(
                        "create_history_search_input_line: before cursor: '{}'",
                        before
                    );
                    spans.push(Span::styled(before, Style::default()));
                }

                // Show cursor character
                let cursor_char = chars[cursor_pos];
                tracing::debug!(
                    "create_history_search_input_line: cursor char: '{}'",
                    cursor_char
                );
                spans.push(Span::styled(
                    cursor_char.to_string(),
                    crate::ui::themes::UIThemes::cursor_style(),
                ));

                // Show text after cursor in gray
                if cursor_pos + 1 < chars.len() {
                    let after: String = chars[cursor_pos + 1..].iter().collect();
                    tracing::debug!(
                        "create_history_search_input_line: after cursor: '{}'",
                        after
                    );
                    spans.push(Span::styled(after, Style::default().fg(Color::DarkGray)));
                }
            } else {
                // Cursor at end, show all text and space cursor
                tracing::debug!(
                    "create_history_search_input_line: cursor at end, showing space cursor"
                );
                spans.push(Span::styled(matched_command.to_string(), Style::default()));
                spans.push(Span::styled(
                    " ".to_string(),
                    crate::ui::themes::UIThemes::cursor_style(),
                ));
            }
        } else {
            // No match, just show cursor at end of search query (already included in prompt)
            tracing::debug!("create_history_search_input_line: no match, showing space cursor");
            spans.push(Span::styled(
                " ".to_string(),
                crate::ui::themes::UIThemes::cursor_style(),
            ));
        }

        Line::from(spans)
    }

    /// Create a styled input line with cursor, auto-suggestion and history search support
    fn create_input_line(
        &self,
        prompt: &str,
        input_text: &str,
        cursor_pos: usize,
        state: &CommandPanelState,
    ) -> Line<'static> {
        let chars: Vec<char> = input_text.chars().collect();
        let mut spans = Vec::new();

        // Display history search indicator if in search mode
        if state.is_in_history_search() {
            spans.push(Span::styled(
                format!("(reverse-i-search)`{}': ", state.get_history_search_query()),
                Style::default().fg(Color::Cyan),
            ));
        } else {
            spans.push(Span::styled(
                prompt.to_string(),
                Style::default().fg(Color::Magenta),
            ));
        }

        if chars.is_empty() {
            // Empty input, show auto-suggestion if available
            if let Some(suggestion_text) = state.get_suggestion_text() {
                // Show first character of suggestion as block cursor, rest as gray
                let suggestion_chars: Vec<char> = suggestion_text.chars().collect();
                if !suggestion_chars.is_empty() {
                    spans.push(Span::styled(
                        suggestion_chars[0].to_string(),
                        crate::ui::themes::UIThemes::cursor_style(),
                    ));
                    if suggestion_chars.len() > 1 {
                        let remaining: String = suggestion_chars[1..].iter().collect();
                        spans.push(Span::styled(
                            remaining,
                            Style::default().fg(Color::DarkGray),
                        ));
                    }
                } else {
                    spans.push(Span::styled(
                        " ".to_string(),
                        crate::ui::themes::UIThemes::cursor_style(),
                    ));
                }
            } else {
                // No suggestion, show space as block cursor
                spans.push(Span::styled(
                    " ".to_string(),
                    crate::ui::themes::UIThemes::cursor_style(),
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
                        crate::ui::themes::UIThemes::cursor_style(),
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
                        crate::ui::themes::UIThemes::cursor_style(),
                    ));
                }
            } else {
                // No auto-suggestion, show block cursor at end
                spans.push(Span::styled(input_text.to_string(), Style::default()));
                spans.push(Span::styled(
                    " ".to_string(),
                    crate::ui::themes::UIThemes::cursor_style(),
                ));
            }
        } else {
            // Cursor in middle of text - show character as block cursor
            let before_cursor: String = chars[..cursor_pos].iter().collect();
            let at_cursor = if cursor_pos < chars.len() {
                chars[cursor_pos]
            } else {
                ' ' // If cursor is at end, show space as block cursor
            };
            let after_cursor: String = if cursor_pos < chars.len() {
                chars[cursor_pos + 1..].iter().collect()
            } else {
                String::new()
            };

            // Text before cursor
            if !before_cursor.is_empty() {
                spans.push(Span::styled(before_cursor, Style::default()));
            }

            // Character at cursor position as block cursor
            spans.push(Span::styled(
                at_cursor.to_string(),
                crate::ui::themes::UIThemes::cursor_style(),
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

    /// Create a script line with cursor visualization
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
            // Empty line, show block cursor
            spans.push(Span::styled(
                " ".to_string(),
                crate::ui::themes::UIThemes::cursor_style(),
            ));
        } else if cursor_pos >= chars.len() {
            // Cursor at end
            spans.push(Span::styled(
                content.to_string(),
                Style::default().fg(Color::White),
            ));
            spans.push(Span::styled(
                " ".to_string(),
                crate::ui::themes::UIThemes::cursor_style(),
            ));
        } else {
            // Cursor in middle
            let before_cursor: String = chars[..cursor_pos].iter().collect();
            let at_cursor = chars[cursor_pos];
            let after_cursor: String = chars[cursor_pos + 1..].iter().collect();

            if !before_cursor.is_empty() {
                spans.push(Span::styled(
                    before_cursor,
                    Style::default().fg(Color::White),
                ));
            }
            // Show character at cursor position as block cursor
            spans.push(Span::styled(
                at_cursor.to_string(),
                crate::ui::themes::UIThemes::cursor_style(),
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

    /// Get style for response type
    fn get_response_style(&self, response_type: Option<ResponseType>) -> Style {
        match response_type {
            Some(ResponseType::Success) => Style::default().fg(Color::Green),
            Some(ResponseType::Error) => Style::default().fg(Color::Red),
            Some(ResponseType::Warning) => Style::default().fg(Color::Yellow),
            Some(ResponseType::Info) => Style::default().fg(Color::Cyan),
            Some(ResponseType::Progress) => Style::default().fg(Color::Blue),
            Some(ResponseType::ScriptDisplay) => Style::default().fg(Color::Magenta),
            None => Style::default().fg(Color::Gray),
        }
    }

    /// Split response into lines
    fn split_response_lines(&self, response: &str) -> Vec<String> {
        response.lines().map(String::from).collect()
    }

    /// Calculate hash for content
    fn calculate_hash(&self, content: &str) -> u64 {
        let mut hasher = DefaultHasher::new();
        content.hash(&mut hasher);
        self.last_width.hash(&mut hasher); // Include width in hash
        hasher.finish()
    }

    /// Wrap text to fit within the specified width
    fn wrap_text(&self, text: &str, width: u16) -> Vec<String> {
        if width <= 2 {
            return vec![text.to_string()];
        }

        let max_width = width as usize;
        let mut lines = Vec::new();

        for line in text.lines() {
            // Calculate the actual display width using Unicode width
            let line_width: usize = line
                .chars()
                .map(|c| UnicodeWidthChar::width(c).unwrap_or(0))
                .sum();

            if line_width <= max_width {
                lines.push(line.to_string());
            } else {
                // Need to wrap this line
                let mut current_line = String::new();
                let mut current_width = 0;

                for ch in line.chars() {
                    let char_width = UnicodeWidthChar::width(ch).unwrap_or(0);

                    if current_width + char_width > max_width && !current_line.is_empty() {
                        // Start a new line
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

    /// Handle wrapped input that spans multiple lines
    fn handle_wrapped_input(&mut self, state: &CommandPanelState, prompt: &str, width: u16) {
        let prompt_len = if state.is_in_history_search() {
            format!("(reverse-i-search)`{}': ", state.get_history_search_query())
                .chars()
                .count()
        } else {
            prompt.chars().count()
        };
        let input_text = state.get_display_text();
        let cursor_pos = state.get_display_cursor_position();

        // Handle history search mode prompt differently
        let display_prompt = if state.is_in_history_search() {
            format!("(reverse-i-search)`{}': ", state.get_history_search_query())
        } else {
            prompt.to_string()
        };

        // Wrap the full content (prompt + input)
        let full_content = format!("{}{}", display_prompt, input_text);
        let wrapped_lines = self.wrap_text(&full_content, width);

        let mut char_count = 0;
        let mut cursor_line = 0;
        let mut cursor_col_in_line = 0;

        // Find which line the cursor is on
        for (line_idx, line) in wrapped_lines.iter().enumerate() {
            let line_char_count = line.chars().count();
            let cursor_pos_with_prompt = cursor_pos + prompt_len;

            if char_count + line_char_count >= cursor_pos_with_prompt {
                cursor_line = line_idx;
                cursor_col_in_line = cursor_pos_with_prompt - char_count;
                break;
            }
            char_count += line_char_count;
        }

        // Create cached lines for each wrapped line
        for (line_idx, line) in wrapped_lines.iter().enumerate() {
            let line_hash = self.calculate_hash(line);

            let styled_line = if line_idx == 0 {
                // First line: handle prompt and possible cursor
                if cursor_line == 0 {
                    self.create_wrapped_input_line_with_cursor(line, prompt_len, cursor_col_in_line)
                } else {
                    // First line without cursor - create input line without cursor
                    self.create_wrapped_input_line_without_cursor(line, prompt_len)
                }
            } else {
                // Continuation line
                if line_idx == cursor_line {
                    self.create_wrapped_input_line_with_cursor(line, 0, cursor_col_in_line)
                } else {
                    Line::from(Span::styled(line.clone(), Style::default()))
                }
            };

            self.cached_lines.push(CachedLine {
                content_hash: line_hash,
                rendered_line: styled_line,
                line_type: LineType::CurrentInput,
                response_type: None,
                original_content: line.clone(),
            });
        }
    }

    /// Create a wrapped input line with cursor
    fn create_wrapped_input_line_with_cursor(
        &self,
        line: &str,
        prompt_len: usize,
        cursor_pos: usize,
    ) -> Line<'static> {
        let chars: Vec<char> = line.chars().collect();
        let mut spans = Vec::new();

        if prompt_len > 0 && prompt_len <= chars.len() {
            // This line contains the prompt
            let prompt_part: String = chars[..prompt_len].iter().collect();
            spans.push(Span::styled(
                prompt_part,
                Style::default().fg(Color::Magenta),
            ));

            let text_part: String = chars[prompt_len..].iter().collect();
            let cursor_in_text = cursor_pos.saturating_sub(prompt_len);

            // Handle cursor in the text part
            self.add_text_with_cursor(&mut spans, &text_part, cursor_in_text);
        } else {
            // This line doesn't contain the prompt
            self.add_text_with_cursor(&mut spans, line, cursor_pos);
        }

        Line::from(spans)
    }

    /// Create a wrapped input line without cursor
    fn create_wrapped_input_line_without_cursor(
        &self,
        line: &str,
        prompt_len: usize,
    ) -> Line<'static> {
        let chars: Vec<char> = line.chars().collect();
        let mut spans = Vec::new();

        if prompt_len > 0 && prompt_len <= chars.len() {
            // This line contains the prompt
            let prompt_part: String = chars[..prompt_len].iter().collect();
            spans.push(Span::styled(
                prompt_part,
                Style::default().fg(Color::Magenta),
            ));

            let text_part: String = chars[prompt_len..].iter().collect();
            spans.push(Span::styled(text_part, Style::default()));
        } else {
            // This line doesn't contain the prompt
            spans.push(Span::styled(line.to_string(), Style::default()));
        }

        Line::from(spans)
    }

    /// Add text with cursor to spans vector
    fn add_text_with_cursor(&self, spans: &mut Vec<Span<'static>>, text: &str, cursor_pos: usize) {
        let chars: Vec<char> = text.chars().collect();

        if chars.is_empty() {
            // Empty text, show space as block cursor
            spans.push(Span::styled(
                " ".to_string(),
                crate::ui::themes::UIThemes::cursor_style(),
            ));
        } else if cursor_pos == 0 {
            // Cursor at beginning - show first character as block cursor
            let first_char = chars[0];
            spans.push(Span::styled(
                first_char.to_string(),
                crate::ui::themes::UIThemes::cursor_style(),
            ));
            if chars.len() > 1 {
                let remaining: String = chars[1..].iter().collect();
                spans.push(Span::styled(remaining, Style::default()));
            }
        } else if cursor_pos >= chars.len() {
            // Cursor at end
            spans.push(Span::styled(text.to_string(), Style::default()));
            spans.push(Span::styled(
                " ".to_string(),
                crate::ui::themes::UIThemes::cursor_style(),
            ));
        } else {
            // Cursor in middle
            let before_cursor: String = chars[..cursor_pos].iter().collect();
            let at_cursor = chars[cursor_pos];
            let after_cursor: String = chars[cursor_pos + 1..].iter().collect();

            if !before_cursor.is_empty() {
                spans.push(Span::styled(before_cursor, Style::default()));
            }

            spans.push(Span::styled(
                at_cursor.to_string(),
                crate::ui::themes::UIThemes::cursor_style(),
            ));

            if !after_cursor.is_empty() {
                spans.push(Span::styled(after_cursor, Style::default()));
            }
        }
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
            // No focus: white border
            Style::default().fg(Color::White)
        } else {
            // Has focus: different colors based on state and mode
            match state.input_state {
                crate::model::panel_state::InputState::WaitingResponse { .. } => {
                    // Waiting for response: yellow border
                    Style::default().fg(Color::Yellow)
                }
                _ => match state.mode {
                    crate::model::panel_state::InteractionMode::Input => {
                        // Input mode: green border
                        Style::default().fg(Color::Green)
                    }
                    crate::model::panel_state::InteractionMode::Command => {
                        // Command mode: cyan border
                        Style::default().fg(Color::Cyan)
                    }
                    crate::model::panel_state::InteractionMode::ScriptEditor => {
                        Style::default().fg(Color::Green)
                    }
                },
            }
        };

        let title = match state.input_state {
            crate::model::panel_state::InputState::WaitingResponse { .. } => {
                "Interactive Command (waiting for response...)".to_string()
            }
            _ => match state.mode {
                crate::model::panel_state::InteractionMode::Input => {
                    "Interactive Command (input mode)".to_string()
                }
                crate::model::panel_state::InteractionMode::Command => {
                    "Interactive Command (command mode)".to_string()
                }
                crate::model::panel_state::InteractionMode::ScriptEditor => {
                    "Interactive Command (script mode)".to_string()
                }
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

    /// Render content with viewport management
    fn render_content(&self, f: &mut Frame, area: Rect, state: &CommandPanelState) {
        let inner_area = Rect::new(
            area.x + 1,
            area.y + 1,
            area.width.saturating_sub(2),
            area.height.saturating_sub(2),
        );

        // Determine which lines to show (viewport)
        let total_lines = self.cached_lines.len();
        let visible_count = inner_area.height as usize;

        // In command mode or history search mode, adjust viewport to show the cursor line
        let (start_line, cursor_visible_line) = if matches!(
            state.mode,
            crate::model::panel_state::InteractionMode::Command
        ) || state.is_in_history_search()
        {
            // Calculate viewport to keep cursor visible
            let cursor_line = if state.is_in_history_search() {
                // In history search mode, cursor should be on the last line (current input)
                total_lines.saturating_sub(1)
            } else {
                state.command_cursor_line
            };
            let mut start = if total_lines > visible_count {
                total_lines - visible_count
            } else {
                0
            };

            // Adjust start to make cursor visible
            if cursor_line < start {
                start = cursor_line;
            } else if cursor_line >= start + visible_count {
                start = cursor_line.saturating_sub(visible_count - 1);
            }

            (start, Some(cursor_line.saturating_sub(start)))
        } else {
            // Normal mode: show most recent lines (bottom-up)
            let start = if total_lines > visible_count {
                total_lines - visible_count
            } else {
                0
            };
            (start, None)
        };

        let mut visible_lines: Vec<Line> = self
            .cached_lines
            .iter()
            .skip(start_line)
            .take(visible_count)
            .map(|cached| cached.rendered_line.clone())
            .collect();

        // In command mode, show cursor at specific character position
        if let Some(cursor_line_idx) = cursor_visible_line {
            if cursor_line_idx < visible_lines.len() {
                let original_line = &visible_lines[cursor_line_idx];
                let cursor_col = state.command_cursor_column;

                // Create new line with cursor character highlighted
                let mut new_spans = Vec::new();
                let mut current_pos = 0;

                for span in &original_line.spans {
                    let span_len = span.content.chars().count();
                    let span_end = current_pos + span_len;

                    if cursor_col >= current_pos && cursor_col < span_end {
                        // Cursor is within this span
                        let chars: Vec<char> = span.content.chars().collect();
                        let cursor_pos_in_span = cursor_col - current_pos;

                        // Add text before cursor
                        if cursor_pos_in_span > 0 {
                            let before: String = chars[..cursor_pos_in_span].iter().collect();
                            new_spans.push(ratatui::text::Span::styled(before, span.style));
                        }

                        // Add cursor character with inverted colors
                        if cursor_pos_in_span < chars.len() {
                            let cursor_char = chars[cursor_pos_in_span];
                            new_spans.push(ratatui::text::Span::styled(
                                cursor_char.to_string(),
                                crate::ui::themes::UIThemes::cursor_style(),
                            ));

                            // Add text after cursor
                            if cursor_pos_in_span + 1 < chars.len() {
                                let after: String =
                                    chars[cursor_pos_in_span + 1..].iter().collect();
                                new_spans.push(ratatui::text::Span::styled(after, span.style));
                            }
                        } else {
                            // Cursor at end of span, add space cursor
                            new_spans.push(ratatui::text::Span::styled(
                                " ".to_string(),
                                crate::ui::themes::UIThemes::cursor_style(),
                            ));
                        }
                    } else {
                        // Cursor not in this span, keep original
                        new_spans.push(span.clone());
                    }

                    current_pos = span_end;
                }

                // If cursor is beyond all text, add a space cursor at the end
                if cursor_col >= current_pos {
                    new_spans.push(ratatui::text::Span::styled(
                        " ".to_string(),
                        crate::ui::themes::UIThemes::cursor_style(),
                    ));
                }

                visible_lines[cursor_line_idx] = Line::from(new_spans);
            }
        }

        let paragraph = Paragraph::new(visible_lines);
        f.render_widget(paragraph, inner_area);
    }

    /// Update scroll offset for history browsing
    pub fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
            self.mark_pending_updates();
        }
    }

    pub fn scroll_down(&mut self) {
        let max_scroll = self.cached_lines.len().saturating_sub(self.visible_lines);
        if self.scroll_offset < max_scroll {
            self.scroll_offset += 1;
            self.mark_pending_updates();
        }
    }
}

impl Default for OptimizedRenderer {
    fn default() -> Self {
        Self::new()
    }
}

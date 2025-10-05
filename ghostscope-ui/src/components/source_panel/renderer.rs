use crate::components::command_panel::FileCompletionCache;
use crate::model::panel_state::{SourcePanelMode, SourcePanelState};
use crate::ui::themes::UIThemes;
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph},
    Frame,
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

/// Handles source panel rendering
pub struct SourceRenderer;

impl SourceRenderer {
    /// Render the source panel
    pub fn render(
        f: &mut Frame,
        area: Rect,
        state: &mut SourcePanelState,
        cache: &FileCompletionCache,
        is_focused: bool,
    ) {
        state.area_height = area.height;
        state.area_width = area.width;

        // Ensure both horizontal and vertical cursor are visible with actual panel dimensions
        crate::components::source_panel::navigation::SourceNavigation::ensure_horizontal_cursor_visible(state, area.width);
        crate::components::source_panel::navigation::SourceNavigation::ensure_cursor_visible(
            state,
            area.height,
        );

        // If in file search mode, render only the overlay
        if state.mode == SourcePanelMode::FileSearch {
            Self::render_file_search_overlay(f, area, state, cache);
            return;
        }

        // Render normal source view
        Self::render_source_content(f, area, state, is_focused);

        // Render overlays based on mode
        if is_focused {
            match state.mode {
                SourcePanelMode::Normal => {
                    Self::render_number_buffer(f, area, state);
                    Self::render_cursor(f, area, state);
                }
                SourcePanelMode::TextSearch => {
                    Self::render_search_prompt(f, area, state);
                }
                SourcePanelMode::FileSearch => {
                    // Already handled above
                }
            }
        }
    }

    /// Render main source content
    fn render_source_content(
        f: &mut Frame,
        area: Rect,
        state: &SourcePanelState,
        is_focused: bool,
    ) {
        let items: Vec<ListItem> = state
            .content
            .iter()
            .enumerate()
            .skip(state.scroll_offset)
            .map(|(i, line)| {
                let line_num = i + 1;
                let is_current_line = i == state.cursor_line;

                // Check trace status for this line
                let is_enabled = state.traced_lines.contains(&line_num);
                let is_disabled = state.disabled_lines.contains(&line_num);
                let is_pending = state.pending_trace_line == Some(line_num);

                let line_number_style = if is_enabled {
                    // Green bold for enabled traces
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else if is_disabled {
                    // Yellow bold for disabled traces
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else if is_pending {
                    // Light yellow for pending trace
                    Style::default()
                        .fg(Color::LightYellow)
                        .add_modifier(Modifier::BOLD)
                } else if is_current_line && is_focused {
                    Style::default().fg(Color::LightYellow).bg(Color::DarkGray)
                } else {
                    Style::default().fg(Color::DarkGray)
                };

                // Apply horizontal scrolling to the line content
                let visible_line = if state.horizontal_scroll_offset > 0 {
                    let chars: Vec<char> = line.chars().collect();
                    if state.horizontal_scroll_offset < chars.len() {
                        chars[state.horizontal_scroll_offset..].iter().collect()
                    } else {
                        String::new()
                    }
                } else {
                    line.to_string()
                };

                // Calculate available width for content dynamically

                // Pure vim-style display - no truncation, just show what fits
                // Horizontal scrolling is already applied above
                let display_line = visible_line;

                // Apply syntax highlighting
                let highlighted_spans = Self::highlight_line(&display_line, &state.language);

                // Apply search highlighting overlay
                let final_spans =
                    Self::apply_search_overlay(&display_line, highlighted_spans, i, state);

                let mut spans = vec![Span::styled(format!("{line_num:4} "), line_number_style)];
                spans.extend(final_spans);

                ListItem::new(Line::from(spans))
            })
            .collect();

        let border_style = if is_focused {
            UIThemes::panel_focused()
        } else {
            UIThemes::panel_unfocused()
        };

        let title = match &state.file_path {
            Some(path) => format!("Source Code - {path}"),
            None => "Source Code".to_string(),
        };

        let border_type = if is_focused {
            BorderType::Thick
        } else {
            BorderType::Rounded
        };

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(border_type)
                .title(title)
                .border_style(border_style),
        );

        f.render_widget(list, area);
    }

    /// Render file search overlay
    fn render_file_search_overlay(
        f: &mut Frame,
        area: Rect,
        state: &SourcePanelState,
        cache: &FileCompletionCache,
    ) {
        // Clear the entire area
        f.render_widget(ratatui::widgets::Clear, area);

        // Render background
        let background = Block::default()
            .style(Style::default().bg(Color::Rgb(16, 16, 16)))
            .borders(Borders::NONE);
        f.render_widget(background, area);

        // Calculate overlay dimensions
        let overlay_height = 13u16.min(area.height);
        let overlay_width = area.width.saturating_sub(10).max(40);
        let overlay_area = Rect::new(
            area.x + (area.width.saturating_sub(overlay_width)) / 2,
            area.y + (area.height.saturating_sub(overlay_height)) / 2,
            overlay_width,
            overlay_height,
        );

        // Clear overlay area
        f.render_widget(ratatui::widgets::Clear, overlay_area);

        // Outer block
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Thick)
            .title("Open File")
            .border_style(Style::default().fg(Color::Cyan))
            .style(Style::default().bg(Color::Rgb(20, 20, 20)));
        f.render_widget(block, overlay_area);

        if overlay_area.width <= 2 || overlay_area.height <= 2 {
            return;
        }

        let inner = Rect {
            x: overlay_area.x + 1,
            y: overlay_area.y + 1,
            width: overlay_area.width - 2,
            height: overlay_area.height - 2,
        };

        // Input line with cursor support
        let prefix = "🔎 ";
        Self::render_input_with_cursor(f, inner, state, prefix);

        // Body: message or file list
        if let Some(msg) = &state.file_search_message {
            let msg_para = Paragraph::new(msg.clone()).style(
                Style::default()
                    .fg(if msg.starts_with('✗') {
                        Color::Red
                    } else {
                        Color::DarkGray
                    })
                    .bg(Color::Rgb(30, 30, 30)),
            );
            if inner.height > 2 {
                f.render_widget(
                    msg_para,
                    Rect::new(inner.x, inner.y + 1, inner.width, inner.height - 1),
                );
            }
        } else {
            Self::render_file_list(f, inner, state, cache);
        }
    }

    /// Render file list in file search overlay
    fn render_file_list(
        f: &mut Frame,
        area: Rect,
        state: &SourcePanelState,
        cache: &FileCompletionCache,
    ) {
        let mut items: Vec<ListItem> = Vec::new();
        let start = state.file_search_scroll;
        let end = (start + 10).min(state.file_search_filtered_indices.len());

        let all_files = cache.get_all_files();
        for idx in start..end {
            let real_idx = state.file_search_filtered_indices[idx];
            let path = &all_files[real_idx];

            // Get file icon based on extension
            let icon = Self::get_file_icon(path);

            let is_selected = idx == state.file_search_selected;
            let text_color = if is_selected {
                Color::LightMagenta
            } else {
                Color::White
            };

            // Create display text with safe truncation
            let full_text = format!("{icon} {path}");
            let max_width = (area.width.saturating_sub(4)) as usize;
            let display_text = Self::truncate_text(&full_text, max_width);

            let line = Line::from(vec![Span::styled(
                display_text,
                Style::default().fg(text_color),
            )]);
            items.push(ListItem::new(line));
        }

        let list = List::new(items)
            .block(Block::default().style(Style::default().bg(Color::Rgb(30, 30, 30))));
        let list_area = Rect::new(
            area.x,
            area.y + 1,
            area.width,
            area.height.saturating_sub(1),
        );
        f.render_widget(list, list_area);
    }

    /// Render number buffer display
    fn render_number_buffer(f: &mut Frame, area: Rect, state: &SourcePanelState) {
        if state.number_buffer.is_empty() && !state.g_pressed {
            return;
        }

        let mut display_text = String::new();
        if !state.number_buffer.is_empty() {
            display_text.push_str(&state.number_buffer);
        }
        if state.g_pressed {
            display_text.push('g');
        }

        if display_text.is_empty() {
            return;
        }

        let hint_text = if state.g_pressed && state.number_buffer.is_empty() {
            "Press 'g' again for top"
        } else if !state.number_buffer.is_empty() {
            "Press 'G' to jump to line"
        } else {
            ""
        };

        let mut spans = Vec::new();
        spans.push(Span::styled(
            display_text.clone(),
            Style::default().fg(Color::Green).bg(Color::Rgb(30, 30, 30)),
        ));

        if !hint_text.is_empty() {
            spans.push(Span::styled(
                format!(" ({hint_text})"),
                Style::default().fg(Color::Cyan).bg(Color::Rgb(30, 30, 30)),
            ));
        }

        let text = ratatui::text::Text::from(Line::from(spans));
        let full_text = if !hint_text.is_empty() {
            format!("{display_text} ({hint_text})")
        } else {
            display_text
        };

        let text_width = full_text.len() as u16;
        let display_x = area.x + area.width.saturating_sub(text_width + 2);
        let display_y = area.y + area.height.saturating_sub(1);

        f.render_widget(
            Paragraph::new(text).alignment(ratatui::layout::Alignment::Right),
            Rect::new(display_x, display_y, text_width + 2, 1),
        );
    }

    /// Render search prompt
    fn render_search_prompt(f: &mut Frame, area: Rect, state: &SourcePanelState) {
        let text = ratatui::text::Text::from(Line::from(vec![
            Span::styled("/", Style::default().fg(Color::Yellow)),
            Span::styled(&state.search_query, Style::default().fg(Color::White)),
        ]));

        let display_x = area.x + 1;
        let display_y = area.y + area.height.saturating_sub(1);
        let text_width = (1 + state.search_query.len()) as u16 + 1;

        f.render_widget(
            Paragraph::new(text),
            Rect::new(display_x, display_y, text_width, 1),
        );
    }

    /// Render cursor
    fn render_cursor(f: &mut Frame, area: Rect, state: &SourcePanelState) {
        if state.content.is_empty() {
            return;
        }

        let cursor_y = area.y + 1 + (state.cursor_line.saturating_sub(state.scroll_offset)) as u16;
        const LINE_NUMBER_WIDTH: u16 = 5;

        // Calculate cursor X position considering horizontal scroll
        // Only render cursor if it's actually within the horizontally visible area
        if state.cursor_col >= state.horizontal_scroll_offset {
            let visible_cursor_column = state.cursor_col - state.horizontal_scroll_offset;
            let cursor_x = area.x + 1 + LINE_NUMBER_WIDTH + visible_cursor_column as u16;

            // Calculate content area boundaries
            let content_start_x = area.x + 1 + LINE_NUMBER_WIDTH;
            let content_area_width = area.width.saturating_sub(LINE_NUMBER_WIDTH + 2); // 2 for borders
            let content_end_x = content_start_x + content_area_width;

            // Only render cursor if it's within the visible area (more permissive boundary check)
            if cursor_y < area.y + area.height - 1
                && cursor_x < content_end_x  // Allow cursor to be at the edge
                && cursor_x >= content_start_x
            {
                f.render_widget(
                    Block::default().style(crate::ui::themes::UIThemes::cursor_style()),
                    Rect::new(cursor_x, cursor_y, 1, 1),
                );
            }
        }
    }

    /// Improved syntax highlighting with proper comment support
    fn highlight_line(line: &str, language: &str) -> Vec<Span<'static>> {
        let mut spans = Vec::new();

        // Check for single-line comments first
        if let Some(comment_pos) = line.find("//") {
            // Handle text before comment
            if comment_pos > 0 {
                spans.extend(Self::highlight_code(&line[..comment_pos], language));
            }
            // Handle comment (everything after //)
            spans.push(Span::styled(
                line[comment_pos..].to_string(),
                Style::default().fg(Color::DarkGray),
            ));
            return spans;
        }

        // Check for multi-line comment markers
        if line.trim_start().starts_with("/*")
            || line.contains("*/")
            || line.trim_start().starts_with("*")
        {
            spans.push(Span::styled(
                line.to_string(),
                Style::default().fg(Color::DarkGray),
            ));
            return spans;
        }

        // Regular code highlighting
        spans.extend(Self::highlight_code(line, language));
        spans
    }

    /// Highlight code without comments
    fn highlight_code(text: &str, language: &str) -> Vec<Span<'static>> {
        // Check for preprocessor directives first (for C/C++)
        if (language == "c" || language == "cpp") && text.trim_start().starts_with('#') {
            return vec![Span::styled(
                text.to_string(),
                Style::default().fg(Color::LightRed),
            )];
        }

        let mut spans = Vec::new();
        let mut current_pos = 0;
        let mut in_string = false;
        let mut string_char = '\0';
        let chars: Vec<char> = text.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let ch = chars[i];

            // Handle strings
            if ch == '"' || ch == '\'' {
                if !in_string {
                    // Add text before string
                    if i > 0 {
                        let before_string = &text[current_pos..Self::char_to_byte_pos(&chars, i)];
                        spans.extend(Self::highlight_words(before_string, language));
                    }
                    // Start string
                    in_string = true;
                    string_char = ch;
                    current_pos = Self::char_to_byte_pos(&chars, i);
                } else if ch == string_char {
                    // End string
                    spans.push(Span::styled(
                        text[current_pos..Self::char_to_byte_pos(&chars, i + 1)].to_string(),
                        Style::default().fg(Color::Yellow),
                    ));
                    in_string = false;
                    current_pos = Self::char_to_byte_pos(&chars, i + 1);
                }
            }

            i += 1;
        }

        // Handle remaining text
        if current_pos < text.len() && !in_string {
            spans.extend(Self::highlight_words(&text[current_pos..], language));
        } else if in_string {
            // Unclosed string
            spans.push(Span::styled(
                text[current_pos..].to_string(),
                Style::default().fg(Color::Yellow),
            ));
        }

        if spans.is_empty() {
            spans.push(Span::styled(text.to_string(), Style::default()));
        }

        spans
    }

    /// Convert character position to byte position
    fn char_to_byte_pos(chars: &[char], char_pos: usize) -> usize {
        chars.iter().take(char_pos).map(|c| c.len_utf8()).sum()
    }

    /// Highlight words (keywords, types, numbers)
    fn highlight_words(text: &str, language: &str) -> Vec<Span<'static>> {
        let mut spans = Vec::new();
        let mut current_word = String::new();
        let mut current_text = String::new();

        for ch in text.chars() {
            if ch.is_alphanumeric() || ch == '_' {
                if !current_text.is_empty() {
                    spans.push(Span::styled(current_text.clone(), Style::default()));
                    current_text.clear();
                }
                current_word.push(ch);
            } else {
                if !current_word.is_empty() {
                    let style = Self::get_word_style(&current_word, language);
                    spans.push(Span::styled(current_word.clone(), style));
                    current_word.clear();
                }
                current_text.push(ch);
            }
        }

        // Handle remaining word or text
        if !current_word.is_empty() {
            let style = Self::get_word_style(&current_word, language);
            spans.push(Span::styled(current_word, style));
        }
        if !current_text.is_empty() {
            spans.push(Span::styled(current_text, Style::default()));
        }

        spans
    }

    /// Get style for a word based on its type
    fn get_word_style(word: &str, language: &str) -> Style {
        if word.chars().all(|c| c.is_ascii_digit()) {
            // Numbers
            Style::default().fg(Color::Magenta)
        } else if Self::is_keyword(word, language) {
            // Keywords
            Style::default().fg(Color::Blue)
        } else if Self::is_type(word, language) {
            // Types
            Style::default().fg(Color::Cyan)
        } else {
            // Normal text
            Style::default()
        }
    }

    /// Check if a word is a keyword
    fn is_keyword(word: &str, language: &str) -> bool {
        match language {
            "c" => matches!(
                word,
                "auto"
                    | "break"
                    | "case"
                    | "char"
                    | "const"
                    | "continue"
                    | "default"
                    | "do"
                    | "double"
                    | "else"
                    | "enum"
                    | "extern"
                    | "float"
                    | "for"
                    | "goto"
                    | "if"
                    | "int"
                    | "long"
                    | "register"
                    | "return"
                    | "short"
                    | "signed"
                    | "sizeof"
                    | "static"
                    | "struct"
                    | "switch"
                    | "typedef"
                    | "union"
                    | "unsigned"
                    | "void"
                    | "volatile"
                    | "while"
            ),
            "cpp" => {
                Self::is_keyword(word, "c")
                    || matches!(
                        word,
                        "class"
                            | "namespace"
                            | "template"
                            | "typename"
                            | "public"
                            | "private"
                            | "protected"
                            | "virtual"
                            | "override"
                            | "final"
                            | "explicit"
                            | "friend"
                            | "inline"
                            | "mutable"
                            | "new"
                            | "delete"
                            | "this"
                            | "operator"
                            | "throw"
                            | "try"
                            | "catch"
                            | "bool"
                            | "true"
                            | "false"
                    )
            }
            "rust" => matches!(
                word,
                "as" | "break"
                    | "const"
                    | "continue"
                    | "crate"
                    | "else"
                    | "enum"
                    | "extern"
                    | "false"
                    | "fn"
                    | "for"
                    | "if"
                    | "impl"
                    | "in"
                    | "let"
                    | "loop"
                    | "match"
                    | "mod"
                    | "move"
                    | "mut"
                    | "pub"
                    | "ref"
                    | "return"
                    | "self"
                    | "Self"
                    | "static"
                    | "struct"
                    | "super"
                    | "trait"
                    | "true"
                    | "type"
                    | "unsafe"
                    | "use"
                    | "where"
                    | "while"
                    | "async"
                    | "await"
                    | "dyn"
            ),
            _ => false,
        }
    }

    /// Check if a word is a type
    fn is_type(word: &str, language: &str) -> bool {
        match language {
            "c" | "cpp" => matches!(
                word,
                "int"
                    | "char"
                    | "float"
                    | "double"
                    | "void"
                    | "short"
                    | "long"
                    | "unsigned"
                    | "signed"
                    | "bool"
                    | "size_t"
                    | "uint8_t"
                    | "uint16_t"
                    | "uint32_t"
                    | "uint64_t"
                    | "int8_t"
                    | "int16_t"
                    | "int32_t"
                    | "int64_t"
            ),
            "rust" => matches!(
                word,
                "i8" | "i16"
                    | "i32"
                    | "i64"
                    | "i128"
                    | "isize"
                    | "u8"
                    | "u16"
                    | "u32"
                    | "u64"
                    | "u128"
                    | "usize"
                    | "f32"
                    | "f64"
                    | "bool"
                    | "char"
                    | "str"
                    | "String"
                    | "Vec"
                    | "Option"
                    | "Result"
            ),
            _ => false,
        }
    }

    /// Apply search highlighting overlay
    fn apply_search_overlay(
        visible_line: &str,
        spans: Vec<Span<'static>>,
        line_index: usize,
        state: &SourcePanelState,
    ) -> Vec<Span<'static>> {
        if state.search_query.is_empty() || state.search_matches.is_empty() {
            return spans
                .into_iter()
                .map(|s| Span::styled(s.content.to_string(), s.style))
                .collect();
        }

        // Find matches for this line in visible coordinates
        let h_off = state.horizontal_scroll_offset;
        let ranges: Vec<(usize, usize)> = state
            .search_matches
            .iter()
            .filter_map(|(li, s, e)| {
                if *li != line_index {
                    return None;
                }
                if *e <= h_off || *s >= h_off + visible_line.len() {
                    return None;
                }
                let vis_start = s.saturating_sub(h_off);
                let vis_end = e.saturating_sub(h_off);
                Some((vis_start, vis_end))
            })
            .collect();

        if ranges.is_empty() {
            return spans
                .into_iter()
                .map(|s| Span::styled(s.content.to_string(), s.style))
                .collect();
        }

        // Apply highlighting (simplified implementation)
        let mut result: Vec<Span<'static>> = Vec::new();
        let mut pos = 0usize;

        for span in spans {
            let text = span.content.clone();
            let base_style = span.style;
            let mut cursor = 0usize;

            while cursor < text.len() {
                let mut next_break = text.len() - cursor;
                let mut highlight_now = false;

                for (rs, re) in &ranges {
                    if pos >= *re || pos + next_break <= *rs {
                        continue;
                    }
                    if pos < *rs {
                        next_break = (*rs - pos).min(next_break);
                        highlight_now = false;
                    } else {
                        next_break = (*re - pos).min(next_break);
                        highlight_now = true;
                    }
                }

                let end_cursor = cursor + next_break;
                let slice = &text[cursor..end_cursor];
                let style = if highlight_now {
                    Style::default().fg(Color::LightMagenta)
                } else {
                    base_style
                };

                result.push(Span::styled(slice.to_string(), style));
                pos += next_break;
                cursor = end_cursor;
            }
        }

        result
    }

    /// Get file icon based on extension
    fn get_file_icon(path: &str) -> &'static str {
        match std::path::Path::new(path)
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_ascii_lowercase())
        {
            Some(ref e) if ["h", "hpp", "hh", "hxx"].contains(&e.as_str()) => "📑",
            Some(ref e) if ["c", "cc", "cpp", "cxx"].contains(&e.as_str()) => "📝",
            Some(ref e) if e == "rs" => "🦀",
            Some(ref e) if ["s", "asm"].contains(&e.as_str()) => "🛠️",
            _ => "📄",
        }
    }

    /// Safely truncate text to fit width (vim-style - just cut off, no dots)
    fn truncate_text(text: &str, max_width: usize) -> String {
        if text.width() <= max_width {
            text.to_string()
        } else {
            let mut truncated = String::new();
            let mut current_width = 0;

            for ch in text.chars() {
                let char_width = ch.width().unwrap_or(1);
                if current_width + char_width > max_width {
                    break;
                }
                truncated.push(ch);
                current_width += char_width;
            }
            truncated
        }
    }

    /// Render input line with proper cursor positioning
    fn render_input_with_cursor(f: &mut Frame, area: Rect, state: &SourcePanelState, prefix: &str) {
        let chars: Vec<char> = state.file_search_query.chars().collect();
        let cursor_pos = state.file_search_cursor_pos;

        // Build the input line with cursor
        let mut spans = vec![Span::styled(
            prefix.to_string(),
            Style::default().fg(Color::Cyan),
        )];

        if chars.is_empty() {
            // Empty input, show cursor as a space
            spans.push(Span::styled(" ".to_string(), UIThemes::cursor_style()));
        } else if cursor_pos >= chars.len() {
            // Cursor at end
            spans.push(Span::styled(
                state.file_search_query.clone(),
                Style::default().fg(Color::White),
            ));
            spans.push(Span::styled(" ".to_string(), UIThemes::cursor_style()));
        } else {
            // Cursor in middle of text
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

        let input_line = Line::from(spans);
        let input_para =
            Paragraph::new(input_line).style(Style::default().bg(Color::Rgb(30, 30, 30)));
        f.render_widget(input_para, Rect::new(area.x, area.y, area.width, 1));
    }
}

use super::syntax_highlighter;
use crate::action::ResponseType;
use crate::model::panel_state::{CommandPanelState, LineType, StaticTextLine};
use crate::ui::{strings::UIStrings, symbols::UISymbols, themes::UIThemes};
use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
    Frame,
};
use unicode_width::UnicodeWidthChar;

// Help message dynamic detection removed after pre-styled migration

// Help styling handled upstream; no local emoji-based parsing
// Info dynamic styling removed; titles are generated pre-styled upstream

/// Parameter struct for format_executable_file_info to avoid too many function arguments
pub struct ExecutableFileInfoDisplay<'a> {
    pub file_path: &'a str,
    pub file_type: &'a str,
    pub entry_point: Option<u64>,
    pub has_symbols: bool,
    pub has_debug_info: bool,
    pub debug_file_path: &'a Option<String>,
    pub text_section: &'a Option<crate::events::SectionInfo>,
    pub data_section: &'a Option<crate::events::SectionInfo>,
    pub mode_description: &'a str,
}

/// Handles response formatting and display for the command panel
pub struct ResponseFormatter;

impl ResponseFormatter {
    /// Create enhanced styled lines for generic messages.
    /// - Leading symbols: ✓ (success), ✗ (error), ⚠ (warning)
    /// - Numbers/hex addresses: Yellow
    /// - Keywords (trace/function/line/file/pid/pc/enabled/disabled/deleted/saved/loaded): Cyan
    /// - Error tokens (failed/error/unknown/not/found/cannot/missing): Red
    pub fn style_generic_message_lines(text: &str) -> Vec<Line<'static>> {
        text.lines().map(Self::style_generic_message_line).collect()
    }

    fn style_generic_message_line(line: &str) -> Line<'static> {
        use crate::components::command_panel::style_builder::StylePresets;
        use ratatui::style::{Color, Style};
        use ratatui::text::Span;

        if line.trim().is_empty() {
            return Line::from("");
        }

        // Detect leading status after indentation
        let trimmed = line.trim_start();
        let indent_len = line.len() - trimmed.len();
        let indent = &line[..indent_len];

        if trimmed.starts_with('✗') {
            // Replace leading ✗ with ❌ and paint whole line red
            let mut without = &trimmed['✗'.len_utf8()..];
            // Consume optional variation selector U+FE0F if present
            if without.starts_with('\u{FE0F}') {
                let vs = '\u{FE0F}'.len_utf8();
                without = &without[vs..];
            }
            let replaced = format!("{}{}{}", indent, "❌", without);
            return Line::from(Span::styled(replaced, StylePresets::ERROR));
        }

        // Otherwise, keep semantic token styling
        let mut spans: Vec<Span<'static>> = Vec::new();
        let mut rest = line;

        // Leading symbol without trimming (✓/⚠)
        if let Some(first) = rest.chars().next() {
            let mut style = Style::default();
            let mut consumed: Option<usize> = None;
            let mut sym: Option<&str> = None;
            match first {
                '✓' => {
                    style = StylePresets::SUCCESS;
                    consumed = Some('✓'.len_utf8());
                    sym = Some("✅");
                }
                '⚠' => {
                    style = StylePresets::WARNING;
                    consumed = Some('⚠'.len_utf8());
                    sym = Some("⚠️");
                }
                _ => {}
            }
            if let Some(mut n) = consumed {
                // Consume optional variation selector U+FE0F if present right after the symbol
                if rest[n..].starts_with('\u{FE0F}') {
                    n += '\u{FE0F}'.len_utf8();
                }
                let rendered = sym.unwrap_or("");
                let rendered = if rendered.is_empty() {
                    first.to_string()
                } else {
                    rendered.to_string()
                };
                spans.push(Span::styled(rendered, style));
                rest = &rest[n..];
            }
        }

        // Tokenize remaining by simple boundaries, preserving punctuation as separate tokens
        let mut token = String::new();
        for ch in rest.chars() {
            let is_sep = ch.is_whitespace() || ",.:()[]{}".contains(ch);
            if is_sep {
                if !token.is_empty() {
                    spans.push(Self::style_token(&token));
                    token.clear();
                }
                if ch.is_whitespace() {
                    spans.push(Span::raw(ch.to_string()));
                } else {
                    spans.push(Span::styled(
                        ch.to_string(),
                        Style::default().fg(Color::DarkGray),
                    ));
                }
            } else {
                token.push(ch);
            }
        }
        if !token.is_empty() {
            spans.push(Self::style_token(&token));
        }

        Line::from(spans)
    }

    fn style_token(tok: &str) -> Span<'static> {
        use ratatui::style::{Color, Style};
        let lower = tok.to_ascii_lowercase();

        // Hex or number
        if tok.starts_with("0x") || tok.chars().all(|c| c.is_ascii_hexdigit()) && tok.len() > 1 {
            return Span::styled(tok.to_string(), Style::default().fg(Color::Yellow));
        }

        // Keywords for structure
        const KEYS: &[&str] = &[
            "trace", "function", "line", "file", "pid", "pc", "saved", "loaded", "deleted",
            "enabled", "disabled",
        ];
        if KEYS.iter().any(|k| lower == *k) {
            return Span::styled(tok.to_string(), Style::default().fg(Color::Cyan));
        }

        // Error tokens
        const ERR: &[&str] = &[
            "failed", "error", "unknown", "not", "found", "cannot", "missing",
        ];
        if ERR.iter().any(|k| lower == *k) {
            return Span::styled(tok.to_string(), Style::default().fg(Color::Red));
        }

        // Default
        Span::styled(tok.to_string(), Style::default().fg(Color::White))
    }

    /// Add a response with pre-styled lines (preferred when available)
    pub fn add_response_with_style(
        state: &mut CommandPanelState,
        content: String,
        styled_lines: Option<Vec<Line<'static>>>,
        response_type: ResponseType,
    ) {
        if let Some(last_item) = state.command_history.last_mut() {
            last_item.response = Some(content);
            last_item.response_styled = styled_lines;
            last_item.response_type = Some(response_type);
            tracing::debug!(
                "add_response_with_style: Added styled response to command '{}'",
                last_item.command
            );
        } else {
            tracing::warn!("add_response_with_style: No command in history to attach response to!");
        }

        Self::update_static_lines(state);
    }

    /// Helper method to create a simple single-line styled response
    /// This reduces code duplication for common response patterns
    pub fn add_simple_styled_response(
        state: &mut CommandPanelState,
        content: String,
        style: ratatui::style::Style,
        response_type: ResponseType,
    ) {
        let styled = vec![
            crate::components::command_panel::style_builder::StyledLineBuilder::new()
                .styled(&content, style)
                .build(),
        ];
        Self::add_response_with_style(state, content, Some(styled), response_type);
    }

    /// Format styled lines for batch trace loading summary
    /// This reduces code duplication in app.rs for source command responses
    pub fn format_batch_load_summary_styled(
        filename: &str,
        total_count: usize,
        success_count: usize,
        failed_count: usize,
        disabled_count: usize,
        details: &[crate::events::TraceLoadDetail],
    ) -> Vec<Line<'static>> {
        use crate::components::command_panel::style_builder::{StylePresets, StyledLineBuilder};
        let mut lines = Vec::new();

        // Title line
        lines.push(
            StyledLineBuilder::new()
                .styled(
                    format!("📂 Loaded traces from {filename}"),
                    StylePresets::TITLE,
                )
                .build(),
        );

        // Summary line
        let summary = if disabled_count > 0 {
            format!(
                "  Total: {total_count}, Success: {success_count}, Failed: {failed_count}, Disabled: {disabled_count}"
            )
        } else {
            format!("  Total: {total_count}, Success: {success_count}, Failed: {failed_count}")
        };
        lines.push(StyledLineBuilder::new().value(&summary).build());

        // Details
        if !details.is_empty() {
            lines.push(
                StyledLineBuilder::new()
                    .styled("", StylePresets::VALUE)
                    .build(),
            );
            lines.push(
                StyledLineBuilder::new()
                    .styled("📊 Details:", StylePresets::SECTION)
                    .build(),
            );
            for detail in details {
                match detail.status {
                    crate::events::LoadStatus::Created => {
                        let text = if let Some(id) = detail.trace_id {
                            format!("  ✓ {} → trace #{}", detail.target, id)
                        } else {
                            format!("  ✓ {}", detail.target)
                        };
                        lines.push(
                            StyledLineBuilder::new()
                                .styled(text, StylePresets::SUCCESS)
                                .build(),
                        );
                    }
                    crate::events::LoadStatus::CreatedDisabled => {
                        let text = if let Some(id) = detail.trace_id {
                            format!("  ⊘ {} → trace #{} (disabled)", detail.target, id)
                        } else {
                            format!("  ⊘ {} (disabled)", detail.target)
                        };
                        lines.push(
                            StyledLineBuilder::new()
                                .styled(text, StylePresets::WARNING)
                                .build(),
                        );
                    }
                    crate::events::LoadStatus::Failed => {
                        let text = if let Some(ref error) = detail.error {
                            format!("  ✗ {}: {}", detail.target, error)
                        } else {
                            format!("  ✗ {}", detail.target)
                        };
                        lines.push(
                            StyledLineBuilder::new()
                                .styled(text, StylePresets::ERROR)
                                .build(),
                        );
                    }
                    _ => {}
                }
            }
        }

        lines
    }

    // Removed add_welcome_message - now using direct styled approach

    /// Update the static lines display from command history
    pub fn update_static_lines(state: &mut CommandPanelState) {
        // Keep welcome messages but remove command/response lines
        state
            .static_lines
            .retain(|line| line.line_type == LineType::Welcome);
        state.styled_buffer = None;
        state.styled_at_history_index = None;

        // Add history items
        for (index, item) in state.command_history.iter().enumerate() {
            // Add command line
            let command_line = format!(
                "{prompt}{command}",
                prompt = item.prompt,
                command = item.command
            );
            state.static_lines.push(StaticTextLine {
                content: command_line,
                line_type: LineType::Command,
                history_index: Some(index),
                response_type: None,
                styled_content: None,
            });

            // Add response lines if they exist
            if let Some(ref styled) = item.response_styled {
                // Preferred path: use pre-styled lines when available
                for line in styled.iter() {
                    let plain: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
                    state.static_lines.push(StaticTextLine {
                        content: plain,
                        line_type: LineType::Response,
                        history_index: Some(index),
                        response_type: item.response_type,
                        styled_content: Some(line.clone()),
                    });
                }
            } else if let Some(ref response) = item.response {
                // Fallback path: plain only (all help/info are pre-styled upstream now)
                for response_line in Self::split_response_lines(response) {
                    state.static_lines.push(StaticTextLine {
                        content: response_line,
                        line_type: LineType::Response,
                        history_index: Some(index),
                        response_type: item.response_type,
                        styled_content: None,
                    });
                }
            }
        }

        // Note: Current input line is rendered separately by the renderer (render_normal_input)
        // Don't add it to static_lines to avoid duplication
    }

    /// Split response into individual lines for display
    fn split_response_lines(response: &str) -> Vec<String> {
        response.lines().map(String::from).collect()
    }

    // Removed: all dynamic help/info styling helpers (pre-styled upstream)

    /// Format a line for display with proper styling
    pub fn format_line_for_display(
        state: &CommandPanelState,
        line: &StaticTextLine,
        is_current_input: bool,
        width: usize,
    ) -> Vec<Line<'static>> {
        match line.line_type {
            LineType::Command => Self::format_command_line(&line.content, width),
            LineType::Response => Self::format_response_line(line, width),
            LineType::Welcome => Self::format_response_line(line, width), // Format welcome messages like responses
            LineType::CurrentInput => {
                if is_current_input {
                    Self::format_current_input_line(state, &line.content, width)
                } else {
                    Self::format_command_line(&line.content, width)
                }
            }
        }
    }

    /// Format a command line
    fn format_command_line(content: &str, width: usize) -> Vec<Line<'static>> {
        let wrapped_lines = Self::wrap_text(content, width);
        wrapped_lines
            .into_iter()
            .map(|line| Line::from(vec![Span::styled(line, Style::default().fg(Color::White))]))
            .collect()
    }

    /// Format a response line with appropriate styling
    fn format_response_line(line: &StaticTextLine, width: usize) -> Vec<Line<'static>> {
        let style = Self::get_response_style(&line.content, line.response_type);

        // Check if this is a script display line
        if Self::is_script_display_line(&line.content) {
            Self::format_script_display_line(&line.content, width)
        } else {
            let wrapped_lines = Self::wrap_text(&line.content, width);
            wrapped_lines
                .into_iter()
                .map(|line_content| Line::from(vec![Span::styled(line_content, style)]))
                .collect()
        }
    }

    /// Format current input line with cursor indication
    fn format_current_input_line(
        _state: &CommandPanelState,
        content: &str,
        width: usize,
    ) -> Vec<Line<'static>> {
        let wrapped_lines = Self::wrap_text(content, width);

        // For now, just return the styled line without cursor indication
        // TODO: Add proper cursor rendering
        wrapped_lines
            .into_iter()
            .map(|line| Line::from(vec![Span::styled(line, UIThemes::input_mode())]))
            .collect()
    }

    /// Get appropriate style for response based on type and content
    fn get_response_style(content: &str, response_type: Option<ResponseType>) -> Style {
        // First check explicit response type
        if let Some(resp_type) = response_type {
            return match resp_type {
                ResponseType::Success => UIThemes::success_text(),
                ResponseType::Error => UIThemes::error_text(),
                ResponseType::Warning => UIThemes::warning_text(),
                ResponseType::Info => UIThemes::info_text(),
                ResponseType::Progress => UIThemes::progress_text(),
                ResponseType::ScriptDisplay => UIThemes::script_mode(),
            };
        }

        // Fallback to content-based detection
        if content.starts_with(UIStrings::SUCCESS_PREFIX) || content.starts_with("✓") {
            UIThemes::success_text()
        } else if content.starts_with(UIStrings::ERROR_PREFIX) || content.starts_with("✗") {
            UIThemes::error_text()
        } else if content.starts_with(UIStrings::WARNING_PREFIX) || content.starts_with("⚠") {
            UIThemes::warning_text()
        } else if content.starts_with(UIStrings::PROGRESS_PREFIX) || content.starts_with("⏳") {
            UIThemes::progress_text()
        } else if content.starts_with("📝") {
            UIThemes::script_mode()
        } else {
            Style::default()
        }
    }

    /// Check if a line is part of a script display
    fn is_script_display_line(content: &str) -> bool {
        content.starts_with("📝")
            || content.starts_with(UIStrings::SCRIPT_TARGET_PREFIX)
            || content.chars().all(|c| c == '─' || c.is_whitespace())
            || content.contains(" │ ")
    }

    /// Format script display lines with syntax highlighting
    fn format_script_display_line(content: &str, width: usize) -> Vec<Line<'static>> {
        if content.starts_with("📝") || content.starts_with(UIStrings::SCRIPT_TARGET_PREFIX) {
            // Header line - green and bold
            vec![Line::from(vec![Span::styled(
                content.to_string(),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            )])]
        } else if content.chars().all(|c| c == '─' || c.is_whitespace()) {
            // Separator line - dark gray
            vec![Line::from(vec![Span::styled(
                content.to_string(),
                Style::default().fg(Color::DarkGray),
            )])]
        } else if content.contains(" │ ") {
            // Script line with line number - apply syntax highlighting
            Self::format_script_code_line(content, width)
        } else {
            // Regular line
            vec![Line::from(vec![Span::styled(
                content.to_string(),
                Style::default(),
            )])]
        }
    }

    /// Format a script code line with line numbers
    fn format_script_code_line(content: &str, width: usize) -> Vec<Line<'static>> {
        if let Some(separator_pos) = content.find(" │ ") {
            let separator_str = " │ ";
            let end_byte_pos = separator_pos + separator_str.len();

            if end_byte_pos <= content.len() {
                let line_number_part = &content[..end_byte_pos];
                let code_part = &content[end_byte_pos..];

                let wrapped_lines = Self::wrap_text(content, width);
                wrapped_lines
                    .into_iter()
                    .enumerate()
                    .map(|(idx, line)| {
                        if idx == 0 {
                            // First line - format with line number and code parts
                            let mut spans = vec![Span::styled(
                                line_number_part.to_string(),
                                Style::default().fg(Color::DarkGray),
                            )];

                            if !code_part.is_empty() {
                                // Apply syntax highlighting to the code part
                                let highlighted_spans =
                                    syntax_highlighter::highlight_line(code_part);
                                spans.extend(highlighted_spans);
                            }

                            Line::from(spans)
                        } else {
                            // Continuation lines - indent to align with code
                            let indent = " ".repeat(line_number_part.len());
                            let mut spans = vec![Span::styled(indent, Style::default())];

                            // Apply syntax highlighting to continuation lines too
                            let highlighted_spans = syntax_highlighter::highlight_line(&line);
                            spans.extend(highlighted_spans);

                            Line::from(spans)
                        }
                    })
                    .collect()
            } else {
                vec![Line::from(vec![Span::styled(
                    content.to_string(),
                    Style::default(),
                )])]
            }
        } else {
            vec![Line::from(vec![Span::styled(
                content.to_string(),
                Style::default(),
            )])]
        }
    }

    /// Wrap text to fit within specified width (Unicode-aware)
    fn wrap_text(text: &str, width: usize) -> Vec<String> {
        if width == 0 || text.is_empty() {
            return vec![text.to_string()];
        }

        let mut lines: Vec<String> = Vec::new();
        let mut current_line = String::new();
        let mut current_width: usize = 0;

        for ch in text.chars() {
            if ch == '\n' {
                lines.push(current_line);
                current_line = String::new();
                current_width = 0;
                continue;
            }

            let ch_width = UnicodeWidthChar::width(ch).unwrap_or(0).max(1);
            if current_width + ch_width > width {
                lines.push(current_line);
                current_line = String::new();
                current_width = 0;
            }

            current_line.push(ch);
            current_width += ch_width;
        }

        if !current_line.is_empty() {
            lines.push(current_line);
        }

        if lines.is_empty() {
            vec![text.to_string()]
        } else {
            lines
        }
    }

    /// Format file information display
    pub fn format_file_info(groups: &[crate::events::SourceFileGroup], use_ascii: bool) -> String {
        const MAX_FILES_DETAILED: usize = 1000;
        const MAX_FILES_PER_MODULE: usize = 50;

        let total_files: usize = groups.iter().map(|g| g.files.len()).sum();
        let folder_icon = if use_ascii {
            UISymbols::FILE_FOLDER_ASCII
        } else {
            UISymbols::FILE_FOLDER
        };
        let mut response = format!(
            "{folder_icon} {} ({} modules, {total_files} files):\n\n",
            UIStrings::SOURCE_FILES_HEADER,
            groups.len()
        );

        if groups.is_empty() {
            response.push_str(&format!("  {}\n", UIStrings::NO_SOURCE_FILES));
            return response;
        }

        // For large datasets, show summary mode
        if total_files > MAX_FILES_DETAILED {
            response.push_str(&format!(
                "⚠️  Large dataset detected ({total_files} files). Showing summary view.\n\n"
            ));
            Self::format_file_summary(groups, use_ascii, &mut response);
        } else {
            for group in groups {
                // For individual modules with many files, also use limited view
                if group.files.len() > MAX_FILES_PER_MODULE {
                    Self::format_module_summary(group, use_ascii, &mut response);
                } else {
                    Self::format_module_detailed(group, use_ascii, &mut response);
                }
            }
        }

        response
    }

    /// Styled: Format file information display
    pub fn format_file_info_styled(
        groups: &[crate::events::SourceFileGroup],
        use_ascii: bool,
    ) -> Vec<Line<'static>> {
        use crate::components::command_panel::style_builder::{StylePresets, StyledLineBuilder};
        use std::collections::BTreeMap;

        let total_files: usize = groups.iter().map(|g| g.files.len()).sum();
        let mut lines = Vec::new();

        // Title
        lines.push(
            StyledLineBuilder::new()
                .title(format!(
                    "{} ({} modules, {} files):",
                    UIStrings::SOURCE_FILES_HEADER,
                    groups.len(),
                    total_files
                ))
                .build(),
        );
        lines.push(Line::from(""));

        if groups.is_empty() {
            lines.push(
                StyledLineBuilder::new()
                    .text("  ")
                    .value(UIStrings::NO_SOURCE_FILES)
                    .build(),
            );
            return lines;
        }

        for group in groups {
            // Module path as section
            lines.push(
                StyledLineBuilder::new()
                    .styled(format!("📦 {}", group.module_path), StylePresets::SECTION)
                    .build(),
            );

            if group.files.is_empty() {
                lines.push(
                    StyledLineBuilder::new()
                        .styled("   └─", StylePresets::TREE)
                        .value("(no files)")
                        .build(),
                );
                lines.push(Line::from(""));
                continue;
            }

            // Group by directory (same logic as plain)
            let mut dir_map: BTreeMap<String, Vec<&crate::events::SourceFileInfo>> =
                BTreeMap::new();
            for f in &group.files {
                dir_map.entry(f.directory.clone()).or_default().push(f);
            }

            let dir_count = dir_map.len();
            for (didx, (dir, files)) in dir_map.into_iter().enumerate() {
                let last_dir = didx + 1 == dir_count;
                let dir_prefix = if last_dir {
                    if use_ascii {
                        "   └-"
                    } else {
                        "   └─"
                    }
                } else if use_ascii {
                    "   |-"
                } else {
                    "   ├─"
                };

                lines.push(
                    StyledLineBuilder::new()
                        .styled(dir_prefix, StylePresets::TREE)
                        .text(" ")
                        .key(&dir)
                        .text(format!(" ({} files)", files.len()))
                        .build(),
                );

                for (fidx, file) in files.iter().enumerate() {
                    let last_file = fidx + 1 == files.len();
                    let file_prefix = if last_dir {
                        if last_file {
                            "      └─"
                        } else {
                            "      ├─"
                        }
                    } else if last_file {
                        "   │  └─"
                    } else {
                        "   │  ├─"
                    };
                    lines.push(
                        StyledLineBuilder::new()
                            .styled(file_prefix, StylePresets::TREE)
                            .text(" ")
                            .value(&file.path)
                            .build(),
                    );
                }
            }
            lines.push(Line::from(""));
        }

        lines
    }

    /// Format file information in summary mode for large datasets
    fn format_file_summary(
        groups: &[crate::events::SourceFileGroup],
        use_ascii: bool,
        response: &mut String,
    ) {
        // Show top N modules and file type statistics
        let mut file_types = std::collections::HashMap::new();

        for group in groups.iter().take(10) {
            // Show top 10 modules
            let module_icon = if use_ascii { "+" } else { "📦" };
            response.push_str(&format!(
                "{module_icon} {} ({} files)\n",
                group.module_path,
                group.files.len()
            ));

            // Count file types in this module
            for file in &group.files {
                let ext = std::path::Path::new(&file.path)
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("(none)")
                    .to_ascii_lowercase();
                *file_types.entry(ext).or_insert(0) += 1;
            }
        }

        if groups.len() > 10 {
            response.push_str(&format!("... and {} more modules\n", groups.len() - 10));
        }

        response.push_str("\n📊 File Type Summary:\n");
        let mut sorted_types: Vec<_> = file_types.into_iter().collect();
        sorted_types.sort_by(|a, b| b.1.cmp(&a.1));

        for (ext, count) in sorted_types.into_iter().take(10) {
            let icon = UISymbols::get_file_icon(&ext, use_ascii);
            response.push_str(&format!("  {icon} .{ext}: {count} files\n"));
        }

        response.push_str("\n💡 Use 'o' key in source panel to search for specific files.\n");
    }

    /// Format a single module in summary mode
    fn format_module_summary(
        group: &crate::events::SourceFileGroup,
        use_ascii: bool,
        response: &mut String,
    ) {
        let package_icon = if use_ascii {
            UISymbols::FILE_PACKAGE_ASCII
        } else {
            UISymbols::FILE_PACKAGE
        };
        response.push_str(&format!(
            "{package_icon} {} ({} files - showing summary)\n",
            group.module_path,
            group.files.len()
        ));

        // Group by directory and show counts
        let mut dir_map: std::collections::BTreeMap<String, usize> =
            std::collections::BTreeMap::new();
        for file in &group.files {
            *dir_map.entry(file.directory.clone()).or_insert(0) += 1;
        }

        for (i, (dir, count)) in dir_map.iter().enumerate().take(5) {
            let is_last = i == 4 || i == dir_map.len() - 1;
            let prefix = if is_last { "  └─" } else { "  ├─" };
            response.push_str(&format!("{prefix} {dir} ({count} files)\n"));
        }

        if dir_map.len() > 5 {
            response.push_str(&format!(
                "  └─ ... and {} more directories\n",
                dir_map.len() - 5
            ));
        }

        response.push('\n');
    }

    /// Format a single module with full details
    fn format_module_detailed(
        group: &crate::events::SourceFileGroup,
        use_ascii: bool,
        response: &mut String,
    ) {
        let group_file_count = group.files.len();
        let package_icon = if use_ascii {
            UISymbols::FILE_PACKAGE_ASCII
        } else {
            UISymbols::FILE_PACKAGE
        };
        response.push_str(&format!(
            "{package_icon} {} ({group_file_count} files)\n",
            group.module_path
        ));

        if group.files.is_empty() {
            response.push_str("  └─ (no files)\n\n");
            return;
        }

        let mut dir_map: std::collections::BTreeMap<String, Vec<&crate::events::SourceFileInfo>> =
            std::collections::BTreeMap::new();
        for f in &group.files {
            dir_map.entry(f.directory.clone()).or_default().push(f);
        }

        let dir_count = dir_map.len();
        for (didx, (dir, files)) in dir_map.into_iter().enumerate() {
            let last_dir = didx + 1 == dir_count;
            let dir_prefix = if last_dir {
                if use_ascii {
                    UISymbols::NAV_TREE_LAST_ASCII
                } else {
                    UISymbols::NAV_TREE_LAST
                }
            } else if use_ascii {
                UISymbols::NAV_TREE_BRANCH_ASCII
            } else {
                UISymbols::NAV_TREE_BRANCH
            };
            response.push_str(&format!("  {dir_prefix} {dir} ({} files)\n", files.len()));

            for (fidx, file) in files.iter().enumerate() {
                let last_file = fidx + 1 == files.len();
                let file_prefix = if last_dir {
                    if last_file {
                        "     └─"
                    } else {
                        "     ├─"
                    }
                } else if last_file {
                    "  │  └─"
                } else {
                    "  │  ├─"
                };

                let ext = std::path::Path::new(&file.path)
                    .extension()
                    .and_then(|s| s.to_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let icon = UISymbols::get_file_icon(&ext, use_ascii);
                let path = &file.path;
                response.push_str(&format!("{file_prefix} {icon} {path}\n"));
            }
        }

        response.push('\n');
    }

    /// Format shared library information
    pub fn format_shared_library_info(
        libraries: &[crate::events::SharedLibraryInfo],
        use_ascii: bool,
    ) -> String {
        let mut response = format!(
            "{} {} ({}):\n\n",
            if use_ascii {
                UISymbols::LIBRARY_ICON_ASCII
            } else {
                UISymbols::LIBRARY_ICON
            },
            UIStrings::SHARED_LIBRARIES_HEADER,
            libraries.len()
        );

        if !libraries.is_empty() {
            response.push_str(UIStrings::SHARED_LIB_TABLE_HEADER);
            response.push('\n');
            response.push_str(&UIStrings::SCRIPT_SEPARATOR.repeat(90));
            response.push('\n');

            // Collect libraries with debug links for later display
            let mut debug_links = Vec::new();

            for lib in libraries {
                let from_str = format!("0x{:016x}", lib.from_address);
                let to_str = format!("0x{:016x}", lib.to_address);

                let syms_read = UISymbols::get_yes_no_icon(lib.symbols_read, use_ascii);
                let debug_read = UISymbols::get_yes_no_icon(lib.debug_info_available, use_ascii);

                response.push_str(&format!(
                    "{}  {}  {}         {}         {}\n",
                    from_str, to_str, syms_read, debug_read, lib.library_path
                ));

                // Collect debug link info
                if let Some(ref debug_path) = lib.debug_file_path {
                    debug_links.push((lib.library_path.clone(), debug_path.clone()));
                }

                if !lib.debug_info_available {
                    let library_name = lib
                        .library_path
                        .rsplit('/')
                        .next()
                        .unwrap_or(lib.library_path.as_str());
                    response.push_str(&format!(
                        "⚠️  Warning: {library_name} {}\n",
                        UIStrings::NO_DEBUG_INFO_WARNING
                    ));
                }
            }

            // Show debug links section if any
            if !debug_links.is_empty() {
                response.push('\n');
                response.push_str("Debug files (.gnu_debuglink):\n");
                for (lib_path, debug_path) in debug_links {
                    response.push_str(&format!("  {lib_path} → {debug_path}\n"));
                }
            }
        } else {
            response.push_str(&format!("  {}\n", UIStrings::NO_SHARED_LIBRARIES));
        }

        response
    }

    /// Format executable file information for display
    pub fn format_executable_file_info(info: &ExecutableFileInfoDisplay) -> String {
        let ExecutableFileInfoDisplay {
            file_path,
            file_type,
            entry_point,
            has_symbols,
            has_debug_info,
            debug_file_path,
            text_section,
            data_section,
            mode_description,
        } = info;
        let mut response = String::new();

        // Header
        response.push_str("📄 Executable File Information:\n\n");

        // File path
        response.push_str(&format!("  File: {file_path}\n"));

        // File type
        response.push_str(&format!("  Type: {file_type}\n"));

        // Entry point
        if let Some(entry) = entry_point {
            response.push_str(&format!("  Entry point: 0x{entry:x}\n"));
        }

        response.push('\n');

        // Symbol and debug information status
        response.push_str("  Symbols:      ");
        if *has_symbols {
            response.push_str("✓ Available\n");
        } else {
            response.push_str("✗ Not available\n");
        }

        response.push_str("  Debug info:   ");
        if *has_debug_info {
            response.push_str("✓ Available");
            if let Some(ref debug_path) = debug_file_path {
                response.push_str(&format!(" (via debug link: {debug_path})"));
            }
            response.push('\n');
        } else {
            response.push_str("✗ Not available\n");
        }

        response.push('\n');

        // Determine if this is static analysis mode
        let is_static_mode = mode_description.contains("Static analysis mode");

        // Sections
        if is_static_mode {
            response.push_str("  Sections (ELF virtual addresses):\n");
        } else {
            response.push_str("  Sections (runtime loaded addresses):\n");
        }

        if let Some(text) = text_section {
            response.push_str(&format!(
                "    .text:  0x{:016x} - 0x{:016x}  (size: {} bytes)\n",
                text.start_address, text.end_address, text.size
            ));
        }

        if let Some(data) = data_section {
            response.push_str(&format!(
                "    .data:  0x{:016x} - 0x{:016x}  (size: {} bytes)\n",
                data.start_address, data.end_address, data.size
            ));
        }

        response.push('\n');

        // Mode description
        response.push_str(&format!("  Mode: {mode_description}\n"));

        response
    }

    /// Styled shared library information (new)
    pub fn format_shared_library_info_styled(
        libraries: &[crate::events::SharedLibraryInfo],
        _use_ascii: bool,
    ) -> Vec<Line<'static>> {
        use crate::components::command_panel::style_builder::{StylePresets, StyledLineBuilder};
        let mut lines = Vec::new();
        lines.push(
            StyledLineBuilder::new()
                .title(format!(
                    "📚 {} ({})",
                    UIStrings::SHARED_LIBRARIES_HEADER,
                    libraries.len()
                ))
                .build(),
        );
        lines.push(Line::from(""));

        if libraries.is_empty() {
            lines.push(
                StyledLineBuilder::new()
                    .text("  ")
                    .value(UIStrings::NO_SHARED_LIBRARIES)
                    .build(),
            );
            return lines;
        }

        for lib in libraries {
            let from_str = format!("0x{:016x}", lib.from_address);
            let to_str = format!("0x{:016x}", lib.to_address);
            let syms = if lib.symbols_read { "✅" } else { "❌" };
            let dbg = if lib.debug_info_available {
                "✅"
            } else {
                "❌"
            };

            let mut b = StyledLineBuilder::new().text("  ");
            b = b
                .text(from_str)
                .text("  ")
                .text(to_str)
                .text("  ")
                .key("sym:")
                .text(" ")
                .styled(
                    syms,
                    if lib.symbols_read {
                        StylePresets::SUCCESS
                    } else {
                        StylePresets::ERROR
                    },
                )
                .text("  ")
                .key("dbg:")
                .text(" ")
                .styled(
                    dbg,
                    if lib.debug_info_available {
                        StylePresets::SUCCESS
                    } else {
                        StylePresets::ERROR
                    },
                )
                .text("  ")
                .value(&lib.library_path);
            lines.push(b.build());

            if !lib.debug_info_available {
                let library_name = lib
                    .library_path
                    .rsplit('/')
                    .next()
                    .unwrap_or(lib.library_path.as_str());
                lines.push(
                    StyledLineBuilder::new()
                        .text("  ")
                        .styled(
                            format!(
                                "⚠️  Warning: {} {}",
                                library_name,
                                UIStrings::NO_DEBUG_INFO_WARNING
                            ),
                            StylePresets::WARNING,
                        )
                        .build(),
                );
            }

            if let Some(ref debug_path) = lib.debug_file_path {
                lines.push(
                    StyledLineBuilder::new()
                        .text("    ")
                        .key("Debug file:")
                        .text(" ")
                        .value(debug_path)
                        .build(),
                );
            }
        }

        lines
    }

    /// Styled executable file information (new)
    pub fn format_executable_file_info_styled(
        info: &ExecutableFileInfoDisplay,
    ) -> Vec<Line<'static>> {
        use crate::components::command_panel::style_builder::{StylePresets, StyledLineBuilder};
        let mut lines = vec![
            StyledLineBuilder::new()
                .title("📄 Executable File Information:")
                .build(),
            Line::from(""),
        ];

        lines.push(
            StyledLineBuilder::new()
                .text("  ")
                .key("File:")
                .text(" ")
                .value(info.file_path)
                .build(),
        );
        lines.push(
            StyledLineBuilder::new()
                .text("  ")
                .key("Type:")
                .text(" ")
                .value(info.file_type)
                .build(),
        );
        if let Some(entry) = info.entry_point {
            lines.push(
                StyledLineBuilder::new()
                    .text("  ")
                    .key("Entry point:")
                    .text(" ")
                    .address(entry)
                    .build(),
            );
        }

        lines.push(Line::from(""));

        lines.push(
            StyledLineBuilder::new()
                .text("  ")
                .key("Symbols:")
                .text(" ")
                .styled(
                    if info.has_symbols {
                        "✅ Available"
                    } else {
                        "❌ Not available"
                    },
                    if info.has_symbols {
                        StylePresets::SUCCESS
                    } else {
                        StylePresets::ERROR
                    },
                )
                .build(),
        );

        let mut dbg_line = StyledLineBuilder::new()
            .text("  ")
            .key("Debug info:")
            .text(" ");
        if info.has_debug_info {
            dbg_line = dbg_line.styled("✅ Available", StylePresets::SUCCESS);
            if let Some(ref dbg_path) = info.debug_file_path {
                dbg_line = dbg_line
                    .text(" (via debug link: ")
                    .value(dbg_path)
                    .text(")");
            }
        } else {
            dbg_line = dbg_line.styled("❌ Not available", StylePresets::ERROR);
        }
        lines.push(dbg_line.build());

        lines.push(Line::from(""));
        let is_static_mode = info.mode_description.contains("Static analysis mode");
        lines.push(
            StyledLineBuilder::new()
                .text("  ")
                .styled(
                    if is_static_mode {
                        "Sections (ELF virtual addresses):"
                    } else {
                        "Sections (runtime loaded addresses):"
                    },
                    StylePresets::SECTION,
                )
                .build(),
        );
        if let Some(text) = info.text_section {
            lines.push(
                StyledLineBuilder::new()
                    .text("    ")
                    .key(".text:")
                    .text("  ")
                    .text(format!(
                        "0x{:016x} - 0x{:016x}  (size: {} bytes)",
                        text.start_address, text.end_address, text.size
                    ))
                    .build(),
            );
        }
        if let Some(data) = info.data_section {
            lines.push(
                StyledLineBuilder::new()
                    .text("    ")
                    .key(".data:")
                    .text("  ")
                    .text(format!(
                        "0x{:016x} - 0x{:016x}  (size: {} bytes)",
                        data.start_address, data.end_address, data.size
                    ))
                    .build(),
            );
        }

        lines.push(Line::from(""));
        lines.push(
            StyledLineBuilder::new()
                .text("  ")
                .key("Mode:")
                .text(" ")
                .value(info.mode_description)
                .build(),
        );

        lines
    }

    /// Render the command panel content
    pub fn render_panel(f: &mut Frame, area: Rect, state: &CommandPanelState) {
        // Calculate inner area (excluding borders)
        let inner_area = Rect::new(
            area.x + 1,
            area.y + 1,
            area.width.saturating_sub(2),
            area.height.saturating_sub(2),
        );

        // Create simple display content
        let mut lines = Vec::new();

        // Show command history
        for item in state
            .command_history
            .iter()
            .rev()
            .take(inner_area.height as usize)
        {
            // Add command line
            let command_line = Line::from(vec![
                Span::styled(&item.prompt, Style::default().fg(Color::DarkGray)),
                Span::raw(&item.command),
            ]);
            lines.push(command_line);

            // Add response if exists
            if let Some(ref response) = item.response {
                for line in response.lines().take(3) {
                    // Limit response lines
                    lines.push(Line::from(Span::raw(line)));
                }
            }
        }

        // Always show current input line (with prompt)
        let current_prompt = "gs> "; // Use fixed prompt for now
        let current_line = Line::from(vec![
            Span::styled(current_prompt, Style::default().fg(Color::Magenta)),
            Span::raw(&state.input_text),
            Span::styled("_", Style::default().fg(Color::White)), // Simple cursor
        ]);
        lines.push(current_line);

        let paragraph = Paragraph::new(lines);
        f.render_widget(paragraph, inner_area);
    }
}

// Removed tests for dynamic help styling (now pre-styled upstream)

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

/// Handles response formatting and display for the command panel
pub struct ResponseFormatter;

impl ResponseFormatter {
    /// Add a response to the command history and update display
    pub fn add_response(
        state: &mut CommandPanelState,
        content: String,
        response_type: ResponseType,
    ) {
        if let Some(last_item) = state.command_history.last_mut() {
            last_item.response = Some(content);
            last_item.response_type = Some(response_type);
        }
        // Note: Optimized renderer will handle display updates via cache rebuild
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
            if let Some(ref response) = item.response {
                let response_lines = Self::split_response_lines(response);
                for response_line in response_lines {
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

        // Add current input line if should show prompt
        if Self::should_show_input_prompt(state) {
            let prompt = Self::get_prompt(state);
            let input_line = format!("{prompt}{input}", input = state.input_text);
            state.static_lines.push(StaticTextLine {
                content: input_line,
                line_type: LineType::CurrentInput,
                history_index: None,
                response_type: None,
                styled_content: None,
            });
        }
    }

    /// Split response into individual lines for display
    fn split_response_lines(response: &str) -> Vec<String> {
        response.lines().map(String::from).collect()
    }

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
                                spans.push(Span::styled(
                                    code_part.to_string(),
                                    Style::default().fg(Color::White),
                                ));
                            }

                            Line::from(spans)
                        } else {
                            // Continuation lines - indent to align with code
                            let indent = " ".repeat(line_number_part.len());
                            Line::from(vec![
                                Span::styled(indent, Style::default()),
                                Span::styled(line, Style::default().fg(Color::White)),
                            ])
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

    /// Check if input prompt should be shown
    fn should_show_input_prompt(state: &CommandPanelState) -> bool {
        matches!(
            state.input_state,
            crate::model::panel_state::InputState::Ready
        )
    }

    /// Get the current prompt string
    fn get_prompt(state: &CommandPanelState) -> String {
        if !Self::should_show_input_prompt(state) {
            return String::new();
        }
        UIStrings::GHOSTSCOPE_PROMPT.to_string()
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

            for lib in libraries {
                let from_str = format!("0x{:016x}", lib.from_address);
                let to_str = format!("0x{:016x}", lib.to_address);

                let syms_read = UISymbols::get_yes_no_icon(lib.symbols_read, use_ascii);
                let debug_read = UISymbols::get_yes_no_icon(lib.debug_info_available, use_ascii);

                response.push_str(&format!(
                    "{}  {}  {}         {}         {}\n",
                    from_str, to_str, syms_read, debug_read, lib.library_path
                ));

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
        } else {
            response.push_str(&format!("  {}\n", UIStrings::NO_SHARED_LIBRARIES));
        }

        response
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

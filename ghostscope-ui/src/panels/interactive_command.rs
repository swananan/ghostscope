use ratatui::{
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem},
    Frame,
};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InteractionMode {
    Input,        // Normal input mode
    Command,      // Command mode (previously VimCommand)
    ScriptEditor, // Multi-line script editing mode
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScriptStatus {
    Draft,     // Script is being edited
    Submitted, // Script was submitted successfully
    Error,     // Script had errors
}

#[derive(Debug, Clone)]
pub struct ScriptCache {
    pub target: String,       // Trace target (function name or file:line)
    pub lines: Vec<String>,   // Script lines
    pub cursor_line: usize,   // Current cursor line (0-based)
    pub cursor_col: usize,    // Current cursor column (0-based)
    pub status: ScriptStatus, // Current script status
    pub saved_scripts: HashMap<String, String>, // target -> complete script cache
}

#[derive(Debug, Clone)]
pub struct CommandHistoryItem {
    pub command: String,
    pub response: Option<String>,
    pub timestamp: std::time::Instant,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResponseType {
    Success,
    Error,
    Warning,
    Info,
    Progress,
}

#[derive(Debug, Clone)]
pub struct StaticTextLine {
    pub content: String,
    pub line_type: LineType,
    pub history_index: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LineType {
    Command,
    Response,
    CurrentInput,
}

pub struct InteractiveCommandPanel {
    pub input_text: String,
    pub cursor_position: usize,
    pub command_history: Vec<CommandHistoryItem>,
    pub history_index: Option<usize>,
    pub mode: InteractionMode,
    pub max_history_items: usize,

    // Script editing state
    pub script_cache: Option<ScriptCache>,

    // Command mode navigation (vim-like)
    pub command_cursor_line: usize,
    pub command_cursor_column: usize,

    pub static_lines: Vec<StaticTextLine>,

    // UI state
    pub scroll_offset: usize,
}

impl InteractiveCommandPanel {
    pub fn new() -> Self {
        let mut panel = Self {
            input_text: String::new(),
            cursor_position: 0,
            command_history: Vec::new(),
            history_index: None,
            mode: InteractionMode::Input,
            max_history_items: 1000,
            script_cache: None,
            command_cursor_line: 0,
            command_cursor_column: 0,
            static_lines: Vec::new(),
            scroll_offset: 0,
        };
        panel.update_static_lines();
        panel
    }

    pub fn get_prompt(&self) -> String {
        match self.mode {
            InteractionMode::Input => "(ghostscope) ".to_string(),
            InteractionMode::Command => "(ghostscope) ".to_string(),
            InteractionMode::ScriptEditor => {
                if let Some(ref cache) = self.script_cache {
                    format!("script:{} > ", cache.target)
                } else {
                    "script > ".to_string()
                }
            }
        }
    }

    pub fn insert_char(&mut self, c: char) {
        self.input_text.insert(self.cursor_position, c);
        self.cursor_position += 1;
        self.update_static_lines();
    }

    pub fn delete_char(&mut self) {
        if self.cursor_position > 0 {
            self.input_text.remove(self.cursor_position - 1);
            self.cursor_position -= 1;
            self.update_static_lines();
        }
    }

    pub fn move_cursor_left(&mut self) {
        if self.mode == InteractionMode::Command {
            if self.command_cursor_column > 0 {
                self.command_cursor_column -= 1;
            }
        } else {
            if self.cursor_position > 0 {
                self.cursor_position -= 1;
            }
        }
    }

    pub fn move_cursor_right(&mut self) {
        if self.mode == InteractionMode::Command {
            if let Some(line) = self.static_lines.get(self.command_cursor_line) {
                if self.command_cursor_column < line.content.len() {
                    self.command_cursor_column += 1;
                }
            }
        } else {
            if self.cursor_position < self.input_text.len() {
                self.cursor_position += 1;
            }
        }
    }

    pub fn move_to_next_word(&mut self) {
        let text = &self.input_text;
        let mut pos = self.cursor_position;

        // Skip current word if we're in the middle of one
        while pos < text.len() && !text.chars().nth(pos).unwrap_or(' ').is_whitespace() {
            pos += 1;
        }

        // Skip whitespace
        while pos < text.len() && text.chars().nth(pos).unwrap_or(' ').is_whitespace() {
            pos += 1;
        }

        self.cursor_position = pos;
    }

    pub fn move_to_previous_word(&mut self) {
        let text = &self.input_text;
        let mut pos = self.cursor_position;

        // Skip whitespace backwards
        while pos > 0 && text.chars().nth(pos - 1).unwrap_or(' ').is_whitespace() {
            pos -= 1;
        }

        // Skip current word backwards
        while pos > 0 && !text.chars().nth(pos - 1).unwrap_or(' ').is_whitespace() {
            pos -= 1;
        }

        self.cursor_position = pos;
    }

    pub fn move_to_next_word_in_history(&mut self) {
        if let Some(line) = self.static_lines.get(self.command_cursor_line) {
            let content = &line.content;
            let mut pos = self.command_cursor_column;

            // Skip current word if we're in the middle of one
            while pos < content.len() && !content.chars().nth(pos).unwrap_or(' ').is_whitespace() {
                pos += 1;
            }

            // Skip whitespace
            while pos < content.len() && content.chars().nth(pos).unwrap_or(' ').is_whitespace() {
                pos += 1;
            }

            self.command_cursor_column = pos;
        }
    }

    pub fn move_to_previous_word_in_history(&mut self) {
        if let Some(line) = self.static_lines.get(self.command_cursor_line) {
            let content = &line.content;
            let mut pos = self.command_cursor_column;

            // Skip whitespace backwards
            while pos > 0 && content.chars().nth(pos - 1).unwrap_or(' ').is_whitespace() {
                pos -= 1;
            }

            // Skip current word backwards
            while pos > 0 && !content.chars().nth(pos - 1).unwrap_or(' ').is_whitespace() {
                pos -= 1;
            }

            self.command_cursor_column = pos;
        }
    }

    pub fn submit_command(&mut self) -> Option<CommandAction> {
        if self.input_text.trim().is_empty() {
            return None;
        }

        let command = self.input_text.clone();
        let action = match self.mode {
            InteractionMode::Input => {
                if command.trim().starts_with("trace ") {
                    // Two-step trace interaction: parse target and enter script editor
                    self.enter_script_editor_for_trace(&command)
                } else {
                    CommandAction::ExecuteCommand(command.clone())
                }
            }
            InteractionMode::Command => {
                // Handle command mode commands
                CommandAction::ExecuteCommand(command.clone())
            }
            InteractionMode::ScriptEditor => {
                // Should not happen - script editor handles its own submission
                return None;
            }
        };

        self.add_to_history(command, None);
        self.update_static_lines();

        self.input_text.clear();
        self.cursor_position = 0;
        self.history_index = None;

        Some(action)
    }

    /// Parse trace command and enter script editor mode
    fn enter_script_editor_for_trace(&mut self, command: &str) -> CommandAction {
        let target = command.trim_start_matches("trace").trim();

        if target.is_empty() {
            return CommandAction::ExecuteCommand(
                "Usage: trace <function_name|file:line>".to_string(),
            );
        }

        // Check if we have a cached script for this target
        let (lines, restored_from_cache) = if let Some(ref cache) = self.script_cache {
            if let Some(cached_script) = cache.saved_scripts.get(target) {
                (cached_script.lines().map(String::from).collect(), true)
            } else {
                (
                    vec![
                        "// Trace script for target: ".to_string() + target,
                        String::new(),
                    ],
                    false,
                )
            }
        } else {
            (
                vec![
                    "// Trace script for target: ".to_string() + target,
                    String::new(),
                ],
                false,
            )
        };

        // Create new script cache
        self.script_cache = Some(ScriptCache {
            target: target.to_string(),
            lines,
            cursor_line: if restored_from_cache { 0 } else { 1 }, // Position after comment
            cursor_col: 0,
            status: ScriptStatus::Draft,
            saved_scripts: self
                .script_cache
                .as_ref()
                .map(|c| c.saved_scripts.clone())
                .unwrap_or_else(HashMap::new),
        });

        // Switch to script editor mode
        self.mode = InteractionMode::ScriptEditor;

        if restored_from_cache {
            CommandAction::EnterScriptMode(format!(
                "🔨 Entering script mode for target: {} [Restored from cache]",
                target
            ))
        } else {
            CommandAction::EnterScriptMode(format!(
                "🔨 Entering script mode for target: {}",
                target
            ))
        }
    }

    /// Submit the current script but keep editor displayed
    pub fn submit_script(&mut self) -> Option<CommandAction> {
        if let Some(ref mut cache) = self.script_cache {
            let script_content = cache.lines.join("\n");

            // Save to cache
            cache
                .saved_scripts
                .insert(cache.target.clone(), script_content.clone());
            cache.status = ScriptStatus::Submitted;

            // Return to Input mode for command input, but keep script cache
            self.mode = InteractionMode::Input;

            Some(CommandAction::SubmitScript(format!(
                "trace {} {}",
                cache.target, script_content
            )))
        } else {
            None
        }
    }

    /// Cancel script editing and return to command mode
    pub fn cancel_script_editor(&mut self) {
        if self.mode == InteractionMode::ScriptEditor {
            self.mode = InteractionMode::Input;
            // Keep script_cache for potential restoration
        }
    }

    pub fn cancel_script(&mut self) -> bool {
        match self.mode {
            InteractionMode::ScriptEditor => {
                self.cancel_script_editor();
                true
            }
            _ => false,
        }
    }

    /// Add script editing helper methods
    pub fn insert_char_in_script(&mut self, c: char) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_line < cache.lines.len() {
                cache.lines[cache.cursor_line].insert(cache.cursor_col, c);
                cache.cursor_col += 1;
                cache.status = ScriptStatus::Draft;
            }
        }
    }

    pub fn delete_char_in_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_line < cache.lines.len() && cache.cursor_col > 0 {
                cache.lines[cache.cursor_line].remove(cache.cursor_col - 1);
                cache.cursor_col -= 1;
                cache.status = ScriptStatus::Draft;
            }
        }
    }

    pub fn insert_newline_in_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_line < cache.lines.len() {
                let current_line = cache.lines[cache.cursor_line].clone();
                let (left, right) = current_line.split_at(cache.cursor_col);

                cache.lines[cache.cursor_line] = left.to_string();
                cache.lines.insert(cache.cursor_line + 1, right.to_string());

                cache.cursor_line += 1;
                cache.cursor_col = 0;
                cache.status = ScriptStatus::Draft;
            }
        }
    }

    pub fn move_cursor_up_in_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_line > 0 {
                cache.cursor_line -= 1;
                // Adjust cursor column if new line is shorter
                if cache.cursor_col > cache.lines[cache.cursor_line].len() {
                    cache.cursor_col = cache.lines[cache.cursor_line].len();
                }
            }
        }
    }

    pub fn move_cursor_down_in_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_line + 1 < cache.lines.len() {
                cache.cursor_line += 1;
                // Adjust cursor column if new line is shorter
                if cache.cursor_col > cache.lines[cache.cursor_line].len() {
                    cache.cursor_col = cache.lines[cache.cursor_line].len();
                }
            }
        }
    }

    pub fn move_cursor_left_in_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_col > 0 {
                cache.cursor_col -= 1;
            }
        }
    }

    pub fn move_cursor_right_in_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.cursor_line < cache.lines.len()
                && cache.cursor_col < cache.lines[cache.cursor_line].len()
            {
                cache.cursor_col += 1;
            }
        }
    }

    /// Check if we can edit again (F2 key)
    pub fn can_edit_script(&self) -> bool {
        if let Some(ref cache) = self.script_cache {
            cache.status == ScriptStatus::Submitted
        } else {
            false
        }
    }

    /// Re-enter script editing mode (F2 key)
    pub fn edit_script_again(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            if cache.status == ScriptStatus::Submitted {
                cache.status = ScriptStatus::Draft;
                self.mode = InteractionMode::ScriptEditor;
            }
        }
    }

    /// Clear current script (F3 key)  
    pub fn clear_current_script(&mut self) {
        if let Some(ref mut cache) = self.script_cache {
            cache.lines = vec![
                format!("// Trace script for target: {}", cache.target),
                String::new(),
            ];
            cache.cursor_line = 1;
            cache.cursor_col = 0;
            cache.status = ScriptStatus::Draft;
        }
    }

    pub fn enter_command_mode(&mut self) {
        self.mode = InteractionMode::Command;
        self.update_static_lines();
        // Position cursor at the last line (current input line)
        self.command_cursor_line = self.static_lines.len().saturating_sub(1);
        self.command_cursor_column = self.get_prompt().len() + self.cursor_position;
    }

    pub fn exit_command_mode(&mut self) {
        self.mode = InteractionMode::Input;
        if let Some(line) = self.static_lines.get(self.command_cursor_line) {
            if line.line_type == LineType::CurrentInput {
                let prompt_len = self.get_prompt().len();
                if self.command_cursor_column >= prompt_len {
                    self.cursor_position = self.command_cursor_column - prompt_len;
                } else {
                    self.cursor_position = 0;
                }
            }
        }
    }

    pub fn handle_vim_navigation(&mut self, key: &str) -> bool {
        match key {
            "i" => {
                // Enter input mode from command mode
                self.exit_command_mode();
                true
            }
            "h" => {
                // Move left with boundary check
                self.move_cursor_left();
                true
            }
            "l" => {
                // Move right with boundary check
                self.move_cursor_right();
                true
            }
            "j" => {
                // Move down with boundary check
                self.move_cursor_down();
                true
            }
            "k" => {
                // Move up with boundary check
                self.move_cursor_up();
                true
            }
            "g" => {
                // Go to top of history (vim style)
                self.command_cursor_line = 0;
                self.command_cursor_column = 0;
                true
            }
            "G" => {
                // Go to current input line (bottom of all content)
                self.command_cursor_line = self.static_lines.len().saturating_sub(1);
                if let Some(line) = self.static_lines.get(self.command_cursor_line) {
                    self.command_cursor_column = line.content.len();
                }
                true
            }
            "0" => {
                // Go to beginning of current line
                self.command_cursor_column = 0;
                true
            }
            "$" => {
                // Go to end of current line
                if let Some(line) = self.static_lines.get(self.command_cursor_line) {
                    self.command_cursor_column = line.content.len();
                }
                true
            }
            "w" => {
                // Move to next word (vim style) in current history line
                self.move_to_next_word_in_history();
                true
            }
            "b" => {
                // Move to previous word (vim style) in current history line
                self.move_to_previous_word_in_history();
                true
            }
            _ => false,
        }
    }

    fn move_cursor_up(&mut self) {
        if self.command_cursor_line > 0 {
            self.command_cursor_line -= 1;
            // Adjust column position to stay within line bounds
            if let Some(line) = self.static_lines.get(self.command_cursor_line) {
                self.command_cursor_column = self.command_cursor_column.min(line.content.len());
            }
        }
    }

    fn move_cursor_down(&mut self) {
        if self.command_cursor_line < self.static_lines.len().saturating_sub(1) {
            self.command_cursor_line += 1;
            // Adjust column position to stay within line bounds
            if let Some(line) = self.static_lines.get(self.command_cursor_line) {
                self.command_cursor_column = self.command_cursor_column.min(line.content.len());
            }
        }
    }

    fn move_to_next_word_in_current_line(&mut self) {
        if let Some(line) = self.static_lines.get(self.command_cursor_line) {
            let content = &line.content;
            let mut pos = self.command_cursor_column;

            // Skip current word if we're in the middle of one
            while pos < content.len() && !content.chars().nth(pos).unwrap_or(' ').is_whitespace() {
                pos += 1;
            }

            // Skip whitespace
            while pos < content.len() && content.chars().nth(pos).unwrap_or(' ').is_whitespace() {
                pos += 1;
            }

            self.command_cursor_column = pos;
        }
    }

    fn move_to_previous_word_in_current_line(&mut self) {
        if let Some(line) = self.static_lines.get(self.command_cursor_line) {
            let content = &line.content;
            let mut pos = self.command_cursor_column;

            // Skip whitespace backwards
            while pos > 0 && content.chars().nth(pos - 1).unwrap_or(' ').is_whitespace() {
                pos -= 1;
            }

            // Skip current word backwards
            while pos > 0 && !content.chars().nth(pos - 1).unwrap_or(' ').is_whitespace() {
                pos -= 1;
            }

            self.command_cursor_column = pos;
        }
    }

    pub fn add_response(&mut self, response: String, _response_type: ResponseType) {
        if let Some(last_item) = self.command_history.last_mut() {
            last_item.response = Some(response);
        }
        self.update_static_lines();
    }

    fn add_to_history(&mut self, command: String, response: Option<String>) {
        let item = CommandHistoryItem {
            command,
            response,
            timestamp: std::time::Instant::now(),
        };

        self.command_history.push(item);

        if self.command_history.len() > self.max_history_items {
            self.command_history.remove(0);
        }
    }

    pub fn history_up(&mut self) {
        if self.command_history.is_empty() {
            return;
        }

        let new_index = match self.history_index {
            None => self.command_history.len() - 1,
            Some(i) if i > 0 => i - 1,
            Some(_) => return,
        };

        self.history_index = Some(new_index);
        let item = &self.command_history[new_index];
        self.input_text = item.command.clone();
        self.cursor_position = self.input_text.len();
        self.update_static_lines();
    }

    pub fn history_down(&mut self) {
        match self.history_index {
            None => return,
            Some(i) if i < self.command_history.len() - 1 => {
                let new_index = i + 1;
                self.history_index = Some(new_index);
                let item = &self.command_history[new_index];
                self.input_text = item.command.clone();
                self.cursor_position = self.input_text.len();
            }
            Some(_) => {
                self.history_index = None;
                self.input_text.clear();
                self.cursor_position = 0;
            }
        }
        self.update_static_lines();
    }

    // Update static text lines list
    fn update_static_lines(&mut self) {
        self.static_lines.clear();

        // Add history records
        for (history_idx, item) in self.command_history.iter().enumerate() {
            let prompt = self.get_prompt();
            let command_line = format!("{}{}", prompt, item.command);

            self.static_lines.push(StaticTextLine {
                content: command_line,
                line_type: LineType::Command,
                history_index: Some(history_idx),
            });

            if let Some(ref response) = item.response {
                self.static_lines.push(StaticTextLine {
                    content: response.clone(),
                    line_type: LineType::Response,
                    history_index: Some(history_idx),
                });
            }
        }

        // Add current input line
        let prompt = self.get_prompt();
        let current_line = format!("{}{}", prompt, self.input_text);
        self.static_lines.push(StaticTextLine {
            content: current_line,
            line_type: LineType::CurrentInput,
            history_index: None,
        });
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        // Use script editor layout only in script editor mode
        if self.mode == InteractionMode::ScriptEditor {
            self.render_script_integrated_layout(frame, area, is_focused);
        } else {
            // Use original layout for normal input/command modes
            self.render_original_layout(frame, area, is_focused);
        }
    }

    fn should_show_script_editor(&self) -> bool {
        self.mode == InteractionMode::ScriptEditor || self.script_cache.is_some()
    }

    fn render_original_layout(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let available_height = area.height.saturating_sub(2) as usize; // Account for borders
        let content_area = Rect::new(
            area.x + 1,
            area.y + 1,
            area.width.saturating_sub(2),
            available_height as u16,
        );

        // Render static text content using original method
        self.render_static_content(frame, content_area, is_focused);

        // Render border
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(if is_focused {
                BorderType::Thick
            } else {
                BorderType::Plain
            })
            .title(self.get_panel_title())
            .border_style(border_style);

        frame.render_widget(block, area);
    }

    fn get_panel_title(&self) -> String {
        match self.mode {
            InteractionMode::Input => "Interactive Command (input mode)".to_string(),
            InteractionMode::Command => "Interactive Command (command mode)".to_string(),
            InteractionMode::ScriptEditor => "Interactive Command (script mode)".to_string(),
        }
    }

    fn render_script_integrated_layout(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let available_height = area.height.saturating_sub(2) as usize;
        let content_area = Rect::new(
            area.x + 1,
            area.y + 1,
            area.width.saturating_sub(2),
            available_height as u16,
        );

        // Render script content
        self.render_script_integrated_content(frame, content_area, is_focused);

        // Render border with unified title
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(if is_focused {
                BorderType::Thick
            } else {
                BorderType::Plain
            })
            .title(self.get_panel_title())
            .border_style(border_style);

        frame.render_widget(block, area);
    }

    fn render_script_integrated_content(&self, frame: &mut Frame, area: Rect, _is_focused: bool) {
        let available_width = area.width as usize;
        let available_height = area.height as usize;
        let mut rendered_lines = Vec::new();

        // First, render all command history using consistent styling
        for line in &self.static_lines {
            let wrapped_lines = self.wrap_text(&line.content, available_width);

            let style = match line.line_type {
                LineType::Command => Style::default().fg(Color::Gray),
                LineType::Response => self.get_response_style(&line.content),
                LineType::CurrentInput => {
                    // In ScriptEditor mode, show the trace command that started script mode with different color
                    if self.mode == InteractionMode::ScriptEditor {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    }
                }
            };

            for wrapped_line in wrapped_lines {
                rendered_lines.push(ListItem::new(Line::from(vec![Span::styled(
                    wrapped_line,
                    style,
                )])));
            }
        }

        // Add script editor section if in script mode
        if let Some(ref cache) = self.script_cache {
            // Add a separator line
            rendered_lines.push(ListItem::new(Line::from(vec![Span::styled(
                "─".repeat(available_width.saturating_sub(2)),
                Style::default().fg(Color::Cyan),
            )])));

            // Add script editor prompt with line wrapping support
            let script_prompt = "Script Editor (Ctrl+Enter to submit, Esc to cancel):";
            let prompt_wrapped = self.wrap_text(script_prompt, available_width.saturating_sub(2));
            for prompt_line in prompt_wrapped {
                rendered_lines.push(ListItem::new(Line::from(vec![Span::styled(
                    prompt_line,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )])));
            }

            // Add script lines with syntax highlighting and word wrapping
            for (line_idx, script_line) in cache.lines.iter().enumerate() {
                let is_cursor_line = line_idx == cache.cursor_line;
                let cursor_indicator = if is_cursor_line { "▶" } else { " " };
                let line_prefix = format!("{}{:2} │ ", cursor_indicator, line_idx + 1);

                // Calculate available width for content (accounting for prefix)
                let prefix_width = line_prefix.chars().count();
                let content_width = available_width.saturating_sub(prefix_width + 2);

                if script_line.chars().count() <= content_width {
                    // Single line - no wrapping needed
                    let mut spans = vec![Span::styled(
                        line_prefix,
                        Style::default().fg(Color::DarkGray),
                    )];

                    // Add syntax-highlighted content (cursor handled by ratatui)
                    spans.extend(self.syntax_highlight_line(script_line));

                    rendered_lines.push(ListItem::new(Line::from(spans)));
                } else {
                    // Multi-line - need wrapping
                    let wrapped_parts = self.wrap_script_line_with_syntax(
                        script_line,
                        content_width,
                        is_cursor_line,
                        if is_cursor_line {
                            Some(cache.cursor_col)
                        } else {
                            None
                        },
                    );

                    for (_part_idx, (content_spans, is_first_line)) in
                        wrapped_parts.into_iter().enumerate()
                    {
                        let prefix = if is_first_line {
                            line_prefix.clone()
                        } else {
                            // Continuation line - just indent, no pipe symbol
                            format!("{}   ", " ".repeat(cursor_indicator.len() + 4))
                            // Simple indent
                        };

                        let mut line_spans =
                            vec![Span::styled(prefix, Style::default().fg(Color::DarkGray))];
                        line_spans.extend(content_spans);

                        rendered_lines.push(ListItem::new(Line::from(line_spans)));
                    }
                }
            }

            // Add empty line for new input
            if cache.lines.is_empty() || cache.cursor_line == cache.lines.len() {
                let cursor_indicator = if cache.cursor_line == cache.lines.len() {
                    "▶"
                } else {
                    " "
                };
                let line_content = format!("{}{:2} │ ", cursor_indicator, cache.lines.len() + 1);
                rendered_lines.push(ListItem::new(Line::from(vec![Span::styled(
                    line_content,
                    Style::default().fg(Color::DarkGray),
                )])));
            }
        }

        // Calculate scroll position to show latest content
        let scroll_position = if rendered_lines.len() > available_height {
            rendered_lines.len().saturating_sub(available_height)
        } else {
            0
        };

        let visible_lines: Vec<_> = rendered_lines.into_iter().skip(scroll_position).collect();

        let list = List::new(visible_lines);
        frame.render_widget(list, area);

        // Render cursor for script editor mode
        if let Some(ref cache) = self.script_cache {
            self.render_script_cursor(frame, area, cache, scroll_position);
        }
    }

    fn render_static_content(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let max_lines = area.height as usize;
        let content_width = area.width.saturating_sub(2) as usize;

        // Calculate which lines to show
        let total_lines = self.static_lines.len();
        let start_idx = if self.mode == InteractionMode::Command {
            // In command mode, ensure cursor line is visible
            if self.command_cursor_line >= max_lines {
                self.command_cursor_line + 1 - max_lines
            } else {
                0
            }
        } else {
            // In input mode, show latest content
            if total_lines > max_lines {
                total_lines - max_lines
            } else {
                0
            }
        };

        let end_idx = (start_idx + max_lines).min(total_lines);

        // Render visible lines
        let mut items = Vec::new();
        for i in start_idx..end_idx {
            if let Some(line) = self.static_lines.get(i) {
                let style = match line.line_type {
                    LineType::Command => Style::default().fg(Color::Gray),
                    LineType::Response => self.get_response_style(&line.content),
                    LineType::CurrentInput => {
                        if self.mode == InteractionMode::Input {
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::White)
                        }
                    }
                };

                // Handle text wrapping
                let wrapped_lines = self.wrap_text(&line.content, content_width);
                for wrapped_line in wrapped_lines {
                    items.push(ListItem::new(Line::from(vec![Span::styled(
                        wrapped_line,
                        style,
                    )])));
                }
            }
        }

        let list = List::new(items);
        frame.render_widget(list, area);

        // Render cursor
        if is_focused {
            self.render_cursor(frame, area, start_idx);
        }
    }

    fn render_cursor(&self, frame: &mut Frame, area: Rect, start_idx: usize) {
        if self.mode == InteractionMode::Input {
            // Input mode: render cursor on current input line, considering text wrapping
            let content_width = area.width.saturating_sub(2) as usize;
            let prompt = self.get_prompt();
            let prompt_len = prompt.len();
            let full_text = format!("{}{}", prompt, self.input_text);

            // Calculate cursor position in wrapped text
            let mut remaining_cursor_pos = self.cursor_position;
            let mut cursor_line_offset = 0;

            // Calculate which line the cursor should be on
            let wrapped_lines = self.wrap_text(&full_text, content_width);
            for (line_idx, line) in wrapped_lines.iter().enumerate() {
                let line_content_len = if line_idx == 0 {
                    // First line includes prompt
                    line.len().saturating_sub(prompt_len)
                } else {
                    line.len()
                };

                if remaining_cursor_pos <= line_content_len {
                    // Cursor is on this line
                    cursor_line_offset = line_idx;
                    break;
                } else {
                    remaining_cursor_pos -= line_content_len;
                }
            }

            // Find the current input line's position in the rendered display
            let mut current_line_rendered_pos = 0;
            let mut found_current_input = false;

            // Count rendered lines up to the current input line
            for i in start_idx..self.static_lines.len() {
                if let Some(line) = self.static_lines.get(i) {
                    if line.line_type == LineType::CurrentInput {
                        found_current_input = true;
                        break;
                    }
                    let wrapped_lines = self.wrap_text(&line.content, content_width);
                    current_line_rendered_pos += wrapped_lines.len();
                }
            }

            if found_current_input {
                // Add the wrapped lines of the current input up to the cursor line
                current_line_rendered_pos += cursor_line_offset;

                let relative_line = current_line_rendered_pos.saturating_sub(start_idx);
                if relative_line < area.height as usize {
                    let cursor_x = if cursor_line_offset == 0 {
                        area.x + prompt_len as u16 + remaining_cursor_pos as u16
                    } else {
                        area.x + remaining_cursor_pos as u16
                    };
                    let cursor_y = area.y + relative_line as u16;

                    if cursor_x < area.x + area.width && cursor_y < area.y + area.height {
                        frame.render_widget(
                            Block::default()
                                .style(Style::default().bg(Color::White).fg(Color::Black)),
                            Rect::new(cursor_x, cursor_y, 1, 1),
                        );
                    }
                }
            }
        } else if self.mode == InteractionMode::Command {
            // Command mode: render cursor on selected line, considering text wrapping
            if self.command_cursor_line < self.static_lines.len() {
                let content_width = area.width.saturating_sub(2) as usize;

                // Calculate the actual rendered position of the selected line
                let mut rendered_line_pos = 0;
                for i in start_idx..self.static_lines.len() {
                    if i == self.command_cursor_line {
                        break;
                    }
                    if let Some(line) = self.static_lines.get(i) {
                        let wrapped_lines = self.wrap_text(&line.content, content_width);
                        rendered_line_pos += wrapped_lines.len();
                    }
                }

                // Add the wrapped lines of the selected line up to the cursor position
                if let Some(selected_line) = self.static_lines.get(self.command_cursor_line) {
                    let wrapped_lines = self.wrap_text(&selected_line.content, content_width);

                    // Find which wrapped line the cursor is on
                    let mut remaining_cursor_pos = self.command_cursor_column;
                    let mut cursor_line_offset = 0;

                    for (line_idx, line) in wrapped_lines.iter().enumerate() {
                        if remaining_cursor_pos <= line.len() {
                            cursor_line_offset = line_idx;
                            break;
                        } else {
                            remaining_cursor_pos -= line.len();
                        }
                    }

                    rendered_line_pos += cursor_line_offset;
                    let relative_line = rendered_line_pos.saturating_sub(start_idx);

                    if relative_line < area.height as usize {
                        let cursor_x = area.x + remaining_cursor_pos as u16;
                        let cursor_y = area.y + relative_line as u16;

                        if cursor_x < area.x + area.width && cursor_y < area.y + area.height {
                            frame.render_widget(
                                Block::default()
                                    .style(Style::default().bg(Color::White).fg(Color::Black)),
                                Rect::new(cursor_x, cursor_y, 1, 1),
                            );
                        }
                    }
                }
            }
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

    fn get_response_style(&self, response: &str) -> Style {
        if response.starts_with("✓") {
            Style::default().fg(Color::Green)
        } else if response.starts_with("✗") {
            Style::default().fg(Color::Red)
        } else if response.starts_with("⚠") {
            Style::default().fg(Color::Yellow)
        } else if response.starts_with("⏳") {
            Style::default().fg(Color::Blue)
        } else if response.starts_with("🔨") {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        }
    }

    /// Syntax highlighting for script lines
    fn syntax_highlight_line(&self, line: &str) -> Vec<Span> {
        let mut spans = Vec::new();
        let mut current_pos = 0;
        let line_chars: Vec<char> = line.chars().collect();

        // Define keywords and their styles
        let keywords = &[
            (
                "print",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            (
                "if",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            (
                "else",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
            (
                "elseif",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
        ];

        while current_pos < line_chars.len() {
            // Check for comments (// style)
            if current_pos + 1 < line_chars.len()
                && line_chars[current_pos] == '/'
                && line_chars[current_pos + 1] == '/'
            {
                // Rest of line is comment
                let comment_text: String = line_chars[current_pos..].iter().collect();
                spans.push(Span::styled(
                    comment_text,
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                ));
                break;
            }

            // Check for string literals
            if line_chars[current_pos] == '"' {
                let mut end_pos = current_pos + 1;
                while end_pos < line_chars.len() && line_chars[end_pos] != '"' {
                    if line_chars[end_pos] == '\\' && end_pos + 1 < line_chars.len() {
                        end_pos += 2; // Skip escaped character
                    } else {
                        end_pos += 1;
                    }
                }
                if end_pos < line_chars.len() {
                    end_pos += 1; // Include closing quote
                }

                let string_text: String = line_chars[current_pos..end_pos].iter().collect();
                spans.push(Span::styled(string_text, Style::default().fg(Color::Green)));
                current_pos = end_pos;
                continue;
            }

            // Check for keywords
            let mut keyword_found = false;
            for (keyword, style) in keywords {
                if self.match_keyword_at_position(&line_chars, current_pos, keyword) {
                    spans.push(Span::styled(keyword.to_string(), *style));
                    current_pos += keyword.len();
                    keyword_found = true;
                    break;
                }
            }

            if keyword_found {
                continue;
            }

            // Check for numbers
            if line_chars[current_pos].is_ascii_digit() {
                let mut end_pos = current_pos;
                while end_pos < line_chars.len()
                    && (line_chars[end_pos].is_ascii_digit() || line_chars[end_pos] == '.')
                {
                    end_pos += 1;
                }

                let number_text: String = line_chars[current_pos..end_pos].iter().collect();
                spans.push(Span::styled(
                    number_text,
                    Style::default()
                        .fg(Color::Blue)
                        .add_modifier(Modifier::BOLD),
                ));
                current_pos = end_pos;
                continue;
            }

            // Default: regular text
            spans.push(Span::styled(
                line_chars[current_pos].to_string(),
                Style::default().fg(Color::Cyan),
            ));
            current_pos += 1;
        }

        spans
    }

    /// Helper function to check if a keyword matches at a specific position
    fn match_keyword_at_position(&self, chars: &[char], pos: usize, keyword: &str) -> bool {
        let keyword_chars: Vec<char> = keyword.chars().collect();

        // Check if there's enough space for the keyword
        if pos + keyword_chars.len() > chars.len() {
            return false;
        }

        // Check if keyword matches
        for (i, &kw_char) in keyword_chars.iter().enumerate() {
            if chars[pos + i] != kw_char {
                return false;
            }
        }

        // Check word boundaries (keyword should not be part of a larger word)
        let before_is_boundary = pos == 0 || !chars[pos - 1].is_alphabetic();
        let after_pos = pos + keyword_chars.len();
        let after_is_boundary = after_pos >= chars.len() || !chars[after_pos].is_alphabetic();

        before_is_boundary && after_is_boundary
    }

    /// Syntax highlighting with cursor display for the current line
    fn syntax_highlight_line_with_cursor(&self, line: &str, cursor_col: usize) -> Vec<Span> {
        let line_chars: Vec<char> = line.chars().collect();
        let safe_cursor_pos = cursor_col.min(line_chars.len());

        // Get syntax highlighting spans for the entire line
        let mut base_spans = self.syntax_highlight_line(line);

        // Insert cursor at the correct position
        let mut result_spans = Vec::new();
        let mut char_position = 0;

        for span in base_spans {
            let span_text = span.content.to_string();
            let span_chars: Vec<char> = span_text.chars().collect();
            let span_start = char_position;
            let span_end = char_position + span_chars.len();

            if safe_cursor_pos >= span_start && safe_cursor_pos <= span_end {
                // Cursor is within this span
                let cursor_pos_in_span = safe_cursor_pos - span_start;

                if cursor_pos_in_span == 0 {
                    // Cursor at the beginning of span
                    result_spans.push(Span::styled(
                        "▎",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ));
                    result_spans.push(span);
                } else if cursor_pos_in_span == span_chars.len() {
                    // Cursor at the end of span
                    result_spans.push(span);
                    result_spans.push(Span::styled(
                        "▎",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ));
                } else {
                    // Cursor in the middle of span - split the span
                    let before: String = span_chars[..cursor_pos_in_span].iter().collect();
                    let after: String = span_chars[cursor_pos_in_span..].iter().collect();

                    if !before.is_empty() {
                        result_spans.push(Span::styled(before, span.style));
                    }
                    result_spans.push(Span::styled(
                        "▎",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ));
                    if !after.is_empty() {
                        result_spans.push(Span::styled(after, span.style));
                    }
                }
            } else {
                result_spans.push(span);
            }

            char_position = span_end;
        }

        // If cursor is at the very end of the line, add it
        if safe_cursor_pos >= line_chars.len() {
            result_spans.push(Span::styled(
                "▎",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ));
        }

        result_spans
    }

    /// Wrap a script line with syntax highlighting, preserving cursor position
    fn wrap_script_line_with_syntax(
        &self,
        line: &str,
        content_width: usize,
        is_cursor_line: bool,
        cursor_col: Option<usize>,
    ) -> Vec<(Vec<Span>, bool)> {
        if content_width == 0 {
            return vec![(Vec::new(), true)];
        }

        // Get syntax highlighted spans (cursor handled separately)
        let spans = self.syntax_highlight_line(line);

        let mut result = Vec::new();
        let mut current_line_spans = Vec::new();
        let mut current_line_width = 0;
        let mut is_first_line = true;

        for span in spans {
            let span_text = span.content.to_string();
            let span_chars: Vec<char> = span_text.chars().collect();

            if span_chars.is_empty() {
                continue;
            }

            // If the entire span fits in the current line
            if current_line_width + span_chars.len() <= content_width {
                current_line_spans.push(span);
                current_line_width += span_chars.len();
            } else {
                // Need to split the span
                let mut remaining_chars = span_chars;
                let mut current_style = span.style;

                while !remaining_chars.is_empty() {
                    let space_left = content_width - current_line_width;

                    if space_left == 0 {
                        // Start a new line
                        if !current_line_spans.is_empty() {
                            result.push((current_line_spans, is_first_line));
                            current_line_spans = Vec::new();
                            current_line_width = 0;
                            is_first_line = false;
                        }
                        continue;
                    }

                    let chunk_size = space_left.min(remaining_chars.len());
                    let chunk: String = remaining_chars[..chunk_size].iter().collect();

                    current_line_spans.push(Span::styled(chunk, current_style));
                    current_line_width += chunk_size;

                    remaining_chars = remaining_chars[chunk_size..].to_vec();

                    if current_line_width >= content_width {
                        // Line is full, start a new one
                        result.push((current_line_spans, is_first_line));
                        current_line_spans = Vec::new();
                        current_line_width = 0;
                        is_first_line = false;
                    }
                }
            }
        }

        // Add the last line if it has content
        if !current_line_spans.is_empty() {
            result.push((current_line_spans, is_first_line));
        }

        // Ensure we always return at least one line
        if result.is_empty() {
            result.push((Vec::new(), true));
        }

        result
    }

    /// Render cursor for script editor mode, similar to insert mode cursor
    fn render_script_cursor(
        &self,
        frame: &mut Frame,
        area: Rect,
        cache: &ScriptCache,
        scroll_offset: usize,
    ) {
        let available_width = area.width as usize;
        let mut total_visual_lines = 0;

        // Count ALL visual lines in the rendered content (including history)
        // 1. Count history lines
        for line in &self.static_lines {
            let wrapped_lines = self.wrap_text(&line.content, available_width);
            total_visual_lines += wrapped_lines.len();
        }

        // 2. Count separator line
        total_visual_lines += 1;

        // 3. Count prompt lines (with wrapping)
        let script_prompt = "Script Editor (Ctrl+Enter to submit, Esc to cancel):";
        let prompt_wrapped = self.wrap_text(script_prompt, available_width.saturating_sub(2));
        total_visual_lines += prompt_wrapped.len();

        // 4. Count script lines up to cursor line
        for line_idx in 0..cache.cursor_line {
            if let Some(script_line) = cache.lines.get(line_idx) {
                let cursor_indicator_len = 1; // "▶" or " "
                let line_prefix_len = 5; // " 1 │ "
                let content_width =
                    available_width.saturating_sub(cursor_indicator_len + line_prefix_len + 2);

                if script_line.chars().count() <= content_width {
                    total_visual_lines += 1; // Single line
                } else {
                    // Multi-line - count wrapped lines
                    let line_count =
                        (script_line.chars().count() + content_width - 1) / content_width;
                    total_visual_lines += line_count;
                }
            }
        }

        // 5. Calculate cursor position within current line
        if let Some(_current_line) = cache.lines.get(cache.cursor_line) {
            let cursor_indicator_len = 1; // "▶"
            let line_prefix_len = 5; // " 1 │ "
            let prefix_total = cursor_indicator_len + line_prefix_len;
            let content_width = available_width.saturating_sub(prefix_total + 2);

            // Find which visual line the cursor is on for this logical line
            let cursor_visual_offset = if content_width > 0 {
                cache.cursor_col / content_width
            } else {
                0
            };
            total_visual_lines += cursor_visual_offset;

            // Calculate cursor column position within the visual line
            let cursor_col_in_visual_line = if content_width > 0 {
                cache.cursor_col % content_width
            } else {
                0
            };
            let cursor_x = area.x + prefix_total as u16 + cursor_col_in_visual_line as u16;
            let cursor_y = area.y + (total_visual_lines.saturating_sub(scroll_offset)) as u16;

            // Only draw cursor if it's within the visible area
            if cursor_y < area.y + area.height && cursor_x < area.x + area.width {
                frame.set_cursor_position((cursor_x, cursor_y));
            }
        } else if cache.cursor_line == cache.lines.len() {
            // Cursor is on empty line at the end
            let cursor_indicator_len = 1; // "▶"
            let line_prefix_len = 5; // " 1 │ "
            let prefix_total = cursor_indicator_len + line_prefix_len;

            let cursor_x = area.x + prefix_total as u16;
            let cursor_y = area.y + (total_visual_lines.saturating_sub(scroll_offset)) as u16;

            // Only draw cursor if it's within the visible area
            if cursor_y < area.y + area.height && cursor_x < area.x + area.width {
                frame.set_cursor_position((cursor_x, cursor_y));
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum CommandAction {
    ExecuteCommand(String),
    EnterScriptMode(String),
    AddScriptLine(String),
    SubmitScript(String),
    CancelScript,
}

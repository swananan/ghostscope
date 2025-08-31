use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph},
    Frame,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InteractionMode {
    Input, // Normal input mode
    Script,
    Command, // Command mode (previously VimCommand)
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

pub struct InteractiveCommandPanel {
    pub input_text: String,
    pub cursor_position: usize,
    pub command_history: Vec<CommandHistoryItem>,
    pub history_index: Option<usize>,
    pub mode: InteractionMode,
    pub script_lines: Vec<String>,
    pub current_script_line: usize,
    pub scroll_offset: usize,
    pub max_history_items: usize,
    pub vim_cursor_line: usize, // Cursor position in vim mode (line in history)
    pub vim_cursor_column: usize, // Cursor column position in vim mode
}

impl InteractiveCommandPanel {
    pub fn new() -> Self {
        Self {
            input_text: String::new(),
            cursor_position: 0,
            command_history: Vec::new(),
            history_index: None,
            mode: InteractionMode::Input,
            script_lines: Vec::new(),
            current_script_line: 0,
            scroll_offset: 0,
            max_history_items: 1000, // TODO: Make this configurable via command line arguments or config file
            vim_cursor_line: 0,
            vim_cursor_column: 0,
        }
    }

    pub fn get_prompt(&self) -> String {
        match self.mode {
            InteractionMode::Input => "(ghostscope) ".to_string(),
            InteractionMode::Script => "> ".to_string(),
            InteractionMode::Command => "(ghostscope) ".to_string(),
        }
    }

    pub fn insert_char(&mut self, c: char) {
        self.input_text.insert(self.cursor_position, c);
        self.cursor_position += 1;
    }

    pub fn delete_char(&mut self) {
        if self.cursor_position > 0 {
            self.input_text.remove(self.cursor_position - 1);
            self.cursor_position -= 1;
        }
    }

    pub fn move_cursor_left(&mut self) {
        if self.mode == InteractionMode::Command {
            if self.vim_cursor_column > 0 {
                self.vim_cursor_column -= 1;
            }
        } else {
            if self.cursor_position > 0 {
                self.cursor_position -= 1;
            }
        }
    }

    pub fn move_cursor_right(&mut self) {
        if self.mode == InteractionMode::Command {
            let current_line_content = self.get_current_history_line_content();
            if self.vim_cursor_column < current_line_content.len() {
                self.vim_cursor_column += 1;
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
        let current_line_content = self.get_current_history_line_content();
        let prompt = self.get_prompt();

        // Get the command part only (excluding the prompt)
        if current_line_content.len() > prompt.len() {
            let command_text = &current_line_content[prompt.len()..];
            let mut pos = self.vim_cursor_column.saturating_sub(prompt.len());

            // Skip current word if we're in the middle of one
            while pos < command_text.len()
                && !command_text.chars().nth(pos).unwrap_or(' ').is_whitespace()
            {
                pos += 1;
            }

            // Skip whitespace
            while pos < command_text.len()
                && command_text.chars().nth(pos).unwrap_or(' ').is_whitespace()
            {
                pos += 1;
            }

            self.vim_cursor_column = prompt.len() + pos;
        }
    }

    pub fn move_to_previous_word_in_history(&mut self) {
        let current_line_content = self.get_current_history_line_content();
        let prompt = self.get_prompt();

        // Get the command part only (excluding the prompt)
        if current_line_content.len() > prompt.len() && self.vim_cursor_column > prompt.len() {
            let command_text = &current_line_content[prompt.len()..];
            let mut pos = self.vim_cursor_column.saturating_sub(prompt.len());

            // Skip whitespace backwards
            while pos > 0
                && command_text
                    .chars()
                    .nth(pos - 1)
                    .unwrap_or(' ')
                    .is_whitespace()
            {
                pos -= 1;
            }

            // Skip current word backwards
            while pos > 0
                && !command_text
                    .chars()
                    .nth(pos - 1)
                    .unwrap_or(' ')
                    .is_whitespace()
            {
                pos -= 1;
            }

            self.vim_cursor_column = prompt.len() + pos;
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
                    // Treat trace command as complete script and send directly to compiler
                    CommandAction::SubmitScript(command.clone())
                } else {
                    CommandAction::ExecuteCommand(command.clone())
                }
            }
            InteractionMode::Script => {
                if command.trim() == "end" || command.trim() == "}" {
                    let script = self.script_lines.join("\n");
                    self.mode = InteractionMode::Input;
                    self.script_lines.clear();
                    self.current_script_line = 0;
                    CommandAction::SubmitScript(script)
                } else {
                    self.script_lines.push(command.clone());
                    self.current_script_line += 1;
                    CommandAction::AddScriptLine(command.clone())
                }
            }
            InteractionMode::Command => {
                // Handle command mode commands
                CommandAction::ExecuteCommand(command.clone())
            }
        };

        self.add_to_history(command, None);

        self.input_text.clear();
        self.cursor_position = 0;
        self.history_index = None;

        Some(action)
    }

    pub fn cancel_script(&mut self) -> bool {
        if self.mode == InteractionMode::Script {
            self.mode = InteractionMode::Input;
            self.script_lines.clear();
            self.current_script_line = 0;
            self.input_text.clear();
            self.cursor_position = 0;
            true
        } else {
            false
        }
    }

    pub fn enter_command_mode(&mut self) {
        self.mode = InteractionMode::Command;
        // Start from current input line (at the end of all content)
        self.vim_cursor_line = self.command_history.len(); // Point to current input line
        let prompt = self.get_prompt();
        self.vim_cursor_column = prompt.len() + self.cursor_position;
    }

    pub fn exit_command_mode(&mut self) {
        self.mode = InteractionMode::Input;
        // Don't clear input_text - preserve what user was typing
        // Reset cursor position to end of current input
        self.cursor_position = self.input_text.len();
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
                self.vim_cursor_line = 0;
                self.vim_cursor_column = 0;
                true
            }
            "G" => {
                // Go to current input line (bottom of all content)
                self.vim_cursor_line = self.command_history.len();
                let current_line_content = self.get_current_history_line_content();
                self.vim_cursor_column = current_line_content.len().min(self.vim_cursor_column);
                true
            }
            "0" => {
                // Go to beginning of current line
                self.vim_cursor_column = 0;
                true
            }
            "$" => {
                // Go to end of current line
                let current_line_content = self.get_current_history_line_content();
                self.vim_cursor_column = current_line_content.len();
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
        if self.vim_cursor_line > 0 {
            self.vim_cursor_line -= 1;
            // Adjust column to stay within line bounds
            let current_line_content = self.get_current_history_line_content();
            self.vim_cursor_column = self.vim_cursor_column.min(current_line_content.len());
        }
    }

    fn move_cursor_down(&mut self) {
        // Can move down to current input line (command_history.len())
        if self.vim_cursor_line < self.command_history.len() {
            self.vim_cursor_line += 1;
            // Adjust column to stay within line bounds
            let current_line_content = self.get_current_history_line_content();
            self.vim_cursor_column = self.vim_cursor_column.min(current_line_content.len());
        }
    }

    pub fn add_response(&mut self, response: String, _response_type: ResponseType) {
        if let Some(last_item) = self.command_history.last_mut() {
            last_item.response = Some(response);
        }
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
    }

    pub fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
        }
    }

    pub fn scroll_down(&mut self) {
        let max_scroll = self.command_history.len().saturating_sub(1);
        if self.scroll_offset < max_scroll {
            self.scroll_offset += 1;
        }
    }

    pub fn clear_screen(&mut self) {
        self.command_history.clear();
        self.scroll_offset = 0;
    }

    fn calculate_history_lines(&self) -> usize {
        let mut lines = 0;
        for item in &self.command_history {
            lines += 1; // Command line
            if item.response.is_some() {
                lines += 1; // Response line
            }
        }
        lines
    }

    fn get_current_history_line_content(&self) -> String {
        if self.vim_cursor_line < self.command_history.len() {
            let item = &self.command_history[self.vim_cursor_line];
            let prompt = self.get_prompt();
            format!("{}{}", prompt, item.command)
        } else if self.vim_cursor_line == self.command_history.len() {
            // This is the current input line
            let prompt = self.get_prompt();
            format!("{}{}", prompt, self.input_text)
        } else {
            String::new()
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
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

        // Render all content (history + current input) as a continuous flow like GDB
        self.render_gdb_style_content(frame, content_area, is_focused);

        // Render border
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(if is_focused {
                BorderType::Thick
            } else {
                BorderType::Plain
            })
            .title(format!(
                "Interactive Command ({})",
                match self.mode {
                    InteractionMode::Input => "Input",
                    InteractionMode::Command => "Command",
                    InteractionMode::Script => "Script",
                }
            ))
            .border_style(border_style);

        frame.render_widget(block, area);
    }

    fn render_gdb_style_content(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let mut all_lines = Vec::new();
        let max_lines = area.height as usize;

        // Add all history items with dimmed color
        for item in &self.command_history {
            let prompt = self.get_prompt();
            let command_line = format!("{}{}", prompt, item.command);
            all_lines.push((command_line, Style::default().fg(Color::DarkGray), false));

            if let Some(ref response) = item.response {
                let response_style = self.get_response_style(response);
                all_lines.push((response.clone(), response_style, false));
            }
        }

        // Add current input line with highlighted color in input mode
        let current_prompt = self.get_prompt();
        let current_line = format!("{}{}", current_prompt, self.input_text);
        let input_line_style = if self.mode == InteractionMode::Input {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(ratatui::style::Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        all_lines.push((current_line, input_line_style, true)); // Mark as current input

        // Calculate which lines to show
        let total_lines = all_lines.len();
        let start_idx = if self.mode == InteractionMode::Command {
            // In command mode, show content based on cursor position
            if self.vim_cursor_line < self.command_history.len() {
                // Show around the selected history item
                let history_line_idx = self.vim_cursor_line * 2; // Each history item takes ~2 lines
                if history_line_idx >= max_lines {
                    history_line_idx + 1 - max_lines
                } else {
                    0
                }
            } else {
                // If somehow beyond history, show recent content
                if total_lines > max_lines {
                    total_lines - max_lines
                } else {
                    0
                }
            }
        } else {
            // In input mode, always show the most recent content (like GDB)
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
            let (line_content, style, _) = &all_lines[i];
            items.push(ListItem::new(Line::from(vec![Span::styled(
                line_content.clone(),
                *style,
            )])));
        }

        let list = List::new(items);
        frame.render_widget(list, area);

        // Render cursor
        if is_focused {
            self.render_gdb_cursor(frame, area, start_idx, &all_lines);
        }
    }

    fn render_gdb_cursor(
        &self,
        frame: &mut Frame,
        area: Rect,
        start_idx: usize,
        all_lines: &[(String, Style, bool)],
    ) {
        if self.mode == InteractionMode::Input {
            // In input mode, cursor is on the current input line
            let current_input_line_idx = all_lines.len() - 1;
            if current_input_line_idx >= start_idx
                && current_input_line_idx < start_idx + area.height as usize
            {
                let relative_line = current_input_line_idx - start_idx;
                let prompt = self.get_prompt();
                let cursor_x = area.x + prompt.len() as u16 + self.cursor_position as u16;
                let cursor_y = area.y + relative_line as u16;

                if cursor_x < area.x + area.width && cursor_y < area.y + area.height {
                    frame.render_widget(
                        Block::default().style(Style::default().bg(Color::White).fg(Color::Black)),
                        Rect::new(cursor_x, cursor_y, 1, 1),
                    );
                }
            }
        } else if self.mode == InteractionMode::Command {
            // In command mode, cursor can be on history lines or current input line
            if self.vim_cursor_line < self.command_history.len() {
                // Cursor is on a history line
                let history_line_idx = self.vim_cursor_line * 2; // History items are at even indices
                if history_line_idx >= start_idx
                    && history_line_idx < start_idx + area.height as usize
                {
                    let relative_line = history_line_idx - start_idx;
                    let cursor_x = area.x + self.vim_cursor_column as u16;
                    let cursor_y = area.y + relative_line as u16;

                    if cursor_x < area.x + area.width && cursor_y < area.y + area.height {
                        frame.render_widget(
                            Block::default()
                                .style(Style::default().bg(Color::White).fg(Color::Black)),
                            Rect::new(cursor_x, cursor_y, 1, 1),
                        );
                    }
                }
            } else if self.vim_cursor_line == self.command_history.len() {
                // Cursor is on the current input line (last line in all_lines)
                let current_input_line_idx = all_lines.len() - 1;
                if current_input_line_idx >= start_idx
                    && current_input_line_idx < start_idx + area.height as usize
                {
                    let relative_line = current_input_line_idx - start_idx;
                    let cursor_x = area.x + self.vim_cursor_column as u16;
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

    fn render_history_with_scroll(&self, frame: &mut Frame, area: Rect) {
        let mut items = Vec::new();
        let max_items = area.height as usize;
        let total_items = self.command_history.len();

        if total_items == 0 {
            return;
        }

        let start_idx = if self.mode == InteractionMode::Command {
            // In command mode, scroll to show the cursor position
            let cursor_line = self.vim_cursor_line;
            if cursor_line >= max_items {
                cursor_line + 1 - max_items
            } else {
                0
            }
        } else {
            // In input mode, always show the most recent items
            if total_items > max_items {
                total_items - max_items
            } else {
                0
            }
        };

        let end_idx = (start_idx + max_items).min(total_items);

        // Show selected range of history items
        for i in start_idx..end_idx {
            let item = &self.command_history[i];
            let prompt = self.get_prompt();
            let command_line = format!("{}{}", prompt, item.command);

            let style = Style::default().fg(Color::White);

            items.push(ListItem::new(Line::from(vec![Span::styled(
                command_line,
                style,
            )])));

            if let Some(ref response) = item.response {
                let response_style = self.get_response_style(response);

                items.push(ListItem::new(Line::from(vec![Span::styled(
                    response.clone(),
                    response_style,
                )])));
            }
        }

        let list = List::new(items);
        frame.render_widget(list, area);

        // Render cursor in command mode
        if self.mode == InteractionMode::Command {
            self.render_cursor_in_history_scroll(frame, area, start_idx);
        }
    }

    fn render_history(&self, frame: &mut Frame, area: Rect) {
        let mut items = Vec::new();

        // Calculate how many items we can show
        let max_items = area.height as usize;
        let total_items = self.command_history.len();

        // Determine which items to show
        let start_idx = if total_items > max_items {
            total_items - max_items
        } else {
            0
        };

        // Show history items
        for i in start_idx..total_items {
            let item = &self.command_history[i];
            let prompt = self.get_prompt();
            let command_line = format!("{}{}", prompt, item.command);

            // In command mode, show cursor instead of highlighting
            let style = Style::default().fg(Color::White);

            items.push(ListItem::new(Line::from(vec![Span::styled(
                command_line,
                style,
            )])));

            if let Some(ref response) = item.response {
                let response_style = self.get_response_style(response);

                items.push(ListItem::new(Line::from(vec![Span::styled(
                    response.clone(),
                    response_style,
                )])));
            }
        }

        let list = List::new(items);
        frame.render_widget(list, area);

        // Render cursor in command mode
        if self.mode == InteractionMode::Command {
            self.render_cursor_in_history(frame, area, start_idx);
        }
    }

    fn render_cursor_in_history(&self, frame: &mut Frame, area: Rect, start_idx: usize) {
        if self.vim_cursor_line < self.command_history.len() {
            let prompt = self.get_prompt();

            // Calculate cursor position within the visible area
            if self.vim_cursor_line >= start_idx {
                let relative_line = self.vim_cursor_line - start_idx;

                // Each history item takes 2 lines (command + response, if exists)
                let cursor_x = area.x + prompt.len() as u16 + self.vim_cursor_column as u16;
                let cursor_y = area.y + relative_line as u16 * 2; // Command line, not response line

                // Ensure cursor is within the visible area
                if cursor_x < area.x + area.width
                    && cursor_y < area.y + area.height
                    && cursor_x >= area.x
                {
                    frame.render_widget(
                        Block::default().style(Style::default().bg(Color::White).fg(Color::Black)),
                        Rect::new(cursor_x, cursor_y, 1, 1),
                    );
                }
            }
        }
    }

    fn render_cursor_in_history_scroll(&self, frame: &mut Frame, area: Rect, start_idx: usize) {
        if self.vim_cursor_line < self.command_history.len() && self.vim_cursor_line >= start_idx {
            let prompt = self.get_prompt();
            let relative_line = self.vim_cursor_line - start_idx;

            // Each history item takes 2 lines (command + response, if exists)
            let cursor_x = area.x + prompt.len() as u16 + self.vim_cursor_column as u16;
            let cursor_y = area.y + relative_line as u16 * 2; // Command line, not response line

            // Ensure cursor is within the visible area
            if cursor_x < area.x + area.width
                && cursor_y < area.y + area.height
                && cursor_x >= area.x
            {
                frame.render_widget(
                    Block::default().style(Style::default().bg(Color::White).fg(Color::Black)),
                    Rect::new(cursor_x, cursor_y, 1, 1),
                );
            }
        }
    }

    fn render_input(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let prompt = self.get_prompt();
        let input_line = format!("{}{}", prompt, self.input_text);

        let paragraph = Paragraph::new(input_line);
        frame.render_widget(paragraph, area);

        if is_focused {
            let cursor_x = area.x + prompt.len() as u16 + self.cursor_position as u16;
            let cursor_y = area.y;

            if cursor_x < area.x + area.width && cursor_y < area.y + area.height {
                frame.render_widget(
                    Block::default().style(Style::default().bg(Color::White)),
                    Rect::new(cursor_x, cursor_y, 1, 1),
                );
            }
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
        } else {
            Style::default()
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

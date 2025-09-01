use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem},
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
    pub script_lines: Vec<String>,
    pub current_script_line: usize,
    pub max_history_items: usize,
    
    pub command_cursor_line: usize,
    pub command_cursor_column: usize,
    
    pub static_lines: Vec<StaticTextLine>,
}

impl InteractiveCommandPanel {
    pub fn new() -> Self {
        let mut panel = Self {
            input_text: String::new(),
            cursor_position: 0,
            command_history: Vec::new(),
            history_index: None,
            mode: InteractionMode::Input,
            script_lines: Vec::new(),
            current_script_line: 0,
            max_history_items: 1000,
            command_cursor_line: 0,
            command_cursor_column: 0,
            static_lines: Vec::new(),
        };
        panel.update_static_lines();
        panel
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
        self.update_static_lines();

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

        // Render static text content
        self.render_static_content(frame, content_area, is_focused);

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
                    LineType::Command => Style::default().fg(Color::White),
                    LineType::Response => self.get_response_style(&line.content),
                    LineType::CurrentInput => {
                        if self.mode == InteractionMode::Input {
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(ratatui::style::Modifier::BOLD)
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
                            Block::default().style(Style::default().bg(Color::White).fg(Color::Black)),
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
                                Block::default().style(Style::default().bg(Color::White).fg(Color::Black)),
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

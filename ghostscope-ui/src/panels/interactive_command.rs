use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem, Paragraph},
    Frame,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InteractionMode {
    Normal,
    Script,
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
}

impl InteractiveCommandPanel {
    pub fn new() -> Self {
        Self {
            input_text: String::new(),
            cursor_position: 0,
            command_history: Vec::new(),
            history_index: None,
            mode: InteractionMode::Normal,
            script_lines: Vec::new(),
            current_script_line: 0,
            scroll_offset: 0,
            max_history_items: 1000,
        }
    }

    pub fn get_prompt(&self) -> String {
        match self.mode {
            InteractionMode::Normal => "(ghostscope) ".to_string(),
            InteractionMode::Script => "> ".to_string(),
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
        if self.cursor_position > 0 {
            self.cursor_position -= 1;
        }
    }

    pub fn move_cursor_right(&mut self) {
        if self.cursor_position < self.input_text.len() {
            self.cursor_position += 1;
        }
    }

    pub fn submit_command(&mut self) -> Option<CommandAction> {
        if self.input_text.trim().is_empty() {
            return None;
        }

        let command = self.input_text.clone();
        let action = match self.mode {
            InteractionMode::Normal => {
                if command.starts_with("trace ") {
                    self.mode = InteractionMode::Script;
                    self.script_lines.clear();
                    self.current_script_line = 0;
                    CommandAction::EnterScriptMode(command.clone())
                } else {
                    CommandAction::ExecuteCommand(command.clone())
                }
            }
            InteractionMode::Script => {
                if command.trim() == "end" || command.trim() == "}" {
                    let script = self.script_lines.join("\n");
                    self.mode = InteractionMode::Normal;
                    self.script_lines.clear();
                    self.current_script_line = 0;
                    CommandAction::SubmitScript(script)
                } else {
                    self.script_lines.push(command.clone());
                    self.current_script_line += 1;
                    CommandAction::AddScriptLine(command.clone())
                }
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
            self.mode = InteractionMode::Normal;
            self.script_lines.clear();
            self.current_script_line = 0;
            self.input_text.clear();
            self.cursor_position = 0;
            true
        } else {
            false
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

    pub fn render(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        // Calculate how many lines the history will take
        let history_lines = self.calculate_history_lines();
        let available_height = area.height.saturating_sub(2) as usize; // Account for borders
        
        // Always show from the beginning, let history grow naturally
        let start_y = area.y + 1;
        
        let history_area = Rect::new(
            area.x + 1,
            start_y,
            area.width.saturating_sub(2),
            available_height as u16,
        );

        // Render history
        self.render_history(frame, history_area);

        // Input area follows after history
        let input_y = start_y + history_lines as u16;
        let input_area = Rect::new(
            area.x + 1,
            input_y,
            area.width.saturating_sub(2),
            1,
        );
        
        self.render_input(frame, input_area, is_focused);

        // Render border
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(if is_focused {
                BorderType::Thick
            } else {
                BorderType::Plain
            })
            .title("Command Interactive Window")
            .border_style(border_style);

        frame.render_widget(block, area);
    }

    fn render_history(&self, frame: &mut Frame, area: Rect) {
        let mut items = Vec::new();
        
        // Show all history items, let them flow naturally
        for item in &self.command_history {
            let prompt = self.get_prompt();
            let command_line = format!("{}{}", prompt, item.command);
            items.push(ListItem::new(Line::from(vec![
                Span::styled(command_line, Style::default().fg(Color::White)),
            ])));
            
            if let Some(ref response) = item.response {
                let response_style = self.get_response_style(response);
                items.push(ListItem::new(Line::from(vec![
                    Span::styled(response.clone(), response_style),
                ])));
            }
        }
        
        let list = List::new(items);
        frame.render_widget(list, area);
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

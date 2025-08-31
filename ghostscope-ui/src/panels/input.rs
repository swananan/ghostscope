use ratatui::{
    layout::Rect,
    style::{Color, Style},
    widgets::{Block, Borders, BorderType, Paragraph},
    Frame,
};

pub struct InputPanel {
    pub input_text: String,
    pub cursor_position: usize,
    pub command_history: Vec<String>,
    pub history_index: Option<usize>,
    pub prompt: String,
}

impl InputPanel {
    pub fn new() -> Self {
        Self {
            input_text: String::new(),
            cursor_position: 0,
            command_history: Vec::new(),
            history_index: None,
            prompt: "(ghostscope) ".to_string(),
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

    pub fn submit_command(&mut self) -> Option<String> {
        if !self.input_text.trim().is_empty() {
            let command = self.input_text.clone();
            self.command_history.push(command.clone());
            self.input_text.clear();
            self.cursor_position = 0;
            self.history_index = None;
            Some(command)
        } else {
            None
        }
    }

    pub fn history_up(&mut self) {
        if self.command_history.is_empty() {
            return;
        }

        let new_index = match self.history_index {
            None => self.command_history.len() - 1,
            Some(i) if i > 0 => i - 1,
            Some(_) => return, // Already at the top
        };

        self.history_index = Some(new_index);
        self.input_text = self.command_history[new_index].clone();
        self.cursor_position = self.input_text.len();
    }

    pub fn history_down(&mut self) {
        match self.history_index {
            None => return,
            Some(i) if i < self.command_history.len() - 1 => {
                let new_index = i + 1;
                self.history_index = Some(new_index);
                self.input_text = self.command_history[new_index].clone();
                self.cursor_position = self.input_text.len();
            }
            Some(_) => {
                // At the bottom, clear input
                self.history_index = None;
                self.input_text.clear();
                self.cursor_position = 0;
            }
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let input_line = format!("{}{}", self.prompt, self.input_text);

        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let paragraph = Paragraph::new(input_line).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(if is_focused { BorderType::Thick } else { BorderType::Plain })
                .border_style(border_style),
        );

        frame.render_widget(paragraph, area);

        // Render cursor
        let cursor_x = area.x + self.prompt.len() as u16 + self.cursor_position as u16 + 1;
        let cursor_y = area.y + 1;

        if cursor_x < area.x + area.width - 1 && cursor_y < area.y + area.height - 1 {
            frame.render_widget(
                Block::default().style(Style::default().bg(Color::White)),
                Rect::new(cursor_x, cursor_y, 1, 1),
            );
        }
    }
}

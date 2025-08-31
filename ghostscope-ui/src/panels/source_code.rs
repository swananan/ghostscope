use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, BorderType, List, ListItem},
    Frame,
};

pub struct SourceCodePanel {
    pub content: Vec<String>,
    pub current_line: usize,
    pub current_column: usize, // Add horizontal cursor position
    pub scroll_offset: usize,
    pub file_path: Option<String>,
    pub area_height: u16, // Store the current area height for scroll calculations
}

impl SourceCodePanel {

    pub fn new() -> Self {
        Self {
            content: vec!["// No source code loaded".to_string()],
            current_line: 0,
            current_column: 0,
            scroll_offset: 0,
            file_path: None,
            area_height: 10, // Default height
        }
    }

    pub fn load_source(
        &mut self,
        file_path: String,
        content: Vec<String>,
        highlight_line: Option<usize>,
    ) {
        self.file_path = Some(file_path);
        self.content = content;

        if let Some(line) = highlight_line {
            if line > 0 && line <= self.content.len() {
                self.current_line = line - 1;
                self.current_column = 0;
            } else {
                self.current_line = 0;
                self.current_column = 0;
            }
        } else {
            self.current_line = 0;
            self.current_column = 0;
        }
        
        self.scroll_offset = 0;
    }

    pub fn clear_source(&mut self) {
        self.content = vec!["// No source code loaded".to_string()];
        self.file_path = None;
        self.current_line = 0;
        self.current_column = 0;
        self.scroll_offset = 0;
    }


    pub fn move_up(&mut self) {
        if self.current_line > 0 {
            let old_column = self.current_column;
            self.current_line -= 1;
            self.adjust_column_for_new_line(old_column);
            self.ensure_cursor_visible();
        }
    }

    pub fn move_down(&mut self) {
        if self.current_line + 1 < self.content.len() {
            let old_column = self.current_column;
            self.current_line += 1;
            self.adjust_column_for_new_line(old_column);
            self.ensure_cursor_visible();
        }
    }

    pub fn move_up_fast(&mut self) {
        let new_line = self.current_line.saturating_sub(10);
        self.current_line = new_line;
        self.ensure_column_bounds();
        self.ensure_cursor_visible();
    }

    pub fn move_down_fast(&mut self) {
        let new_line = (self.current_line + 10).min(self.content.len().saturating_sub(1));
        self.current_line = new_line;
        self.ensure_column_bounds();
        self.ensure_cursor_visible();
    }

    pub fn move_to_top(&mut self) {
        self.current_line = 0;
        self.current_column = 0;
        self.scroll_offset = 0;
    }

    pub fn move_to_bottom(&mut self) {
        if !self.content.is_empty() {
            self.current_line = self.content.len() - 1;
            self.current_column = 0;
            self.ensure_cursor_visible();
        }
    }



    pub fn move_right(&mut self) {
        if let Some(current_line_content) = self.content.get(self.current_line) {
            if self.current_column < current_line_content.len() {
                self.current_column += 1;
            } else if self.current_line + 1 < self.content.len() {
                self.current_line += 1;
                self.current_column = 0;
                self.ensure_cursor_visible();
            }
        }
        self.ensure_column_bounds();
    }

    pub fn move_left(&mut self) {
        if self.current_column > 0 {
            self.current_column -= 1;
        } else if self.current_line > 0 {
            self.current_line -= 1;
            if let Some(prev_line_content) = self.content.get(self.current_line) {
                self.current_column = prev_line_content.len();
            }
            self.ensure_cursor_visible();
        }
        self.ensure_column_bounds();
    }

    fn adjust_column_for_new_line(&mut self, old_column: usize) {
        if let Some(current_line_content) = self.content.get(self.current_line) {
            self.current_column = old_column.min(current_line_content.len());
        }
    }

    fn ensure_column_bounds(&mut self) {
        if let Some(current_line_content) = self.content.get(self.current_line) {
            self.current_column = self.current_column.min(current_line_content.len());
        }
    }

    fn ensure_cursor_visible(&mut self) {
        if self.content.is_empty() {
            return;
        }

        let visible_lines = (self.area_height.saturating_sub(2)) as usize;
        
        if self.content.len() <= visible_lines {
            self.scroll_offset = 0;
            return;
        }

        let scrolloff = visible_lines / 3;
        
        let ideal_scroll = self.current_line.saturating_sub(scrolloff);

        let max_scroll = self.content.len().saturating_sub(visible_lines);
        let near_end = self.current_line >= max_scroll.saturating_add(scrolloff);
        
        if near_end {
            self.scroll_offset = max_scroll;
        } else {
            self.scroll_offset = ideal_scroll.min(max_scroll);
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect, is_focused: bool) {
        self.area_height = area.height;
        
        if is_focused {
            self.ensure_cursor_visible();
        }
        
        let items: Vec<ListItem> = self
            .content
            .iter()
            .enumerate()
            .skip(self.scroll_offset)
            .map(|(i, line)| {
                let line_num = i + 1;
                let is_current_line = i == self.current_line;

                let line_number_style = if is_current_line {
                    Style::default().fg(Color::LightYellow).bg(Color::DarkGray)
                } else {
                    Style::default().fg(Color::DarkGray)
                };

                let style = Style::default();

                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{:4} ", line_num),
                        line_number_style,
                    ),
                    Span::styled(line.clone(), style),
                ]))
            })
            .collect();

        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let title = match &self.file_path {
            Some(path) => format!("Source Code - {}", path),
            None => "Source Code".to_string(),
        };

        let list = List::new(items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(if is_focused { BorderType::Thick } else { BorderType::Plain })
                .title(title)
                .border_style(border_style),
        );

        frame.render_widget(list, area);

        if is_focused && !self.content.is_empty() {
            self.ensure_column_bounds();
            
            let cursor_y = area.y + 1 + (self.current_line.saturating_sub(self.scroll_offset)) as u16;
            let line_number_width = 5u16;
            let cursor_x = area.x + 1 + line_number_width + self.current_column as u16;

            if cursor_y < area.y + area.height - 1 && cursor_x < area.x + area.width - 1 {
                frame.render_widget(
                    Block::default().style(Style::default().bg(Color::Cyan)),
                    Rect::new(cursor_x, cursor_y, 1, 1),
                );
            }
        }
    }
}

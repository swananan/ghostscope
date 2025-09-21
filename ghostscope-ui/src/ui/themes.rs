use ratatui::style::{Color, Modifier, Style};

/// UI theme definitions
pub struct UIThemes;

impl UIThemes {
    // Panel styles
    pub fn panel_focused() -> Style {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    }

    pub fn panel_unfocused() -> Style {
        Style::default().fg(Color::DarkGray)
    }

    // Text styles
    pub fn success_text() -> Style {
        Style::default().fg(Color::Green)
    }

    pub fn error_text() -> Style {
        Style::default().fg(Color::Red)
    }

    pub fn warning_text() -> Style {
        Style::default().fg(Color::Yellow)
    }

    pub fn info_text() -> Style {
        Style::default().fg(Color::Blue)
    }

    pub fn progress_text() -> Style {
        Style::default().fg(Color::Cyan)
    }

    // Mode indicators
    pub fn input_mode() -> Style {
        Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD)
    }

    pub fn command_mode() -> Style {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    }

    pub fn script_mode() -> Style {
        Style::default()
            .fg(Color::Magenta)
            .add_modifier(Modifier::BOLD)
    }

    // Cursor and selection
    pub fn cursor_style() -> Style {
        Style::reset().bg(Color::Blue).add_modifier(Modifier::BOLD)
    }

    pub fn selection_style() -> Style {
        Style::default().bg(Color::Blue)
    }
}

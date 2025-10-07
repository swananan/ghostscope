use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
};

/// Style presets for different UI elements
pub struct StylePresets;

impl StylePresets {
    pub const TITLE: Style = Style::new().fg(Color::Green).add_modifier(Modifier::BOLD);
    pub const SECTION: Style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
    pub const KEY: Style = Style::new().fg(Color::Cyan);
    pub const VALUE: Style = Style::new().fg(Color::White);
    pub const ADDRESS: Style = Style::new().fg(Color::Yellow);
    pub const TYPE: Style = Style::new().fg(Color::Blue);
    pub const LOCATION: Style = Style::new().fg(Color::DarkGray);
    pub const TIP: Style = Style::new().fg(Color::Blue);
    pub const SUCCESS: Style = Style::new().fg(Color::Green);
    pub const ERROR: Style = Style::new().fg(Color::Red);
    pub const WARNING: Style = Style::new().fg(Color::Yellow);
    pub const TREE: Style = Style::new().fg(Color::DarkGray);
    pub const MARKER: Style = Style::new().fg(Color::Magenta);
}

/// Builder for creating styled lines
#[derive(Default)]
pub struct StyledLineBuilder {
    spans: Vec<Span<'static>>,
}

impl StyledLineBuilder {
    pub fn new() -> Self {
        Self { spans: Vec::new() }
    }

    pub fn text(mut self, text: impl Into<String>) -> Self {
        self.spans.push(Span::raw(text.into()));
        self
    }

    pub fn styled(mut self, text: impl Into<String>, style: Style) -> Self {
        self.spans.push(Span::styled(text.into(), style));
        self
    }

    pub fn title(self, text: impl Into<String>) -> Self {
        self.styled(text, StylePresets::TITLE)
    }

    pub fn key(self, text: impl Into<String>) -> Self {
        self.styled(text, StylePresets::KEY)
    }

    pub fn value(self, text: impl Into<String>) -> Self {
        self.styled(text, StylePresets::VALUE)
    }

    pub fn address(self, addr: u64) -> Self {
        self.styled(format!("0x{addr:x}"), StylePresets::ADDRESS)
    }

    pub fn build(self) -> Line<'static> {
        Line::from(self.spans)
    }
}

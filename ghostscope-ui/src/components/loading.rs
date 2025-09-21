use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Gauge, Padding, Paragraph},
    Frame,
};
use std::time::{Duration, Instant};

/// Loading UI component with animated spinner
#[derive(Clone, Debug)]
pub struct LoadingUI {
    start_time: Instant,
    spinner_chars: Vec<char>,
    current_spinner_idx: usize,
}

impl LoadingUI {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            spinner_chars: vec!['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
            current_spinner_idx: 0,
        }
    }

    /// Update spinner animation based on elapsed time
    pub fn update(&mut self) {
        let elapsed = self.start_time.elapsed();
        // Update spinner every 100ms
        let frames = (elapsed.as_millis() / 100) as usize;
        self.current_spinner_idx = frames % self.spinner_chars.len();
    }

    /// Get current spinner character
    fn current_spinner(&self) -> char {
        self.spinner_chars[self.current_spinner_idx]
    }

    /// Get formatted elapsed time
    fn elapsed_time(&self) -> String {
        let elapsed = self.start_time.elapsed();
        let seconds = elapsed.as_secs();
        if seconds < 60 {
            format!("{}s", seconds)
        } else {
            let minutes = seconds / 60;
            let remaining_seconds = seconds % 60;
            format!("{}m{}s", minutes, remaining_seconds)
        }
    }

    /// Render loading screen covering the entire terminal
    pub fn render(f: &mut Frame, loading_ui: &mut LoadingUI, message: &str, progress: Option<f64>) {
        loading_ui.update();

        // Clear the entire screen
        f.render_widget(Clear, f.area());

        // Create centered layout
        let vertical_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(8), // Height for loading box
                Constraint::Fill(1),
            ])
            .split(f.area());

        let horizontal_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(60), // Width for loading box
                Constraint::Fill(1),
            ])
            .split(vertical_chunks[1]);

        let loading_area = horizontal_chunks[1];

        // Main loading container
        let loading_block = Block::default()
            .title(" Ghostscope ")
            .title_alignment(Alignment::Center)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan));

        f.render_widget(loading_block, loading_area);

        // Inner content area
        let inner_area = loading_area.inner(ratatui::layout::Margin {
            vertical: 1,
            horizontal: 2,
        });

        let content_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Spinner line
                Constraint::Length(1), // Message line
                Constraint::Length(1), // Empty line
                Constraint::Length(1), // Progress bar (if present)
                Constraint::Length(1), // Time line
            ])
            .split(inner_area);

        // Spinner and status line
        let spinner_line = Line::from(vec![
            Span::styled(
                format!("{} ", loading_ui.current_spinner()),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                "Loading Ghostscope...",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);

        let spinner_paragraph = Paragraph::new(spinner_line).alignment(Alignment::Center);
        f.render_widget(spinner_paragraph, content_chunks[0]);

        // Message line
        let message_paragraph = Paragraph::new(Line::from(Span::styled(
            message,
            Style::default().fg(Color::Gray),
        )))
        .alignment(Alignment::Center);
        f.render_widget(message_paragraph, content_chunks[1]);

        // Progress bar (if progress is provided)
        if let Some(progress_value) = progress {
            let progress_bar = Gauge::default()
                .block(
                    Block::default()
                        .borders(Borders::NONE)
                        .padding(Padding::horizontal(1)),
                )
                .gauge_style(Style::default().fg(Color::Cyan))
                .ratio(progress_value.clamp(0.0, 1.0))
                .label(format!("{:.0}%", progress_value * 100.0));
            f.render_widget(progress_bar, content_chunks[3]);
        }

        // Elapsed time
        let time_line = Line::from(Span::styled(
            format!("Elapsed: {}", loading_ui.elapsed_time()),
            Style::default().fg(Color::DarkGray),
        ));
        let time_paragraph = Paragraph::new(time_line).alignment(Alignment::Center);
        f.render_widget(time_paragraph, content_chunks[4]);
    }

    /// Render a smaller loading indicator in a specific area
    pub fn render_inline(f: &mut Frame, area: Rect, loading_ui: &mut LoadingUI, message: &str) {
        loading_ui.update();

        let spinner_text = format!("{} {}", loading_ui.current_spinner(), message);
        let paragraph = Paragraph::new(Line::from(Span::styled(
            spinner_text,
            Style::default().fg(Color::Yellow),
        )));

        f.render_widget(paragraph, area);
    }
}

impl Default for LoadingUI {
    fn default() -> Self {
        Self::new()
    }
}

/// Loading states for different initialization phases
#[derive(Debug, Clone, PartialEq)]
pub enum LoadingState {
    /// Application is starting up
    Initializing,
    /// Waiting for runtime to connect
    ConnectingToRuntime,
    /// Waiting for DWARF symbols to load
    LoadingSymbols { progress: Option<f64> },
    /// Waiting for source code information
    LoadingSourceCode,
    /// Loading completed, application ready
    Ready,
    /// Loading failed with error
    Failed(String),
}

impl LoadingState {
    /// Get display message for current loading state
    pub fn message(&self) -> &str {
        match self {
            LoadingState::Initializing => "Initializing application...",
            LoadingState::ConnectingToRuntime => "Connecting to runtime...",
            LoadingState::LoadingSymbols { .. } => "Loading DWARF symbols...",
            LoadingState::LoadingSourceCode => "Loading source code information...",
            LoadingState::Ready => "Ready",
            LoadingState::Failed(error) => error,
        }
    }

    /// Get progress value (0.0 to 1.0) if available
    pub fn progress(&self) -> Option<f64> {
        match self {
            LoadingState::LoadingSymbols { progress } => *progress,
            LoadingState::Ready => Some(1.0),
            _ => None,
        }
    }

    /// Check if loading is complete
    pub fn is_ready(&self) -> bool {
        matches!(self, LoadingState::Ready)
    }

    /// Check if loading failed
    pub fn is_failed(&self) -> bool {
        matches!(self, LoadingState::Failed(_))
    }
}

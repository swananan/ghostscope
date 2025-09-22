use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
    Frame,
};
use std::time::{Duration, Instant};

use super::{LoadingProgress, LoadingState, ProgressRenderer};

/// Enhanced Loading UI component with detailed progress tracking
#[derive(Clone, Debug)]
pub struct LoadingUI {
    start_time: Instant,
    spinner_chars: Vec<char>,
    current_spinner_idx: usize,
    pub progress: LoadingProgress,
}

impl LoadingUI {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            spinner_chars: vec!['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
            current_spinner_idx: 0,
            progress: LoadingProgress::new(),
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
            format!("{:.1}s", elapsed.as_secs_f64())
        } else {
            let minutes = seconds / 60;
            let remaining_seconds = seconds % 60;
            format!("{}m{:.1}s", minutes, remaining_seconds)
        }
    }

    /// Render enhanced loading screen with DWARF loading progress
    pub fn render_dwarf_loading(
        f: &mut Frame,
        loading_ui: &mut LoadingUI,
        loading_state: &LoadingState,
        pid: Option<u32>,
    ) {
        loading_ui.update();

        // Clear the entire screen
        f.render_widget(Clear, f.area());

        // Create main layout - more space for content
        let main_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(18), // Height for loading box - increased for more content
                Constraint::Fill(1),
            ])
            .split(f.area());

        let horizontal_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Fill(1),
                Constraint::Length(78), // Width for loading box - increased
                Constraint::Fill(1),
            ])
            .split(main_chunks[1]);

        let loading_area = horizontal_chunks[1];

        // Main loading container with enhanced styling
        let loading_block = Block::default()
            .title(" Ghostscope Debugger ")
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

        // Create content layout
        let content_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Header line
                Constraint::Length(1), // Copyright line
                Constraint::Length(1), // License line
                Constraint::Length(1), // Empty line
                Constraint::Length(1), // Loading status line
                Constraint::Length(1), // Empty line
                Constraint::Length(1), // Progress bar
                Constraint::Length(1), // Empty line
                Constraint::Length(4), // Recently loaded modules (4 lines)
                Constraint::Length(1), // Current loading status
                Constraint::Length(1), // Stats line
            ])
            .split(inner_area);

        // Header
        let header_line = Line::from(vec![
            Span::styled("🔍 ", Style::default().fg(Color::Yellow)),
            Span::styled(
                "Ghostscope v0.1.0 - A DWARF-friendly eBPF userspace probe with gdb-like TUI",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]);
        let header_paragraph = Paragraph::new(header_line).alignment(Alignment::Center);
        f.render_widget(header_paragraph, content_chunks[0]);

        // Copyright
        let copyright_line = Line::from(Span::styled(
            "Copyright (C) 2025 Ghostscope Project",
            Style::default().fg(Color::Gray),
        ));
        let copyright_paragraph = Paragraph::new(copyright_line).alignment(Alignment::Center);
        f.render_widget(copyright_paragraph, content_chunks[1]);

        // License
        let license_line = Line::from(Span::styled(
            "Licensed under GPL License",
            Style::default().fg(Color::Gray),
        ));
        let license_paragraph = Paragraph::new(license_line).alignment(Alignment::Center);
        f.render_widget(license_paragraph, content_chunks[2]);

        // Loading status with PID
        let status_message = if let Some(pid) = pid {
            format!("Loading debug information for PID {}...", pid)
        } else {
            loading_state.message().to_string()
        };

        let status_line = Line::from(vec![
            Span::styled(
                format!("{} ", loading_ui.current_spinner()),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(status_message, Style::default().fg(Color::White)),
        ]);
        let status_paragraph = Paragraph::new(status_line).alignment(Alignment::Center);
        f.render_widget(status_paragraph, content_chunks[4]);

        // Progress bar - only show if we have modules
        if !loading_ui.progress.modules.is_empty() {
            ProgressRenderer::render_progress_bar(f, content_chunks[6], &loading_ui.progress);
        }

        // Recently loaded modules
        ProgressRenderer::render_recent_modules(f, content_chunks[8], &loading_ui.progress, 4);

        // Current loading status
        ProgressRenderer::render_current_status(f, content_chunks[9], &loading_ui.progress);

        // Stats line
        ProgressRenderer::render_stats(f, content_chunks[10], &loading_ui.progress);
    }

    /// Generate styled welcome message for command panel
    pub fn create_welcome_message(&self, total_time: f64) -> Vec<ratatui::text::Line<'static>> {
        use ratatui::style::{Color, Modifier, Style};
        use ratatui::text::{Line, Span};

        let total_stats = self.progress.total_stats();
        let total_modules = self.progress.total_modules();
        let failed_count = self.progress.failed_count;
        let successful_modules = total_modules - failed_count;

        let mut lines = Vec::new();

        // Header with cyan color and bold
        lines.push(Line::from(Span::styled(
            "🔍 Ghostscope v0.1.0",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )));

        // License in gray
        lines.push(Line::from(Span::styled(
            "Licensed under GPL",
            Style::default().fg(Color::Gray),
        )));

        // Empty line
        lines.push(Line::from(""));

        // Debug information section with green checkmark
        lines.push(Line::from(Span::styled(
            "✅ Debug Information Loaded:",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )));

        // Module loading stats in white
        if failed_count > 0 {
            lines.push(Line::from(Span::styled(
                format!(
                    "• {} modules loaded successfully ({} failed) in {:.1} seconds",
                    successful_modules, failed_count, total_time
                ),
                Style::default().fg(Color::White),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                format!(
                    "• {} modules loaded successfully in {:.1} seconds",
                    successful_modules, total_time
                ),
                Style::default().fg(Color::White),
            )));
        }

        // DWARF statistics in yellow
        lines.push(Line::from(Span::styled(
            format!(
                "• {} functions, {} variables, {} types indexed",
                total_stats.functions, total_stats.variables, total_stats.types
            ),
            Style::default().fg(Color::Yellow),
        )));

        // Empty line
        lines.push(Line::from(""));

        // Bug reporting info in gray
        lines.push(Line::from(Span::styled(
            "For bug reporting instructions, please see:",
            Style::default().fg(Color::Gray),
        )));

        // GitHub URL in white
        lines.push(Line::from(Span::styled(
            "https://github.com/swananan/ghostscope/issues",
            Style::default().fg(Color::White),
        )));

        lines
    }

    /// Generate completion summary for command panel (backward compatibility)
    pub fn generate_completion_summary(&self, total_time: f64) -> Vec<String> {
        // Convert styled lines back to strings for backward compatibility
        self.create_welcome_message(total_time)
            .into_iter()
            .map(|line| {
                line.spans
                    .into_iter()
                    .map(|span| span.content.to_string())
                    .collect::<String>()
            })
            .collect()
    }

    /// Render the simple loading screen (fallback for non-DWARF loading)
    pub fn render_simple(
        f: &mut Frame,
        loading_ui: &mut LoadingUI,
        message: &str,
        progress: Option<f64>,
    ) {
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
            use ratatui::widgets::{Gauge, Padding};
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

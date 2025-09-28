/// Unified output formatter for consistent UI messages
/// This module owns the emoji configuration and generates styled lines
use super::emoji::{EmojiConfig, ScriptStatus, StatusType, TraceElement, TraceStatusType};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// OutputFormatter owns the emoji configuration and generates formatted output
#[derive(Debug)]
pub struct OutputFormatter {
    emoji_config: EmojiConfig,
}

impl OutputFormatter {
    /// Create a new OutputFormatter with the given emoji enabled state
    pub fn new(emoji_enabled: bool) -> Self {
        Self {
            emoji_config: EmojiConfig::new(emoji_enabled),
        }
    }

    /// Get the internal emoji configuration
    pub fn emoji_config(&self) -> &EmojiConfig {
        &self.emoji_config
    }

    /// Update emoji enabled state
    pub fn set_emoji_enabled(&mut self, enabled: bool) {
        self.emoji_config.enabled = enabled;
    }

    // === Quick styled methods ===

    /// Generate styled success message
    pub fn success(&self, msg: &str) -> Vec<Line<'static>> {
        vec![Line::from(vec![
            Span::styled(
                self.emoji_config.get_status_prefix(StatusType::Success),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(msg.to_string(), Style::default().fg(Color::Green)),
        ])]
    }

    /// Generate styled error message
    pub fn error(&self, msg: &str) -> Vec<Line<'static>> {
        vec![Line::from(vec![
            Span::styled(
                self.emoji_config.get_status_prefix(StatusType::Error),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(msg.to_string(), Style::default().fg(Color::Red)),
        ])]
    }

    /// Generate styled warning message
    pub fn warning(&self, msg: &str) -> Vec<Line<'static>> {
        vec![Line::from(vec![
            Span::styled(
                self.emoji_config.get_status_prefix(StatusType::Warning),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(msg.to_string(), Style::default().fg(Color::Yellow)),
        ])]
    }

    /// Generate styled info message
    pub fn info(&self, msg: &str) -> Vec<Line<'static>> {
        vec![Line::from(vec![
            Span::styled(
                self.emoji_config.get_status_prefix(StatusType::Info),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(msg.to_string(), Style::default().fg(Color::White)),
        ])]
    }

    /// Generate styled progress message
    pub fn progress(&self, msg: &str) -> Vec<Line<'static>> {
        vec![Line::from(vec![
            Span::styled(
                self.emoji_config.get_status_prefix(StatusType::Progress),
                Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(msg.to_string(), Style::default().fg(Color::Gray)),
        ])]
    }

    // === Builder pattern for complex outputs ===

    /// Start building a section
    pub fn section(&self, title: &str) -> SectionBuilder {
        SectionBuilder::new(self.emoji_config.clone(), title.to_string())
    }

    /// Format trace status with styled output
    pub fn format_trace_status(
        &self,
        trace_id: u32,
        target: &str,
        status: TraceStatusType,
    ) -> Vec<Line<'static>> {
        vec![Line::from(vec![
            Span::styled(
                self.emoji_config.get_trace_status(status),
                match status {
                    TraceStatusType::Active => Style::default().fg(Color::Green),
                    TraceStatusType::Disabled => Style::default().fg(Color::Gray),
                    TraceStatusType::Failed => Style::default().fg(Color::Red),
                    TraceStatusType::Skipped => Style::default().fg(Color::Yellow),
                },
            ),
            Span::raw(" "),
            Span::styled(
                format!("Trace #{}", trace_id),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(" at "),
            Span::styled(target.to_string(), Style::default().fg(Color::Cyan)),
        ])]
    }

    /// Format script status
    pub fn format_script_status(&self, status: ScriptStatus, message: &str) -> Vec<Line<'static>> {
        vec![Line::from(vec![
            Span::styled(
                self.emoji_config.get_script_status(status),
                match status {
                    ScriptStatus::Success => Style::default().fg(Color::Green),
                    ScriptStatus::Error => Style::default().fg(Color::Red),
                    ScriptStatus::Partial => Style::default().fg(Color::Yellow),
                    ScriptStatus::Compiling => Style::default().fg(Color::Blue),
                },
            ),
            Span::raw(" "),
            Span::raw(message.to_string()),
        ])]
    }

    /// Format successful trace setup with details
    pub fn format_trace_success(
        &self,
        trace_id: u32,
        target: &str,
        binary: Option<&str>,
    ) -> Vec<Line<'static>> {
        let mut lines = Vec::new();

        // Main success message
        lines.push(Line::from(vec![
            Span::styled(
                self.emoji_config.get_status_prefix(StatusType::Success),
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                format!("Trace #{} set successfully", trace_id),
                Style::default().fg(Color::Green),
            ),
        ]));

        // Target info
        lines.push(Line::from(vec![
            Span::raw("   "),
            Span::styled(
                self.emoji_config.get_trace_element(TraceElement::Target),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(" Target: "),
            Span::styled(
                target.to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));

        // Binary info if available
        if let Some(bin) = binary {
            lines.push(Line::from(vec![
                Span::raw("   "),
                Span::styled(
                    self.emoji_config.get_trace_element(TraceElement::Binary),
                    Style::default().fg(Color::Blue),
                ),
                Span::raw(" Binary: "),
                Span::styled(bin.to_string(), Style::default().fg(Color::Blue)),
            ]));
        }

        // Status
        lines.push(Line::from(vec![
            Span::raw("   "),
            Span::styled(
                if self.emoji_config.enabled {
                    "✨"
                } else {
                    "[*]"
                },
                Style::default().fg(Color::Green),
            ),
            Span::raw(" Status: "),
            Span::styled(
                "Active",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ]));

        lines
    }

    /// Format info trace all with grouping
    pub fn format_trace_overview(
        &self,
        total: usize,
        active: usize,
        disabled: usize,
    ) -> Vec<Line<'static>> {
        let mut lines = Vec::new();

        // Header
        lines.push(Line::from(vec![
            Span::styled(
                if self.emoji_config.enabled {
                    "📊"
                } else {
                    "[INFO]"
                },
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                "Trace Overview",
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]));

        // Summary with colored numbers
        lines.push(Line::from(vec![
            Span::raw("   Total: "),
            Span::styled(
                format!("{} traces", total),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(" • "),
            Span::styled(
                format!("{} active", active),
                Style::default().fg(Color::Green),
            ),
            Span::raw(" • "),
            Span::styled(
                format!("{} disabled", disabled),
                Style::default().fg(Color::Gray),
            ),
        ]));

        lines
    }

    /// Format batch loading results with details
    pub fn format_batch_loading_summary(
        &self,
        filename: &str,
        success_count: usize,
        failed_count: usize,
        total_count: usize,
    ) -> Vec<Line<'static>> {
        let mut lines = Vec::new();

        // Header with appropriate status
        let (status_emoji, color) = if failed_count == 0 {
            (StatusType::Success, Color::Green)
        } else if success_count == 0 {
            (StatusType::Error, Color::Red)
        } else {
            (StatusType::Warning, Color::Yellow)
        };

        lines.push(Line::from(vec![
            Span::styled(
                self.emoji_config.get_status_prefix(status_emoji),
                Style::default().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" "),
            Span::styled(
                format!("Loaded {} traces from {}", success_count, filename),
                Style::default().fg(color),
            ),
        ]));

        // Add empty line for spacing
        lines.push(Line::from(""));

        // Success rate bar
        let percentage = if total_count > 0 {
            (success_count as f32 / total_count as f32 * 100.0) as usize
        } else {
            0
        };
        let bar_width = 20;
        let filled = bar_width * percentage / 100;
        let empty = bar_width - filled;

        lines.push(Line::from(vec![
            Span::raw("   "),
            Span::raw("["),
            Span::styled("█".repeat(filled), Style::default().fg(Color::Green)),
            Span::styled("░".repeat(empty), Style::default().fg(Color::Gray)),
            Span::raw("] "),
            Span::styled(
                format!("{}%", percentage),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" ({}/{})", success_count, total_count)),
        ]));

        lines
    }
}

/// Builder for complex multi-line sections
pub struct SectionBuilder {
    emoji_config: EmojiConfig,
    title: String,
    lines: Vec<Line<'static>>,
}

impl SectionBuilder {
    fn new(emoji_config: EmojiConfig, title: String) -> Self {
        Self {
            emoji_config,
            title,
            lines: Vec::new(),
        }
    }

    /// Add a summary line
    pub fn summary(mut self, text: &str) -> Self {
        self.lines.push(Line::from(vec![
            Span::raw("  "),
            Span::raw(text.to_string()),
        ]));
        self
    }

    /// Add an item with status
    pub fn item(mut self, status: StatusType, text: &str) -> Self {
        let color = match status {
            StatusType::Success => Color::Green,
            StatusType::Error => Color::Red,
            StatusType::Warning => Color::Yellow,
            StatusType::Info => Color::Cyan,
            StatusType::Progress => Color::Blue,
        };

        self.lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                self.emoji_config.get_status_prefix(status),
                Style::default().fg(color),
            ),
            Span::raw(" "),
            Span::raw(text.to_string()),
        ]));
        self
    }

    /// Add a subsection header
    pub fn subsection(mut self, title: &str) -> Self {
        if !self.lines.is_empty() {
            self.lines.push(Line::from("")); // Empty line
        }
        self.lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("{}:", title),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]));
        self
    }

    /// Add a list item
    pub fn list_item(mut self, text: &str) -> Self {
        self.lines.push(Line::from(vec![
            Span::raw("    • "),
            Span::raw(text.to_string()),
        ]));
        self
    }

    /// Add a trace element
    pub fn trace_element(mut self, element: TraceElement, value: &str) -> Self {
        self.lines.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                self.emoji_config.get_trace_element(element),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(" "),
            Span::raw(value.to_string()),
        ]));
        self
    }

    /// Build the final styled lines
    pub fn build(mut self) -> Vec<Line<'static>> {
        let mut result = Vec::new();

        // Add title line
        result.push(Line::from(vec![Span::styled(
            self.title,
            Style::default().add_modifier(Modifier::BOLD),
        )]));

        // Add all content lines
        result.append(&mut self.lines);

        result
    }
}

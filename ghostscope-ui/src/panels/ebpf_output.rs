use chrono::{DateTime, Local, TimeZone, Timelike, Utc};
use ratatui::{
    layout::Rect,
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, List, ListItem},
    Frame,
};
use std::collections::VecDeque;

use crate::events::{RuntimeStatus, TraceEvent};
use ghostscope_protocol::MessageType;

pub struct EbpfInfoPanel {
    pub status_messages: VecDeque<RuntimeStatus>,
    pub trace_events: VecDeque<TraceEvent>,
    pub scroll_offset: usize,
    pub max_messages: usize,
    pub auto_scroll: bool,
}

impl EbpfInfoPanel {
    pub fn new() -> Self {
        Self {
            status_messages: VecDeque::new(),
            trace_events: VecDeque::new(),
            scroll_offset: 0,
            max_messages: 1000,
            auto_scroll: true,
        }
    }

    pub fn add_status_message(&mut self, status: RuntimeStatus) {
        self.status_messages.push_back(status);
        if self.status_messages.len() > 100 {
            // Keep fewer status messages
            self.status_messages.pop_front();
        }
    }

    pub fn add_trace_event(&mut self, trace_event: TraceEvent) {
        self.trace_events.push_back(trace_event);
        if self.trace_events.len() > self.max_messages {
            self.trace_events.pop_front();
        }

        if self.auto_scroll {
            self.scroll_to_bottom();
        }
    }

    pub fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
            self.auto_scroll = false;
        }
    }

    pub fn scroll_down(&mut self) {
        let total_lines = self.status_messages.len() + self.trace_events.len();
        if self.scroll_offset + 1 < total_lines {
            self.scroll_offset += 1;
        } else {
            self.auto_scroll = true;
        }
    }

    pub fn scroll_to_bottom(&mut self) {
        let total_lines = self.status_messages.len() + self.trace_events.len();
        self.scroll_offset = total_lines.saturating_sub(1);
        self.auto_scroll = true;
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, is_focused: bool) {
        let mut all_items = Vec::new();

        // Calculate content width for text wrapping (subtract borders and prefix)
        let content_width = area.width.saturating_sub(4); // 2 for borders + 2 for padding

        // Add status messages first (in chronological order)
        for status in &self.status_messages {
            let (style, text) = match status {
                RuntimeStatus::DwarfLoadingStarted => (
                    Style::default().fg(Color::Yellow),
                    "Loading DWARF information...".to_string(),
                ),
                RuntimeStatus::DwarfLoadingCompleted { symbols_count } => (
                    Style::default().fg(Color::Green),
                    format!("DWARF loaded successfully ({} symbols)", symbols_count),
                ),
                RuntimeStatus::DwarfLoadingFailed(err) => (
                    Style::default().fg(Color::Red),
                    format!("DWARF loading failed: {}", err),
                ),
                RuntimeStatus::ScriptCompilationStarted => (
                    Style::default().fg(Color::Yellow),
                    "Compiling script...".to_string(),
                ),
                RuntimeStatus::ScriptCompilationCompleted => (
                    Style::default().fg(Color::Green),
                    "Script compiled successfully".to_string(),
                ),
                RuntimeStatus::ScriptCompilationFailed(err) => (
                    Style::default().fg(Color::Red),
                    format!("Script compilation failed: {}", err),
                ),
                RuntimeStatus::UprobeAttached { function, address } => (
                    Style::default().fg(Color::Green),
                    format!("Uprobe attached: {} @ 0x{:x}", function, address),
                ),
                RuntimeStatus::UprobeDetached { function } => (
                    Style::default().fg(Color::Yellow),
                    format!("Uprobe detached: {}", function),
                ),
                RuntimeStatus::ProcessAttached(pid) => (
                    Style::default().fg(Color::Green),
                    format!("Attached to process {}", pid),
                ),
                RuntimeStatus::ProcessDetached => (
                    Style::default().fg(Color::Yellow),
                    "Detached from process".to_string(),
                ),
                RuntimeStatus::SourceCodeLoaded(source_info) => (
                    Style::default().fg(Color::Green),
                    format!("Source code loaded: {}", source_info.file_path),
                ),
                RuntimeStatus::SourceCodeLoadFailed(err) => (
                    Style::default().fg(Color::Red),
                    format!("Source code load failed: {}", err),
                ),
                RuntimeStatus::Error(err) => {
                    (Style::default().fg(Color::Red), format!("Error: {}", err))
                }
            };

            // Wrap long messages
            let status_prefix = "[STATUS] ";
            let full_text = format!("{}{}", status_prefix, text);
            let wrapped_lines = self.wrap_text(&full_text, content_width as usize);

            for (i, line) in wrapped_lines.iter().enumerate() {
                if i == 0 {
                    // First line includes the [STATUS] prefix
                    all_items.push(ListItem::new(Line::from(vec![Span::styled(
                        line.clone(),
                        style,
                    )])));
                } else {
                    // Continuation lines are indented to align with content after prefix
                    let indent = " ".repeat(status_prefix.len());
                    all_items.push(ListItem::new(Line::from(vec![Span::styled(
                        format!("{}{}", indent, line),
                        style,
                    )])));
                }
            }
        }

        // Add trace events (from ringbuf processing)
        for trace in &self.trace_events {
            // Format timestamp as HH:MM:SS.mmm
            let formatted_time = self.format_timestamp(trace.timestamp);
            let timestamp_text = format!("[{}] ", formatted_time);

            let level_style = match trace.trace_type {
                MessageType::Error => Style::default().fg(Color::Red),
                MessageType::ExecutionFailure => Style::default().fg(Color::Red),
                MessageType::Log => Style::default().fg(Color::Green),
                MessageType::VariableData => Style::default().fg(Color::Cyan),
                MessageType::Heartbeat => Style::default().fg(Color::DarkGray),
                MessageType::BatchVariables => Style::default().fg(Color::Blue),
                MessageType::Reserved => Style::default().fg(Color::White),
            };

            let level_text = format!("[{:^5}] ", format!("{:?}", trace.trace_type));
            let trace_info = format!("TraceID:{} PID:{} - ", trace.trace_id, trace.pid);
            let full_line = format!(
                "{}{}{}{}",
                timestamp_text, level_text, trace_info, trace.message
            );

            let wrapped_lines = self.wrap_text(&full_line, content_width as usize);
            for (i, line) in wrapped_lines.iter().enumerate() {
                if i == 0 {
                    // First line with proper coloring
                    let timestamp_len = timestamp_text.len();
                    let level_len = level_text.len();
                    let trace_info_len = trace_info.len();
                    let total_prefix_len = timestamp_len + level_len + trace_info_len;

                    let timestamp_part = &line[..timestamp_len.min(line.len())];
                    let level_part = if line.len() > timestamp_len {
                        &line[timestamp_len..(timestamp_len + level_len).min(line.len())]
                    } else {
                        ""
                    };
                    let trace_info_part = if line.len() > timestamp_len + level_len {
                        &line[(timestamp_len + level_len)
                            ..(timestamp_len + level_len + trace_info_len).min(line.len())]
                    } else {
                        ""
                    };
                    let content_part = if line.len() > total_prefix_len {
                        &line[total_prefix_len..]
                    } else {
                        ""
                    };

                    all_items.push(ListItem::new(Line::from(vec![
                        Span::styled(
                            timestamp_part.to_string(),
                            Style::default().fg(Color::DarkGray),
                        ),
                        Span::styled(level_part.to_string(), level_style),
                        Span::styled(
                            trace_info_part.to_string(),
                            Style::default().fg(Color::Blue),
                        ),
                        Span::styled(content_part.to_string(), Style::default()),
                    ])));
                } else {
                    // Continuation lines - indent to align with content after prefixes
                    let indent =
                        " ".repeat(timestamp_text.len() + level_text.len() + trace_info.len());
                    all_items.push(ListItem::new(Line::from(vec![Span::styled(
                        format!("{}{}", indent, line),
                        Style::default(),
                    )])));
                }
            }
        }

        // Apply scrolling
        let visible_items: Vec<_> = all_items.into_iter().skip(self.scroll_offset).collect();

        let border_style = if is_focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default()
        };

        let list = List::new(visible_items).block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(if is_focused {
                    BorderType::Thick
                } else {
                    BorderType::Plain
                })
                .title(format!(
                    "eBPF Trace Output ({} events)",
                    self.trace_events.len()
                ))
                .border_style(border_style),
        );

        frame.render_widget(list, area);
    }

    /// Format nanosecond timestamp to HH:MM:SS.mmm format using chrono with local timezone
    fn format_timestamp(&self, timestamp_ns: u64) -> String {
        // Convert nanoseconds to seconds and nanoseconds
        let secs = timestamp_ns / 1_000_000_000;
        let nsecs = (timestamp_ns % 1_000_000_000) as u32;

        // Create UTC DateTime from timestamp
        let utc_dt: DateTime<Utc> = match Utc.timestamp_opt(secs as i64, nsecs) {
            chrono::LocalResult::Single(dt) => dt,
            chrono::LocalResult::None => {
                // Fallback to current time if timestamp is invalid
                Utc::now()
            }
            chrono::LocalResult::Ambiguous(dt, _) => dt, // Use first occurrence in case of ambiguity
        };

        // Convert to local timezone
        let local_dt: DateTime<Local> = DateTime::from(utc_dt);

        // Format as HH:MM:SS.mmm
        let millis = local_dt.nanosecond() / 1_000_000;
        format!(
            "{:02}:{:02}:{:02}.{:03}",
            local_dt.hour(),
            local_dt.minute(),
            local_dt.second(),
            millis
        )
    }

    /// Wrap text to fit within the specified width
    /// This improved version handles long words and special characters better
    fn wrap_text(&self, text: &str, width: usize) -> Vec<String> {
        if width == 0 {
            return vec![text.to_string()];
        }

        let mut lines = Vec::new();
        let mut current_line = String::new();

        for word in text.split_whitespace() {
            // If the word itself is longer than the width, we need to break it
            if word.len() > width {
                // If we have content on the current line, push it first
                if !current_line.is_empty() {
                    lines.push(current_line);
                    current_line = String::new();
                }

                // For long words (like file paths), try to break at more sensible points
                if word.contains('/') {
                    // Try to break at path separators for file paths
                    let mut remaining = word;
                    while !remaining.is_empty() {
                        let mut chunk_size = (width - 3).min(remaining.len());

                        // If we're not at the end, try to find a good break point
                        if chunk_size < remaining.len() {
                            // Look for a path separator near the end of the chunk
                            let chunk = &remaining[..chunk_size];
                            if let Some(last_slash) = chunk.rfind('/') {
                                // Break after the last slash in the chunk
                                chunk_size = last_slash + 1;
                            }
                        }

                        let chunk = &remaining[..chunk_size];
                        lines.push(chunk.to_string());
                        remaining = &remaining[chunk_size..];
                    }
                } else {
                    // For other long words, break at character boundaries
                    let mut remaining = word;
                    while !remaining.is_empty() {
                        let chunk_size = (width - 3).min(remaining.len());
                        let chunk = &remaining[..chunk_size];
                        lines.push(chunk.to_string());
                        remaining = &remaining[chunk_size..];
                    }
                }
            } else if current_line.is_empty() {
                // First word on the line
                current_line = word.to_string();
            } else if current_line.len() + 1 + word.len() <= width {
                // Word fits on current line
                current_line.push(' ');
                current_line.push_str(word);
            } else {
                // Word doesn't fit, start new line
                lines.push(current_line);
                current_line = word.to_string();
            }
        }

        // Add the last line if it's not empty
        if !current_line.is_empty() {
            lines.push(current_line);
        }

        // If no lines were created, return the original text
        if lines.is_empty() {
            vec![text.to_string()]
        } else {
            lines
        }
    }
}

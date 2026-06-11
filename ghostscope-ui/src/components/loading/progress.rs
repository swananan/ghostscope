use ratatui::{
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
    Frame,
};

use super::{DebugSourceCounts, LoadingProgress, ModuleState};

/// Progress bar component for loading
pub struct ProgressRenderer;

impl ProgressRenderer {
    /// Render overall progress bar
    pub fn render_progress_bar(
        f: &mut Frame,
        area: ratatui::layout::Rect,
        progress: &LoadingProgress,
    ) {
        let ratio = progress.progress_ratio();
        let completed = progress.completed_count;
        let total = progress.total_modules();

        let progress_bar = Gauge::default()
            .block(Block::default().borders(Borders::NONE))
            .gauge_style(Style::default().fg(Color::Cyan))
            .ratio(ratio)
            .label(format!(
                "{completed}/{total} modules ({}%)",
                (ratio * 100.0) as u8
            ));

        f.render_widget(progress_bar, area);
    }

    /// Render recently loaded modules list
    pub fn render_recent_modules(
        f: &mut Frame,
        area: ratatui::layout::Rect,
        progress: &LoadingProgress,
        max_items: usize,
    ) {
        let recent = progress.recently_finished(max_items);
        let mut lines = Vec::new();

        for module in recent {
            let path = if module.path.len() > 50 {
                format!("...{}", &module.path[module.path.len() - 47..])
            } else {
                module.path.clone()
            };

            match &module.state {
                ModuleState::Completed => {
                    if let Some(stats) = &module.stats {
                        let load_time = module.load_time.unwrap_or(0.0);
                        let mut spans = vec![
                            Span::styled("✅ ", Style::default().fg(Color::Green)),
                            Span::styled(path, Style::default().fg(Color::White)),
                            Span::styled("  debug: ", Style::default().fg(Color::Gray)),
                        ];
                        push_module_debug_source_spans(&mut spans, stats);
                        spans.push(Span::styled(
                            format!(
                                " | Functions: {} | Variables: {} | Types: {} | Time: {:.1}s",
                                stats.functions, stats.variables, stats.types, load_time
                            ),
                            Style::default().fg(Color::Gray),
                        ));
                        let line = Line::from(spans);
                        lines.push(line);
                    }
                }
                ModuleState::Failed(error) => {
                    let load_time = module.load_time.unwrap_or(0.0);
                    let line = Line::from(vec![
                        Span::styled("✗ ", Style::default().fg(Color::Red)),
                        Span::styled(path, Style::default().fg(Color::White)),
                        Span::styled(
                            format!("  ❌ Failed: {error} | Time: {load_time:.1}s"),
                            Style::default().fg(Color::Red),
                        ),
                    ]);
                    lines.push(line);
                }
                _ => {} // Skip queued and loading states
            }
        }

        if lines.is_empty() {
            lines.push(Line::from(Span::styled(
                "No modules processed yet...",
                Style::default().fg(Color::DarkGray),
            )));
        }

        let title = if progress.failed_count > 0 {
            format!("📁 Recently processed: ({} failed)", progress.failed_count)
        } else {
            "📁 Recently loaded:".to_string()
        };

        let paragraph = Paragraph::new(lines).block(
            Block::default()
                .title(title)
                .borders(Borders::NONE)
                .title_style(Style::default().fg(Color::Yellow)),
        );

        f.render_widget(paragraph, area);
    }

    /// Render current loading status
    pub fn render_current_status(
        f: &mut Frame,
        area: ratatui::layout::Rect,
        progress: &LoadingProgress,
    ) {
        let status_line = if let Some(current) = &progress.current_loading {
            let path = if current.len() > 60 {
                format!("...{}", &current[current.len() - 57..])
            } else {
                current.clone()
            };
            Line::from(vec![
                Span::styled("⏳ Loading: ", Style::default().fg(Color::Yellow)),
                Span::styled(path, Style::default().fg(Color::White)),
            ])
        } else {
            Line::from(Span::styled(
                "Waiting for next module...",
                Style::default().fg(Color::DarkGray),
            ))
        };

        let paragraph = Paragraph::new(status_line);
        f.render_widget(paragraph, area);
    }

    /// Render total statistics
    pub fn render_stats(f: &mut Frame, area: ratatui::layout::Rect, progress: &LoadingProgress) {
        let stats = progress.total_stats();
        let elapsed = progress.elapsed_time();
        let debug_sources = progress.debug_sources.summary();

        let mut spans = vec![
            Span::styled("⏱️ Elapsed: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{elapsed:.1}s"), Style::default().fg(Color::White)),
            Span::styled(" | ", Style::default().fg(Color::DarkGray)),
            Span::styled("📊 Total: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!(
                    "{} functions | {} variables | {} types",
                    stats.functions, stats.variables, stats.types
                ),
                Style::default().fg(Color::Cyan),
            ),
        ];
        if !debug_sources.is_empty() {
            spans.push(Span::styled(" | ", Style::default().fg(Color::DarkGray)));
            spans.push(Span::styled(
                "Debug: ",
                Style::default().fg(Color::DarkGray),
            ));
            push_debug_source_count_spans(&mut spans, &progress.debug_sources);
        }

        let stats_line = Line::from(spans);

        let paragraph = Paragraph::new(stats_line);
        f.render_widget(paragraph, area);
    }
}

fn push_module_debug_source_spans(
    spans: &mut Vec<Span<'static>>,
    stats: &crate::components::loading::ModuleStats,
) {
    spans.push(Span::styled(
        stats.debug_source.clone(),
        debug_source_style(&stats.debug_source),
    ));

    if let Some(path) = stats.debug_source_path.as_deref() {
        let file = std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(path);
        spans.push(Span::styled(
            format!(" {file}"),
            Style::default().fg(Color::Gray),
        ));
    }
}

pub(crate) fn push_debug_source_count_spans(
    spans: &mut Vec<Span<'static>>,
    counts: &DebugSourceCounts,
) {
    let mut first = true;
    push_debug_source_count(spans, &mut first, "embedded", counts.embedded);
    push_debug_source_count(spans, &mut first, "explicit", counts.explicit);
    push_debug_source_count(spans, &mut first, "debuglink", counts.debuglink);
    push_debug_source_count(spans, &mut first, "debuginfod", counts.debuginfod);
    push_debug_source_count(spans, &mut first, "missing", counts.missing);
    push_debug_source_count(spans, &mut first, "other", counts.other);
}

fn push_debug_source_count(
    spans: &mut Vec<Span<'static>>,
    first: &mut bool,
    label: &str,
    count: usize,
) {
    if count == 0 {
        return;
    }

    if !*first {
        spans.push(Span::styled("  ", Style::default().fg(Color::DarkGray)));
    }
    *first = false;

    spans.push(Span::styled(
        format!("{label}:{count}"),
        debug_source_style(label),
    ));
}

pub(crate) fn debug_source_style(source: &str) -> Style {
    Style::default().fg(match source {
        "embedded" => Color::Green,
        "explicit" => Color::Cyan,
        "debuglink" => Color::Blue,
        "debuginfod" => Color::Magenta,
        "missing" => Color::Yellow,
        _ => Color::DarkGray,
    })
}

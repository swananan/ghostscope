use ghostscope_dwarf::{DebugInfoSource, ModuleLoadingEvent};
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::time::{Duration, Instant};

const DEFAULT_RENDER_DELAY: Duration = Duration::from_millis(300);
const PROGRESS_BAR_WIDTH: usize = 20;
const SPINNER_FRAMES: [char; 4] = ['|', '/', '-', '\\'];
const MAX_MODULE_REPORT_LINES: usize = 32;
const SOURCE_COLUMN_WIDTH: usize = 44;
const SOURCE_NAME_MAX_WIDTH: usize = 32;

#[derive(Debug)]
pub struct CliLoadingReporter {
    enabled: bool,
    colors: crate::cli::color::CliColors,
    render_delay: Duration,
    progress: LoadingProgress,
    target_summary: Option<String>,
    last_render_width: usize,
    rendered_anything: bool,
}

impl CliLoadingReporter {
    pub fn new(
        console_stderr_logging_active: bool,
        color_mode: crate::config::CliColorMode,
        status_enabled: bool,
    ) -> Self {
        Self::new_with_enabled(
            should_enable_loading_reporter(
                console_stderr_logging_active,
                status_enabled,
                io::stderr().is_terminal(),
            ),
            crate::cli::color::CliColors::for_stderr(color_mode),
            DEFAULT_RENDER_DELAY,
        )
    }

    fn new_with_enabled(
        enabled: bool,
        colors: crate::cli::color::CliColors,
        render_delay: Duration,
    ) -> Self {
        Self {
            enabled,
            colors,
            render_delay,
            progress: LoadingProgress::new(),
            target_summary: None,
            last_render_width: 0,
            rendered_anything: false,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn handle_event(&mut self, event: ModuleLoadingEvent) {
        self.progress.apply_event(event);
    }

    pub fn set_target_summary(&mut self, summary: String) {
        self.target_summary = (!summary.is_empty()).then_some(summary);
    }

    pub fn render_tick(&mut self) {
        if !self.enabled || self.progress.total_modules == 0 {
            return;
        }

        if self.progress.start_time.elapsed() < self.render_delay {
            return;
        }

        self.render_line(&self.progress.status_line(&self.colors));
    }

    pub fn finish_success(&mut self) {
        if self.enabled {
            let lines = self
                .progress
                .success_report_lines(&self.colors, self.target_summary.as_deref());
            self.render_final_report(&lines);
        }
    }

    pub fn finish_failure(&mut self, error: &str) {
        if self.enabled {
            let lines = self.progress.failure_report_lines(
                &self.colors,
                self.target_summary.as_deref(),
                error,
            );
            self.render_final_report(&lines);
        }
    }

    fn render_line(&mut self, line: &str) {
        let padding = " ".repeat(self.last_render_width.saturating_sub(line.len()));
        eprint!("\r{line}{padding}");
        let _ = io::stderr().flush();
        self.last_render_width = line.len();
        self.rendered_anything = true;
    }

    fn render_final_line(&mut self, line: &str) {
        let padding = " ".repeat(self.last_render_width.saturating_sub(line.len()));
        eprint!("\r{line}{padding}\n");
        let _ = io::stderr().flush();
        self.last_render_width = 0;
        self.rendered_anything = false;
    }

    fn render_final_report(&mut self, lines: &[String]) {
        if let Some((first, rest)) = lines.split_first() {
            self.render_final_line(first);
            for line in rest {
                eprintln!("{line}");
            }
            let _ = io::stderr().flush();
        }
    }
}

fn should_enable_loading_reporter(
    console_stderr_logging_active: bool,
    status_enabled: bool,
    stderr_is_terminal: bool,
) -> bool {
    status_enabled && !console_stderr_logging_active && stderr_is_terminal
}

#[derive(Debug)]
struct LoadingProgress {
    start_time: Instant,
    total_modules: usize,
    completed_modules: usize,
    failed_modules: usize,
    current_module: Option<String>,
    debug_sources: DebugSourceCounts,
    module_reports: Vec<ModuleLoadReport>,
    module_failures: Vec<ModuleFailureReport>,
    functions: usize,
    variables: usize,
    types: usize,
}

impl LoadingProgress {
    fn new() -> Self {
        Self {
            start_time: Instant::now(),
            total_modules: 0,
            completed_modules: 0,
            failed_modules: 0,
            current_module: None,
            debug_sources: DebugSourceCounts::default(),
            module_reports: Vec::new(),
            module_failures: Vec::new(),
            functions: 0,
            variables: 0,
            types: 0,
        }
    }

    fn apply_event(&mut self, event: ModuleLoadingEvent) {
        match event {
            ModuleLoadingEvent::Discovered {
                module_path, total, ..
            } => {
                self.total_modules = total;
                if self.current_module.is_none() {
                    self.current_module = Some(module_path);
                }
            }
            ModuleLoadingEvent::LoadingStarted {
                module_path, total, ..
            } => {
                self.total_modules = total;
                self.current_module = Some(module_path);
            }
            ModuleLoadingEvent::LoadingCompleted {
                module_path,
                stats,
                total,
                ..
            } => {
                self.total_modules = total;
                self.completed_modules += 1;
                self.debug_sources.record(&stats.debug_info_source);
                self.functions += stats.functions;
                self.variables += stats.variables;
                self.types += stats.types;
                self.module_reports.push(ModuleLoadReport {
                    path: module_path.clone(),
                    source: stats.debug_info_source,
                    functions: stats.functions,
                    variables: stats.variables,
                    types: stats.types,
                    load_time_ms: stats.load_time_ms,
                });
                if self.current_module.as_deref() == Some(module_path.as_str()) {
                    self.current_module = None;
                }
            }
            ModuleLoadingEvent::LoadingFailed {
                module_path,
                error,
                total,
                ..
            } => {
                self.total_modules = total;
                self.failed_modules += 1;
                self.module_failures.push(ModuleFailureReport {
                    path: module_path.clone(),
                    error,
                });
                if self.current_module.as_deref() == Some(module_path.as_str()) {
                    self.current_module = None;
                }
            }
        }
    }

    fn status_line(&self, colors: &crate::cli::color::CliColors) -> String {
        let elapsed = self.start_time.elapsed();
        let spinner = SPINNER_FRAMES[(elapsed.as_millis() as usize / 120) % SPINNER_FRAMES.len()];
        let processed = self.completed_modules + self.failed_modules;
        let module_name = self
            .current_module
            .as_deref()
            .map(short_module_name)
            .unwrap_or_else(|| "discovering modules".to_string());

        let mut line = format!(
            "{} {} {} {processed}/{} | {} | {}",
            colors.cyan(spinner),
            colors.bold("Startup DWARF"),
            colors.blue(progress_bar(self.progress_ratio())),
            self.total_modules,
            colors.yellow(module_name),
            colors.dim(format_duration(elapsed)),
        );

        let source_summary = self.debug_sources.compact_summary();
        if !source_summary.is_empty() {
            line.push_str(&format!(
                " | {}",
                self.debug_sources.compact_summary_colored(colors)
            ));
        }

        if self.failed_modules > 0 {
            line.push_str(&format!(
                " | {}",
                colors.red(format!("{} failed", self.failed_modules))
            ));
        }

        line
    }

    fn success_report_lines(
        &self,
        colors: &crate::cli::color::CliColors,
        target_summary: Option<&str>,
    ) -> Vec<String> {
        let mut lines = vec![self.success_summary_line(colors, target_summary)];
        self.append_report_details(&mut lines, colors, target_summary);
        lines
    }

    fn failure_report_lines(
        &self,
        colors: &crate::cli::color::CliColors,
        target_summary: Option<&str>,
        error: &str,
    ) -> Vec<String> {
        let mut lines = vec![self.failure_summary_line(colors, error)];
        self.append_report_details(&mut lines, colors, target_summary);
        lines
    }

    fn append_report_details(
        &self,
        lines: &mut Vec<String>,
        colors: &crate::cli::color::CliColors,
        target_summary: Option<&str>,
    ) {
        lines.push("Startup load report:".to_string());
        if let Some(summary) = target_summary {
            lines.push(format!("  target: {summary}"));
        }

        let debug_summary = self.debug_sources.compact_summary();
        if !debug_summary.is_empty() {
            lines.push(format!(
                "  debug sources: {}",
                self.debug_sources.compact_summary_colored(colors)
            ));
        }

        let debuggable_modules = self.debuggable_module_reports();
        if !self.module_reports.is_empty() || !self.module_failures.is_empty() {
            lines.push(format!(
                "  modules loaded: {} completed, {} failed",
                self.completed_modules, self.failed_modules
            ));
            if !debuggable_modules.is_empty() {
                lines.push("  module details:".to_string());
                for module in debuggable_modules.iter().take(MAX_MODULE_REPORT_LINES) {
                    lines.push(format!(
                        "    {} {:>6} funcs {:>6} vars {:>6} types {:>5}ms  {}",
                        format_source_column(&module.source, colors),
                        module.functions,
                        module.variables,
                        module.types,
                        module.load_time_ms,
                        shorten_path(&module.path, 88),
                    ));
                }
                if debuggable_modules.len() > MAX_MODULE_REPORT_LINES {
                    lines.push(format!(
                        "    ... {} more module(s) omitted",
                        debuggable_modules.len() - MAX_MODULE_REPORT_LINES
                    ));
                }
            }
        }

        if self.debug_sources.missing > 0 {
            lines.push(format!(
                "  {} {}",
                colors.yellow("missing DWARF:"),
                self.missing_module_hint()
            ));
        }

        if !self.module_failures.is_empty() {
            lines.push("  module failures:".to_string());
            for failure in self.module_failures.iter().take(MAX_MODULE_REPORT_LINES) {
                lines.push(format!(
                    "    {} {:<88} {}",
                    colors.red("failed"),
                    shorten_path(&failure.path, 88),
                    failure.error
                ));
            }
            if self.module_failures.len() > MAX_MODULE_REPORT_LINES {
                lines.push(format!(
                    "    ... {} more failure(s) omitted",
                    self.module_failures.len() - MAX_MODULE_REPORT_LINES
                ));
            }
        }
    }

    fn debuggable_module_reports(&self) -> Vec<&ModuleLoadReport> {
        self.module_reports
            .iter()
            .filter(|module| !matches!(module.source, DebugInfoSource::Missing))
            .collect()
    }

    fn missing_module_hint(&self) -> String {
        let missing_modules: Vec<_> = self
            .module_reports
            .iter()
            .filter(|module| matches!(module.source, DebugInfoSource::Missing))
            .collect();

        let count = missing_modules.len();
        if count == 0 {
            return "0 modules".to_string();
        }

        let examples: Vec<String> = missing_modules
            .iter()
            .take(3)
            .map(|module| short_module_name(&module.path))
            .collect();

        let mut message = format!("{count} module{}", if count == 1 { "" } else { "s" });
        if !examples.is_empty() {
            message.push_str(&format!(" ({})", examples.join(", ")));
            if count > examples.len() {
                message.push_str(&format!(" +{} more", count - examples.len()));
            }
        }
        message.push_str("; use --log --log-level debug --log-file <path> for full paths");
        message
    }

    fn success_summary_line(
        &self,
        colors: &crate::cli::color::CliColors,
        target_summary: Option<&str>,
    ) -> String {
        let mut line = format!(
            "{} {} module{}, {} functions, {} variables, {} types, {}, {}",
            colors.green("DWARF ready:"),
            self.completed_modules,
            if self.completed_modules == 1 { "" } else { "s" },
            self.functions,
            self.variables,
            self.types,
            self.debug_sources.summary_for_sentence(colors),
            colors.dim(format_duration(self.start_time.elapsed())),
        );
        if let Some(summary) = target_summary {
            line.push_str(&format!(" | {}", colors.dim(summary)));
        }
        line
    }

    fn failure_summary_line(&self, colors: &crate::cli::color::CliColors, error: &str) -> String {
        format!(
            "{} {}: {}",
            colors.red("DWARF loading failed after"),
            colors.dim(format_duration(self.start_time.elapsed())),
            error
        )
    }

    fn progress_ratio(&self) -> f64 {
        if self.total_modules == 0 {
            0.0
        } else {
            (self.completed_modules + self.failed_modules) as f64 / self.total_modules as f64
        }
    }
}

#[derive(Debug)]
struct ModuleLoadReport {
    path: String,
    source: DebugInfoSource,
    functions: usize,
    variables: usize,
    types: usize,
    load_time_ms: u64,
}

#[derive(Debug)]
struct ModuleFailureReport {
    path: String,
    error: String,
}

#[derive(Debug, Default)]
struct DebugSourceCounts {
    embedded: usize,
    explicit: usize,
    debuglink: usize,
    debuginfod: usize,
    missing: usize,
}

impl DebugSourceCounts {
    fn record(&mut self, source: &DebugInfoSource) {
        match source {
            DebugInfoSource::Embedded { .. } => self.embedded += 1,
            DebugInfoSource::Explicit { .. } => self.explicit += 1,
            DebugInfoSource::Debuglink { .. } => self.debuglink += 1,
            DebugInfoSource::Debuginfod { .. } => self.debuginfod += 1,
            DebugInfoSource::Missing => self.missing += 1,
        }
    }

    fn compact_summary(&self) -> String {
        let mut parts = Vec::new();
        self.push_nonzero(&mut parts, "embedded", self.embedded);
        self.push_nonzero(&mut parts, "explicit", self.explicit);
        self.push_nonzero(&mut parts, "debuglink", self.debuglink);
        self.push_nonzero(&mut parts, "debuginfod", self.debuginfod);
        self.push_nonzero(&mut parts, "missing", self.missing);
        parts.join(" ")
    }

    fn compact_summary_colored(&self, colors: &crate::cli::color::CliColors) -> String {
        let mut parts = Vec::new();
        self.push_nonzero_colored(&mut parts, "embedded", self.embedded, colors);
        self.push_nonzero_colored(&mut parts, "explicit", self.explicit, colors);
        self.push_nonzero_colored(&mut parts, "debuglink", self.debuglink, colors);
        self.push_nonzero_colored(&mut parts, "debuginfod", self.debuginfod, colors);
        self.push_nonzero_colored(&mut parts, "missing", self.missing, colors);
        parts.join(" ")
    }

    fn summary_for_sentence(&self, colors: &crate::cli::color::CliColors) -> String {
        let summary = self.compact_summary();
        if summary.is_empty() {
            "debug sources unknown".to_string()
        } else {
            format!("debug: {}", self.compact_summary_colored(colors))
        }
    }

    fn push_nonzero(&self, parts: &mut Vec<String>, label: &str, count: usize) {
        if count > 0 {
            parts.push(format!("{label}:{count}"));
        }
    }

    fn push_nonzero_colored(
        &self,
        parts: &mut Vec<String>,
        label: &str,
        count: usize,
        colors: &crate::cli::color::CliColors,
    ) {
        if count > 0 {
            parts.push(color_debug_source_label(
                format!("{label}:{count}"),
                label,
                colors,
            ));
        }
    }
}

fn progress_bar(ratio: f64) -> String {
    let filled = ((ratio.clamp(0.0, 1.0)) * PROGRESS_BAR_WIDTH as f64).round() as usize;
    let filled = filled.min(PROGRESS_BAR_WIDTH);
    format!(
        "[{}{}]",
        "=".repeat(filled),
        " ".repeat(PROGRESS_BAR_WIDTH - filled)
    )
}

fn short_module_name(path: &str) -> String {
    let display = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path);

    const MAX_WIDTH: usize = 32;
    shorten_middle(display, MAX_WIDTH)
}

fn format_source_column(source: &DebugInfoSource, colors: &crate::cli::color::CliColors) -> String {
    let label = source.kind_label();
    let suffix = source
        .display_path()
        .map(|path| format!(" {}", source_file_name(path)))
        .unwrap_or_default();
    let plain_width = label.chars().count() + suffix.chars().count();
    let padding = " ".repeat(SOURCE_COLUMN_WIDTH.saturating_sub(plain_width));
    let suffix = if suffix.is_empty() {
        suffix
    } else {
        colors.dim(suffix)
    };
    format!(
        "{}{}{}",
        color_debug_source_label(label, label, colors),
        suffix,
        padding
    )
}

fn source_file_name(path: &str) -> String {
    let display = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(path);
    shorten_middle(display, SOURCE_NAME_MAX_WIDTH)
}

fn color_debug_source_label<T: std::fmt::Display>(
    value: T,
    label: &str,
    colors: &crate::cli::color::CliColors,
) -> String {
    match label {
        "embedded" => colors.green(value),
        "explicit" => colors.cyan(value),
        "debuglink" => colors.blue(value),
        "debuginfod" => colors.magenta(value),
        "missing" => colors.yellow(value),
        _ => colors.dim(value),
    }
}

fn shorten_path(path: &str, max_width: usize) -> String {
    let width = path.chars().count();
    if width <= max_width {
        return path.to_string();
    }

    if max_width <= 3 {
        return ".".repeat(max_width);
    }

    let suffix: String = path.chars().skip(width - (max_width - 3)).collect();
    format!("...{suffix}")
}

fn shorten_middle(value: &str, max_width: usize) -> String {
    let width = value.chars().count();
    if width <= max_width {
        return value.to_string();
    }

    if max_width <= 3 {
        return ".".repeat(max_width);
    }

    let prefix_width = (max_width - 3) / 2;
    let suffix_width = max_width - 3 - prefix_width;
    let prefix: String = value.chars().take(prefix_width).collect();
    let suffix: String = value.chars().skip(width - suffix_width).collect();
    format!("{prefix}...{suffix}")
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs_f64();
    if seconds < 60.0 {
        format!("{seconds:.1}s")
    } else {
        let minutes = duration.as_secs() / 60;
        let remaining_seconds = seconds - (minutes as f64) * 60.0;
        format!("{minutes}m{remaining_seconds:.1}s")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        format_source_column, progress_bar, short_module_name, should_enable_loading_reporter,
        CliLoadingReporter, DebugSourceCounts,
    };
    use crate::config::CliColorMode;
    use ghostscope_dwarf::{DebugInfoSource, ModuleLoadingEvent, ModuleLoadingStats};
    use std::time::Duration;

    #[test]
    fn progress_bar_uses_completed_ratio() {
        assert_eq!(progress_bar(0.0), "[                    ]");
        assert_eq!(progress_bar(0.5), "[==========          ]");
        assert_eq!(progress_bar(1.0), "[====================]");
    }

    #[test]
    fn short_module_name_prefers_file_name() {
        assert_eq!(short_module_name("/usr/lib/libc.so.6"), "libc.so.6");
    }

    #[test]
    fn short_module_name_truncates_utf8_on_char_boundaries() {
        let display = "模块名字模块名字模块名字模块名字模块名字模块名字模块名字模块名字模块名字.so";
        let shortened = short_module_name(&format!("/tmp/{display}"));
        let expected_prefix: String = display.chars().take(14).collect();
        let expected_suffix: String = display.chars().skip(display.chars().count() - 15).collect();

        assert_eq!(shortened, format!("{expected_prefix}...{expected_suffix}"));
        assert_eq!(shortened.chars().count(), 32);
    }

    #[test]
    fn reporter_accumulates_module_stats() {
        let mut reporter = CliLoadingReporter::new_with_enabled(
            false,
            crate::cli::color::CliColors::new(false),
            Duration::ZERO,
        );
        reporter.handle_event(ModuleLoadingEvent::Discovered {
            module_path: "/usr/bin/app".to_string(),
            current: 1,
            total: 2,
        });
        reporter.handle_event(ModuleLoadingEvent::LoadingStarted {
            module_path: "/usr/bin/app".to_string(),
            current: 1,
            total: 2,
        });
        reporter.handle_event(ModuleLoadingEvent::LoadingCompleted {
            module_path: "/usr/bin/app".to_string(),
            stats: ModuleLoadingStats {
                functions: 12,
                variables: 3,
                types: 7,
                debug_info_source: DebugInfoSource::Embedded {
                    path: "/usr/bin/app".to_string(),
                },
                load_time_ms: 42,
                parse_time_ms: 30,
                index_time_ms: 8,
                module_total_time_ms: 40,
            },
            current: 1,
            total: 2,
        });

        let status = reporter.progress.status_line(&reporter.colors);
        let summary = reporter
            .progress
            .success_summary_line(&reporter.colors, Some("pid=123"));
        let report = reporter
            .progress
            .success_report_lines(&reporter.colors, Some("pid=123"))
            .join("\n");

        assert!(status.contains("1/2"));
        assert!(summary.contains("12 functions"));
        assert!(summary.contains("3 variables"));
        assert!(summary.contains("7 types"));
        assert!(summary.contains("debug: embedded:1"));
        assert!(summary.contains("pid=123"));
        assert!(report.contains("Startup load report:"));
        assert!(report.contains("module details:"));
        assert!(report.contains("embedded"));
        assert!(report.contains("/usr/bin/app"));
    }

    #[test]
    fn reporter_summarizes_missing_modules_without_details_by_default() {
        let mut reporter = CliLoadingReporter::new_with_enabled(
            false,
            crate::cli::color::CliColors::new(false),
            Duration::ZERO,
        );
        reporter.handle_event(ModuleLoadingEvent::LoadingCompleted {
            module_path: "/lib/libmissing.so".to_string(),
            stats: ModuleLoadingStats {
                functions: 0,
                variables: 0,
                types: 0,
                debug_info_source: DebugInfoSource::Missing,
                load_time_ms: 5,
                parse_time_ms: 0,
                index_time_ms: 0,
                module_total_time_ms: 5,
            },
            current: 1,
            total: 1,
        });

        let report = reporter
            .progress
            .success_report_lines(&reporter.colors, Some("pid=123"))
            .join("\n");

        assert!(report.contains("missing DWARF: 1 module"));
        assert!(report.contains("libmissing.so"));
        assert!(!report.contains("module details:"));
        assert!(!report.contains("missing                           0 funcs"));
    }

    #[test]
    fn reporter_includes_module_failures_on_failure_report() {
        let mut reporter = CliLoadingReporter::new_with_enabled(
            false,
            crate::cli::color::CliColors::new(false),
            Duration::ZERO,
        );
        reporter.handle_event(ModuleLoadingEvent::LoadingFailed {
            module_path: "/tmp/debug-source-fixture".to_string(),
            error: "failed to parse debug file /tmp/bad.debug".to_string(),
            current: 1,
            total: 1,
        });

        let report = reporter
            .progress
            .failure_report_lines(
                &reporter.colors,
                Some("target=/tmp/debug-source-fixture debug_file=/tmp/bad.debug"),
                "Failed to create debug session",
            )
            .join("\n");

        assert!(report.contains("DWARF loading failed after"));
        assert!(report.contains("Startup load report:"));
        assert!(report.contains("modules loaded: 0 completed, 1 failed"));
        assert!(report.contains("module failures:"));
        assert!(report.contains("/tmp/debug-source-fixture"));
        assert!(report.contains("failed to parse debug file"));
    }

    #[test]
    fn reporter_colors_module_failure_label() {
        let mut reporter = CliLoadingReporter::new_with_enabled(
            false,
            crate::cli::color::CliColors::new(true),
            Duration::ZERO,
        );
        reporter.handle_event(ModuleLoadingEvent::LoadingFailed {
            module_path: "/tmp/debug-source-fixture".to_string(),
            error: "failed to parse debug file /tmp/bad.debug".to_string(),
            current: 1,
            total: 1,
        });

        let report = reporter
            .progress
            .failure_report_lines(
                &reporter.colors,
                Some("target=/tmp/debug-source-fixture debug_file=/tmp/bad.debug"),
                "Failed to create debug session",
            )
            .join("\n");

        assert!(report.contains("\u{1b}[31mfailed\u{1b}[0m"));
    }

    #[test]
    fn reporter_colors_debug_source_labels() {
        let colors = crate::cli::color::CliColors::new(true);
        let mut counts = DebugSourceCounts::default();
        counts.record(&DebugInfoSource::Embedded {
            path: "/usr/bin/app".to_string(),
        });
        counts.record(&DebugInfoSource::Missing);

        let summary = counts.compact_summary_colored(&colors);
        assert!(summary.contains("\u{1b}[32membedded:1\u{1b}[0m"));
        assert!(summary.contains("\u{1b}[33mmissing:1\u{1b}[0m"));

        let column = format_source_column(
            &DebugInfoSource::Embedded {
                path: "/usr/bin/app".to_string(),
            },
            &colors,
        );
        assert!(column.contains("\u{1b}[32membedded\u{1b}[0m"));
        assert!(column.contains("app"));
    }

    #[test]
    fn reporter_source_column_uses_file_name_without_leading_ellipsis() {
        let colors = crate::cli::color::CliColors::new(false);
        let column = format_source_column(
            &DebugInfoSource::Embedded {
                path: "/usr/local/openresty/luajit/lib/libluajit-5.1.so.2.1.ROLLING".to_string(),
            },
            &colors,
        );

        assert!(column.contains("embedded libluajit-5.1.so.2.1.ROLLING"));
        assert!(!column.contains("...."));
    }

    #[test]
    fn reporter_accepts_color_mode() {
        let reporter = CliLoadingReporter::new(false, CliColorMode::Never, true);
        assert!(!reporter.colors.enabled());
    }

    #[test]
    fn status_enabled_keeps_interactive_loading_reporter_enabled_on_tty() {
        assert!(should_enable_loading_reporter(false, true, true));
    }

    #[test]
    fn disabled_status_turns_off_interactive_loading_reporter() {
        assert!(!should_enable_loading_reporter(false, false, true));
    }
}

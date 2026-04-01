use ghostscope_dwarf::ModuleLoadingEvent;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::time::{Duration, Instant};

const DEFAULT_RENDER_DELAY: Duration = Duration::from_millis(300);
const PROGRESS_BAR_WIDTH: usize = 20;
const SPINNER_FRAMES: [char; 4] = ['|', '/', '-', '\\'];

#[derive(Debug)]
pub struct CliLoadingReporter {
    enabled: bool,
    render_delay: Duration,
    progress: LoadingProgress,
    last_render_width: usize,
    rendered_anything: bool,
}

impl CliLoadingReporter {
    pub fn new(enable_console_logging: bool) -> Self {
        Self::new_with_enabled(
            !enable_console_logging && io::stderr().is_terminal(),
            DEFAULT_RENDER_DELAY,
        )
    }

    fn new_with_enabled(enabled: bool, render_delay: Duration) -> Self {
        Self {
            enabled,
            render_delay,
            progress: LoadingProgress::new(),
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

    pub fn render_tick(&mut self) {
        if !self.enabled || self.progress.total_modules == 0 {
            return;
        }

        if self.progress.start_time.elapsed() < self.render_delay {
            return;
        }

        self.render_line(&self.progress.status_line());
    }

    pub fn finish_success(&mut self) {
        if self.rendered_anything {
            self.render_final_line(&self.progress.success_summary_line());
        }
    }

    pub fn finish_failure(&mut self, error: &str) {
        if self.rendered_anything {
            self.render_final_line(&self.progress.failure_summary_line(error));
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
}

#[derive(Debug)]
struct LoadingProgress {
    start_time: Instant,
    total_modules: usize,
    completed_modules: usize,
    failed_modules: usize,
    current_module: Option<String>,
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
                self.functions += stats.functions;
                self.variables += stats.variables;
                self.types += stats.types;
                if self.current_module.as_deref() == Some(module_path.as_str()) {
                    self.current_module = None;
                }
            }
            ModuleLoadingEvent::LoadingFailed {
                module_path, total, ..
            } => {
                self.total_modules = total;
                self.failed_modules += 1;
                if self.current_module.as_deref() == Some(module_path.as_str()) {
                    self.current_module = None;
                }
            }
        }
    }

    fn status_line(&self) -> String {
        let elapsed = self.start_time.elapsed();
        let spinner = SPINNER_FRAMES[(elapsed.as_millis() as usize / 120) % SPINNER_FRAMES.len()];
        let processed = self.completed_modules + self.failed_modules;
        let module_name = self
            .current_module
            .as_deref()
            .map(short_module_name)
            .unwrap_or_else(|| "discovering modules".to_string());

        let mut line = format!(
            "{spinner} Loading DWARF {} {processed}/{} | {} | {}",
            progress_bar(self.progress_ratio()),
            self.total_modules,
            module_name,
            format_duration(elapsed),
        );

        if self.failed_modules > 0 {
            line.push_str(&format!(" | {} failed", self.failed_modules));
        }

        line
    }

    fn success_summary_line(&self) -> String {
        format!(
            "DWARF ready: {} module{}, {} functions, {} variables, {} types, {}",
            self.completed_modules,
            if self.completed_modules == 1 { "" } else { "s" },
            self.functions,
            self.variables,
            self.types,
            format_duration(self.start_time.elapsed()),
        )
    }

    fn failure_summary_line(&self, error: &str) -> String {
        format!(
            "DWARF loading failed after {}: {}",
            format_duration(self.start_time.elapsed()),
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
    if display.len() <= MAX_WIDTH {
        display.to_string()
    } else {
        format!("...{}", &display[display.len() - (MAX_WIDTH - 3)..])
    }
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
    use super::{progress_bar, short_module_name, CliLoadingReporter};
    use ghostscope_dwarf::{ModuleLoadingEvent, ModuleLoadingStats};
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
    fn reporter_accumulates_module_stats() {
        let mut reporter = CliLoadingReporter::new_with_enabled(false, Duration::ZERO);
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
                load_time_ms: 42,
            },
            current: 1,
            total: 2,
        });

        let status = reporter.progress.status_line();
        let summary = reporter.progress.success_summary_line();

        assert!(status.contains("1/2"));
        assert!(summary.contains("12 functions"));
        assert!(summary.contains("3 variables"));
        assert!(summary.contains("7 types"));
    }
}

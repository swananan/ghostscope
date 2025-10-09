use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

use crate::config::LayoutMode;

/// Panel type enumeration for configuration
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize, Default)]
pub enum PanelType {
    Source,
    EbpfInfo,
    #[default]
    InteractiveCommand,
}

/// Log level enumeration for configuration
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    #[default]
    Warn,
    Info,
    Debug,
    Trace,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Error => write!(f, "error"),
            LogLevel::Warn => write!(f, "warn"),
            LogLevel::Info => write!(f, "info"),
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Trace => write!(f, "trace"),
        }
    }
}

impl LogLevel {
    /// Convert to tracing level filter
    pub fn to_tracing_level_filter(self) -> tracing::level_filters::LevelFilter {
        match self {
            LogLevel::Error => tracing::level_filters::LevelFilter::ERROR,
            LogLevel::Warn => tracing::level_filters::LevelFilter::WARN,
            LogLevel::Info => tracing::level_filters::LevelFilter::INFO,
            LogLevel::Debug => tracing::level_filters::LevelFilter::DEBUG,
            LogLevel::Trace => tracing::level_filters::LevelFilter::TRACE,
        }
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "error" => Ok(LogLevel::Error),
            "warn" => Ok(LogLevel::Warn),
            "info" => Ok(LogLevel::Info),
            "debug" => Ok(LogLevel::Debug),
            "trace" => Ok(LogLevel::Trace),
            _ => Err(anyhow::anyhow!(
                "Invalid log level: {}. Valid options: error, warn, info, debug, trace",
                s
            )),
        }
    }
}

/// Main configuration structure loaded from TOML files
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub general: GeneralConfig,
    #[serde(default)]
    pub dwarf: DwarfConfig,
    #[serde(default)]
    pub files: FilesConfig,
    #[serde(default)]
    pub ui: UiConfigToml,
    #[serde(default)]
    pub ebpf: EbpfConfig,
    #[serde(default)]
    pub source: SourceConfig,

    /// Path to the config file that was loaded (not serialized)
    #[serde(skip)]
    pub loaded_from: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GeneralConfig {
    /// Default log file path (overridden by --log-file)
    #[serde(default = "default_log_file")]
    pub log_file: String,
    /// Default UI mode when no script is provided (overridden by --tui)
    #[serde(default = "default_tui_mode")]
    pub default_tui_mode: bool,
    /// Enable/disable file logging (overridden by --log/--no-log)
    #[serde(default = "default_enable_logging")]
    pub enable_logging: bool,
    /// Enable/disable console logging (overridden by --log-console/--no-log-console)
    #[serde(default = "default_enable_console_logging")]
    pub enable_console_logging: bool,
    /// Log level filter
    /// Priority: 1. Command line args, 2. RUST_LOG env var, 3. Config file (default: warn)
    #[serde(default)]
    pub log_level: LogLevel,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DwarfConfig {
    /// DWARF debug information search paths (for future --debug-file auto-discovery)
    #[serde(default = "default_debug_search_paths")]
    pub search_paths: Vec<String>,
    /// Allow non-strict matching of separate debug files (CRC/Build-ID)
    /// Default: false (strict). When true, CRC/Build-ID mismatches are allowed with WARN logs.
    #[serde(default)]
    pub allow_loose_debug_match: bool,
}

/// Source code path configuration
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SourceConfig {
    /// Path substitution rules (highest priority)
    /// Replaces compilation-time path prefix with runtime path
    #[serde(default)]
    pub substitutions: Vec<PathSubstitution>,

    /// Additional search directories (fallback)
    /// When file not found via substitution, search these dirs by basename
    #[serde(default)]
    pub search_dirs: Vec<String>,
}

/// Path substitution rule for source code location
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct PathSubstitution {
    /// Compilation-time path prefix
    pub from: String,
    /// Runtime path prefix
    pub to: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EbpfConfig {
    /// RingBuf map size in bytes (must be power of 2)
    /// Recommended values:
    ///   - Low-frequency tracing: 131072 (128KB)
    ///   - Medium-frequency tracing: 262144 (256KB, default)
    ///   - High-frequency tracing: 524288 (512KB) or 1048576 (1MB)
    #[serde(default = "default_ringbuf_size")]
    pub ringbuf_size: u64,
    /// PerfEventArray page count (must be power of 2, fallback when RingBuf not supported)
    /// Recommended values:
    ///   - Low-frequency tracing: 32 pages (~128KB per CPU)
    ///   - Medium-frequency tracing: 64 pages (~256KB per CPU, default)
    ///   - High-frequency tracing: 128-256 pages (512KB-1MB per CPU)
    #[serde(default = "default_perf_page_count")]
    pub perf_page_count: u32,
    /// Maximum number of (pid, module) offset entries for ASLR translation
    /// Recommended values:
    ///   - Single process: 1024
    ///   - Multi-process (default): 4096
    ///   - System-wide tracing: 8192 or 16384
    #[serde(default = "default_proc_module_offsets_max_entries")]
    pub proc_module_offsets_max_entries: u64,
    /// Force use of PerfEventArray instead of RingBuf (for testing only)
    /// WARNING: This is for testing purposes only. Set to true to force PerfEventArray
    /// even on kernels that support RingBuf.
    #[serde(default = "default_force_perf_event_array")]
    pub force_perf_event_array: bool,
    /// Per-argument memory dump cap for extended format specifiers ({:x}/{:s})
    /// Default: 1024 bytes; increase for larger previews.
    #[serde(default = "default_mem_dump_cap")]
    pub mem_dump_cap: u32,
    /// Max bytes compared by builtins (strncmp/starts_with/memcmp)
    /// Default: 64 bytes
    #[serde(default = "default_compare_cap")]
    pub compare_cap: u32,
    /// Maximum size of a single trace event (bytes). Applies to PerfEventArray accumulation buffer.
    /// Default: 32768 bytes (32KB). Increase for larger formatted prints.
    #[serde(default = "default_max_trace_event_size")]
    pub max_trace_event_size: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilesConfig {
    /// Save LLVM IR files (overridden by --save-llvm-ir/--no-save-llvm-ir)
    #[serde(default = "default_save_option")]
    pub save_llvm_ir: SaveOption,
    /// Save eBPF bytecode files (overridden by --save-ebpf/--no-save-ebpf)
    #[serde(default = "default_save_option")]
    pub save_ebpf: SaveOption,
    /// Save AST files (overridden by --save-ast/--no-save-ast)
    #[serde(default = "default_save_option")]
    pub save_ast: SaveOption,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UiConfigToml {
    /// TUI layout mode (overridden by --layout)
    #[serde(default = "default_layout")]
    pub layout: LayoutMode,
    /// Default focused panel when TUI starts
    #[serde(default)]
    pub default_focus: PanelType,
    /// Panel size ratios [Source, EbpfInfo, InteractiveCommand]
    #[serde(default = "default_panel_ratios")]
    pub panel_ratios: [u16; 3],
    /// Command history configuration
    #[serde(default)]
    pub history: HistoryConfigToml,
    /// Maximum number of eBPF trace messages to keep in the output panel
    #[serde(default = "default_ebpf_max_messages")]
    pub ebpf_max_messages: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HistoryConfigToml {
    /// Enable/disable command history file functionality
    #[serde(default = "default_history_enabled")]
    pub enabled: bool,
    /// Maximum number of history entries to keep
    #[serde(default = "default_history_max_entries")]
    pub max_entries: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SaveOption {
    /// Save files in debug builds
    #[serde(default = "default_debug_save")]
    pub debug: bool,
    /// Save files in release builds
    #[serde(default = "default_release_save")]
    pub release: bool,
}

// Default value functions
fn default_log_file() -> String {
    "ghostscope.log".to_string()
}

fn default_tui_mode() -> bool {
    true
}

fn default_enable_logging() -> bool {
    false // Script mode should default to no logging
}

fn default_enable_console_logging() -> bool {
    false // Console logging disabled by default for cleaner output
}

fn default_debug_search_paths() -> Vec<String> {
    vec![
        "/usr/lib/debug".to_string(),
        "/usr/local/lib/debug".to_string(),
    ]
}

fn default_ringbuf_size() -> u64 {
    262144 // 256KB
}

fn default_perf_page_count() -> u32 {
    64 // 64 pages = ~256KB per CPU
}

fn default_proc_module_offsets_max_entries() -> u64 {
    4096
}

fn default_force_perf_event_array() -> bool {
    false
}

fn default_mem_dump_cap() -> u32 {
    4096
}

fn default_max_trace_event_size() -> u32 {
    32768
}

fn default_compare_cap() -> u32 {
    64
}

fn default_save_option() -> SaveOption {
    SaveOption {
        debug: true,
        release: false,
    }
}

fn default_layout() -> LayoutMode {
    LayoutMode::Horizontal
}

fn default_debug_save() -> bool {
    true
}

fn default_release_save() -> bool {
    false
}

fn default_panel_ratios() -> [u16; 3] {
    [4, 3, 3] // Source, EbpfInfo, InteractiveCommand
}

fn default_history_enabled() -> bool {
    true
}

fn default_history_max_entries() -> usize {
    5000
}

fn default_ebpf_max_messages() -> usize {
    2000
}

// Default implementations for each config section
impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            log_file: default_log_file(),
            default_tui_mode: default_tui_mode(),
            enable_logging: default_enable_logging(),
            enable_console_logging: default_enable_console_logging(),
            log_level: LogLevel::default(),
        }
    }
}

impl Default for DwarfConfig {
    fn default() -> Self {
        Self {
            search_paths: default_debug_search_paths(),
            allow_loose_debug_match: false,
        }
    }
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            ringbuf_size: default_ringbuf_size(),
            perf_page_count: default_perf_page_count(),
            proc_module_offsets_max_entries: default_proc_module_offsets_max_entries(),
            force_perf_event_array: default_force_perf_event_array(),
            mem_dump_cap: default_mem_dump_cap(),
            compare_cap: default_compare_cap(),
            max_trace_event_size: default_max_trace_event_size(),
        }
    }
}

impl EbpfConfig {
    /// Validate eBPF configuration values
    pub fn validate(&self, file_path: &str) -> Result<()> {
        // Validate ringbuf_size is power of 2
        if !self.ringbuf_size.is_power_of_two() {
            return Err(anyhow::anyhow!(
                "❌ Invalid eBPF configuration in '{}':\n\n\
                ringbuf_size must be a power of 2, got {}\n\n\
                💡 Fix: Use a power of 2 value (e.g., 131072, 262144, 524288, 1048576)\n\
                Recommended values:\n\
                  - Low-frequency tracing: 131072 (128KB)\n\
                  - Medium-frequency tracing: 262144 (256KB, default)\n\
                  - High-frequency tracing: 524288 (512KB) or 1048576 (1MB)",
                file_path,
                self.ringbuf_size
            ));
        }

        // Validate ringbuf_size is reasonable (between 4KB and 16MB)
        if self.ringbuf_size < 4096 || self.ringbuf_size > 16 * 1024 * 1024 {
            return Err(anyhow::anyhow!(
                "❌ Invalid eBPF configuration in '{}':\n\n\
                ringbuf_size {} is out of reasonable range\n\n\
                💡 Valid range: 4096 (4KB) to 16777216 (16MB)\n\
                Recommended: 262144 (256KB)",
                file_path,
                self.ringbuf_size
            ));
        }

        // Validate perf_page_count is power of 2
        if !self.perf_page_count.is_power_of_two() {
            return Err(anyhow::anyhow!(
                "❌ Invalid eBPF configuration in '{}':\n\n\
                perf_page_count must be a power of 2, got {}\n\n\
                💡 Fix: Use a power of 2 value (e.g., 32, 64, 128, 256)\n\
                Recommended values:\n\
                  - Low-frequency tracing: 32 pages (~128KB per CPU)\n\
                  - Medium-frequency tracing: 64 pages (~256KB per CPU, default)\n\
                  - High-frequency tracing: 128-256 pages (512KB-1MB per CPU)",
                file_path,
                self.perf_page_count
            ));
        }

        // Validate perf_page_count is reasonable (between 8 and 1024)
        if self.perf_page_count < 8 || self.perf_page_count > 1024 {
            return Err(anyhow::anyhow!(
                "❌ Invalid eBPF configuration in '{}':\n\n\
                perf_page_count {} is out of reasonable range\n\n\
                💡 Valid range: 8 to 1024 pages\n\
                Recommended: 64 pages (~256KB per CPU)",
                file_path,
                self.perf_page_count
            ));
        }

        // Validate proc_module_offsets_max_entries is reasonable (at least 64, at most 65536)
        if self.proc_module_offsets_max_entries < 64 || self.proc_module_offsets_max_entries > 65536
        {
            return Err(anyhow::anyhow!(
                "❌ Invalid eBPF configuration in '{}':\n\n\
                proc_module_offsets_max_entries {} is out of reasonable range\n\n\
                💡 Valid range: 64 to 65536\n\
                Recommended values:\n\
                  - Single process: 1024\n\
                  - Multi-process: 4096 (default)\n\
                  - System-wide: 8192 or 16384",
                file_path,
                self.proc_module_offsets_max_entries
            ));
        }

        Ok(())
    }
}

impl Default for FilesConfig {
    fn default() -> Self {
        Self {
            save_llvm_ir: default_save_option(),
            save_ebpf: default_save_option(),
            save_ast: default_save_option(),
        }
    }
}

impl Default for UiConfigToml {
    fn default() -> Self {
        Self {
            layout: default_layout(),
            default_focus: PanelType::default(),
            panel_ratios: default_panel_ratios(),
            history: HistoryConfigToml::default(),
            ebpf_max_messages: default_ebpf_max_messages(),
        }
    }
}

impl UiConfigToml {
    /// Validate UI configuration values
    pub fn validate(&self, file_path: &str) -> Result<()> {
        // Validate ebpf_max_messages is reasonable (at least 100)
        if self.ebpf_max_messages < 100 {
            return Err(anyhow::anyhow!(
                "❌ Invalid UI configuration in '{}':\n\n\
                ebpf_max_messages {} is too small\n\n\
                💡 Minimum value: 100\n\
                Recommended values:\n\
                  - Low-frequency tracing: 1000-2000\n\
                  - Medium-frequency tracing: 2000-5000 (default: 2000)\n\
                  - High-frequency tracing: 5000-10000\n\
                Note: Larger values consume more memory",
                file_path,
                self.ebpf_max_messages
            ));
        }

        Ok(())
    }
}

impl Default for HistoryConfigToml {
    fn default() -> Self {
        Self {
            enabled: default_history_enabled(),
            max_entries: default_history_max_entries(),
        }
    }
}

impl Default for SaveOption {
    fn default() -> Self {
        SaveOption {
            debug: default_debug_save(),
            release: default_release_save(),
        }
    }
}

impl Config {
    /// Load configuration from files with fallback search
    pub fn load() -> Result<Self> {
        let config_paths = Self::get_config_search_paths();

        for path in &config_paths {
            if path.exists() {
                info!("Loading configuration from: {}", path.display());
                let mut config = Self::load_from_file(path)?;
                config.loaded_from = Some(path.clone());
                return Ok(config);
            } else {
                debug!("Configuration file not found: {}", path.display());
            }
        }

        info!("No configuration file found, using default settings");
        Ok(Self::default())
    }

    /// Load configuration from a specific file path
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = fs::read_to_string(path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to read configuration file '{}': {}",
                path.display(),
                e
            )
        })?;

        // Pre-validate TOML content before parsing
        Self::validate_toml_content(&content, &path.display().to_string())?;

        let config: Config = toml::from_str(&content).map_err(|e| {
            Self::create_friendly_toml_error(&path.display().to_string(), &content, e)
        })?;

        // Validate eBPF configuration
        config.ebpf.validate(&path.display().to_string())?;

        // Validate UI configuration
        config.ui.validate(&path.display().to_string())?;

        Ok(config)
    }

    /// Validate TOML content before parsing
    fn validate_toml_content(content: &str, file_path: &str) -> Result<()> {
        // Look for panel_ratios line and validate it
        if let Some(panel_ratios_line) = content.lines().find(|line| {
            let trimmed = line.trim();
            trimmed.starts_with("panel_ratios") && trimmed.contains('=')
        }) {
            // Extract the array part after the '='
            if let Some(array_part) = panel_ratios_line.split('=').nth(1) {
                let array_str = array_part.trim();

                // Check if it looks like an array with zeros
                if array_str.starts_with('[') && array_str.ends_with(']') {
                    let inner = &array_str[1..array_str.len() - 1];
                    let numbers: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();

                    if numbers.len() == 3 {
                        for (i, num_str) in numbers.iter().enumerate() {
                            if let Ok(num) = num_str.parse::<u16>() {
                                if num == 0 {
                                    let panel_names = ["Source", "EbpfInfo", "InteractiveCommand"];
                                    return Err(anyhow::anyhow!(
                                        "❌ Invalid panel configuration in '{}':\n\n\
                                        Panel ratio for {} panel (index {}) is 0, which would hide the panel.\n\n\
                                        💡 Fix: Change the 0 to a positive number (e.g., 1) in your config file:\n\
                                        panel_ratios = [4, 3, 3]  # Example with all positive values\n\n\
                                        Valid values are positive integers representing relative sizes.",
                                        file_path,
                                        panel_names.get(i).unwrap_or(&"Unknown"),
                                        i
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Create a user-friendly error message for TOML parsing errors
    fn create_friendly_toml_error(
        file_path: &str,
        content: &str,
        error: toml::de::Error,
    ) -> anyhow::Error {
        let error_msg = format!("Configuration file parsing error in '{}'", file_path);

        if let Some(span) = error.span() {
            // Calculate line and column from span
            let lines: Vec<&str> = content.lines().collect();
            let mut current_pos = 0;
            let mut line_num: usize = 1;
            let mut col_num: usize = 1;

            for line in &lines {
                let line_len = line.len() + 1; // +1 for newline
                if current_pos + line_len > span.start {
                    col_num = span.start - current_pos + 1;
                    break;
                }
                current_pos += line_len;
                line_num += 1;
            }

            let context_line = lines.get(line_num.saturating_sub(1)).unwrap_or(&"");

            anyhow::anyhow!(
                "{}\n\nError at line {}, column {}:\n{}\n\n{}\n{}^\n\nSuggestion: {}",
                error_msg,
                line_num,
                col_num,
                error,
                context_line,
                " ".repeat(col_num.saturating_sub(1)),
                Self::get_error_suggestion(&error.to_string())
            )
        } else {
            anyhow::anyhow!(
                "{}\n\n{}\n\nSuggestion: {}",
                error_msg,
                error,
                Self::get_error_suggestion(&error.to_string())
            )
        }
    }

    /// Provide helpful suggestions based on common configuration errors
    fn get_error_suggestion(error_msg: &str) -> &'static str {
        if error_msg.contains("unknown variant") && error_msg.contains("horizontal") {
            "Layout values should be capitalized: use 'Horizontal' instead of 'horizontal'"
        } else if error_msg.contains("unknown variant") && error_msg.contains("vertical") {
            "Layout values should be capitalized: use 'Vertical' instead of 'vertical'"
        } else if error_msg.contains("unknown variant") && error_msg.contains("layout") {
            "Valid layout options are: 'Horizontal', 'Vertical'"
        } else if error_msg.contains("log_level") {
            "Valid log levels are: 'error', 'warn', 'info', 'debug', 'trace'"
        } else if error_msg.contains("unknown field") {
            "Check the field name spelling and ensure it's in the correct section"
        } else if error_msg.contains("invalid type") {
            "Check the value type - strings should be in quotes, numbers should not"
        } else if error_msg.contains("panel_ratios") {
            "Panel ratios must be an array of 3 positive numbers, e.g., [4, 3, 3]"
        } else if error_msg.contains("default_focus") {
            "Valid panel focus options are: 'Source', 'EbpfInfo', 'InteractiveCommand'"
        } else {
            "Please check the configuration file syntax and refer to the example config.toml"
        }
    }

    /// Get configuration file search paths in priority order
    fn get_config_search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // 1. ~/.ghostscope/config.toml (user-level config)
        if let Some(home_dir) = dirs::home_dir() {
            paths.push(home_dir.join(".ghostscope").join("config.toml"));
        }

        // 2. ./ghostscope.toml (project-level config)
        if let Ok(current_dir) = std::env::current_dir() {
            paths.push(current_dir.join("ghostscope.toml"));
        }

        paths
    }

    /// Load configuration with explicit config file path (for --config flag)
    pub fn load_with_explicit_path<P: AsRef<Path>>(config_path: P) -> Result<Self> {
        let path = config_path.as_ref();
        if !path.exists() {
            return Err(anyhow::anyhow!(
                "Specified configuration file does not exist: {}",
                path.display()
            ));
        }
        info!("Loading configuration from: {}", path.display());
        let mut config = Self::load_from_file(path)?;
        config.loaded_from = Some(path.to_path_buf());
        Ok(config)
    }
}

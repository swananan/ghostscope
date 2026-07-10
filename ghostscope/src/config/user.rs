use std::path::PathBuf;

use anyhow::Result;
use tracing::{info, warn};

use crate::config::{
    settings::DebuginfodMode, CliColorMode, Config, LayoutMode, ParsedArgs, ScriptOutputMode,
    ScriptTimestampFormat,
};

/// Immutable user-provided configuration merged from CLI arguments and config file.
#[derive(Debug, Clone)]
pub struct UserConfig {
    // Core application settings
    pub binary_path: Option<String>,
    pub target_path: Option<String>,
    pub binary_args: Vec<String>,
    /// Original PID entered by the user with `-p`.
    pub input_pid: Option<u32>,
    pub log_file: PathBuf,
    pub emit_ready_marker: Option<String>,
    pub enable_logging: bool,
    pub enable_console_logging: bool,
    pub log_level: crate::config::settings::LogLevel,
    pub debug_file: Option<PathBuf>,
    pub script: Option<String>,
    pub script_file: Option<PathBuf>,
    pub script_output_mode: ScriptOutputMode,
    pub script_status: bool,
    pub script_timestamp_format: ScriptTimestampFormat,
    pub script_color_mode: CliColorMode,
    pub script_output_events_per_sec: u64,
    pub tui_mode: bool,
    pub dry_run: bool,
    pub dry_run_details: bool,

    // File saving options
    pub should_save_llvm_ir: bool,
    pub should_save_ebpf: bool,
    pub should_save_ast: bool,

    // UI configuration
    pub layout_mode: LayoutMode,
    pub default_focus: crate::config::PanelType,
    pub panel_ratios: [u16; 3],
    pub show_source_panel: bool,
    pub two_panel_ratios: [u16; 2],
    pub history_enabled: bool,
    pub history_max_entries: usize,
    pub ebpf_max_messages: usize,

    // DWARF configuration
    pub dwarf_search_paths: Vec<String>,
    pub dwarf_allow_loose_debug_match: bool,
    pub dwarf_debuginfod: ResolvedDebuginfodConfig,

    // eBPF configuration
    pub ebpf_config: crate::config::settings::EbpfConfig,

    // Source path configuration
    pub source: crate::config::settings::SourceConfig,

    // Config file metadata
    pub config_file_path: Option<PathBuf>,
}

impl UserConfig {
    /// Create merged user configuration from parsed arguments and config file.
    pub fn new(args: ParsedArgs, config: Config) -> Self {
        let dwarf_debuginfod = ResolvedDebuginfodConfig::resolve(&args, &config);
        let log_file = args
            .log_file
            .unwrap_or_else(|| PathBuf::from(&config.general.log_file));

        // Logging configuration priority:
        // 1. Command line flags (--log/--no-log)
        // 2. Config file setting
        // 3. Default behavior (script mode: false, TUI mode: true)

        let is_script_mode = args.script.is_some() || args.script_file.is_some();

        let enable_logging = if args.has_explicit_log_flag {
            args.enable_logging
        } else if config.general.enable_logging != default_enable_logging_for_mode(is_script_mode) {
            config.general.enable_logging
        } else {
            args.enable_logging
        };

        let enable_console_logging = if args.has_explicit_console_log_flag {
            args.enable_console_logging
        } else {
            config.general.enable_console_logging
        };

        let log_level = if args.log_level != crate::config::settings::LogLevel::Warn {
            args.log_level
        } else {
            config.general.log_level
        };

        let tui_mode = if args.tui_mode {
            args.tui_mode
        } else if args.script.is_none() && args.script_file.is_none() {
            config.general.default_tui_mode
        } else {
            args.tui_mode
        };

        let should_save_llvm_ir = if args.should_save_llvm_ir != cfg!(debug_assertions) {
            args.should_save_llvm_ir
        } else if cfg!(debug_assertions) {
            config.files.save_llvm_ir.debug
        } else {
            config.files.save_llvm_ir.release
        };

        let should_save_ebpf = if args.should_save_ebpf != cfg!(debug_assertions) {
            args.should_save_ebpf
        } else if cfg!(debug_assertions) {
            config.files.save_ebpf.debug
        } else {
            config.files.save_ebpf.release
        };

        let should_save_ast = if args.should_save_ast != cfg!(debug_assertions) {
            args.should_save_ast
        } else if cfg!(debug_assertions) {
            config.files.save_ast.debug
        } else {
            config.files.save_ast.release
        };

        let show_source_panel = if args.no_source_panel {
            false
        } else if args.source_panel {
            true
        } else {
            config.ui.show_source_panel
        };

        let script_status = if args.has_explicit_status_flag {
            args.status_enabled
        } else {
            config.script.status
        };

        let two_panel_ratios = if let Some(r) = config.ui.two_panel_ratios {
            r
        } else {
            [config.ui.panel_ratios[1], config.ui.panel_ratios[2]]
        };

        Self {
            binary_path: args.binary_path,
            target_path: args.target_path,
            binary_args: args.binary_args,
            input_pid: args.pid,
            log_file,
            emit_ready_marker: args.emit_ready_marker,
            enable_logging,
            enable_console_logging,
            log_level,
            debug_file: args.debug_file,
            script: args.script,
            script_file: args.script_file,
            script_output_mode: args.script_output.unwrap_or(config.script.output),
            script_status,
            script_timestamp_format: args.script_timestamp.unwrap_or(config.script.timestamp),
            script_color_mode: config.script.color,
            script_output_events_per_sec: args
                .script_output_events_per_sec
                .unwrap_or(config.script.output_events_per_sec),
            tui_mode,
            dry_run: args.dry_run,
            dry_run_details: args.dry_run_details,
            should_save_llvm_ir,
            should_save_ebpf,
            should_save_ast,
            layout_mode: args.layout_mode,
            default_focus: config.ui.default_focus,
            panel_ratios: config.ui.panel_ratios,
            show_source_panel,
            two_panel_ratios,
            history_enabled: config.ui.history.enabled,
            history_max_entries: config.ui.history.max_entries,
            ebpf_max_messages: config.ui.ebpf_max_messages,
            dwarf_search_paths: config.dwarf.search_paths.clone(),
            dwarf_allow_loose_debug_match: if args.allow_loose_debug_match {
                true
            } else {
                config.dwarf.allow_loose_debug_match
            },
            dwarf_debuginfod,
            ebpf_config: {
                let mut ebpf_config = config.ebpf;
                if args.force_perf_event_array {
                    ebpf_config.force_perf_event_array = true;
                }
                if args.enable_sysmon_for_target {
                    ebpf_config.enable_sysmon_for_target = true;
                }
                if let Some(backtrace_depth) = args.backtrace_depth {
                    ebpf_config.backtrace_depth = backtrace_depth;
                }
                ebpf_config
            },
            source: config.source,
            config_file_path: config.loaded_from,
        }
    }

    /// Create merged user configuration with explicit config file path.
    pub fn new_with_explicit_config(
        args: ParsedArgs,
        config_path: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        let config = if let Some(path) = config_path {
            Config::load_with_explicit_path(path)?
        } else {
            Config::load()?
        };

        Ok(Self::new(args, config))
    }

    pub fn config_source_message(&self) -> String {
        if let Some(config_path) = &self.config_file_path {
            format!("Configuration loaded from: {}", config_path.display())
        } else {
            let home_hint = std::env::var("HOME").unwrap_or_else(|_| "(unset)".into());
            format!(
                "Using built-in defaults (no config found at {home_hint}/.ghostscope/config.toml or ./ghostscope.toml)"
            )
        }
    }

    pub(crate) fn validate_with_pid_state(&self, pid_already_verified: bool) -> Result<()> {
        if self.input_pid.is_none() && self.target_path.is_none() {
            return Err(anyhow::anyhow!(
                "No target specified. Please provide either --pid <PID> or --target <PATH>."
            ));
        }

        if let Some(target_path) = &self.target_path {
            let target_file = PathBuf::from(target_path);
            if !target_file.exists() {
                return Err(anyhow::anyhow!("Target file does not exist: {target_path}"));
            }
            if !target_file.is_file() {
                return Err(anyhow::anyhow!("Target path is not a file: {target_path}"));
            }
            ghostscope_process::ensure_supported_target_path(&target_file)?;
            info!("✓ Target file found: {}", target_path);
        }

        if let Some(pid) = self.input_pid {
            if !pid_already_verified && !is_pid_running(pid) {
                return Err(anyhow::anyhow!(
                    "Process with PID {pid} is not running. Use 'ps -p {pid}' to verify the process exists"
                ));
            }
            info!("✓ Target PID {} is running", pid);
        }

        if let Some(script_file) = &self.script_file {
            if !script_file.exists() {
                return Err(anyhow::anyhow!(
                    "Script file does not exist: {}",
                    script_file.display()
                ));
            }
            if !script_file.is_file() {
                return Err(anyhow::anyhow!(
                    "Script path is not a file: {}",
                    script_file.display()
                ));
            }
        }

        if self.dry_run && self.script.is_none() && self.script_file.is_none() {
            return Err(anyhow::anyhow!(
                "--dry-run requires --script or --script-file because there is no trace plan to resolve"
            ));
        }

        if let Some(debug_file) = &self.debug_file {
            if !debug_file.exists() {
                return Err(anyhow::anyhow!(
                    "Debug file does not exist: {}",
                    debug_file.display()
                ));
            }
        }

        info!("✓ Command line arguments validated successfully");
        Ok(())
    }
}

/// Fully resolved debuginfod configuration.
///
/// The debuginfod client crate is deliberately policy-free. GhostScope resolves
/// CLI/config/env/default precedence here, then later passes explicit values to
/// `ghostscope-debuginfod`.
#[derive(Debug, Clone)]
pub struct ResolvedDebuginfodConfig {
    pub mode: DebuginfodMode,
    pub urls: Vec<String>,
    pub cache_dir: Option<PathBuf>,
    /// None means no request timeout.
    pub timeout_secs: Option<u64>,
    /// None means no explicit client-side response size cap.
    pub max_size_bytes: Option<u64>,
}

impl ResolvedDebuginfodConfig {
    pub fn is_effectively_enabled(&self) -> bool {
        self.mode == DebuginfodMode::On && !self.urls.is_empty()
    }

    fn resolve(args: &ParsedArgs, config: &Config) -> Self {
        let mode = args.debuginfod.unwrap_or(config.dwarf.debuginfod.enabled);

        if mode == DebuginfodMode::Off {
            return Self {
                mode,
                urls: Vec::new(),
                cache_dir: None,
                timeout_secs: None,
                max_size_bytes: None,
            };
        }

        let urls = if !args.debuginfod_urls.is_empty() {
            args.debuginfod_urls.clone()
        } else if !config.dwarf.debuginfod.urls.is_empty() {
            config.dwarf.debuginfod.urls.clone()
        } else {
            env_list("DEBUGINFOD_URLS")
        };

        let cache_dir = args
            .debuginfod_cache_dir
            .clone()
            .filter(|path| !path.as_os_str().is_empty())
            .or_else(|| {
                config
                    .dwarf
                    .debuginfod
                    .cache_dir
                    .clone()
                    .filter(|path| !path.as_os_str().is_empty())
            })
            .or_else(|| env_path("DEBUGINFOD_CACHE_PATH"))
            .or_else(default_debuginfod_cache_dir);

        let timeout_secs = first_u64(
            args.debuginfod_timeout_secs,
            config.dwarf.debuginfod.timeout_secs,
            env_u64("DEBUGINFOD_TIMEOUT"),
        )
        .or(Some(5))
        .and_then(nonzero_u64);

        let max_size_bytes = first_u64(
            args.debuginfod_max_size,
            config.dwarf.debuginfod.max_size_bytes,
            env_u64("DEBUGINFOD_MAXSIZE"),
        )
        .and_then(nonzero_u64);

        if mode == DebuginfodMode::Ask {
            warn!(
                "debuginfod mode 'ask' is reserved for future TUI confirmation support; \
                 debuginfod will not be used until ask-mode is implemented"
            );
        } else if urls.is_empty() {
            info!(
                "debuginfod is enabled but no URLs were configured; skipping debuginfod fallback"
            );
        }

        Self {
            mode,
            urls,
            cache_dir,
            timeout_secs,
            max_size_bytes,
        }
    }
}

impl Default for ResolvedDebuginfodConfig {
    fn default() -> Self {
        Self {
            mode: DebuginfodMode::Off,
            urls: Vec::new(),
            cache_dir: None,
            timeout_secs: None,
            max_size_bytes: None,
        }
    }
}

fn env_list(name: &str) -> Vec<String> {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .split_whitespace()
                .filter(|part| !part.is_empty())
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
}

fn env_u64(name: &str) -> Option<u64> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => match value.parse::<u64>() {
            Ok(parsed) => Some(parsed),
            Err(error) => {
                warn!("Ignoring invalid {name} value '{value}': {error}");
                None
            }
        },
        _ => None,
    }
}

fn first_u64(cli: Option<u64>, config: Option<u64>, env: Option<u64>) -> Option<u64> {
    cli.or(config).or(env)
}

fn nonzero_u64(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}

fn default_debuginfod_cache_dir() -> Option<PathBuf> {
    std::env::var("XDG_CACHE_HOME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| PathBuf::from(value).join("debuginfod_client"))
        .or_else(|| {
            dirs::home_dir().map(|home| {
                let deprecated = home.join(".debuginfod_client_cache");
                if deprecated.exists() {
                    deprecated
                } else {
                    home.join(".cache").join("debuginfod_client")
                }
            })
        })
        .or_else(|| Some(std::env::temp_dir().join("debuginfod_client")))
}

fn default_enable_logging_for_mode(is_script_mode: bool) -> bool {
    !is_script_mode
}

fn is_pid_running(pid: u32) -> bool {
    use std::path::Path;

    let proc_path = format!("/proc/{pid}");
    Path::new(&proc_path).is_dir()
}

use std::path::PathBuf;

use crate::config::{Config, LayoutMode, ParsedArgs};

/// Final merged configuration that combines command line arguments and config file settings
/// Command line arguments take priority over config file settings
#[derive(Debug, Clone)]
pub struct MergedConfig {
    // Core application settings
    pub binary_path: Option<String>,
    pub target_path: Option<String>,
    pub binary_args: Vec<String>,
    pub pid: Option<u32>,
    pub log_file: PathBuf,
    pub enable_logging: bool,
    pub enable_console_logging: bool,
    pub log_level: crate::config::settings::LogLevel,
    pub debug_file: Option<PathBuf>,
    pub script: Option<String>,
    pub script_file: Option<PathBuf>,
    pub tui_mode: bool,

    // File saving options
    pub should_save_llvm_ir: bool,
    pub should_save_ebpf: bool,
    pub should_save_ast: bool,

    // UI configuration
    pub layout_mode: LayoutMode,
    pub default_focus: crate::config::PanelType,
    pub panel_ratios: [u16; 3],
    pub history_enabled: bool,
    pub history_max_entries: usize,
    pub ebpf_max_messages: usize,

    // DWARF configuration
    pub dwarf_search_paths: Vec<String>,
    pub dwarf_allow_loose_debug_match: bool,

    // eBPF configuration
    pub ebpf_config: crate::config::settings::EbpfConfig,

    // Source path configuration
    pub source: crate::config::settings::SourceConfig,

    // Config file metadata
    pub config_file_path: Option<PathBuf>,
}

impl MergedConfig {
    /// Create merged configuration from parsed arguments and config file
    pub fn new(args: ParsedArgs, config: Config) -> Self {
        // Command line arguments override config file settings
        let log_file = args
            .log_file
            .unwrap_or_else(|| PathBuf::from(&config.general.log_file));

        // Logging configuration priority:
        // 1. Command line flags (--log/--no-log)
        // 2. Config file setting
        // 3. Default behavior (script mode: false, TUI mode: true)

        // Check if script mode was detected (args already processed this logic)
        let is_script_mode = args.script.is_some() || args.script_file.is_some();

        let enable_logging = if args.has_explicit_log_flag {
            // Command line explicitly set logging (--log or --no-log takes precedence)
            args.enable_logging
        } else {
            // Use config file setting, fallback to script mode behavior
            if config.general.enable_logging != default_enable_logging_for_mode(is_script_mode) {
                // Config file has non-default setting, use it
                config.general.enable_logging
            } else {
                // Config file has default, use args decision (which considers script mode)
                args.enable_logging
            }
        };

        let enable_console_logging = if args.has_explicit_console_log_flag {
            // Command line explicitly set console logging (--log-console or --no-log-console takes precedence)
            args.enable_console_logging
        } else {
            // Use config file setting
            config.general.enable_console_logging
        };

        // Log level priority: 1. Command line args, 2. RUST_LOG env var, 3. Config file (default: warn)
        // Note: Command line and RUST_LOG are already processed in args.rs
        let log_level = if args.log_level != crate::config::settings::LogLevel::Warn {
            // Command line or RUST_LOG explicitly set log level
            args.log_level
        } else {
            // Use config file setting
            config.general.log_level
        };

        let tui_mode = if args.tui_mode {
            // If TUI mode was explicitly set via args, use that
            args.tui_mode
        } else {
            // Otherwise use the logic from args (which considers script presence)
            // but fallback to config default if no script provided
            if args.script.is_none() && args.script_file.is_none() {
                config.general.default_tui_mode
            } else {
                args.tui_mode
            }
        };

        // File saving options: command line overrides config file
        let should_save_llvm_ir = if args.should_save_llvm_ir != cfg!(debug_assertions) {
            // Command line explicitly set a different value than default
            args.should_save_llvm_ir
        } else {
            // Use config file setting based on build type
            if cfg!(debug_assertions) {
                config.files.save_llvm_ir.debug
            } else {
                config.files.save_llvm_ir.release
            }
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

        Self {
            binary_path: args.binary_path,
            target_path: args.target_path,
            binary_args: args.binary_args,
            pid: args.pid,
            log_file,
            enable_logging,
            enable_console_logging,
            log_level,
            debug_file: args.debug_file,
            script: args.script,
            script_file: args.script_file,
            tui_mode,
            should_save_llvm_ir,
            should_save_ebpf,
            should_save_ast,
            layout_mode: args.layout_mode, // Command line takes priority
            default_focus: config.ui.default_focus, // UI config from file
            panel_ratios: config.ui.panel_ratios, // UI config from file
            history_enabled: config.ui.history.enabled,
            history_max_entries: config.ui.history.max_entries,
            ebpf_max_messages: config.ui.ebpf_max_messages,
            dwarf_search_paths: config.dwarf.search_paths.clone(),
            dwarf_allow_loose_debug_match: if args.allow_loose_debug_match {
                true
            } else {
                config.dwarf.allow_loose_debug_match
            },
            ebpf_config: {
                // Command line --force-perf-event-array overrides config file
                let mut ebpf_config = config.ebpf;
                if args.force_perf_event_array {
                    ebpf_config.force_perf_event_array = true;
                }
                // Command line --enable-sysmon-shared-lib overrides config file
                if args.enable_sysmon_for_shared_lib {
                    ebpf_config.enable_sysmon_for_shared_lib = true;
                }
                ebpf_config
            },
            source: config.source,
            config_file_path: config.loaded_from,
        }
    }

    /// Create merged configuration with explicit config file path
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
}

/// Get default logging behavior for the given mode
fn default_enable_logging_for_mode(is_script_mode: bool) -> bool {
    if is_script_mode {
        false // Script mode defaults to no logging
    } else {
        true // TUI mode defaults to logging enabled
    }
}

// Convenience methods to extract configuration for specific crates
impl MergedConfig {
    /// Extract UI-related configuration for ghostscope-ui crate
    pub fn get_ui_config(&self) -> ghostscope_ui::UiConfig {
        ghostscope_ui::UiConfig {
            layout_mode: match self.layout_mode {
                LayoutMode::Horizontal => ghostscope_ui::LayoutMode::Horizontal,
                LayoutMode::Vertical => ghostscope_ui::LayoutMode::Vertical,
            },
            panel_ratios: self.panel_ratios,
            default_focus: match self.default_focus {
                crate::config::PanelType::Source => ghostscope_ui::PanelType::Source,
                crate::config::PanelType::EbpfInfo => ghostscope_ui::PanelType::EbpfInfo,
                crate::config::PanelType::InteractiveCommand => {
                    ghostscope_ui::PanelType::InteractiveCommand
                }
            },
            history: ghostscope_ui::HistoryConfig {
                enabled: self.history_enabled,
                max_entries: self.history_max_entries,
            },
            ebpf_max_messages: self.ebpf_max_messages,
        }
    }

    /// Extract compilation options for ghostscope-compiler crate
    pub fn get_compile_options(
        &self,
        save_llvm_ir: bool,
        save_ebpf: bool,
        save_ast: bool,
        binary_path_hint: Option<String>,
    ) -> ghostscope_compiler::CompileOptions {
        use ghostscope_loader::KernelCapabilities;

        // Select event map type based on kernel capabilities or config override
        let event_map_type = if self.ebpf_config.force_perf_event_array {
            // Force PerfEventArray for testing (config override)
            ::tracing::warn!(
                "⚠️  TESTING MODE: force_perf_event_array=true in config - using PerfEventArray"
            );
            ghostscope_compiler::EventMapType::PerfEventArray
        } else if KernelCapabilities::ringbuf_supported() {
            ghostscope_compiler::EventMapType::RingBuf
        } else {
            ghostscope_compiler::EventMapType::PerfEventArray
        };

        // Derive effective max_trace_event_size with runtime clamping
        let mut effective_max_event = self.ebpf_config.max_trace_event_size;
        match event_map_type {
            ghostscope_compiler::EventMapType::RingBuf => {
                let ring_cap = self.ebpf_config.ringbuf_size as u32;
                if effective_max_event > ring_cap {
                    ::tracing::warn!(
                        "Clamping max_trace_event_size {} to ringbuf_size {}",
                        effective_max_event,
                        ring_cap
                    );
                    effective_max_event = ring_cap;
                }
            }
            ghostscope_compiler::EventMapType::PerfEventArray => {
                // Conservative clamp: do not exceed per-CPU perf buffer size
                const PAGE_SIZE: u32 = 4096;
                let perf_cap = self.ebpf_config.perf_page_count.saturating_mul(PAGE_SIZE);
                if effective_max_event > perf_cap {
                    ::tracing::warn!(
                        "Clamping max_trace_event_size {} to perf buffer cap {} (pages={})",
                        effective_max_event,
                        perf_cap,
                        self.ebpf_config.perf_page_count
                    );
                    effective_max_event = perf_cap;
                }
            }
        }

        ghostscope_compiler::CompileOptions {
            save_llvm_ir,
            save_ebpf,
            save_ast,
            binary_path_hint,
            ringbuf_size: self.ebpf_config.ringbuf_size,
            proc_module_offsets_max_entries: self.ebpf_config.proc_module_offsets_max_entries,
            perf_page_count: self.ebpf_config.perf_page_count,
            event_map_type,
            mem_dump_cap: self.ebpf_config.mem_dump_cap,
            compare_cap: self.ebpf_config.compare_cap,
            max_trace_event_size: effective_max_event,
            selected_index: None,
        }
    }
}

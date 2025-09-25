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

    // DWARF configuration
    pub dwarf_search_paths: Vec<String>,
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

        let log_level = if args.log_level != crate::config::settings::LogLevel::Warn {
            // Command line explicitly set log level
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
        } else {
            if cfg!(debug_assertions) {
                config.files.save_ebpf.debug
            } else {
                config.files.save_ebpf.release
            }
        };

        let should_save_ast = if args.should_save_ast != cfg!(debug_assertions) {
            args.should_save_ast
        } else {
            if cfg!(debug_assertions) {
                config.files.save_ast.debug
            } else {
                config.files.save_ast.release
            }
        };

        Self {
            binary_path: args.binary_path,
            target_path: args.target_path,
            binary_args: args.binary_args,
            pid: args.pid,
            log_file,
            enable_logging,
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
            dwarf_search_paths: config.dwarf.search_paths,
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
        }
    }

    /// Extract compilation-related configuration for ghostscope-compiler crate
    pub fn get_compiler_config(&self) -> CompilerConfiguration {
        CompilerConfiguration {
            should_save_llvm_ir: self.should_save_llvm_ir,
            should_save_ebpf: self.should_save_ebpf,
            should_save_ast: self.should_save_ast,
        }
    }

    /// Extract DWARF-related configuration for ghostscope-dwarf crate
    pub fn get_dwarf_config(&self) -> DwarfConfiguration {
        DwarfConfiguration {
            search_paths: self.dwarf_search_paths.clone(),
            debug_file: self.debug_file.clone(),
        }
    }
}

/// Configuration subset for compiler components
#[derive(Debug, Clone)]
pub struct CompilerConfiguration {
    pub should_save_llvm_ir: bool,
    pub should_save_ebpf: bool,
    pub should_save_ast: bool,
}

/// Configuration subset for DWARF processing components
#[derive(Debug, Clone)]
pub struct DwarfConfiguration {
    pub search_paths: Vec<String>,
    pub debug_file: Option<PathBuf>,
}

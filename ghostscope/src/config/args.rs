use anyhow::Result;
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum, serde::Serialize, serde::Deserialize)]
pub enum LayoutMode {
    /// Horizontal layout: panels arranged side by side (4:3:3 ratio)
    Horizontal,
    /// Vertical layout: panels arranged top to bottom (4:3:3 ratio)
    Vertical,
}

#[derive(Parser, Debug)]
#[command(name = "ghostscope")]
#[command(
    about = "A DWARF-friendly eBPF userspace probe with gdb-like TUI, built in 100% safe Rust"
)]
#[command(version = "0.1.0")]
pub struct Args {
    /// Binary file to debug (path or name)
    pub binary: Option<String>,

    /// Target file for analysis (executable, shared library, or static library)
    /// Can be an absolute or relative path. Relative paths are converted to absolute paths
    /// based on the command execution directory. Search order for relative paths:
    /// 1. Current working directory
    /// 2. Same directory as the ghostscope command
    ///
    /// - Can be used together with -p to filter events for a specific PID
    #[arg(long, short = 't', value_name = "PATH")]
    pub target: Option<String>,

    /// Process ID to attach to
    #[arg(long, short = 'p', value_name = "PID")]
    pub pid: Option<u32>,

    /// Log file path (default: ./ghostscope.log)
    #[arg(long, value_name = "PATH")]
    pub log_file: Option<PathBuf>,

    /// Enable logging to file (overrides config file)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub log: bool,

    /// Disable logging completely (overrides config file)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub no_log: bool,

    /// Enable console/stdout logging in addition to file logging (overrides config file)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub log_console: bool,

    /// Disable console/stdout logging, file logging only (overrides config file)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub no_log_console: bool,

    /// Set log level (error, warn, info, debug, trace)
    /// Priority: 1. Command line args, 2. RUST_LOG env var, 3. Config file (default: warn)
    #[arg(long, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Specify custom configuration file path
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Debug information file path (overrides auto-detection)
    /// Auto-detection searches:
    /// 1. Binary itself (.debug_info sections)
    /// 2. .gnu_debuglink section
    /// 3. .gnu_debugdata section (Android/compressed)
    /// 4. Standard paths: /usr/lib/debug, /usr/local/lib/debug
    /// 5. Build-ID based paths
    /// 6. Common patterns: binary.debug, binary.dbg
    #[arg(long, short = 'd', value_name = "PATH")]
    pub debug_file: Option<PathBuf>,

    /// Script to execute (inline script - optional for TUI mode)
    #[arg(long, short = 's', value_name = "SCRIPT")]
    pub script: Option<String>,

    /// Script file path (optional for debugging - TUI mode accepts user input)
    #[arg(long, value_name = "PATH")]
    pub script_file: Option<PathBuf>,

    /// Start in TUI mode (default behavior when no script provided)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub tui: bool,

    /// Save LLVM IR files for each trace pattern (debug: true, release: false)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub save_llvm_ir: bool,

    /// Disable saving LLVM IR files (overrides default behavior)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub no_save_llvm_ir: bool,

    /// Save eBPF bytecode files for each trace pattern (debug: true, release: false)  
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub save_ebpf: bool,

    /// Disable saving eBPF bytecode files (overrides default behavior)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub no_save_ebpf: bool,

    /// Save AST files for each trace pattern (debug: true, release: false)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub save_ast: bool,

    /// Disable saving AST files (overrides default behavior)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub no_save_ast: bool,

    /// TUI layout mode: horizontal (h) or vertical (v)
    /// horizontal: panels arranged side by side (4:3:3 ratio)
    /// vertical: panels arranged top to bottom (4:3:3 ratio)
    #[arg(long, value_name = "MODE", value_enum, default_value = "horizontal")]
    pub layout: LayoutMode,

    /// Force using PerfEventArray instead of RingBuf (for testing only)
    /// WARNING: This is for testing purposes only. PerfEventArray has performance overhead
    /// compared to RingBuf on kernels >= 5.8
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub force_perf_event_array: bool,

    /// Remaining arguments (when using --args)
    pub remaining: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedArgs {
    pub binary_path: Option<String>,
    pub target_path: Option<String>,
    pub binary_args: Vec<String>,
    pub log_file: Option<PathBuf>,
    pub enable_logging: bool,
    pub enable_console_logging: bool,
    pub log_level: crate::config::settings::LogLevel,
    pub has_explicit_log_flag: bool, // Track if --log/--no-log was explicitly provided
    pub has_explicit_console_log_flag: bool, // Track if --log-console/--no-log-console was explicitly provided
    pub config: Option<PathBuf>,
    pub debug_file: Option<PathBuf>,
    pub script: Option<String>,
    pub script_file: Option<PathBuf>,
    pub pid: Option<u32>,
    pub tui_mode: bool,
    pub should_save_llvm_ir: bool,
    pub should_save_ebpf: bool,
    pub should_save_ast: bool,
    pub layout_mode: LayoutMode,
    pub force_perf_event_array: bool,
}

impl Args {
    /// Parse command line arguments with special handling for --args
    pub fn parse_args() -> ParsedArgs {
        let args: Vec<String> = std::env::args().collect();

        // Look for --args flag
        if let Some(args_pos) = args.iter().position(|arg| arg == "--args") {
            // Everything after --args is for the target binary
            let (before_args, after_args) = args.split_at(args_pos);

            // Parse options before --args
            let mut modified_args = before_args.to_vec();
            modified_args.push("--args".to_string()); // Keep the flag for clap

            let parsed = Args::try_parse_from(&modified_args).unwrap_or_else(|e| e.exit());

            // Extract binary and its arguments from after --args
            let after_args = &after_args[1..]; // Skip the --args flag itself
            let (binary_path, binary_args) = if !after_args.is_empty() {
                (Some(after_args[0].clone()), after_args[1..].to_vec())
            } else {
                (None, Vec::new())
            };

            let should_save_llvm_ir = Self::should_save_llvm_ir(&parsed);
            let should_save_ebpf = Self::should_save_ebpf(&parsed);
            let should_save_ast = Self::should_save_ast(&parsed);
            let tui_mode = Self::determine_tui_mode(&parsed);
            let target_path = Self::resolve_target_path(&parsed);
            let (
                enable_logging,
                enable_console_logging,
                log_level,
                has_explicit_log_flag,
                has_explicit_console_log_flag,
            ) = Self::determine_logging_config(&parsed);

            ParsedArgs {
                binary_path,
                target_path,
                binary_args,
                log_file: parsed.log_file,
                enable_logging,
                enable_console_logging,
                log_level,
                has_explicit_log_flag,
                has_explicit_console_log_flag,
                config: parsed.config,
                debug_file: parsed.debug_file,
                script: parsed.script,
                script_file: parsed.script_file,
                pid: parsed.pid,
                tui_mode,
                should_save_llvm_ir,
                should_save_ebpf,
                should_save_ast,
                layout_mode: parsed.layout,
                force_perf_event_array: parsed.force_perf_event_array,
            }
        } else {
            // Normal parsing without --args
            let parsed = Args::parse();

            let should_save_llvm_ir = Self::should_save_llvm_ir(&parsed);
            let should_save_ebpf = Self::should_save_ebpf(&parsed);
            let should_save_ast = Self::should_save_ast(&parsed);
            let tui_mode = Self::determine_tui_mode(&parsed);
            let target_path = Self::resolve_target_path(&parsed);
            let (
                enable_logging,
                enable_console_logging,
                log_level,
                has_explicit_log_flag,
                has_explicit_console_log_flag,
            ) = Self::determine_logging_config(&parsed);

            ParsedArgs {
                binary_path: parsed.binary,
                target_path,
                binary_args: Vec::new(),
                log_file: parsed.log_file,
                enable_logging,
                enable_console_logging,
                log_level,
                has_explicit_log_flag,
                has_explicit_console_log_flag,
                config: parsed.config,
                debug_file: parsed.debug_file,
                script: parsed.script,
                script_file: parsed.script_file,
                pid: parsed.pid,
                tui_mode,
                should_save_llvm_ir,
                should_save_ebpf,
                should_save_ast,
                layout_mode: parsed.layout,
                force_perf_event_array: parsed.force_perf_event_array,
            }
        }
    }

    /// Determine whether to save LLVM IR files based on arguments and build type
    fn should_save_llvm_ir(parsed: &Args) -> bool {
        if parsed.no_save_llvm_ir {
            false
        } else if parsed.save_llvm_ir {
            true
        } else {
            // Default behavior: debug = true, release = false
            cfg!(debug_assertions)
        }
    }

    /// Determine whether to save eBPF files based on arguments and build type
    fn should_save_ebpf(parsed: &Args) -> bool {
        if parsed.no_save_ebpf {
            false
        } else if parsed.save_ebpf {
            true
        } else {
            // Default behavior: debug = true, release = false
            cfg!(debug_assertions)
        }
    }

    /// Determine whether to save AST files based on arguments and build type
    fn should_save_ast(parsed: &Args) -> bool {
        if parsed.no_save_ast {
            false
        } else if parsed.save_ast {
            true
        } else {
            // Default behavior: debug = true, release = false
            cfg!(debug_assertions)
        }
    }

    /// Determine whether to start in TUI mode
    fn determine_tui_mode(parsed: &Args) -> bool {
        // Explicit --tui flag takes precedence
        if parsed.tui {
            return true;
        }

        // If no script or script file provided, default to TUI mode
        parsed.script.is_none() && parsed.script_file.is_none()
    }

    /// Resolve target path with fallback search logic
    fn resolve_target_path(parsed: &Args) -> Option<String> {
        if let Some(target) = &parsed.target {
            // Check if it's an absolute path
            let target_path = PathBuf::from(target);
            if target_path.is_absolute() {
                if target_path.exists() {
                    Some(target.clone())
                } else {
                    warn!("Target file not found: {}", target);
                    Some(target.clone()) // Return anyway for error handling later
                }
            } else {
                // Try relative path searches and convert to absolute paths
                // 1. Current working directory
                if target_path.exists() {
                    if let Ok(current_dir) = std::env::current_dir() {
                        let absolute_target = current_dir.join(target);
                        return Some(absolute_target.to_string_lossy().to_string());
                    } else {
                        return Some(target.clone()); // Fallback if can't get current dir
                    }
                }

                // 2. Same directory as the command (executable directory)
                if let Ok(exe_path) = std::env::current_exe() {
                    if let Some(exe_dir) = exe_path.parent() {
                        let exe_target = exe_dir.join(target);
                        if exe_target.exists() {
                            return Some(exe_target.to_string_lossy().to_string());
                        }
                    }
                }

                // 3. If not found, still convert to absolute path based on current directory
                if let Ok(current_dir) = std::env::current_dir() {
                    let absolute_target = current_dir.join(target);
                    warn!(
                        "Target file not found, using absolute path: {}",
                        absolute_target.display()
                    );
                    Some(absolute_target.to_string_lossy().to_string())
                } else {
                    warn!("Cannot determine current directory for target: {}", target);
                    Some(target.clone()) // Last resort fallback
                }
            }
        } else {
            None
        }
    }

    /// Determine logging configuration from command line arguments
    fn determine_logging_config(
        parsed: &Args,
    ) -> (bool, bool, crate::config::settings::LogLevel, bool, bool) {
        // Check if we're in script mode (script provided via --script or --script-file)
        let is_script_mode = parsed.script.is_some() || parsed.script_file.is_some();

        // Check if explicit log flags were provided
        let has_explicit_log_flag = parsed.log || parsed.no_log;
        let has_explicit_console_log_flag = parsed.log_console || parsed.no_log_console;

        // Determine enable_logging (file logging)
        let enable_logging = if parsed.no_log {
            false // --no-log takes precedence, disables all logging
        } else if parsed.log {
            true // --log takes precedence, enables file logging
        } else if is_script_mode {
            false // Script mode defaults to no logging
        } else {
            true // TUI mode defaults to logging enabled
        };

        // Determine enable_console_logging
        let enable_console_logging = if parsed.no_log || parsed.no_log_console {
            false // --no-log or --no-log-console disables console logging
        } else if parsed.log_console {
            true // --log-console explicitly enables console logging
        } else {
            false // Default: console logging is disabled for cleaner output
        };

        // Determine log_level - Priority: 1. Command line, 2. RUST_LOG env, 3. Config file (default: warn)
        let log_level = if let Some(ref level_str) = parsed.log_level {
            // --log-level takes highest precedence
            crate::config::settings::LogLevel::from_str(level_str).unwrap_or_else(|_| {
                warn!("Invalid log level '{}', using default 'warn'", level_str);
                crate::config::settings::LogLevel::Warn
            })
        } else if let Ok(rust_log) = std::env::var("RUST_LOG") {
            // RUST_LOG environment variable as second priority
            crate::config::settings::LogLevel::from_str(&rust_log)
                .unwrap_or(crate::config::settings::LogLevel::Warn)
        } else {
            crate::config::settings::LogLevel::Warn // Default level (will be overridden by config file in merged.rs)
        };

        (
            enable_logging,
            enable_console_logging,
            log_level,
            has_explicit_log_flag,
            has_explicit_console_log_flag,
        )
    }
}

impl ParsedArgs {
    /// Validate command line arguments for consistency and completeness
    pub fn validate(&self) -> Result<()> {
        // Must have either PID or target path for meaningful operation
        if self.pid.is_none() && self.target_path.is_none() {
            warn!("No target PID or target file specified - running in standalone mode");
        }

        // Target path validation
        if let Some(target_path) = &self.target_path {
            let target_file = PathBuf::from(target_path);
            if !target_file.exists() {
                return Err(anyhow::anyhow!(
                    "Target file does not exist: {}",
                    target_path
                ));
            }
            if !target_file.is_file() {
                return Err(anyhow::anyhow!(
                    "Target path is not a file: {}",
                    target_path
                ));
            }
            info!("✓ Target file found: {}", target_path);
        }

        if let Some(pid) = self.pid {
            if !is_pid_running(pid) {
                return Err(anyhow::anyhow!(
                    "Process with PID {} is not running. Use 'ps -p {}' to verify the process exists",
                    pid,
                    pid
                ));
            }
            info!("✓ Target PID {} is running", pid);
        }

        // Script file must exist if specified
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

        // Debug file must exist if specified
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

/// Check if a process with given PID is currently running
fn is_pid_running(pid: u32) -> bool {
    use std::path::Path;

    // On Linux, check if /proc/PID exists and is a directory
    let proc_path = format!("/proc/{}", pid);
    Path::new(&proc_path).is_dir()
}

use anyhow::Result;
use clap::{Args as ClapArgs, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum, serde::Serialize, serde::Deserialize)]
pub enum LayoutMode {
    /// Horizontal layout: panels arranged side by side (4:3:3 ratio)
    Horizontal,
    /// Vertical layout: panels arranged top to bottom (4:3:3 ratio)
    Vertical,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, ValueEnum, serde::Serialize, serde::Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum ScriptOutputMode {
    #[default]
    Pretty,
    Plain,
    Quiet,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, ValueEnum, serde::Serialize, serde::Deserialize, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum ScriptTimestampFormat {
    #[default]
    Local,
    Boot,
    None,
}

#[derive(Debug, Clone)]
pub enum ParsedCommand {
    Trace(Box<ParsedArgs>),
    Bpffs(BpffsCommand),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BpffsCommand {
    Prune(BpffsPruneArgs),
}

#[derive(ClapArgs, Debug, Clone, PartialEq, Eq)]
pub struct BpffsPruneArgs {
    /// Show what would be removed without deleting anything
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub dry_run: bool,

    /// Remove one specific pid-starttime pin directory
    #[arg(long, value_name = "PID-STARTTIME")]
    pub instance: Option<String>,

    /// Remove all pid-starttime pin directories, including live instances
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub all: bool,

    /// Confirm destructive operation for --all
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub force: bool,

    /// Emit machine-readable JSON output
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub json: bool,
}

impl BpffsPruneArgs {
    pub fn validate(&self) -> Result<()> {
        if self.all && self.instance.is_some() {
            return Err(anyhow::anyhow!(
                "--all and --instance cannot be used together"
            ));
        }

        if self.all && !self.force && !self.dry_run {
            return Err(anyhow::anyhow!(
                "--all requires --force because it removes live pid-starttime directories"
            ));
        }

        if self.force && !self.all {
            return Err(anyhow::anyhow!("--force is only valid together with --all"));
        }

        if let Some(instance) = &self.instance {
            if parse_pid_starttime(instance).is_none() {
                return Err(anyhow::anyhow!(
                    "--instance must use pid-starttime format, for example 1234-567890"
                ));
            }
        }

        Ok(())
    }
}

#[derive(Subcommand, Debug)]
enum BpffsTopLevelCommand {
    /// Manage GhostScope bpffs pin directories
    Bpffs(BpffsArgs),
}

#[derive(ClapArgs, Debug)]
struct BpffsArgs {
    #[command(subcommand)]
    command: BpffsSubcommand,
}

#[derive(Subcommand, Debug)]
enum BpffsSubcommand {
    /// Prune stale or explicitly selected GhostScope bpffs pin directories
    Prune(BpffsPruneArgs),
}

#[derive(Parser, Debug)]
#[command(name = "ghostscope")]
#[command(
    about = "A DWARF-aware eBPF tracer with cgdb-like TUI - explore live processes at runtime"
)]
#[command(version = env!("CARGO_PKG_VERSION"))]
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

    /// Emit a readiness marker to stdout after script compilation and uprobe attachment.
    #[arg(long, value_name = "TEXT", hide = true)]
    pub emit_ready_marker: Option<String>,

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

    /// Allow non-strict debug file matching (CRC/Build-ID mismatches)
    /// Default is strict (disabled). When set, CRC/Build-ID mismatches are allowed with WARN logs.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub allow_loose_debug_match: bool,

    /// Script to execute (inline script - optional for TUI mode)
    #[arg(long, short = 's', value_name = "SCRIPT")]
    pub script: Option<String>,

    /// Script file path (optional for debugging - TUI mode accepts user input)
    #[arg(long, value_name = "PATH")]
    pub script_file: Option<PathBuf>,

    /// Start in TUI mode (default behavior when no script provided)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub tui: bool,

    /// Script-mode stdout formatting: pretty, plain, or quiet
    #[arg(long, value_name = "MODE", value_enum)]
    pub script_output: Option<ScriptOutputMode>,

    /// Timestamp style used by pretty script output: local, boot, or none
    #[arg(long, value_name = "FORMAT", value_enum)]
    pub script_timestamp: Option<ScriptTimestampFormat>,

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

    /// Enable sysmon eBPF for -t when the target is a shared library (.so).
    /// This starts system-wide sched exec/fork/exit tracepoints to maintain
    /// ASLR offsets for late-start processes loading the library. Disabled by
    /// default due to possible overhead on systems with high process churn.
    #[arg(long = "enable-sysmon-shared-lib", action = clap::ArgAction::SetTrue)]
    pub enable_sysmon_shared_lib: bool,

    /// Show the source panel explicitly (overrides config)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub source_panel: bool,

    /// Hide the source panel (overrides config)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub no_source_panel: bool,

    /// Remaining arguments (when using --args)
    pub remaining: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedArgs {
    pub binary_path: Option<String>,
    pub target_path: Option<String>,
    pub binary_args: Vec<String>,
    pub log_file: Option<PathBuf>,
    pub emit_ready_marker: Option<String>,
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
    pub script_output: Option<ScriptOutputMode>,
    pub script_timestamp: Option<ScriptTimestampFormat>,
    pub should_save_llvm_ir: bool,
    pub should_save_ebpf: bool,
    pub should_save_ast: bool,
    pub layout_mode: LayoutMode,
    pub force_perf_event_array: bool,
    pub enable_sysmon_for_shared_lib: bool,
    pub allow_loose_debug_match: bool,
    pub source_panel: bool,
    pub no_source_panel: bool,
}

fn parse_pid_starttime(value: &str) -> Option<(u32, u64)> {
    let (pid, starttime) = value.split_once('-')?;
    let pid = pid.parse::<u32>().ok()?;
    let starttime = starttime.parse::<u64>().ok()?;
    Some((pid, starttime))
}

impl Args {
    /// Parse command line arguments with special handling for --args
    pub fn parse_args() -> ParsedCommand {
        let args: Vec<String> = std::env::args().collect();
        Self::parse_args_from(args)
    }

    fn parse_args_from(args: Vec<String>) -> ParsedCommand {
        let bpffs_prune_invocation = Self::is_bpffs_prune_invocation(&args);

        if let Some(args_pos) = args.iter().position(|arg| arg == "--args") {
            // `--args` belongs to trace mode; bpffs maintenance commands do not use it.
            if bpffs_prune_invocation {
                return Self::try_parse_dispatch(&args).unwrap_or_else(|e| e.exit());
            }
            return ParsedCommand::Trace(Box::new(Self::parse_trace_args_with_split(
                args, args_pos,
            )));
        }

        if bpffs_prune_invocation {
            return Self::try_parse_dispatch(&args).unwrap_or_else(|e| e.exit());
        }

        match Self::try_parse_dispatch(&args) {
            Ok(command) => command,
            Err(_err) if matches!(args.get(1).map(String::as_str), Some("bpffs")) => {
                ParsedCommand::Trace(Box::new(Self::parse_trace_args(args)))
            }
            Err(err) => err.exit(),
        }
    }

    fn is_bpffs_prune_invocation(args: &[String]) -> bool {
        matches!(
            (
                args.get(1).map(String::as_str),
                args.get(2).map(String::as_str)
            ),
            (Some("bpffs"), Some("prune"))
        )
    }

    fn parse_trace_args(args: Vec<String>) -> ParsedArgs {
        // Look for --args flag
        if let Some(args_pos) = args.iter().position(|arg| arg == "--args") {
            Self::parse_trace_args_with_split(args, args_pos)
        } else {
            // Normal parsing without --args
            let parsed = Args::try_parse_from(&args).unwrap_or_else(|e| e.exit());
            let binary_path = parsed.binary.clone();
            Self::parsed_trace_args_from_clap(parsed, binary_path, Vec::new())
        }
    }

    fn parse_trace_args_with_split(args: Vec<String>, args_pos: usize) -> ParsedArgs {
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

        Self::parsed_trace_args_from_clap(parsed, binary_path, binary_args)
    }

    fn command_with_bpffs() -> clap::Command {
        BpffsTopLevelCommand::augment_subcommands(Args::command())
    }

    fn try_parse_dispatch(args: &[String]) -> std::result::Result<ParsedCommand, clap::Error> {
        let matches = Self::command_with_bpffs().try_get_matches_from(args.iter().cloned())?;

        if let Some(("bpffs", sub_matches)) = matches.subcommand() {
            let bpffs = BpffsArgs::from_arg_matches(sub_matches)?;
            return Ok(ParsedCommand::Bpffs(match bpffs.command {
                BpffsSubcommand::Prune(prune) => BpffsCommand::Prune(prune),
            }));
        }

        let parsed = Args::from_arg_matches(&matches)?;
        let binary_path = parsed.binary.clone();
        Ok(ParsedCommand::Trace(Box::new(
            Self::parsed_trace_args_from_clap(parsed, binary_path, Vec::new()),
        )))
    }

    fn parsed_trace_args_from_clap(
        parsed: Args,
        binary_path: Option<String>,
        binary_args: Vec<String>,
    ) -> ParsedArgs {
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
            emit_ready_marker: parsed.emit_ready_marker,
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
            script_output: parsed.script_output,
            script_timestamp: parsed.script_timestamp,
            should_save_llvm_ir,
            should_save_ebpf,
            should_save_ast,
            layout_mode: parsed.layout,
            force_perf_event_array: parsed.force_perf_event_array,
            enable_sysmon_for_shared_lib: parsed.enable_sysmon_shared_lib,
            allow_loose_debug_match: parsed.allow_loose_debug_match,
            source_panel: parsed.source_panel,
            no_source_panel: parsed.no_source_panel,
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
        // Require either PID (-p) or target file (-t)
        if self.pid.is_none() && self.target_path.is_none() {
            return Err(anyhow::anyhow!(
                "No target specified. Please provide either --pid <PID> or --target <PATH>."
            ));
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
    let proc_path = format!("/proc/{pid}");
    Path::new(&proc_path).is_dir()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{
        Args, BpffsCommand, BpffsPruneArgs, ParsedCommand, ScriptOutputMode, ScriptTimestampFormat,
    };

    #[test]
    fn parses_bpffs_prune_subcommand() {
        let parsed = Args::parse_args_from(vec![
            "ghostscope".to_string(),
            "bpffs".to_string(),
            "prune".to_string(),
            "--dry-run".to_string(),
            "--json".to_string(),
        ]);

        match parsed {
            ParsedCommand::Bpffs(BpffsCommand::Prune(args)) => {
                assert!(args.dry_run);
                assert!(args.json);
                assert_eq!(args.instance, None);
                assert!(!args.all);
                assert!(!args.force);
            }
            other => panic!("unexpected parse result: {other:?}"),
        }
    }

    #[test]
    fn keeps_positional_binary_named_bpffs_in_trace_mode() {
        let parsed = Args::parse_args_from(vec![
            "ghostscope".to_string(),
            "bpffs".to_string(),
            "--script-file".to_string(),
            "trace.gs".to_string(),
        ]);

        match parsed {
            ParsedCommand::Trace(args) => {
                assert_eq!(args.binary_path.as_deref(), Some("bpffs"));
                assert_eq!(args.script_file, Some(PathBuf::from("trace.gs")));
            }
            other => panic!("unexpected parse result: {other:?}"),
        }
    }

    #[test]
    fn root_help_lists_bpffs_subcommand() {
        let help = Args::command_with_bpffs().render_long_help().to_string();
        assert!(help.contains("bpffs"));
    }

    #[test]
    fn bpffs_prune_requires_force_with_all() {
        let args = BpffsPruneArgs {
            dry_run: false,
            instance: None,
            all: true,
            force: false,
            json: false,
        };

        let err = args.validate().unwrap_err().to_string();
        assert!(err.contains("--all requires --force"));
    }

    #[test]
    fn bpffs_prune_rejects_bad_instance_format() {
        let args = BpffsPruneArgs {
            dry_run: false,
            instance: Some("1234".to_string()),
            all: false,
            force: false,
            json: false,
        };

        let err = args.validate().unwrap_err().to_string();
        assert!(err.contains("pid-starttime"));
    }

    #[test]
    fn parses_script_output_flags() {
        let parsed = Args::parse_args_from(vec![
            "ghostscope".to_string(),
            "--pid".to_string(),
            "1234".to_string(),
            "--script-file".to_string(),
            "trace.gs".to_string(),
            "--script-output".to_string(),
            "plain".to_string(),
            "--script-timestamp".to_string(),
            "boot".to_string(),
        ]);

        match parsed {
            ParsedCommand::Trace(args) => {
                assert_eq!(args.script_output, Some(ScriptOutputMode::Plain));
                assert_eq!(args.script_timestamp, Some(ScriptTimestampFormat::Boot));
            }
            other => panic!("unexpected parse result: {other:?}"),
        }
    }
}

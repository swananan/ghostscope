use anyhow::Result;
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, ValueEnum)]
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

    /// Arguments to pass to the binary (use --args before binary and its arguments)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub args: bool,

    /// Log file path (default: ./ghostscope.log)
    #[arg(long, value_name = "PATH")]
    pub log_file: Option<PathBuf>,

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

    /// Process ID to attach to
    #[arg(long, short = 'p', value_name = "PID")]
    pub pid: Option<u32>,

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

    /// Remaining arguments (when using --args)
    pub remaining: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedArgs {
    pub binary_path: Option<String>,
    pub binary_args: Vec<String>,
    pub log_file: Option<PathBuf>,
    pub debug_file: Option<PathBuf>,
    pub script: Option<String>,
    pub script_file: Option<PathBuf>,
    pub pid: Option<u32>,
    pub tui_mode: bool,
    pub should_save_llvm_ir: bool,
    pub should_save_ebpf: bool,
    pub should_save_ast: bool,
    pub layout_mode: LayoutMode,
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

            ParsedArgs {
                binary_path,
                binary_args,
                log_file: parsed.log_file,
                debug_file: parsed.debug_file,
                script: parsed.script,
                script_file: parsed.script_file,
                pid: parsed.pid,
                tui_mode,
                should_save_llvm_ir,
                should_save_ebpf,
                should_save_ast,
                layout_mode: parsed.layout,
            }
        } else {
            // Normal parsing without --args
            let parsed = Args::parse();

            let should_save_llvm_ir = Self::should_save_llvm_ir(&parsed);
            let should_save_ebpf = Self::should_save_ebpf(&parsed);
            let should_save_ast = Self::should_save_ast(&parsed);
            let tui_mode = Self::determine_tui_mode(&parsed);

            ParsedArgs {
                binary_path: parsed.binary,
                binary_args: Vec::new(),
                log_file: parsed.log_file,
                debug_file: parsed.debug_file,
                script: parsed.script,
                script_file: parsed.script_file,
                pid: parsed.pid,
                tui_mode,
                should_save_llvm_ir,
                should_save_ebpf,
                should_save_ast,
                layout_mode: parsed.layout,
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
}

impl ParsedArgs {
    /// Validate command line arguments for consistency and completeness
    pub fn validate(&self) -> Result<()> {
        // Must have either PID or binary path for meaningful operation
        if self.pid.is_none() && self.binary_path.is_none() {
            warn!("No target PID or binary path specified - running in standalone mode");
        }

        // Cannot specify both PID and binary simultaneously
        if self.pid.is_some() && self.binary_path.is_some() {
            // TODO: actually we can
            return Err(anyhow::anyhow!(
                "Cannot specify both PID (-p) and binary path simultaneously. Choose one target method."
            ));
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

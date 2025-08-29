use clap::Parser;
use std::path::PathBuf;

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

    /// Script to execute (inline script or file path)
    #[arg(long, short = 's', value_name = "SCRIPT")]
    pub script: Option<String>,

    /// Script file path (alternative to inline script)
    #[arg(long, value_name = "PATH")]
    pub script_file: Option<PathBuf>,

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

    /// Remaining arguments (when using --args)
    pub remaining: Vec<String>,
}

#[derive(Debug)]
pub struct ParsedArgs {
    pub binary_path: Option<String>,
    pub binary_args: Vec<String>,
    pub log_file: Option<PathBuf>,
    pub debug_file: Option<PathBuf>,
    pub script: Option<String>,
    pub script_file: Option<PathBuf>,
    pub pid: Option<u32>,
    pub should_save_llvm_ir: bool,
    pub should_save_ebpf: bool,
    pub should_save_ast: bool,
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

            ParsedArgs {
                binary_path,
                binary_args,
                log_file: parsed.log_file,
                debug_file: parsed.debug_file,
                script: parsed.script,
                script_file: parsed.script_file,
                pid: parsed.pid,
                should_save_llvm_ir,
                should_save_ebpf,
                should_save_ast,
            }
        } else {
            // Normal parsing without --args
            let parsed = Args::parse();

            let should_save_llvm_ir = Self::should_save_llvm_ir(&parsed);
            let should_save_ebpf = Self::should_save_ebpf(&parsed);
            let should_save_ast = Self::should_save_ast(&parsed);

            ParsedArgs {
                binary_path: parsed.binary,
                binary_args: Vec::new(),
                log_file: parsed.log_file,
                debug_file: parsed.debug_file,
                script: parsed.script,
                script_file: parsed.script_file,
                pid: parsed.pid,
                should_save_llvm_ir,
                should_save_ebpf,
                should_save_ast,
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
}

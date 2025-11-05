use crate::core::session::GhostSession;
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, LeaveAlternateScreen};
use std::io::{self, Write};

/// Derive a short binary path hint for compiler options and logging.
/// Priority:
/// 1) If started with target file mode (-t), use the target binary's file stem.
/// 2) Else, use the main executable from the DWARF analyzer (file stem).
/// 3) Fallback to "unknown" if neither is available.
pub fn derive_binary_path_hint(session: &GhostSession) -> Option<String> {
    // Prefer explicit target in -t mode
    if session.is_target_mode() {
        if let Some(ref target) = session.target_binary {
            if let Some(stem) = std::path::Path::new(target)
                .file_stem()
                .and_then(|s| s.to_str())
            {
                return Some(stem.to_string());
            }
        }
    }

    // Fallback: main executable from analyzer (PID mode or resolved target)
    if let Some(main_module) = session
        .process_analyzer
        .as_ref()
        .and_then(|analyzer| analyzer.get_main_executable())
    {
        if let Some(stem) = std::path::Path::new(&main_module.path)
            .file_stem()
            .and_then(|s| s.to_str())
        {
            return Some(stem.to_string());
        }
    }

    // Final fallback to maintain previous behavior
    Some("unknown".to_string())
}

const CAP_SYS_ADMIN: i32 = 21;
const CAP_SYS_PTRACE: i32 = 19;
const CAP_BPF: i32 = 39;

fn has_capability(mask: u64, cap: i32) -> bool {
    if !(0..64).contains(&cap) {
        return false;
    }
    let bit = 1u64 << (cap as u64);
    mask & bit != 0
}

fn effective_capabilities() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

/// Ensure the current process has the privileges required for eBPF interaction.
/// Exits with an error message if neither root nor sufficient capabilities are present.
pub fn ensure_privileges() {
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        return;
    }

    let has_caps = effective_capabilities().is_some_and(|mask| {
        has_capability(mask, CAP_SYS_ADMIN)
            || (has_capability(mask, CAP_BPF) && has_capability(mask, CAP_SYS_PTRACE))
    });

    if has_caps {
        return;
    }

    eprintln!("GhostScope needs elevated privileges to load eBPF programs.");
    eprintln!("Options:");
    eprintln!("  • Run with sudo: sudo ghostscope ...");
    eprintln!("  • Or grant capabilities:");
    eprintln!("    sudo setcap cap_bpf,cap_sys_ptrace,cap_sys_admin+ep $(command -v ghostscope)");
    eprintln!(
        "Hint: verify that your kernel has CONFIG_BPF, CONFIG_BPF_SYSCALL, and CONFIG_UPROBE_EVENTS enabled."
    );
    std::process::exit(1);
}
/// Install a panic hook that restores terminal state and prints friendly diagnostics.
pub fn setup_panic_hook() {
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = io::stdout().flush();
        let _ = io::stderr().flush();

        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        let _ = io::stdout().flush();

        eprintln!("\n=== GHOSTSCOPE PANIC ===");
        let _ = io::stderr().flush();

        eprintln!(
            "Location: {}",
            panic_info
                .location()
                .unwrap_or_else(|| std::panic::Location::caller())
        );
        let _ = io::stderr().flush();

        if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            eprintln!("Message: {s}");
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            eprintln!("Message: {s}");
        } else {
            eprintln!("Message: (no message available)");
        }
        let _ = io::stderr().flush();

        eprintln!("\nBacktrace:");
        let _ = io::stderr().flush();

        let backtrace = std::backtrace::Backtrace::force_capture();
        eprintln!("{backtrace}");
        let _ = std::io::stderr().flush();

        eprintln!("======================");
        eprintln!("Terminal state has been restored. You can now see this panic message.");
        eprintln!("Please report this issue at: https://github.com/swananan/ghostscope/issues");
        let _ = std::io::stderr().flush();

        original_hook(panic_info);
    }));
}

/// Perform cleanup of pinned maps when the process exits.
pub extern "C" fn cleanup_pinned_maps_on_exit() {
    let _ = ghostscope_process::maps::cleanup_pinned_proc_offsets();
}

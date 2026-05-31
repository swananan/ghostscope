mod cli;
mod config;
mod core;
mod logging;
mod script;
mod source_path;
mod trace;
mod tui;
mod util;

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Setup panic hook before doing anything else
    crate::util::setup_panic_hook();

    // Parse command line arguments and route explicit maintenance commands
    let parsed_args = match config::Args::parse_args() {
        config::ParsedCommand::Trace(parsed_args) => *parsed_args,
        config::ParsedCommand::Bpffs(config::BpffsCommand::Prune(prune_args)) => {
            return cli::run_bpffs_prune(&prune_args);
        }
        config::ParsedCommand::ScriptHelp => {
            cli::print_script_help();
            return Ok(());
        }
    };

    // Load and merge configuration
    let config_path = parsed_args.config.clone();
    let user_config = match config::UserConfig::new_with_explicit_config(parsed_args, config_path) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("❌ Configuration Error:\n{e}");
            eprintln!("\n💡 Tips:");
            eprintln!("  • Check the example config.toml in the project root");
            eprintln!("  • Verify TOML syntax is correct");
            eprintln!("  • Ensure all values use the correct format");
            std::process::exit(1);
        }
    };

    if let Err(e) = logging::initialize_from_user_config(&user_config) {
        eprintln!("Failed to initialize logging: {e}");
        return Err(anyhow::anyhow!("Failed to initialize logging: {}", e));
    }

    info!("{}", user_config.config_source_message());

    // Dry-run does not attach uprobes, but it still validates the same eBPF
    // privileges and kernel capabilities as a real run.
    crate::util::ensure_privileges();
    let kernel_caps = ghostscope_loader::KernelCapabilities::detect_for_startup(
        user_config.ebpf_config.force_perf_event_array,
    )?;
    let resolved_config = config::ResolvedConfig::resolve(user_config, &kernel_caps)?;

    // Best-effort cleanup for this process's bpffs pins on graceful shutdown and panic unwind.
    let _pinned_maps_cleanup = crate::util::PinnedMapsCleanupGuard::new();

    // Route to appropriate runtime mode
    if resolved_config.tui_mode {
        tui::run_tui_coordinator_with_config(resolved_config).await
    } else {
        cli::run_command_line_runtime_with_config(resolved_config).await
    }
}

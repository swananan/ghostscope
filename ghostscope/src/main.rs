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
use ghostscope_process::{
    build_runtime_pid_plan, PidFilterSpec, PidModeFailFast, RuntimePidPlanInput,
};
use tracing::{info, warn};

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
    };

    // Load and merge configuration
    let config_path = parsed_args.config.clone();
    let mut merged_config =
        match config::MergedConfig::new_with_explicit_config(parsed_args, config_path) {
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

    // Initialize logging with full configuration
    let log_file_string = merged_config.log_file.to_string_lossy().to_string();
    let log_file_path = Some(log_file_string.as_str());
    if let Err(e) = logging::initialize_logging_with_config(
        log_file_path,
        merged_config.enable_logging,
        merged_config.enable_console_logging,
        merged_config.log_level,
        merged_config.tui_mode,
    ) {
        eprintln!("Failed to initialize logging: {e}");
        return Err(anyhow::anyhow!("Failed to initialize logging: {}", e));
    }

    // Log which configuration file was loaded (after logging is initialized)
    if let Some(config_path) = &merged_config.config_file_path {
        info!("Configuration loaded from: {}", config_path.display());
    } else {
        let home_hint = std::env::var("HOME").unwrap_or_else(|_| "(unset)".into());
        info!(
            "Using built-in defaults (no config found at {}/.ghostscope/config.toml or ./ghostscope.toml)",
            home_hint
        );
    }

    // Ensure we have the privileges needed for eBPF interaction
    crate::util::ensure_privileges();

    // Step 1 (PID/-t mode): detect runtime environment first (container/host/unknown).
    if merged_config.input_pid.is_some() || merged_config.target_path.is_some() {
        let env_info = config::detect_runtime_environment();
        info!(
            "Runtime environment detected: {}",
            env_info.compact_display()
        );
        merged_config.runtime_env = Some(env_info);
    }

    // Step 2 (PID mode): resolve PID mapping in the current namespace view.
    if let Some(input_pid) = merged_config.input_pid {
        let pid_views = config::resolve_input_pid(input_pid)?;
        merged_config.pid = Some(pid_views.proc_pid);
        merged_config.host_pid = Some(pid_views.host_pid);
        merged_config.pid_views = Some(pid_views.clone());
        info!("PID views resolved: {}", pid_views.compact_display());
    }

    // Detect kernel eBPF capabilities once at startup.
    let kernel_caps = if merged_config.ebpf_config.force_perf_event_array {
        warn!("⚠️  TESTING MODE: force_perf_event_array=true - will use PerfEventArray");
        info!("Skipping RingBuf detection, validating PerfEventArray support...");
        match ghostscope_loader::KernelCapabilities::get_perf_only() {
            Ok(kernel_caps) => {
                info!("Kernel eBPF capabilities:");
                info!(
                    "  PerfEventArray support: {}",
                    kernel_caps.supports_perf_event_array
                );
                info!(
                    "  bpf_get_ns_current_pid_tgid support: {}",
                    kernel_caps.supports_ns_current_pid_tgid_helper
                );
                kernel_caps
            }
            Err(err) => {
                eprintln!("Error: {err}");
                eprintln!("GhostScope requires Linux kernel >= 4.3 with PerfEventArray enabled.");
                std::process::exit(1);
            }
        }
    } else {
        match ghostscope_loader::KernelCapabilities::get() {
            Ok(kernel_caps) => {
                info!("Kernel eBPF capabilities:");
                info!("  RingBuf support: {}", kernel_caps.supports_ringbuf);
                info!(
                    "  bpf_get_ns_current_pid_tgid support: {}",
                    kernel_caps.supports_ns_current_pid_tgid_helper
                );

                if !kernel_caps.supports_ringbuf {
                    warn!("⚠️  Kernel does not support RingBuf (requires >= 5.8)");
                    warn!("⚠️  GhostScope will use PerfEventArray as fallback");
                }
                kernel_caps
            }
            Err(err) => {
                eprintln!("Error: {err}");
                eprintln!(
                    "GhostScope requires Linux kernel >= 4.3 with either RingBuf (>= 5.8) or PerfEventArray support."
                );
                eprintln!(
                    "Hint: ensure CONFIG_BPF, CONFIG_BPF_SYSCALL and CONFIG_UPROBE_EVENTS are enabled in your kernel."
                );
                std::process::exit(1);
            }
        }
    };

    let helper_supported = kernel_caps.supports_ns_current_pid_tgid_helper;
    let in_container = merged_config
        .runtime_env
        .as_ref()
        .map(|env| env.is_container_likely())
        .unwrap_or(false);
    let self_pid_views = if helper_supported && in_container {
        let self_pid = std::process::id();
        match config::resolve_input_pid(self_pid) {
            Ok(pid_views) => Some(pid_views),
            Err(err) => {
                warn!(
                    "Failed to resolve self PID namespace context (self pid={}): {}",
                    self_pid, err
                );
                None
            }
        }
    } else {
        None
    };

    let runtime_pid_plan = match build_runtime_pid_plan(RuntimePidPlanInput {
        target_pid_views: merged_config.pid_views.as_ref(),
        self_pid_views: self_pid_views.as_ref(),
        in_container,
        helper_supported,
    }) {
        Ok(plan) => plan,
        Err(PidModeFailFast { proc_pid }) => {
            return Err(anyhow::anyhow!(
                "PID filtering with -p is not reliable in this container environment. \
                 Kernel helper bpf_get_ns_current_pid_tgid is unavailable and NSpid does not expose \
                 an explicit host PID mapping for -p {}.\n\
                 Please use target mode (-t <binary_path>) instead of -p in this environment.",
                proc_pid
            ));
        }
    };

    merged_config.pid_filter_spec = runtime_pid_plan.pid_filter;
    merged_config.special_pid_ns = runtime_pid_plan.special_vars_pid_ns;
    merged_config.proc_offsets_pid_ns = runtime_pid_plan.proc_offsets_pid_ns;

    if let Some(pid_views) = merged_config.pid_views.as_ref() {
        let ns_context_needed =
            pid_views.host_pid != pid_views.proc_pid || (in_container && helper_supported);
        match runtime_pid_plan.pid_filter {
            Some(PidFilterSpec::NamespaceTgid { filter_pid, pid_ns }) => {
                let (pid_ns_dev, pid_ns_inode) = pid_ns
                    .helper_dev_inode()
                    .expect("helper PID namespace id must include device id");
                info!(
                    "PID filter strategy selected: ns-helper (filter_pid={} ns_dev={} ns_inode={})",
                    filter_pid, pid_ns_dev, pid_ns_inode
                );
            }
            Some(PidFilterSpec::HostTgid { filter_pid }) => {
                if ns_context_needed && helper_supported && pid_views.pid_ns.is_some() {
                    warn!(
                        "PID filter strategy fallback: missing pid namespace dev/inode, using host-mapped host_pid={}",
                        filter_pid
                    );
                } else if in_container && !helper_supported && pid_views.is_initial_pid_namespace()
                {
                    info!(
                        "PID filter strategy fallback allowed: helper unavailable, but target remains in the initial PID namespace"
                    );
                }
                info!(
                    "PID filter strategy selected: host-mapped (host_pid={})",
                    filter_pid
                );
            }
            None => {}
        }

        if let Some(pid_ns) = runtime_pid_plan.special_vars_pid_ns {
            let (pid_ns_dev, pid_ns_inode) = pid_ns
                .helper_dev_inode()
                .expect("helper PID namespace id must include device id");
            info!(
                "Special var PID namespace configured from target mapping: ns_dev={} ns_inode={}",
                pid_ns_dev, pid_ns_inode
            );
        }

        if let Some(pid_ns) = runtime_pid_plan.proc_offsets_pid_ns {
            let (pid_ns_dev, pid_ns_inode) = pid_ns
                .helper_dev_inode()
                .expect("helper PID namespace id must include device id");
            info!(
                "proc_module_offsets PID namespace configured from target mapping: ns_dev={} ns_inode={}",
                pid_ns_dev, pid_ns_inode
            );
        } else if helper_supported && pid_views.pid_ns.is_some() {
            info!(
                "proc_module_offsets remains on GhostScope /proc PID view because target-namespace filtering is not active for this session"
            );
        }
    } else if helper_supported && in_container {
        let self_pid = std::process::id();
        if let Some(pid_ns) = runtime_pid_plan.special_vars_pid_ns {
            let (pid_ns_dev, pid_ns_inode) = pid_ns
                .helper_dev_inode()
                .expect("helper PID namespace id must include device id");
            info!(
                "Special var PID namespace configured from self PID {}: ns_dev={} ns_inode={}",
                self_pid, pid_ns_dev, pid_ns_inode
            );
        } else {
            warn!(
                "Could not derive self pid namespace dev/inode for special vars (self pid={})",
                self_pid
            );
        }

        if let Some(pid_ns) = runtime_pid_plan.proc_offsets_pid_ns {
            let (pid_ns_dev, pid_ns_inode) = pid_ns
                .helper_dev_inode()
                .expect("helper PID namespace id must include device id");
            info!(
                "proc_module_offsets PID namespace configured from self PID {}: ns_dev={} ns_inode={}",
                self_pid,
                pid_ns_dev,
                pid_ns_inode
            );
        } else if self_pid_views
            .as_ref()
            .and_then(|pid_views| pid_views.pid_ns)
            .is_some()
        {
            warn!(
                "Could not derive self pid namespace dev/inode for proc_module_offsets (self pid={})",
                self_pid
            );
        }
    }

    // Validate core arguments (TODO: move validation to MergedConfig)
    // For now, create a temporary ParsedArgs for validation
    let temp_args = config::ParsedArgs {
        binary_path: merged_config.binary_path.clone(),
        target_path: merged_config.target_path.clone(),
        binary_args: merged_config.binary_args.clone(),
        log_file: Some(merged_config.log_file.clone()),
        emit_ready_marker: merged_config.emit_ready_marker.clone(),
        enable_logging: merged_config.enable_logging,
        enable_console_logging: merged_config.enable_console_logging,
        log_level: merged_config.log_level,
        config: None, // Not needed for validation
        debug_file: merged_config.debug_file.clone(),
        script: merged_config.script.clone(),
        script_file: merged_config.script_file.clone(),
        pid: merged_config.pid,
        tui_mode: merged_config.tui_mode,
        script_output: Some(merged_config.script_output_mode),
        script_timestamp: Some(merged_config.script_timestamp_format),
        should_save_llvm_ir: merged_config.should_save_llvm_ir,
        should_save_ebpf: merged_config.should_save_ebpf,
        should_save_ast: merged_config.should_save_ast,
        layout_mode: merged_config.layout_mode,
        has_explicit_log_flag: false, // Not needed for validation
        has_explicit_console_log_flag: false, // Not needed for validation
        force_perf_event_array: merged_config.ebpf_config.force_perf_event_array,
        enable_sysmon_for_shared_lib: merged_config.ebpf_config.enable_sysmon_for_shared_lib,
        allow_loose_debug_match: merged_config.dwarf_allow_loose_debug_match,
        source_panel: false,
        no_source_panel: false,
    };
    temp_args.validate()?;

    // Best-effort cleanup for this process's bpffs pins on graceful shutdown and panic unwind.
    let _pinned_maps_cleanup = crate::util::PinnedMapsCleanupGuard::new();

    // Route to appropriate runtime mode
    if merged_config.tui_mode {
        tui::run_tui_coordinator_with_config(merged_config).await
    } else {
        cli::run_command_line_runtime_with_config(merged_config).await
    }
}

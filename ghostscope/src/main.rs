mod cli;
mod config;
mod core;
mod logging;
mod pid;
mod runtime;
mod script;
mod tracing;
mod util;

use anyhow::Result;
// Use external tracing crate (not the local tracing module)
use ::tracing::{info, warn};
use libc as c;

fn pid_ns_context_needed(
    mapping: &config::ResolvedPidInfo,
    in_container: bool,
    helper_supported: bool,
) -> bool {
    // We need namespace-aware filtering in two cases:
    // 1) visible PID and host PID differ (cross-namespace mapping is explicit),
    // 2) running in container and helper is available, even if NSpid only has one value.
    //    In private PID namespaces, single-value NSpid cannot prove host TGID equality.
    mapping.host_pid != mapping.process_pid || (in_container && helper_supported)
}

fn should_fail_fast_pid_mode(
    mapping: &config::ResolvedPidInfo,
    in_container: bool,
    helper_supported: bool,
) -> bool {
    in_container
        && !helper_supported
        && !mapping.has_explicit_host_mapping()
        && !mapping.is_initial_pid_namespace()
}

#[tokio::main]
async fn main() -> Result<()> {
    // Setup panic hook before doing anything else
    crate::util::setup_panic_hook();

    // Parse command line arguments
    let parsed_args = config::Args::parse_args();

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

    // Register atexit cleanup for pinned maps (per-process path)
    unsafe {
        c::atexit(crate::util::cleanup_pinned_maps_on_exit);
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

    match ghostscope_process::pinned_bpf_maps::cleanup_stale_pinned_maps_root() {
        Ok(0) => {}
        Ok(removed) => info!("Removed {removed} stale pinned map directories from bpffs"),
        Err(err) => warn!("Failed to clean stale pinned map directories from bpffs: {err}"),
    }

    // Step 1 (PID/-t mode): detect runtime environment first (container/host/unknown).
    if merged_config.pid.is_some() || merged_config.target_path.is_some() {
        let env_info = config::detect_runtime_environment();
        info!(
            "Runtime environment detected: {}",
            env_info.compact_display()
        );
        merged_config.runtime_env = Some(env_info);
    }

    // Step 2 (PID mode): resolve PID mapping in the current namespace view.
    if let Some(input_pid) = merged_config.pid {
        let resolved = config::resolve_pid_info(input_pid)?;
        merged_config.pid = Some(resolved.process_pid);
        merged_config.host_pid = Some(resolved.host_pid);
        merged_config.pid_mapping = Some(resolved.clone());
        info!("PID mapping resolved: {}", resolved.compact_display());
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

    // PID mode: choose PID filter strategy (helper preferred, then host mapping fallback).
    if let Some(mapping) = merged_config.pid_mapping.clone() {
        let helper_supported = kernel_caps.supports_ns_current_pid_tgid_helper;
        let in_container = merged_config
            .runtime_env
            .as_ref()
            .map(|env| env.is_container_likely())
            .unwrap_or(false);

        if should_fail_fast_pid_mode(&mapping, in_container, helper_supported) {
            return Err(anyhow::anyhow!(
                "PID filtering with -p is not reliable in this container environment. \
                 Kernel helper bpf_get_ns_current_pid_tgid is unavailable and NSpid does not expose \
                 an explicit host PID mapping for -p {}.\n\
                 Please use target mode (-t <binary_path>) instead of -p in this environment.",
                mapping.process_pid
            ));
        }

        let ns_context_needed = pid_ns_context_needed(&mapping, in_container, helper_supported);

        if ns_context_needed && helper_supported {
            if let (Some(pid_ns_dev), Some(pid_ns_inode)) =
                (mapping.pid_ns_dev, mapping.pid_ns_inode)
            {
                merged_config.pid_filter_spec =
                    Some(ghostscope_compiler::PidFilterSpec::NamespaceTgid {
                        target_pid: mapping.process_pid,
                        pid_ns_dev,
                        pid_ns_inode,
                    });
                info!(
                    "PID filter strategy selected: ns-helper (target_pid={} ns_dev={} ns_inode={})",
                    mapping.process_pid, pid_ns_dev, pid_ns_inode
                );
            } else {
                merged_config.pid_filter_spec =
                    Some(ghostscope_compiler::PidFilterSpec::HostTgid {
                        target_pid: mapping.host_pid,
                    });
                warn!(
                    "PID filter strategy fallback: missing pid namespace dev/inode, using host-mapped host_pid={}",
                    mapping.host_pid
                );
            }
        } else {
            if in_container && !helper_supported && mapping.is_initial_pid_namespace() {
                info!(
                    "PID filter strategy fallback allowed: helper unavailable, but target remains in the initial PID namespace"
                );
            }
            merged_config.pid_filter_spec = Some(ghostscope_compiler::PidFilterSpec::HostTgid {
                target_pid: mapping.host_pid,
            });
            info!(
                "PID filter strategy selected: host-mapped (host_pid={})",
                mapping.host_pid
            );
        }
    }

    // Configure namespace context for special vars ($pid/$tid), independent of PID filtering.
    // In -p mode prefer resolved target namespace; in -t container mode fallback to current process namespace.
    if kernel_caps.supports_ns_current_pid_tgid_helper {
        if let Some(mapping) = merged_config.pid_mapping.as_ref() {
            if let (Some(pid_ns_dev), Some(pid_ns_inode)) =
                (mapping.pid_ns_dev, mapping.pid_ns_inode)
            {
                merged_config.special_pid_ns = Some(ghostscope_compiler::PidNamespaceSpec {
                    pid_ns_dev,
                    pid_ns_inode,
                });
                info!(
                    "Special var PID namespace configured from target mapping: ns_dev={} ns_inode={}",
                    pid_ns_dev, pid_ns_inode
                );
            }
        } else if merged_config
            .runtime_env
            .as_ref()
            .map(|env| env.is_container_likely())
            .unwrap_or(false)
        {
            let self_pid = std::process::id();
            match config::resolve_pid_info(self_pid) {
                Ok(self_info) => {
                    if let (Some(pid_ns_dev), Some(pid_ns_inode)) =
                        (self_info.pid_ns_dev, self_info.pid_ns_inode)
                    {
                        merged_config.special_pid_ns =
                            Some(ghostscope_compiler::PidNamespaceSpec {
                                pid_ns_dev,
                                pid_ns_inode,
                            });
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
                }
                Err(err) => {
                    warn!(
                        "Failed to resolve self PID namespace for special vars (self pid={}): {}",
                        self_pid, err
                    );
                }
            }
        }
    }

    // Configure namespace context for proc_module_offsets lookups.
    //
    // This intentionally follows GhostScope's own `/proc` view rather than the
    // target namespace used by `$pid`/`$tid`. Offsets are computed from
    // `/proc/<proc_pid>/maps`, so the lookup key must use the same PID view:
    //
    // - host GhostScope => host TGID key
    // - container GhostScope => self namespace TGID key
    //
    // Reusing the target namespace here breaks host -> private-container
    // tracing, because userspace inserts offsets under host PIDs while eBPF
    // would look them up under namespace-local PIDs.
    if kernel_caps.supports_ns_current_pid_tgid_helper
        && merged_config
            .runtime_env
            .as_ref()
            .map(|env| env.is_container_likely())
            .unwrap_or(false)
    {
        let self_pid = std::process::id();
        match config::resolve_pid_info(self_pid) {
            Ok(self_info) => {
                if let (Some(pid_ns_dev), Some(pid_ns_inode)) =
                    (self_info.pid_ns_dev, self_info.pid_ns_inode)
                {
                    merged_config.proc_offsets_pid_ns =
                        Some(ghostscope_compiler::PidNamespaceSpec {
                            pid_ns_dev,
                            pid_ns_inode,
                        });
                    info!(
                        "proc_module_offsets PID namespace configured from self PID {}: ns_dev={} ns_inode={}",
                        self_pid, pid_ns_dev, pid_ns_inode
                    );
                } else {
                    warn!(
                        "Could not derive self pid namespace dev/inode for proc_module_offsets (self pid={})",
                        self_pid
                    );
                }
            }
            Err(err) => {
                warn!(
                    "Failed to resolve self PID namespace for proc_module_offsets (self pid={}): {}",
                    self_pid, err
                );
            }
        }
    }

    // Validate core arguments (TODO: move validation to MergedConfig)
    // For now, create a temporary ParsedArgs for validation
    let temp_args = config::ParsedArgs {
        binary_path: merged_config.binary_path.clone(),
        target_path: merged_config.target_path.clone(),
        binary_args: merged_config.binary_args.clone(),
        log_file: Some(merged_config.log_file.clone()),
        enable_logging: merged_config.enable_logging,
        enable_console_logging: merged_config.enable_console_logging,
        log_level: merged_config.log_level,
        config: None, // Not needed for validation
        debug_file: merged_config.debug_file.clone(),
        script: merged_config.script.clone(),
        script_file: merged_config.script_file.clone(),
        pid: merged_config.pid,
        tui_mode: merged_config.tui_mode,
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

    // Route to appropriate runtime mode
    if merged_config.tui_mode {
        runtime::run_tui_coordinator_with_config(merged_config).await
    } else {
        cli::run_command_line_runtime_with_config(merged_config).await
    }
}

#[cfg(test)]
mod tests {
    use super::{pid_ns_context_needed, should_fail_fast_pid_mode};
    use crate::config::ResolvedPidInfo;
    use crate::pid::PidResolveSource;

    fn make_mapping(process_pid: u32, host_pid: u32) -> ResolvedPidInfo {
        ResolvedPidInfo {
            input_pid: process_pid,
            process_pid,
            host_pid,
            container_pid: None,
            pid_ns_dev: None,
            pid_ns_inode: None,
            nspid_chain: None,
            source: PidResolveSource::DirectProcStatus,
        }
    }

    #[test]
    fn pid_ns_context_not_needed_when_pids_match() {
        assert!(!pid_ns_context_needed(
            &make_mapping(321, 321),
            false,
            false
        ));
        assert!(!pid_ns_context_needed(&make_mapping(321, 321), true, false));
    }

    #[test]
    fn pid_ns_context_needed_when_pids_differ() {
        assert!(pid_ns_context_needed(&make_mapping(1, 4321), false, false));
    }

    #[test]
    fn pid_ns_context_needed_in_container_when_helper_available_even_if_pids_match() {
        assert!(pid_ns_context_needed(&make_mapping(321, 321), true, true));
    }

    #[test]
    fn pid_ns_context_not_needed_outside_container_when_pids_match_even_if_helper_available() {
        assert!(!pid_ns_context_needed(&make_mapping(321, 321), false, true));
    }

    #[test]
    fn fail_fast_in_container_without_helper_and_explicit_host_mapping() {
        assert!(should_fail_fast_pid_mode(
            &make_mapping(321, 321),
            true,
            false
        ));
    }

    #[test]
    fn fail_fast_not_needed_when_helper_or_explicit_mapping_available() {
        assert!(!should_fail_fast_pid_mode(
            &make_mapping(321, 321),
            true,
            true
        ));

        let mut explicit = make_mapping(321, 321);
        explicit.nspid_chain = Some(vec![12345, 321]);
        assert!(!should_fail_fast_pid_mode(&explicit, true, false));
    }

    #[test]
    fn fail_fast_not_needed_in_initial_pid_namespace_without_helper() {
        let mut host_pid_ns = make_mapping(321, 321);
        host_pid_ns.pid_ns_inode = Some(crate::pid::INITIAL_PID_NAMESPACE_INO);
        assert!(!should_fail_fast_pid_mode(&host_pid_ns, true, false));
    }
}

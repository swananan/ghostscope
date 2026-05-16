use std::ops::Deref;

use anyhow::Result;
use ghostscope_loader::KernelCapabilities;
use ghostscope_process::{
    resolve_pid_session, PidFilterSpec, PidNamespaceId, PidViews, ResolvePidSessionError,
    ResolvedPidSession, RuntimeEnvironmentInfo,
};
use tracing::{info, warn};

use crate::config::{LayoutMode, UserConfig};

#[derive(Debug, Clone, Default)]
pub struct RuntimeContext {
    pub proc_pid: Option<u32>,
    pub host_pid: Option<u32>,
    pub pid_views: Option<PidViews>,
    pub runtime_env: RuntimeEnvironmentInfo,
    pub pid_filter_spec: Option<PidFilterSpec>,
    pub special_pid_ns: Option<PidNamespaceId>,
    pub proc_offsets_pid_ns: Option<PidNamespaceId>,
}

impl RuntimeContext {
    pub fn resolve(user_config: &UserConfig, kernel_caps: &KernelCapabilities) -> Result<Self> {
        let helper_supported = kernel_caps.supports_ns_current_pid_tgid_helper;
        let pid_session = resolve_pid_session(user_config.input_pid, helper_supported)
            .map_err(map_pid_session_error)?;

        let runtime = Self {
            proc_pid: pid_session
                .target_pid_views
                .as_ref()
                .map(|pid_views| pid_views.proc_pid),
            host_pid: pid_session
                .target_pid_views
                .as_ref()
                .map(|pid_views| pid_views.host_pid),
            pid_views: pid_session.target_pid_views.clone(),
            runtime_env: pid_session.runtime_env.clone(),
            pid_filter_spec: pid_session.runtime_pid_plan.pid_filter,
            special_pid_ns: pid_session.runtime_pid_plan.special_vars_pid_ns,
            proc_offsets_pid_ns: pid_session.runtime_pid_plan.proc_offsets_pid_ns,
        };

        runtime.log_resolution(&pid_session, helper_supported);
        // Successful PID resolution already proved `/proc/<pid>` exists, so validation can skip
        // the duplicate liveness check on that path.
        user_config.validate_with_pid_state(
            user_config.input_pid.is_some() && runtime.pid_views.is_some(),
        )?;

        Ok(runtime)
    }

    fn log_resolution(&self, pid_session: &ResolvedPidSession, helper_supported: bool) {
        let in_container = self.runtime_env.is_container_likely();
        info!(
            "Runtime environment detected: {}",
            self.runtime_env.compact_display()
        );

        if let Some(pid_views) = self.pid_views.as_ref() {
            info!("PID views resolved: {}", pid_views.compact_display());

            let ns_context_needed =
                pid_views.host_pid != pid_views.proc_pid || (in_container && helper_supported);

            match self.pid_filter_spec {
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
                    } else if in_container
                        && !helper_supported
                        && pid_views.is_initial_pid_namespace()
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

            if let Some(pid_ns) = self.special_pid_ns {
                let (pid_ns_dev, pid_ns_inode) = pid_ns
                    .helper_dev_inode()
                    .expect("helper PID namespace id must include device id");
                info!(
                    "Special var PID namespace configured from target mapping: ns_dev={} ns_inode={}",
                    pid_ns_dev, pid_ns_inode
                );
            }

            if let Some(pid_ns) = self.proc_offsets_pid_ns {
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
            if let Some(pid_ns) = self.special_pid_ns {
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

            if let Some(pid_ns) = self.proc_offsets_pid_ns {
                let (pid_ns_dev, pid_ns_inode) = pid_ns
                    .helper_dev_inode()
                    .expect("helper PID namespace id must include device id");
                info!(
                    "proc_module_offsets PID namespace configured from self PID {}: ns_dev={} ns_inode={}",
                    self_pid, pid_ns_dev, pid_ns_inode
                );
            } else if pid_session
                .self_pid_views
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
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub user: UserConfig,
    pub runtime: RuntimeContext,
    pub kernel_capabilities: KernelCapabilities,
}

impl ResolvedConfig {
    pub fn resolve(user: UserConfig, kernel_caps: &KernelCapabilities) -> Result<Self> {
        let runtime = RuntimeContext::resolve(&user, kernel_caps)?;
        Ok(Self {
            user,
            runtime,
            kernel_capabilities: *kernel_caps,
        })
    }

    pub fn get_ui_config(&self) -> ghostscope_ui::UiConfig {
        ghostscope_ui::UiConfig {
            layout_mode: match self.layout_mode {
                LayoutMode::Horizontal => ghostscope_ui::LayoutMode::Horizontal,
                LayoutMode::Vertical => ghostscope_ui::LayoutMode::Vertical,
            },
            panel_ratios: self.panel_ratios,
            show_source_panel: self.show_source_panel,
            two_panel_ratios: self.two_panel_ratios,
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

    pub fn get_compile_options(
        &self,
        save_llvm_ir: bool,
        save_ebpf: bool,
        save_ast: bool,
        binary_path_hint: Option<String>,
    ) -> ghostscope_compiler::CompileOptions {
        let event_map_type = if self.ebpf_config.force_perf_event_array {
            ::tracing::warn!(
                "⚠️  TESTING MODE: force_perf_event_array=true in config - using PerfEventArray"
            );
            ghostscope_compiler::EventMapType::PerfEventArray
        } else if self.kernel_capabilities.supports_ringbuf {
            ghostscope_compiler::EventMapType::RingBuf
        } else {
            ghostscope_compiler::EventMapType::PerfEventArray
        };

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
            target_binary_path: self.target_path.clone(),
            ringbuf_size: self.ebpf_config.ringbuf_size,
            proc_module_offsets_max_entries: self.ebpf_config.proc_module_offsets_max_entries,
            perf_page_count: self.ebpf_config.perf_page_count,
            event_map_type,
            mem_dump_cap: self.ebpf_config.mem_dump_cap,
            compare_cap: self.ebpf_config.compare_cap,
            max_trace_event_size: effective_max_event,
            selected_index: None,
            pid_filter_spec: self.runtime.pid_filter_spec,
            special_pid_ns: self.runtime.special_pid_ns,
            proc_offsets_pid_ns: self.runtime.proc_offsets_pid_ns,
            input_pid: self.input_pid,
            runtime_capabilities: dwarf_runtime_capabilities_from_kernel(&self.kernel_capabilities),
        }
    }
}

fn dwarf_runtime_capabilities_from_kernel(
    kernel_caps: &KernelCapabilities,
) -> ghostscope_compiler::RuntimeCapabilities {
    ghostscope_compiler::RuntimeCapabilities {
        regular_uprobe: kernel_caps.supports_ringbuf || kernel_caps.supports_perf_event_array,
        ..Default::default()
    }
}

impl Deref for ResolvedConfig {
    type Target = UserConfig;

    fn deref(&self) -> &Self::Target {
        &self.user
    }
}

fn map_pid_session_error(err: ResolvePidSessionError) -> anyhow::Error {
    match err {
        ResolvePidSessionError::Resolve(err) => err,
        ResolvePidSessionError::FailFast(ghostscope_process::PidModeFailFast { proc_pid }) => {
            anyhow::anyhow!(
                "PID filtering with -p is not reliable in this container environment. \
                 Kernel helper bpf_get_ns_current_pid_tgid is unavailable and NSpid does not expose \
                 an explicit host PID mapping for -p {}.\n\
                 Please use target mode (-t <binary_path>) instead of -p in this environment.",
                proc_pid
            )
        }
    }
}

use crate::config::{ParsedArgs, PidViews, ResolvedConfig};
use crate::source_path::SourcePathResolver;
use crate::trace::backtrace_runtime::{
    BacktraceRuntimeModuleObservation, BacktraceRuntimeModuleResolution, BacktraceRuntimeRunner,
    ResolvedBacktraceRuntimeModule,
};
use crate::trace::TraceManager;
use anyhow::Result;
use futures::FutureExt;
use ghostscope_debuginfod::{DebuginfodClient, DebuginfodConfig};
use ghostscope_dwarf::{DwarfAnalyzer, ExplicitDebugFile, ModuleStats, RuntimeBacktraceLoadBudget};
use ghostscope_process::{
    PidFilterSpec, PidNamespaceId, ProcessManager, ProcessSysmon, SysmonConfig, SysmonEventMask,
};
use ghostscope_protocol::{ParsedInstruction, ParsedTraceEvent};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

const BACKTRACE_RUNTIME_MODULE_DISCOVERY_GRACE: Duration = Duration::from_millis(500);
const BACKTRACE_RUNTIME_OBSERVATION_REQUEST_MAX: usize = 1_024;
const BACKTRACE_RUNTIME_OBSERVATION_RETRY_DELAY: Duration = Duration::from_secs(1);
const BACKTRACE_RUNTIME_OBSERVATION_MAX_ATTEMPTS: u8 = 3;

#[derive(Debug)]
struct BacktraceObservationState {
    mapping: Option<(u32, ghostscope_process::PidOffsetsEntry)>,
    attempts: u8,
    retry_at: Option<Instant>,
}

impl BacktraceObservationState {
    fn should_retry(
        &self,
        mapping: &Option<(u32, ghostscope_process::PidOffsetsEntry)>,
        now: Instant,
    ) -> bool {
        self.mapping != *mapping || self.retry_at.is_some_and(|retry_at| now >= retry_at)
    }

    fn finish(&mut self, terminal: bool, now: Instant) {
        self.retry_at = if terminal || self.attempts >= BACKTRACE_RUNTIME_OBSERVATION_MAX_ATTEMPTS {
            None
        } else {
            Some(now + BACKTRACE_RUNTIME_OBSERVATION_RETRY_DELAY * (1 << (self.attempts - 1)))
        };
    }
}

fn observation_mapping(
    coordinator: &ProcessManager,
    proc_pid: Option<u32>,
    observation: BacktraceRuntimeModuleObservation,
) -> Option<(u32, ghostscope_process::PidOffsetsEntry)> {
    for pid in coordinator.candidate_proc_pids_for_runtime_pid(observation.runtime_pid, proc_pid) {
        if let Some(entry) =
            coordinator
                .cached_offsets_with_paths_for_pid(pid)
                .and_then(|entries| {
                    entries.iter().find(|entry| {
                        if observation.raw_ip == 0 {
                            entry.cookie == observation.cookie_hint
                        } else {
                            observation.raw_ip >= entry.base
                                && observation.raw_ip < entry.base.saturating_add(entry.size)
                        }
                    })
                })
        {
            return Some((pid, entry.clone()));
        }
    }
    None
}

#[derive(Debug, Clone, Default)]
pub struct BacktraceRuntimeModuleRequest {
    pub observations: BTreeSet<BacktraceRuntimeModuleObservation>,
}

impl BacktraceRuntimeModuleRequest {
    pub fn from_events(events: &[ParsedTraceEvent]) -> Self {
        let mut request = Self::default();
        for event in events {
            for instruction in &event.instructions {
                let ParsedInstruction::Backtrace { status, frames, .. } = instruction else {
                    continue;
                };
                let requests_runtime_module = matches!(
                    status,
                    ghostscope_protocol::trace_event::BacktraceStatus::DwarfUnavailable
                        | ghostscope_protocol::trace_event::BacktraceStatus::UnsupportedCfi
                        | ghostscope_protocol::trace_event::BacktraceStatus::OffsetsUnavailable
                        | ghostscope_protocol::trace_event::BacktraceStatus::NoUnwindRowsForPc
                );
                if !requests_runtime_module {
                    continue;
                }
                let Some(stopping_frame_index) = frames.len().checked_sub(1) else {
                    continue;
                };
                let offsets_unavailable = matches!(
                    status,
                    ghostscope_protocol::trace_event::BacktraceStatus::OffsetsUnavailable
                );
                for (frame_index, frame) in frames.iter().enumerate() {
                    let is_stopping_frame = frame_index == stopping_frame_index;
                    // Missing offsets can leave earlier, otherwise unwindable
                    // frames without a published runtime mapping. Preserve
                    // their exact PID/raw-IP/cookie tuples so each module can
                    // be recovered without mixing identities across frames.
                    if !offsets_unavailable && !is_stopping_frame {
                        continue;
                    }
                    let observation = BacktraceRuntimeModuleObservation {
                        runtime_pid: event.pid,
                        raw_ip: frame.raw_ip,
                        cookie_hint: frame.module_cookie,
                        // For an offsets failure only the stopping frame may
                        // retain the previous frame's cookie. Earlier frames,
                        // and all other failure modes, carry their own cookie.
                        cookie_is_authoritative: !offsets_unavailable || !is_stopping_frame,
                    };
                    if !observation.is_empty() {
                        request.observations.insert(observation);
                    }
                }
            }
        }
        request
    }

    pub fn is_empty(&self) -> bool {
        self.observations.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BacktraceRuntimeRefreshSchedule {
    NotNeeded,
    Disabled,
    Queued { modules: usize },
    Started { timeout: Duration },
}

#[derive(Debug)]
pub enum BacktraceRuntimeRefreshOutcome {
    Loaded {
        modules: usize,
        unwind_rows: usize,
        next_started: bool,
    },
    ModuleNotFound {
        next_started: bool,
    },
    Failed {
        error: String,
        next_started: bool,
    },
    TimedOut {
        timeout: Duration,
    },
    LimitReached {
        limit: u32,
    },
}

#[derive(Debug)]
enum BacktraceRuntimeRefreshTaskOutcome {
    Prepared(BacktraceRuntimePreparedOutcome),
    Published {
        resolved: ResolvedBacktraceRuntimeModule,
        runtime_symbols: Vec<ghostscope_dwarf::RuntimeTextSymbol>,
        append_result: crate::trace::manager::BacktraceUnwindRowsAppendResult,
    },
}

#[derive(Debug)]
enum BacktraceRuntimePreparedOutcome {
    Loaded {
        resolved: ResolvedBacktraceRuntimeModule,
        runtime_symbols: Vec<ghostscope_dwarf::RuntimeTextSymbol>,
        unwind_modules: Vec<(u64, Vec<ghostscope_protocol::BacktraceUnwindRow>)>,
    },
    AlreadyLoaded(ResolvedBacktraceRuntimeModule),
    AlreadyAttempted(ResolvedBacktraceRuntimeModule),
    ModuleNotFound,
    Failed {
        attempted_cookie: Option<u64>,
        error: String,
    },
    TimedOut {
        attempted_cookie: Option<u64>,
    },
    LimitReached {
        limit: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BacktraceRuntimeModuleLoadDecision {
    Load,
    AlreadyLoaded,
    AlreadyAttempted,
    LimitReached,
}

fn backtrace_runtime_module_load_decision(
    cookie: u64,
    known_cookies: &BTreeSet<u64>,
    attempted_cookies: &BTreeSet<u64>,
    module_limit: u32,
) -> BacktraceRuntimeModuleLoadDecision {
    if known_cookies.contains(&cookie) {
        BacktraceRuntimeModuleLoadDecision::AlreadyLoaded
    } else if attempted_cookies.contains(&cookie) {
        BacktraceRuntimeModuleLoadDecision::AlreadyAttempted
    } else if attempted_cookies.len() >= module_limit as usize {
        BacktraceRuntimeModuleLoadDecision::LimitReached
    } else {
        BacktraceRuntimeModuleLoadDecision::Load
    }
}

#[derive(Debug)]
struct BacktraceRuntimeRefreshTask {
    observation: BacktraceRuntimeModuleObservation,
    timeout: Duration,
    budget: RuntimeBacktraceLoadBudget,
    baseline: Arc<ProcessManager>,
    handle: tokio::task::JoinHandle<BacktraceRuntimeRefreshTaskOutcome>,
    result: Option<BacktraceRuntimeRefreshTaskOutcome>,
}

#[allow(clippy::too_many_arguments)]
fn prepare_backtrace_runtime_module(
    mut coordinator: ProcessManager,
    proc_pid: Option<u32>,
    target_binary: Option<&str>,
    observation: BacktraceRuntimeModuleObservation,
    known_cookies: &BTreeSet<u64>,
    attempted_cookies: &BTreeSet<u64>,
    module_limit: u32,
    max_unwind_rows: usize,
    budget: &RuntimeBacktraceLoadBudget,
) -> BacktraceRuntimePreparedOutcome {
    let discovery_deadline = Instant::now() + BACKTRACE_RUNTIME_MODULE_DISCOVERY_GRACE;
    let mut resolved = loop {
        if budget.check().is_err() {
            return BacktraceRuntimePreparedOutcome::TimedOut {
                attempted_cookie: None,
            };
        }

        let resolution = {
            if let Some(proc_pid) = proc_pid {
                BacktraceRuntimeRunner::resolve_pid_module_for_observation(
                    &mut coordinator,
                    proc_pid,
                    observation,
                )
            } else if let Some(target_binary) = target_binary {
                BacktraceRuntimeRunner::resolve_target_module_for_observation(
                    &mut coordinator,
                    target_binary,
                    observation,
                    true,
                )
            } else {
                BacktraceRuntimeModuleResolution::Unavailable
            }
        };
        match resolution {
            BacktraceRuntimeModuleResolution::Resolved(resolved) => break resolved,
            BacktraceRuntimeModuleResolution::IdentityChanged => {
                return BacktraceRuntimePreparedOutcome::ModuleNotFound;
            }
            BacktraceRuntimeModuleResolution::Unavailable => {}
        }
        let now = Instant::now();
        if now >= discovery_deadline {
            return BacktraceRuntimePreparedOutcome::ModuleNotFound;
        }
        std::thread::sleep(
            Duration::from_millis(10).min(discovery_deadline.saturating_duration_since(now)),
        );
    };

    if budget.check().is_err() {
        return BacktraceRuntimePreparedOutcome::TimedOut {
            attempted_cookie: Some(resolved.cookie),
        };
    }
    tracing::debug!(
        runtime_pid = resolved.observation.runtime_pid,
        proc_pid = resolved.proc_pid,
        raw_ip = format_args!("0x{:x}", resolved.observation.raw_ip),
        cookie = format_args!("0x{:016x}", resolved.cookie),
        module = %resolved.module.module_path.display(),
        "Resolved backtrace observation against one process mapping"
    );
    match backtrace_runtime_module_load_decision(
        resolved.cookie,
        known_cookies,
        attempted_cookies,
        module_limit,
    ) {
        BacktraceRuntimeModuleLoadDecision::Load => {}
        BacktraceRuntimeModuleLoadDecision::AlreadyLoaded => {
            return BacktraceRuntimePreparedOutcome::AlreadyLoaded(resolved);
        }
        BacktraceRuntimeModuleLoadDecision::AlreadyAttempted => {
            return BacktraceRuntimePreparedOutcome::AlreadyAttempted(resolved);
        }
        BacktraceRuntimeModuleLoadDecision::LimitReached => {
            return BacktraceRuntimePreparedOutcome::LimitReached {
                limit: module_limit,
            };
        }
    }

    let cookie = resolved.cookie;
    info!(
        cookie = format_args!("0x{cookie:016x}"),
        module = %resolved.module.module_path.display(),
        "Loading metadata for one backtrace runtime module"
    );
    match ghostscope_dwarf::load_runtime_backtrace_metadata(
        resolved.module.module_path.clone(),
        *resolved
            .probe
            .take()
            .expect("resolution retained a validated ELF mapping"),
        max_unwind_rows,
        budget,
    ) {
        Ok(metadata) => {
            let unwind_modules = metadata
                .unwind_table
                .map(|table| {
                    let rows = table
                        .rows
                        .iter()
                        .map(ghostscope_compiler::backtrace_unwind_row_from_compact)
                        .collect::<Vec<_>>();
                    (cookie, rows)
                })
                .filter(|(_, rows)| !rows.is_empty())
                .into_iter()
                .collect::<Vec<_>>();
            BacktraceRuntimePreparedOutcome::Loaded {
                resolved,
                runtime_symbols: metadata.text_symbols,
                unwind_modules,
            }
        }
        Err(_) if budget.expired_or_cancelled() => BacktraceRuntimePreparedOutcome::TimedOut {
            attempted_cookie: Some(cookie),
        },
        Err(error) => BacktraceRuntimePreparedOutcome::Failed {
            attempted_cookie: Some(cookie),
            error: format!("{error:#}"),
        },
    }
}

/// A timed-out filesystem call must not keep Tokio's blocking pool alive at shutdown.
/// The detached worker owns only private discovery state and cannot publish anything.
/// A timeout disables further discovery for this session, bounding abandoned work to one.
fn spawn_backtrace_discovery(
    timeout: Duration,
    budget: RuntimeBacktraceLoadBudget,
    work: impl FnOnce() -> BacktraceRuntimePreparedOutcome + Send + 'static,
) -> Result<tokio::task::JoinHandle<BacktraceRuntimeRefreshTaskOutcome>> {
    let (sender, receiver) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("backtrace-discovery".into())
        .spawn(move || {
            let _ = sender.send(work());
        })?;
    Ok(tokio::spawn(async move {
        let outcome = match tokio::time::timeout(timeout, receiver).await {
            Ok(Ok(prepared)) if !budget.expired_or_cancelled() => prepared,
            Ok(Err(error)) => BacktraceRuntimePreparedOutcome::Failed {
                attempted_cookie: None,
                error: format!("backtrace runtime worker stopped: {error}"),
            },
            _ => {
                budget.cancel();
                BacktraceRuntimePreparedOutcome::TimedOut {
                    attempted_cookie: None,
                }
            }
        };
        BacktraceRuntimeRefreshTaskOutcome::Prepared(outcome)
    }))
}

fn sysmon_watch_from_config(
    config: &ResolvedConfig,
    fallback_host_pid: Option<u32>,
) -> (Option<u32>, Option<PidNamespaceId>) {
    match config.runtime.pid_filter_spec {
        Some(PidFilterSpec::NamespaceTgid { filter_pid, pid_ns }) => {
            (Some(filter_pid), Some(pid_ns))
        }
        Some(PidFilterSpec::HostTgid { filter_pid }) => (Some(filter_pid), None),
        None => (fallback_host_pid, None),
    }
}

fn target_mode_sysmon_event_mask(_target: &Path) -> SysmonEventMask {
    SysmonEventMask::target_mode_with_map_changes()
}

fn target_mode_map_change_unfiltered(target: &Path) -> bool {
    ghostscope_process::is_shared_object(target)
}

#[derive(Debug, Clone)]
pub struct RuntimePidContext {
    /// PID used for `/proc/<pid>/...` access and DWARF loading in GhostScope's current view.
    pub proc_pid: u32,
    /// PID passed to uprobe attach restrictions in GhostScope's current userspace view.
    pub attach_pid: u32,
    /// Host-view PID kept for logs, UI display, and legacy host-TGID fallback paths.
    pub host_pid: u32,
    /// Optional resolved PID views for namespace/container scenarios.
    pub pid_views: Option<PidViews>,
}

impl RuntimePidContext {
    fn from_config(config: &ResolvedConfig) -> Option<Self> {
        config.runtime.proc_pid.map(|proc_pid| Self {
            proc_pid,
            attach_pid: proc_pid,
            host_pid: config.runtime.host_pid.unwrap_or(proc_pid),
            pid_views: config.runtime.pid_views.clone(),
        })
    }

    fn legacy(proc_pid: u32) -> Self {
        Self {
            proc_pid,
            attach_pid: proc_pid,
            host_pid: proc_pid,
            pid_views: None,
        }
    }
}

/// Ghost session state - manages binary analysis, process tracking, and trace instances
#[derive(Debug)]
pub struct GhostSession {
    pub process_analyzer: Option<DwarfAnalyzer>,
    pub target_binary: Option<String>,
    pub target_args: Vec<String>,
    pid_context: Option<RuntimePidContext>,
    pub trace_manager: TraceManager, // Manages trace metadata and loader-owning actors
    pub source_path_resolver: SourcePathResolver, // Resolves DWARF paths to actual filesystem paths
    #[allow(dead_code)]
    pub debug_file: Option<String>, // Optional debug file path
    pub config: Option<ResolvedConfig>, // Holds the resolved configuration
    pub coordinator: Arc<Mutex<ProcessManager>>, // Manages PID/module offsets prefill and application
    pub sysmon: Option<Arc<Mutex<ProcessSysmon>>>, // Realtime process monitor (exec/fork/exit)
    target_backtrace_runtime_modules_enabled: bool,
    backtrace_runtime_known_cookies: BTreeSet<u64>,
    backtrace_runtime_attempted_cookies: BTreeSet<u64>,
    backtrace_runtime_queued_observations: BTreeSet<BacktraceRuntimeModuleObservation>,
    backtrace_runtime_observations:
        BTreeMap<BacktraceRuntimeModuleObservation, BacktraceObservationState>,
    backtrace_runtime_unwind_modules: Vec<(u64, Vec<ghostscope_protocol::BacktraceUnwindRow>)>,
    backtrace_runtime_refresh_task: Option<BacktraceRuntimeRefreshTask>,
    backtrace_runtime_refresh_timed_out: bool,
    backtrace_runtime_limit_reported: bool,
}

impl GhostSession {
    /// Create a new ghost session with merged configuration
    pub fn new_with_config(config: &ResolvedConfig) -> Self {
        info!("Creating ghost session with merged configuration");

        let mut s = Self {
            process_analyzer: None,
            target_binary: config.target_path.clone(),
            target_args: config.binary_args.clone(),
            pid_context: RuntimePidContext::from_config(config),
            debug_file: config
                .debug_file
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            trace_manager: TraceManager::new(),
            source_path_resolver: SourcePathResolver::new(&config.source),
            config: Some(config.clone()),
            coordinator: Arc::new(Mutex::new(ProcessManager::new())),
            sysmon: None,
            target_backtrace_runtime_modules_enabled: false,
            backtrace_runtime_known_cookies: BTreeSet::new(),
            backtrace_runtime_attempted_cookies: BTreeSet::new(),
            backtrace_runtime_queued_observations: BTreeSet::new(),
            backtrace_runtime_observations: BTreeMap::new(),
            backtrace_runtime_unwind_modules: Vec::new(),
            backtrace_runtime_refresh_task: None,
            backtrace_runtime_refresh_timed_out: false,
            backtrace_runtime_limit_reported: false,
        };

        if let Some(pid_views) = s.pid_views() {
            info!("Session PID views: {}", pid_views.compact_display());
        }
        if let Some(cfg) = s.config.as_ref() {
            info!(
                "Session runtime environment: {}",
                cfg.runtime.runtime_env.compact_display()
            );
            let debuginfod = &cfg.dwarf_debuginfod;
            info!(
                "Session debuginfod config: mode={:?}, effective={}, urls={}, cache_dir={}, timeout_secs={}, max_size_bytes={}",
                debuginfod.mode,
                debuginfod.is_effectively_enabled(),
                debuginfod.urls.len(),
                debuginfod
                    .cache_dir
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "<unset>".to_string()),
                debuginfod
                    .timeout_secs
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                debuginfod
                    .max_size_bytes
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string())
            );
            if let Some(filter) = cfg.runtime.pid_filter_spec {
                info!("Session PID filter spec: {:?}", filter);
            }
            info!(
                enabled = cfg.dwarf_backtrace_runtime_modules,
                max_modules = cfg.dwarf_backtrace_runtime_modules_max,
                timeout_ms = cfg.dwarf_backtrace_runtime_module_timeout_ms,
                "Backtrace runtime module loading policy"
            );
        }

        // Start sysmon for standalone -t lifecycle tracking, or for -p module
        // map-change tracking.
        if config.dry_run {
            info!("Sysmon not started (dry-run mode)");
        } else if s.proc_pid().is_some() {
            let (watched_pid, watched_pid_ns) = sysmon_watch_from_config(config, s.host_pid());
            let cfg = SysmonConfig {
                target_module: None,
                proc_offsets_max_entries: config.ebpf_config.proc_module_offsets_max_entries as u32,
                perf_page_count: Some(config.ebpf_config.perf_page_count as usize),
                event_mask: SysmonEventMask::pid_module_changes(),
                map_change_unfiltered: false,
                watched_pid,
                watched_pid_ns,
                event_pid_ns: None,
                watched_proc_pid: s.proc_pid(),
            };
            let mgr = Arc::clone(&s.coordinator);
            let mut sysmon = ProcessSysmon::new(mgr, cfg);
            sysmon.start();
            s.sysmon = Some(Arc::new(Mutex::new(sysmon)));
            if let Some(watched_pid) = watched_pid {
                info!(
                    "Sysmon started (-p map-change mode, watched event pid={})",
                    watched_pid
                );
            } else {
                info!("Sysmon started (-p map-change mode)");
            }
        } else if let Some(target_binary) = &s.target_binary {
            let tpath = PathBuf::from(target_binary);
            if config.ebpf_config.enable_sysmon_for_target {
                let cfg = SysmonConfig {
                    target_module: Some(tpath.clone()),
                    proc_offsets_max_entries: config.ebpf_config.proc_module_offsets_max_entries
                        as u32,
                    perf_page_count: Some(config.ebpf_config.perf_page_count as usize),
                    event_mask: target_mode_sysmon_event_mask(&tpath),
                    map_change_unfiltered: target_mode_map_change_unfiltered(&tpath),
                    watched_pid: None,
                    watched_pid_ns: None,
                    event_pid_ns: config.runtime.proc_offsets_pid_ns,
                    watched_proc_pid: None,
                };
                let mgr = Arc::clone(&s.coordinator);
                let mut sysmon = ProcessSysmon::new(mgr, cfg);
                sysmon.start();
                s.sysmon = Some(Arc::new(Mutex::new(sysmon)));
                let is_shared = ghostscope_process::is_shared_object(&tpath);
                if is_shared {
                    info!("Sysmon started (-t shared library)");
                } else {
                    info!("Sysmon started (-t executable)");
                }
            } else {
                info!("Sysmon not started (-t disabled by config)");
            }
        } else {
            info!("Sysmon not started (no -t target)");
        }

        s
    }

    /// Create a new ghost session (without binary analysis - call load_binary separately)
    #[allow(dead_code)]
    pub fn new(args: &ParsedArgs) -> Self {
        info!("Creating ghost session");

        let mut s = Self {
            process_analyzer: None,
            target_binary: args.target_path.clone(),
            target_args: args.binary_args.clone(),
            pid_context: args.pid.map(RuntimePidContext::legacy),
            debug_file: args
                .debug_file
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            trace_manager: TraceManager::new(),
            source_path_resolver: SourcePathResolver::new(&Default::default()),
            config: None,
            coordinator: Arc::new(Mutex::new(ProcessManager::new())),
            sysmon: None,
            target_backtrace_runtime_modules_enabled: false,
            backtrace_runtime_known_cookies: BTreeSet::new(),
            backtrace_runtime_attempted_cookies: BTreeSet::new(),
            backtrace_runtime_queued_observations: BTreeSet::new(),
            backtrace_runtime_observations: BTreeMap::new(),
            backtrace_runtime_unwind_modules: Vec::new(),
            backtrace_runtime_refresh_task: None,
            backtrace_runtime_refresh_timed_out: false,
            backtrace_runtime_limit_reported: false,
        };
        if let Some(pid_context) = s.pid_context.as_ref() {
            info!(
                "Session PID (legacy mode): proc_pid={} host_pid={}",
                pid_context.proc_pid, pid_context.host_pid
            );
        }
        if s.proc_pid().is_some() {
            let cfg = SysmonConfig {
                target_module: None,
                proc_offsets_max_entries: 4096,
                perf_page_count: None,
                event_mask: SysmonEventMask::pid_module_changes(),
                map_change_unfiltered: false,
                watched_pid: s.host_pid(),
                watched_pid_ns: None,
                event_pid_ns: None,
                watched_proc_pid: s.proc_pid(),
            };
            let mgr = Arc::clone(&s.coordinator);
            let mut sysmon = ProcessSysmon::new(mgr, cfg);
            sysmon.start();
            s.sysmon = Some(Arc::new(Mutex::new(sysmon)));
            info!("Sysmon started (-p map-change mode)");
        } else if s.target_binary.is_some() {
            let target_module = s.target_binary.as_ref().map(PathBuf::from);
            let event_mask = target_module
                .as_deref()
                .map(target_mode_sysmon_event_mask)
                .unwrap_or_else(SysmonEventMask::target_mode);
            let map_change_unfiltered = target_module
                .as_deref()
                .is_some_and(target_mode_map_change_unfiltered);
            let cfg = SysmonConfig {
                target_module,
                proc_offsets_max_entries: 4096,
                perf_page_count: None,
                event_mask,
                map_change_unfiltered,
                watched_pid: None,
                watched_pid_ns: None,
                event_pid_ns: None,
                watched_proc_pid: None,
            };
            let mgr = Arc::clone(&s.coordinator);
            let mut sysmon = ProcessSysmon::new(mgr, cfg);
            sysmon.start();
            s.sysmon = Some(Arc::new(Mutex::new(sysmon)));
            info!("Sysmon started (-t mode)");
        } else {
            info!("Sysmon not started (no -t target)");
        }
        s
    }

    /// Get debug search paths from configuration
    fn get_debug_search_paths(&self) -> Vec<String> {
        self.config
            .as_ref()
            .map(|c| c.dwarf_search_paths.clone())
            .unwrap_or_default()
    }

    fn get_allow_loose_debug_match(&self) -> bool {
        self.config
            .as_ref()
            .map(|c| c.dwarf_allow_loose_debug_match)
            .unwrap_or(false)
    }

    fn explicit_debug_file_for_target(&self) -> Option<ExplicitDebugFile> {
        let debug_file = self.debug_file.as_ref().map(PathBuf::from)?;
        let target_module = self.target_binary.as_ref().map(PathBuf::from).or_else(|| {
            self.proc_pid()
                .map(|pid| PathBuf::from(format!("/proc/{pid}/exe")))
        })?;

        Some(ExplicitDebugFile::new(target_module, debug_file))
    }

    fn build_debuginfod_client(&self) -> Result<Option<Arc<DebuginfodClient>>> {
        let Some(config) = self.config.as_ref() else {
            return Ok(None);
        };
        let debuginfod = &config.dwarf_debuginfod;
        if !debuginfod.is_effectively_enabled() {
            return Ok(None);
        }

        let Some(cache_dir) = debuginfod.cache_dir.as_ref() else {
            warn!("debuginfod is enabled but no cache directory was resolved; skipping");
            return Ok(None);
        };

        let mut client_config =
            DebuginfodConfig::new(debuginfod.urls.iter().map(String::as_str), cache_dir)?;
        client_config = match debuginfod.timeout_secs {
            Some(timeout_secs) => client_config.with_timeout(Duration::from_secs(timeout_secs)),
            None => client_config.without_timeout(),
        };
        client_config = client_config.with_max_size(debuginfod.max_size_bytes);

        info!(
            "debuginfod fallback enabled: urls={}, cache_dir={}, timeout_secs={}, max_size_bytes={}",
            debuginfod.urls.len(),
            cache_dir.display(),
            debuginfod
                .timeout_secs
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string()),
            debuginfod
                .max_size_bytes
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string())
        );

        Ok(Some(Arc::new(DebuginfodClient::new(client_config)?)))
    }

    fn ensure_pid_runtime_modules(
        &self,
        proc_pid: u32,
    ) -> Result<Vec<ghostscope_dwarf::LoadedModuleRuntimeInfo>> {
        let mut coordinator = self.coordinator.lock().expect("coordinator mutex poisoned");
        coordinator.ensure_prefill_pid(proc_pid)?;

        let Some(entries) = coordinator.cached_offsets_with_paths_for_pid(proc_pid) else {
            return Ok(Vec::new());
        };

        Ok(DwarfAnalyzer::runtime_modules_from_pid_offsets(entries))
    }

    /// Refresh the PID module snapshot and load newly mapped modules before
    /// compiling another script in a long-lived session.
    pub(crate) async fn refresh_pid_analyzer_before_compile(&mut self) -> Result<usize> {
        let Some(proc_pid) = self.proc_pid() else {
            return Ok(0);
        };

        let runtime_modules = {
            let mut coordinator = self.coordinator.lock().expect("coordinator mutex poisoned");
            coordinator.refresh_prefill_pid(proc_pid)?;
            let Some(entries) = coordinator.cached_offsets_with_paths_for_pid(proc_pid) else {
                return Ok(0);
            };
            DwarfAnalyzer::runtime_modules_from_pid_offsets(entries)
        };
        if runtime_modules.is_empty() {
            return Ok(0);
        }

        let debug_search_paths = self.get_debug_search_paths();
        let allow_loose = self.get_allow_loose_debug_match();
        let debuginfod_client = self.build_debuginfod_client()?;
        let Some(analyzer) = self.process_analyzer.as_mut() else {
            return Ok(0);
        };

        let loaded = analyzer
            .refresh_pid_runtime_modules_with_config_and_debuginfod(
                runtime_modules,
                &debug_search_paths,
                allow_loose,
                debuginfod_client,
                |_| {},
            )
            .await?;
        if loaded > 0 {
            info!(
                "Refreshed PID {} analyzer with {} newly mapped module(s) before compilation",
                proc_pid, loaded
            );
        }
        Ok(loaded)
    }

    fn backtrace_runtime_modules_configured(&self) -> bool {
        self.config
            .as_ref()
            .map(|config| config.dwarf_backtrace_runtime_modules)
            .unwrap_or(true)
    }

    fn backtrace_runtime_modules_max(&self) -> u32 {
        self.config
            .as_ref()
            .map(|config| config.dwarf_backtrace_runtime_modules_max)
            .unwrap_or(32)
    }

    fn backtrace_runtime_module_timeout(&self) -> Duration {
        Duration::from_millis(
            self.config
                .as_ref()
                .map(|config| config.dwarf_backtrace_runtime_module_timeout_ms)
                .unwrap_or(5_000),
        )
    }

    fn backtrace_runtime_unwind_rows_max(&self) -> usize {
        self.config
            .as_ref()
            .map(|config| config.ebpf_config.backtrace_unwind_rows_max_entries)
            .unwrap_or(ghostscope_compiler::DEFAULT_BACKTRACE_UNWIND_ROWS_MAX_ENTRIES)
            as usize
    }

    fn backtrace_runtime_queued_module_count(&self) -> usize {
        self.backtrace_runtime_queued_observations.len()
    }

    fn backtrace_runtime_modules_allowed(&self) -> bool {
        if !self.backtrace_runtime_modules_configured()
            || self.backtrace_runtime_refresh_timed_out
            || self.backtrace_runtime_limit_reported
        {
            return false;
        }
        self.proc_pid().is_some() || self.target_backtrace_runtime_modules_enabled
    }

    pub(crate) fn record_backtrace_compiled_module_cookies(
        &mut self,
        cookies: impl IntoIterator<Item = u64>,
    ) {
        self.backtrace_runtime_known_cookies.extend(cookies);
    }

    fn record_backtrace_runtime_module(&mut self, cookie: u64) {
        self.backtrace_runtime_known_cookies.insert(cookie);
    }

    pub(crate) fn seed_backtrace_runtime_rows(
        &self,
        loader: &mut ghostscope_loader::GhostScopeLoader,
    ) -> Result<()> {
        loader.append_backtrace_unwind_rows_for_modules(&self.backtrace_runtime_unwind_modules)?;
        Ok(())
    }

    pub fn schedule_backtrace_runtime_module_refresh(
        &mut self,
        request: BacktraceRuntimeModuleRequest,
    ) -> Result<BacktraceRuntimeRefreshSchedule> {
        if request.is_empty() {
            return Ok(BacktraceRuntimeRefreshSchedule::NotNeeded);
        }
        if !self.backtrace_runtime_modules_allowed() || self.process_analyzer.is_none() {
            return Ok(BacktraceRuntimeRefreshSchedule::Disabled);
        }

        let now = Instant::now();
        let coordinator = Arc::clone(&self.coordinator);
        let Ok(coordinator) = coordinator.try_lock() else {
            return Ok(BacktraceRuntimeRefreshSchedule::NotNeeded);
        };
        let active_observation = self
            .backtrace_runtime_refresh_task
            .as_ref()
            .map(|task| task.observation);
        let mut queued = 0usize;
        let mut dropped = 0usize;
        for observation in request.observations {
            if active_observation == Some(observation)
                || self
                    .backtrace_runtime_queued_observations
                    .contains(&observation)
            {
                continue;
            }
            let mapping = observation_mapping(&coordinator, self.proc_pid(), observation);
            if let Some(state) = self.backtrace_runtime_observations.get(&observation) {
                if !state.should_retry(&mapping, now) {
                    continue;
                }
            }
            if self.backtrace_runtime_observations.len()
                >= BACKTRACE_RUNTIME_OBSERVATION_REQUEST_MAX
                && !self
                    .backtrace_runtime_observations
                    .contains_key(&observation)
            {
                dropped += 1;
                continue;
            }
            let state = self
                .backtrace_runtime_observations
                .entry(observation)
                .or_insert(BacktraceObservationState {
                    mapping: mapping.clone(),
                    attempts: 0,
                    retry_at: Some(now),
                });
            if state.mapping != mapping {
                state.mapping = mapping;
                state.attempts = 0;
            }
            self.backtrace_runtime_queued_observations
                .insert(observation);
            queued += 1;
        }
        drop(coordinator);
        if dropped > 0 {
            warn!(
                dropped,
                capacity = BACKTRACE_RUNTIME_OBSERVATION_REQUEST_MAX,
                "Backtrace runtime observation budget is full; dropping recovery work"
            );
        }

        if queued == 0 {
            if self.backtrace_runtime_refresh_task.is_none()
                && self.backtrace_runtime_queued_module_count() > 0
            {
                if let Some(timeout) = self.start_next_backtrace_runtime_module_refresh()? {
                    return Ok(BacktraceRuntimeRefreshSchedule::Started { timeout });
                }
            }
            return Ok(BacktraceRuntimeRefreshSchedule::NotNeeded);
        }
        if self.backtrace_runtime_refresh_task.is_some() {
            return Ok(BacktraceRuntimeRefreshSchedule::Queued { modules: queued });
        }

        let Some(timeout) = self.start_next_backtrace_runtime_module_refresh()? else {
            return Ok(BacktraceRuntimeRefreshSchedule::NotNeeded);
        };
        Ok(BacktraceRuntimeRefreshSchedule::Started { timeout })
    }

    fn start_next_backtrace_runtime_module_refresh(&mut self) -> Result<Option<Duration>> {
        if self.backtrace_runtime_refresh_task.is_some()
            || self.backtrace_runtime_refresh_timed_out
            || self.backtrace_runtime_limit_reported
        {
            return Ok(None);
        }
        if self.backtrace_runtime_queued_module_count() == 0 {
            return Ok(None);
        }

        let baseline = match self.coordinator.try_lock() {
            Ok(coordinator) => Arc::new(coordinator.fork_for_runtime_discovery()),
            Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                anyhow::bail!("coordinator mutex poisoned")
            }
        };

        let observation = self
            .backtrace_runtime_queued_observations
            .iter()
            .next()
            .copied()
            .expect("checked non-empty runtime module queue");
        self.backtrace_runtime_queued_observations
            .remove(&observation);
        if let Some(state) = self.backtrace_runtime_observations.get_mut(&observation) {
            state.attempts += 1;
            state.retry_at = None;
        }

        let worker_baseline = Arc::clone(&baseline);
        let proc_pid = self.proc_pid();
        let target_binary = self.target_binary.clone();
        let timeout = self.backtrace_runtime_module_timeout();
        let max_unwind_rows = self.backtrace_runtime_unwind_rows_max();
        let known_cookies = self.backtrace_runtime_known_cookies.clone();
        let attempted_cookies = self.backtrace_runtime_attempted_cookies.clone();
        let module_limit = self.backtrace_runtime_modules_max();
        let budget = RuntimeBacktraceLoadBudget::new(timeout);
        let worker_budget = budget.clone();
        let handle = spawn_backtrace_discovery(timeout, budget.clone(), move || {
            prepare_backtrace_runtime_module(
                worker_baseline.fork_for_runtime_discovery(),
                proc_pid,
                target_binary.as_deref(),
                observation,
                &known_cookies,
                &attempted_cookies,
                module_limit,
                max_unwind_rows,
                &worker_budget,
            )
        })?;

        self.backtrace_runtime_refresh_task = Some(BacktraceRuntimeRefreshTask {
            observation,
            timeout,
            budget,
            baseline,
            handle,
            result: None,
        });
        info!(
            runtime_pid = observation.runtime_pid,
            cookie = format_args!("0x{:016x}", observation.cookie_hint),
            raw_ip = format_args!("0x{:x}", observation.raw_ip),
            timeout_ms = timeout.as_millis(),
            "Resolving one backtrace runtime module in the background"
        );
        Ok(Some(timeout))
    }

    pub async fn poll_backtrace_runtime_module_refresh(
        &mut self,
    ) -> Result<Option<BacktraceRuntimeRefreshOutcome>> {
        let Some(task) = self.backtrace_runtime_refresh_task.as_mut() else {
            return Ok(None);
        };
        if task.result.is_none() {
            if !task.handle.is_finished() {
                return Ok(None);
            }
            task.result = Some(
                match (&mut task.handle).now_or_never().expect("finished worker") {
                    Ok(result) => result,
                    Err(error) => BacktraceRuntimeRefreshTaskOutcome::Prepared(
                        BacktraceRuntimePreparedOutcome::Failed {
                            attempted_cookie: None,
                            error: format!("backtrace runtime task failed: {error}"),
                        },
                    ),
                },
            );
        }
        let coordinator = Arc::clone(&self.coordinator);
        let needs_mapping = matches!(
            task.result,
            Some(BacktraceRuntimeRefreshTaskOutcome::Prepared(
                BacktraceRuntimePreparedOutcome::Loaded { .. }
                    | BacktraceRuntimePreparedOutcome::AlreadyLoaded(_)
                    | BacktraceRuntimePreparedOutcome::AlreadyAttempted(_)
            ))
        );
        let mut coordinator = if needs_mapping {
            match coordinator.try_lock() {
                Ok(guard) => Some(guard),
                Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    anyhow::bail!("coordinator mutex poisoned")
                }
            }
        } else {
            None
        };
        let task = self
            .backtrace_runtime_refresh_task
            .take()
            .expect("runtime refresh task was present");
        let observation = task.observation;
        let timeout = task.timeout;
        let task_result = task.result.expect("completed worker result");
        let mut mapping_published = true;
        if let BacktraceRuntimeRefreshTaskOutcome::Prepared(
            BacktraceRuntimePreparedOutcome::Loaded { resolved, .. }
            | BacktraceRuntimePreparedOutcome::AlreadyLoaded(resolved)
            | BacktraceRuntimePreparedOutcome::AlreadyAttempted(resolved),
        ) = &task_result
        {
            let coordinator = coordinator.as_mut().expect("mapping publication guard");
            if coordinator.apply_runtime_pid_snapshot(
                resolved.proc_pid,
                task.baseline
                    .cached_offsets_with_paths_for_pid(resolved.proc_pid),
                &resolved.entries,
            ) {
                BacktraceRuntimeRunner::publish_observation_pid_snapshot(
                    coordinator,
                    resolved.proc_pid,
                    observation,
                    &resolved.entries,
                );
                if let Some(state) = self.backtrace_runtime_observations.get_mut(&observation) {
                    state.mapping =
                        observation_mapping(coordinator, Some(resolved.proc_pid), observation);
                }
            } else {
                // A newer PID snapshot wins, but CFI from the validated mapping
                // remains valid under its cookie. Retain it and charge the load
                // budget; a bounded retry can refresh offsets without parsing again.
                mapping_published = false;
            }
        }
        drop(coordinator);

        if let Some(state) = self
            .backtrace_runtime_observations
            .get_mut(&observation)
            .filter(|_| {
                !matches!(
                    task_result,
                    BacktraceRuntimeRefreshTaskOutcome::Published { .. }
                )
            })
        {
            state.finish(
                mapping_published
                    && !matches!(
                        task_result,
                        BacktraceRuntimeRefreshTaskOutcome::Prepared(
                            BacktraceRuntimePreparedOutcome::ModuleNotFound
                                | BacktraceRuntimePreparedOutcome::Failed { .. }
                        )
                    ),
                Instant::now(),
            );
        }

        let outcome = match task_result {
            BacktraceRuntimeRefreshTaskOutcome::Prepared(
                BacktraceRuntimePreparedOutcome::Loaded {
                    resolved,
                    runtime_symbols,
                    mut unwind_modules,
                },
            ) => {
                self.backtrace_runtime_attempted_cookies
                    .insert(resolved.cookie);
                // Retain a bounded set of completed rows to seed traces attached later,
                // including replacements attached while this publication is in flight.
                let retained: usize = self
                    .backtrace_runtime_unwind_modules
                    .iter()
                    .map(|(_, rows)| rows.len())
                    .sum();
                let mut remaining = self
                    .backtrace_runtime_unwind_rows_max()
                    .saturating_sub(retained);
                for (_, rows) in &mut unwind_modules {
                    rows.truncate(remaining);
                    remaining -= rows.len();
                }
                self.backtrace_runtime_unwind_modules
                    .extend(unwind_modules.clone());
                let appender = self.trace_manager.backtrace_unwind_rows_appender();
                let handle = tokio::spawn(async move {
                    let append_result = appender.append(unwind_modules).await;
                    BacktraceRuntimeRefreshTaskOutcome::Published {
                        resolved,
                        runtime_symbols,
                        append_result,
                    }
                });
                self.backtrace_runtime_refresh_task = Some(BacktraceRuntimeRefreshTask {
                    observation,
                    timeout,
                    budget: task.budget,
                    baseline: task.baseline,
                    handle,
                    result: None,
                });
                return Ok(None);
            }
            BacktraceRuntimeRefreshTaskOutcome::Published {
                resolved,
                runtime_symbols,
                append_result,
            } => {
                // Make symbols visible with the Loaded notification that clears
                // renderer caches, never between CFI publication phases.
                if let Some(analyzer) = self.process_analyzer.as_mut() {
                    analyzer.add_runtime_text_symbols(resolved.cookie, runtime_symbols);
                }
                self.record_backtrace_runtime_module(resolved.cookie);
                let append_stats = self
                    .trace_manager
                    .apply_backtrace_unwind_rows_append(append_result);
                let next_started = self
                    .start_next_backtrace_runtime_module_refresh()?
                    .is_some();
                BacktraceRuntimeRefreshOutcome::Loaded {
                    modules: 1,
                    unwind_rows: append_stats.rows,
                    next_started,
                }
            }
            BacktraceRuntimeRefreshTaskOutcome::Prepared(
                BacktraceRuntimePreparedOutcome::AlreadyLoaded(resolved),
            ) => {
                self.record_backtrace_runtime_module(resolved.cookie);
                let next_started = self
                    .start_next_backtrace_runtime_module_refresh()?
                    .is_some();
                BacktraceRuntimeRefreshOutcome::Loaded {
                    modules: 0,
                    unwind_rows: 0,
                    next_started,
                }
            }
            BacktraceRuntimeRefreshTaskOutcome::Prepared(
                BacktraceRuntimePreparedOutcome::AlreadyAttempted(_),
            ) => {
                let next_started = self
                    .start_next_backtrace_runtime_module_refresh()?
                    .is_some();
                BacktraceRuntimeRefreshOutcome::Loaded {
                    modules: 0,
                    unwind_rows: 0,
                    next_started,
                }
            }
            BacktraceRuntimeRefreshTaskOutcome::Prepared(
                BacktraceRuntimePreparedOutcome::ModuleNotFound,
            ) => {
                let next_started = self
                    .start_next_backtrace_runtime_module_refresh()?
                    .is_some();
                BacktraceRuntimeRefreshOutcome::ModuleNotFound { next_started }
            }
            BacktraceRuntimeRefreshTaskOutcome::Prepared(
                BacktraceRuntimePreparedOutcome::TimedOut { attempted_cookie },
            ) => {
                self.backtrace_runtime_attempted_cookies
                    .extend(attempted_cookie);
                self.backtrace_runtime_refresh_timed_out = true;
                self.backtrace_runtime_queued_observations.clear();
                BacktraceRuntimeRefreshOutcome::TimedOut { timeout }
            }
            BacktraceRuntimeRefreshTaskOutcome::Prepared(
                BacktraceRuntimePreparedOutcome::Failed {
                    attempted_cookie,
                    error,
                },
            ) => {
                self.backtrace_runtime_attempted_cookies
                    .extend(attempted_cookie);
                let next_started = self
                    .start_next_backtrace_runtime_module_refresh()?
                    .is_some();
                BacktraceRuntimeRefreshOutcome::Failed {
                    error,
                    next_started,
                }
            }
            BacktraceRuntimeRefreshTaskOutcome::Prepared(
                BacktraceRuntimePreparedOutcome::LimitReached { limit },
            ) => {
                self.backtrace_runtime_queued_observations.clear();
                if self.backtrace_runtime_limit_reported {
                    BacktraceRuntimeRefreshOutcome::Loaded {
                        modules: 0,
                        unwind_rows: 0,
                        next_started: false,
                    }
                } else {
                    self.backtrace_runtime_limit_reported = true;
                    BacktraceRuntimeRefreshOutcome::LimitReached { limit }
                }
            }
        };

        Ok(Some(outcome))
    }

    /// Load binary and perform DWARF analysis using parallel loading (TUI mode)
    pub async fn load_binary_parallel(&mut self) -> Result<()> {
        info!("Loading binary and performing DWARF analysis (parallel mode)");

        let debug_search_paths = self.get_debug_search_paths();
        let allow_loose = self.get_allow_loose_debug_match();
        let explicit_debug_file = self.explicit_debug_file_for_target();
        let debuginfod_client = self.build_debuginfod_client()?;

        let process_analyzer = if let Some(proc_pid) = self.proc_pid() {
            info!("Loading binary from PID: {} (parallel)", proc_pid);
            let runtime_modules = self.ensure_pid_runtime_modules(proc_pid)?;
            Some(
                DwarfAnalyzer::from_pid_runtime_modules_with_config_debuginfod_and_explicit_debug_file(
                    proc_pid,
                    runtime_modules,
                    &debug_search_paths,
                    allow_loose,
                    debuginfod_client.clone(),
                    explicit_debug_file.clone(),
                    |_| {},
                )
                .await?,
            )
        } else if let Some(ref binary_path) = self.target_binary {
            info!("Loading binary from executable path: {}", binary_path);
            Some(
                DwarfAnalyzer::from_exec_path_with_config_debuginfod_explicit_debug_file_and_progress(
                    binary_path,
                    &debug_search_paths,
                    allow_loose,
                    debuginfod_client.clone(),
                    explicit_debug_file.map(|explicit| explicit.debug_file),
                    |_| {},
                )
                .await?,
            )
        } else {
            warn!("No PID or binary path specified - running without binary analysis");
            None
        };

        self.process_analyzer = process_analyzer;
        Ok(())
    }

    /// Load binary and perform DWARF analysis using parallel loading with progress callback
    pub async fn load_binary_parallel_with_progress<F>(
        &mut self,
        progress_callback: F,
    ) -> Result<()>
    where
        F: Fn(ghostscope_dwarf::ModuleLoadingEvent) + Send + Sync + 'static,
    {
        info!("Loading binary and performing DWARF analysis (parallel mode with progress)");

        let debug_search_paths = self.get_debug_search_paths();
        let allow_loose = self.get_allow_loose_debug_match();
        let explicit_debug_file = self.explicit_debug_file_for_target();
        let debuginfod_client = self.build_debuginfod_client()?;

        let process_analyzer = if let Some(proc_pid) = self.proc_pid() {
            info!(
                "Loading binary from PID: {} (parallel with progress)",
                proc_pid
            );
            let runtime_modules = self.ensure_pid_runtime_modules(proc_pid)?;
            Some(
                DwarfAnalyzer::from_pid_runtime_modules_with_config_debuginfod_and_explicit_debug_file(
                    proc_pid,
                    runtime_modules,
                    &debug_search_paths,
                    allow_loose,
                    debuginfod_client.clone(),
                    explicit_debug_file.clone(),
                    progress_callback,
                )
                .await?,
            )
        } else if let Some(ref binary_path) = self.target_binary {
            info!("Loading binary from executable path: {}", binary_path);
            Some(
                DwarfAnalyzer::from_exec_path_with_config_debuginfod_explicit_debug_file_and_progress(
                    binary_path,
                    &debug_search_paths,
                    allow_loose,
                    debuginfod_client.clone(),
                    explicit_debug_file.map(|explicit| explicit.debug_file),
                    progress_callback,
                )
                .await?,
            )
        } else {
            warn!("No PID or binary path specified - running without binary analysis");
            None
        };

        self.process_analyzer = process_analyzer;
        Ok(())
    }

    /// Load binary and perform DWARF analysis (backwards compatibility - now uses parallel)
    pub async fn load_binary(&mut self) -> Result<()> {
        self.load_binary_parallel().await
    }

    /// Create ghost session and load binary in one step (now uses parallel loading)
    #[allow(dead_code)]
    pub async fn new_with_binary(args: &ParsedArgs) -> Result<Self> {
        let mut session = Self::new(args);
        session.load_binary().await?;
        Ok(session)
    }

    /// Create a new session with config and binary loading in parallel mode with progress callback
    pub async fn new_with_config_and_progress<F>(
        config: &ResolvedConfig,
        progress_callback: F,
    ) -> Result<Self>
    where
        F: Fn(ghostscope_dwarf::ModuleLoadingEvent) + Send + Sync + 'static,
    {
        let mut session = Self::new_with_config(config);
        session
            .load_binary_parallel_with_progress(progress_callback)
            .await?;
        Ok(session)
    }

    /// Get module statistics from the process analyzer
    pub fn get_module_stats(&self) -> Option<ModuleStats> {
        self.process_analyzer
            .as_ref()
            .map(|analyzer| analyzer.get_module_stats())
    }

    /// List available functions
    pub fn list_functions(&self) -> Vec<String> {
        if let Some(ref analyzer) = self.process_analyzer {
            analyzer.lookup_all_function_names()
        } else {
            Vec::new()
        }
    }

    /// Get binary path if available
    pub fn binary_path(&self) -> Option<String> {
        self.target_binary.clone()
    }

    /// PID to use for userspace /proc reads.
    pub fn proc_pid(&self) -> Option<u32> {
        self.pid_context
            .as_ref()
            .map(|pid_context| pid_context.proc_pid)
    }

    /// Host-view PID kept for logs, UI display, and host-TGID fallback paths.
    pub fn host_pid(&self) -> Option<u32> {
        self.pid_context
            .as_ref()
            .map(|pid_context| pid_context.host_pid)
    }

    /// PID to use for uprobe attach restrictions.
    pub fn attach_pid(&self) -> Option<u32> {
        self.pid_context
            .as_ref()
            .map(|pid_context| pid_context.attach_pid)
    }

    /// Get resolved PID mapping diagnostics if available.
    pub fn pid_views(&self) -> Option<&PidViews> {
        self.pid_context
            .as_ref()
            .and_then(|pid_context| pid_context.pid_views.as_ref())
    }

    /// Check if session was started with target path (target file mode)
    pub fn is_target_mode(&self) -> bool {
        self.proc_pid().is_none() && self.target_binary.is_some()
    }

    pub fn enable_target_backtrace_runtime_modules(&mut self) {
        if self.is_target_mode() {
            self.target_backtrace_runtime_modules_enabled = true;
        }
    }

    pub fn prepare_target_backtrace_module_mappings(&mut self) -> Result<usize> {
        if !self.is_target_mode() {
            return Ok(0);
        }
        let Some(target_binary) = self.target_binary.as_deref() else {
            return Ok(0);
        };
        let mut coordinator = self.coordinator.lock().expect("coordinator mutex poisoned");
        BacktraceRuntimeRunner::prepare_target_module_mappings(&mut coordinator, target_binary)
    }
}

impl Drop for GhostSession {
    fn drop(&mut self) {
        if let Some(task) = self.backtrace_runtime_refresh_task.take() {
            task.budget.cancel();
            task.handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::runtime::RuntimeContext;
    use crate::config::settings::{PathSubstitution, SourceConfig};
    use crate::config::UserConfig;

    #[test]
    fn terminal_observations_only_retry_after_the_mapping_changes() {
        let now = Instant::now();
        let mut state = BacktraceObservationState {
            mapping: None,
            attempts: 1,
            retry_at: Some(now),
        };
        state.finish(true, now);
        assert!(!state.should_retry(&None, now + Duration::from_secs(3600)));
        let changed = Some((
            42,
            ghostscope_process::PidOffsetsEntry {
                module_path: "late.so".into(),
                cookie: 1,
                offsets: Default::default(),
                base: 0x1000,
                size: 0x100,
            },
        ));
        assert!(state.should_retry(&changed, now));
    }

    #[test]
    fn unresolved_observations_have_bounded_exponential_retries() {
        let now = Instant::now();
        let mut state = BacktraceObservationState {
            mapping: None,
            attempts: 1,
            retry_at: None,
        };
        state.finish(false, now);
        assert!(!state.should_retry(&None, now));
        assert!(state.should_retry(&None, now + Duration::from_secs(1)));
        state.attempts = 2;
        state.finish(false, now);
        assert!(!state.should_retry(&None, now + Duration::from_secs(1)));
        assert!(state.should_retry(&None, now + Duration::from_secs(2)));
        state.attempts = 3;
        state.finish(false, now);
        assert!(!state.should_retry(&None, now + Duration::from_secs(3600)));
    }

    #[test]
    fn runtime_timeout_and_shutdown_do_not_join_a_blocked_discovery_worker() {
        let (release, blocked) = std::sync::mpsc::channel();
        let (finished, completion) = std::sync::mpsc::channel();
        let supervisor = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = runtime.block_on(async {
                let timeout = Duration::from_millis(20);
                let budget = RuntimeBacktraceLoadBudget::new(timeout);
                spawn_backtrace_discovery(timeout, budget, move || {
                    let _ = blocked.recv();
                    BacktraceRuntimePreparedOutcome::ModuleNotFound
                })
                .unwrap()
                .await
                .unwrap()
            });
            drop(runtime);
            finished
                .send(matches!(
                    result,
                    BacktraceRuntimeRefreshTaskOutcome::Prepared(
                        BacktraceRuntimePreparedOutcome::TimedOut { .. }
                    )
                ))
                .unwrap();
        });
        let completed_before_release = completion.recv_timeout(Duration::from_secs(2));
        let _ = release.send(());
        supervisor.join().unwrap();
        assert!(completed_before_release.unwrap());
    }

    #[test]
    fn backtrace_runtime_request_preserves_stopping_frame_identity() {
        let event = ParsedTraceEvent {
            generation: 0,
            trace_id: 1,
            timestamp: 2,
            pid: 42,
            tid: 43,
            instructions: vec![ParsedInstruction::Backtrace {
                requested_depth: 3,
                flags: 0,
                status: ghostscope_protocol::trace_event::BacktraceStatus::NoUnwindRowsForPc,
                error_code: 0,
                frames: vec![
                    ghostscope_protocol::ParsedBacktraceFrame {
                        module_cookie: 0x11,
                        pc: 0x22,
                        raw_ip: 0x33,
                        flags: 0,
                    },
                    ghostscope_protocol::ParsedBacktraceFrame {
                        module_cookie: 0x22,
                        pc: 0x44,
                        raw_ip: 0x55,
                        flags: 0,
                    },
                ],
            }],
        };

        let request = BacktraceRuntimeModuleRequest::from_events(&[event]);
        assert_eq!(
            request.observations,
            BTreeSet::from([BacktraceRuntimeModuleObservation {
                runtime_pid: 42,
                raw_ip: 0x55,
                cookie_hint: 0x22,
                cookie_is_authoritative: true,
            }])
        );
    }

    #[test]
    fn offsets_unavailable_requests_each_frame_with_only_stopping_cookie_relaxed() {
        let event = ParsedTraceEvent {
            generation: 0,
            trace_id: 1,
            timestamp: 2,
            pid: 42,
            tid: 43,
            instructions: vec![ParsedInstruction::Backtrace {
                requested_depth: 3,
                flags: 0,
                status: ghostscope_protocol::trace_event::BacktraceStatus::OffsetsUnavailable,
                error_code: 0,
                frames: vec![
                    ghostscope_protocol::ParsedBacktraceFrame {
                        module_cookie: 0x11,
                        pc: 0x22,
                        raw_ip: 0x33,
                        flags: 0,
                    },
                    ghostscope_protocol::ParsedBacktraceFrame {
                        module_cookie: 0x11,
                        pc: 0x44,
                        raw_ip: 0x55,
                        flags: 0,
                    },
                ],
            }],
        };

        let request = BacktraceRuntimeModuleRequest::from_events(&[event]);
        assert_eq!(
            request.observations,
            BTreeSet::from([
                BacktraceRuntimeModuleObservation {
                    runtime_pid: 42,
                    raw_ip: 0x33,
                    cookie_hint: 0x11,
                    cookie_is_authoritative: true,
                },
                BacktraceRuntimeModuleObservation {
                    runtime_pid: 42,
                    raw_ip: 0x55,
                    cookie_hint: 0x11,
                    cookie_is_authoritative: false,
                },
            ])
        );
    }

    #[test]
    fn backtrace_runtime_request_keeps_same_raw_ip_separate_by_pid() {
        let event = |pid| ParsedTraceEvent {
            generation: 0,
            trace_id: 1,
            timestamp: 2,
            pid,
            tid: pid,
            instructions: vec![ParsedInstruction::Backtrace {
                requested_depth: 2,
                flags: 0,
                status: ghostscope_protocol::trace_event::BacktraceStatus::OffsetsUnavailable,
                error_code: 0,
                frames: vec![ghostscope_protocol::ParsedBacktraceFrame {
                    module_cookie: 0x11,
                    pc: 0x22,
                    raw_ip: 0x55,
                    flags: 0,
                }],
            }],
        };

        let request = BacktraceRuntimeModuleRequest::from_events(&[event(42), event(43)]);
        assert_eq!(request.observations.len(), 2);
        assert!(request
            .observations
            .contains(&BacktraceRuntimeModuleObservation {
                runtime_pid: 42,
                raw_ip: 0x55,
                cookie_hint: 0x11,
                cookie_is_authoritative: false,
            }));
        assert!(request
            .observations
            .contains(&BacktraceRuntimeModuleObservation {
                runtime_pid: 43,
                raw_ip: 0x55,
                cookie_hint: 0x11,
                cookie_is_authoritative: false,
            }));
    }

    #[test]
    fn runtime_module_limit_counts_distinct_resolved_cookies() {
        let known = BTreeSet::new();
        let attempted = BTreeSet::from([0x11]);

        assert_eq!(
            backtrace_runtime_module_load_decision(0x11, &known, &attempted, 1),
            BacktraceRuntimeModuleLoadDecision::AlreadyAttempted
        );
        assert_eq!(
            backtrace_runtime_module_load_decision(0x22, &known, &attempted, 1),
            BacktraceRuntimeModuleLoadDecision::LimitReached
        );
    }

    #[tokio::test]
    async fn runtime_symbols_wait_for_the_cache_invalidation_outcome() {
        let mut session = test_session();
        session.process_analyzer = Some(
            DwarfAnalyzer::from_pid_runtime_modules_with_config_and_debuginfod(
                0,
                Vec::new(),
                &[],
                false,
                None,
                |_| {},
            )
            .await
            .unwrap(),
        );
        let observation = BacktraceRuntimeModuleObservation {
            runtime_pid: 42,
            raw_ip: 0x1010,
            cookie_hint: 2,
            cookie_is_authoritative: true,
        };
        let prepared = BacktraceRuntimePreparedOutcome::Loaded {
            resolved: ResolvedBacktraceRuntimeModule {
                observation,
                proc_pid: 42,
                cookie: 2,
                module: ghostscope_dwarf::LoadedModuleRuntimeInfo {
                    module_path: "runtime.so".into(),
                    loaded_address: Some(0x1000),
                    load_bias: Some(0x1000),
                    size: 0x100,
                },
                entries: Vec::new(),
                probe: None,
            },
            runtime_symbols: vec![ghostscope_dwarf::RuntimeTextSymbol {
                name: "late_symbol".into(),
                address: 0x10,
                size: 0x10,
            }],
            unwind_modules: Vec::new(),
        };
        let timeout = Duration::from_secs(2);
        session.backtrace_runtime_refresh_task = Some(BacktraceRuntimeRefreshTask {
            observation,
            timeout,
            budget: RuntimeBacktraceLoadBudget::new(timeout),
            baseline: Arc::new(ProcessManager::new()),
            handle: tokio::spawn(
                async move { BacktraceRuntimeRefreshTaskOutcome::Prepared(prepared) },
            ),
            result: None,
        });
        let published = tokio::time::timeout(timeout, async {
            loop {
                let outcome = session
                    .poll_backtrace_runtime_module_refresh()
                    .await
                    .unwrap();
                let symbol = session
                    .process_analyzer
                    .as_ref()
                    .unwrap()
                    .find_runtime_function_name_for_display(2, 0x10, false);
                if let Some(outcome) = outcome {
                    assert_eq!(symbol.as_deref(), Some("late_symbol"));
                    break outcome;
                }
                // None does not invalidate renderer caches, even if parsing has
                // finished and publication to the current actors has started.
                assert!(symbol.is_none());
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(matches!(
            published,
            BacktraceRuntimeRefreshOutcome::Loaded { modules: 1, .. }
        ));
    }

    #[tokio::test]
    async fn completed_cfi_survives_a_newer_mapping_and_consumes_the_load_budget() {
        let mut session = test_session();
        let entry = |cookie| ghostscope_process::PidOffsetsEntry {
            module_path: "runtime.so".into(),
            cookie,
            offsets: Default::default(),
            base: 0x1000,
            size: 0x100,
        };
        let observation = BacktraceRuntimeModuleObservation {
            runtime_pid: 42,
            raw_ip: 0x1010,
            cookie_hint: 0,
            cookie_is_authoritative: false,
        };
        let baseline = Arc::new(ProcessManager::new());
        // Sysmon has published a newer mapping before the prepared result is consumed.
        assert!(session
            .coordinator
            .lock()
            .unwrap()
            .apply_runtime_pid_snapshot(42, None, &[entry(3)]));
        session.backtrace_runtime_observations.insert(
            observation,
            BacktraceObservationState {
                mapping: None,
                attempts: 1,
                retry_at: None,
            },
        );
        let resolved = ResolvedBacktraceRuntimeModule {
            observation,
            proc_pid: 42,
            cookie: 2,
            module: ghostscope_dwarf::LoadedModuleRuntimeInfo {
                module_path: "runtime.so".into(),
                loaded_address: Some(0x1000),
                load_bias: Some(0x1000),
                size: 0x100,
            },
            entries: vec![entry(2)],
            probe: None,
        };
        let timeout = Duration::from_secs(2);
        let handle = tokio::spawn(async move {
            BacktraceRuntimeRefreshTaskOutcome::Prepared(BacktraceRuntimePreparedOutcome::Loaded {
                resolved,
                runtime_symbols: Vec::new(),
                unwind_modules: vec![(2, vec![Default::default()])],
            })
        });
        session.backtrace_runtime_refresh_task = Some(BacktraceRuntimeRefreshTask {
            observation,
            timeout,
            budget: RuntimeBacktraceLoadBudget::new(timeout),
            baseline,
            handle,
            result: None,
        });
        tokio::time::timeout(timeout, async {
            while session.backtrace_runtime_refresh_task.is_some() {
                tokio::task::yield_now().await;
                session
                    .poll_backtrace_runtime_module_refresh()
                    .await
                    .unwrap();
            }
        })
        .await
        .unwrap();
        assert!(session.backtrace_runtime_known_cookies.contains(&2));
        assert_eq!(session.backtrace_runtime_unwind_modules.len(), 1);
        assert_eq!(
            backtrace_runtime_module_load_decision(
                4,
                &session.backtrace_runtime_known_cookies,
                &session.backtrace_runtime_attempted_cookies,
                1,
            ),
            BacktraceRuntimeModuleLoadDecision::LimitReached
        );
        assert!(session.backtrace_runtime_observations[&observation]
            .retry_at
            .is_some());
        assert_eq!(
            session
                .coordinator
                .lock()
                .unwrap()
                .cached_offsets_with_paths_for_pid(42)
                .unwrap()[0]
                .cookie,
            3
        );
    }

    fn test_session() -> GhostSession {
        // Create a merged config with source settings
        let args = ParsedArgs {
            binary_path: None,
            target_path: None,
            binary_args: vec![],
            pid: None,
            log_file: None,
            emit_ready_marker: None,
            enable_logging: false,
            enable_console_logging: false,
            has_explicit_log_flag: false,
            has_explicit_console_log_flag: false,
            log_level: crate::config::settings::LogLevel::Warn,
            config: None,
            debug_file: None,
            script: None,
            script_file: None,
            tui_mode: false,
            dry_run: false,
            dry_run_details: false,
            script_output: None,
            status_enabled: true,
            has_explicit_status_flag: false,
            script_timestamp: None,
            script_output_events_per_sec: None,
            backtrace_depth: None,
            no_backtrace_runtime_modules: false,
            backtrace_runtime_modules_max: None,
            backtrace_runtime_module_timeout_ms: None,
            should_save_llvm_ir: false,
            should_save_ebpf: false,
            should_save_ast: false,
            layout_mode: crate::config::LayoutMode::Horizontal,
            force_perf_event_array: false,
            sleepable_uprobe: false,
            enable_sysmon_for_target: false,
            allow_loose_debug_match: false,
            debuginfod: None,
            debuginfod_urls: Vec::new(),
            debuginfod_cache_dir: None,
            debuginfod_timeout_secs: None,
            debuginfod_max_size: None,
            source_panel: false,
            no_source_panel: false,
        };

        let config = crate::config::Config {
            source: SourceConfig {
                substitutions: vec![
                    PathSubstitution {
                        from: "/build/path".to_string(),
                        to: "/local/path".to_string(),
                    },
                    PathSubstitution {
                        from: "/usr/src".to_string(),
                        to: "/home/src".to_string(),
                    },
                ],
                search_dirs: vec!["/home/user/sources".to_string()],
            },
            ..Default::default()
        };

        let user_config = UserConfig::new(args, config);
        let resolved_config = ResolvedConfig {
            user: user_config,
            runtime: RuntimeContext::default(),
            kernel_capabilities: ghostscope_loader::KernelCapabilities {
                supports_ringbuf: true,
                supports_perf_event_array: true,
                supports_ns_current_pid_tgid_helper: false,
                supports_sleepable_uprobe: false,
                supports_sleepable_tail_calls: false,
            },
        };

        GhostSession::new_with_config(&resolved_config)
    }

    #[test]
    fn test_new_with_config_sets_source_resolver() {
        let session = test_session();

        // Verify resolver was set correctly from config
        let rules = session.source_path_resolver.get_all_rules();
        assert_eq!(rules.config_substitution_count, 2);
        assert_eq!(rules.config_search_dir_count, 1);

        // Verify the substitutions are present
        assert!(rules
            .substitutions
            .iter()
            .any(|s| s.from == "/build/path" && s.to == "/local/path"));
        assert!(rules
            .substitutions
            .iter()
            .any(|s| s.from == "/usr/src" && s.to == "/home/src"));

        // Verify search dir is present
        assert!(rules
            .search_dirs
            .contains(&"/home/user/sources".to_string()));
    }
}

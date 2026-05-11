use crate::config::{ParsedArgs, PidViews, ResolvedConfig};
use crate::source_path::SourcePathResolver;
use crate::trace::TraceManager;
use anyhow::Result;
use ghostscope_debuginfod::{DebuginfodClient, DebuginfodConfig};
use ghostscope_dwarf::{DwarfAnalyzer, ModuleStats};
use ghostscope_process::{ProcessManager, ProcessSysmon, SysmonConfig};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

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
    pub trace_manager: TraceManager, // Manages all trace instances with their loaders
    pub source_path_resolver: SourcePathResolver, // Resolves DWARF paths to actual filesystem paths
    #[allow(dead_code)]
    pub debug_file: Option<String>, // Optional debug file path
    pub config: Option<ResolvedConfig>, // Holds the resolved configuration
    pub coordinator: Arc<Mutex<ProcessManager>>, // Manages PID/module offsets prefill and application
    pub sysmon: Option<Arc<Mutex<ProcessSysmon>>>, // Realtime process monitor (exec/fork/exit)
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
        }

        // Start sysmon:
        // -t executable: always start (PID collection is constrained in eBPF)
        // -t shared library: start only if enabled in config
        if s.proc_pid().is_none() && s.target_binary.is_some() {
            let tpath = PathBuf::from(s.target_binary.as_ref().unwrap());
            let is_shared = ghostscope_process::is_shared_object(&tpath);
            let should_start = if is_shared {
                config.ebpf_config.enable_sysmon_for_shared_lib
            } else {
                true
            };
            if should_start {
                let cfg = SysmonConfig {
                    target_module: Some(tpath.clone()),
                    proc_offsets_max_entries: config.ebpf_config.proc_module_offsets_max_entries
                        as u32,
                    perf_page_count: Some(config.ebpf_config.perf_page_count as usize),
                };
                let mgr = Arc::clone(&s.coordinator);
                let mut sysmon = ProcessSysmon::new(mgr, cfg);
                sysmon.start();
                s.sysmon = Some(Arc::new(Mutex::new(sysmon)));
                if is_shared {
                    info!("Sysmon started (-t shared library)");
                } else {
                    info!("Sysmon started (-t executable)");
                }
            } else {
                info!("Sysmon not started (-t shared library disabled by config)");
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
        };
        if let Some(pid_context) = s.pid_context.as_ref() {
            info!(
                "Session PID (legacy mode): proc_pid={} host_pid={}",
                pid_context.proc_pid, pid_context.host_pid
            );
        }
        if s.proc_pid().is_none() && s.target_binary.is_some() {
            let target_module = s.target_binary.as_ref().map(PathBuf::from);
            let cfg = SysmonConfig {
                target_module,
                proc_offsets_max_entries: 4096,
                perf_page_count: None,
            };
            let mgr = Arc::clone(&s.coordinator);
            let mut sysmon = ProcessSysmon::new(mgr, cfg);
            sysmon.start();
            s.sysmon = Some(Arc::new(Mutex::new(sysmon)));
            info!("Sysmon started (-t mode)");
        } else {
            info!("Sysmon not started (-p mode)");
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

    /// Load binary and perform DWARF analysis using parallel loading (TUI mode)
    pub async fn load_binary_parallel(&mut self) -> Result<()> {
        info!("Loading binary and performing DWARF analysis (parallel mode)");

        let debug_search_paths = self.get_debug_search_paths();
        let allow_loose = self.get_allow_loose_debug_match();
        let debuginfod_client = self.build_debuginfod_client()?;

        let process_analyzer = if let Some(proc_pid) = self.proc_pid() {
            info!("Loading binary from PID: {} (parallel)", proc_pid);
            Some(
                DwarfAnalyzer::from_pid_parallel_with_config_and_debuginfod(
                    proc_pid,
                    &debug_search_paths,
                    allow_loose,
                    debuginfod_client.clone(),
                    |_| {},
                )
                .await?,
            )
        } else if let Some(ref binary_path) = self.target_binary {
            info!("Loading binary from executable path: {}", binary_path);
            Some(
                DwarfAnalyzer::from_exec_path_with_config_and_debuginfod(
                    binary_path,
                    &debug_search_paths,
                    allow_loose,
                    debuginfod_client.clone(),
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
        let debuginfod_client = self.build_debuginfod_client()?;

        let process_analyzer = if let Some(proc_pid) = self.proc_pid() {
            info!(
                "Loading binary from PID: {} (parallel with progress)",
                proc_pid
            );
            Some(
                DwarfAnalyzer::from_pid_parallel_with_config_and_debuginfod(
                    proc_pid,
                    &debug_search_paths,
                    allow_loose,
                    debuginfod_client.clone(),
                    progress_callback,
                )
                .await?,
            )
        } else if let Some(ref binary_path) = self.target_binary {
            info!("Loading binary from executable path: {}", binary_path);
            Some(
                DwarfAnalyzer::from_exec_path_with_config_and_debuginfod_and_progress(
                    binary_path,
                    &debug_search_paths,
                    allow_loose,
                    debuginfod_client.clone(),
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::runtime::RuntimeContext;
    use crate::config::settings::{PathSubstitution, SourceConfig};
    use crate::config::UserConfig;

    #[test]
    fn test_new_with_config_sets_source_resolver() {
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
            script_output: None,
            status_enabled: true,
            has_explicit_status_flag: false,
            script_timestamp: None,
            script_output_events_per_sec: None,
            should_save_llvm_ir: false,
            should_save_ebpf: false,
            should_save_ast: false,
            layout_mode: crate::config::LayoutMode::Horizontal,
            force_perf_event_array: false,
            enable_sysmon_for_shared_lib: false,
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
            },
        };

        // Create session with config - should automatically set resolver
        let session = GhostSession::new_with_config(&resolved_config);

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

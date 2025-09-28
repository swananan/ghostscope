use crate::config::{MergedConfig, ParsedArgs};
use crate::tracing::TraceManager;
use anyhow::Result;
use ghostscope_dwarf::{DwarfAnalyzer, ModuleStats};
use tracing::{info, warn};

/// Trace information for save/load operations
#[derive(Debug, Clone)]
pub struct TraceInfo {
    pub trace_id: u32,
    pub target_display: String,
    pub script: String,
    pub enabled: bool,
    pub binary_path: Option<String>,
}

/// Ghost session state - manages binary analysis, process tracking, and trace instances
#[derive(Debug)]
pub struct GhostSession {
    pub process_analyzer: Option<DwarfAnalyzer>,
    pub target_binary: Option<String>,
    pub target_args: Vec<String>,
    pub target_pid: Option<u32>,
    pub trace_manager: TraceManager, // Manages all trace instances with their loaders
    #[allow(dead_code)]
    pub debug_file: Option<String>, // Optional debug file path
    #[allow(dead_code)]
    pub is_attached: bool,
    #[allow(dead_code)]
    pub config: Option<MergedConfig>, // Holds the merged configuration
}

impl GhostSession {
    /// Create a new ghost session with merged configuration
    pub fn new_with_config(config: &MergedConfig) -> Self {
        info!("Creating ghost session with merged configuration");

        Self {
            process_analyzer: None,
            target_binary: config.target_path.clone(),
            target_args: config.binary_args.clone(),
            target_pid: config.pid,
            debug_file: config
                .debug_file
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            trace_manager: TraceManager::new(),
            is_attached: false,
            config: Some(config.clone()),
        }
    }

    /// Create a new ghost session (without binary analysis - call load_binary separately)
    pub fn new(args: &ParsedArgs) -> Self {
        info!("Creating ghost session");

        Self {
            process_analyzer: None,
            target_binary: args.target_path.clone(),
            target_args: args.binary_args.clone(),
            target_pid: args.pid,
            debug_file: args
                .debug_file
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            trace_manager: TraceManager::new(),
            is_attached: false,
            config: None,
        }
    }

    /// Load binary and perform DWARF analysis using parallel loading (TUI mode)
    pub async fn load_binary_parallel(&mut self) -> Result<()> {
        info!("Loading binary and performing DWARF analysis (parallel mode)");

        let process_analyzer = if let Some(pid) = self.target_pid {
            info!("Loading binary from PID: {} (parallel)", pid);
            Some(DwarfAnalyzer::from_pid_parallel(pid).await?)
        } else if let Some(ref binary_path) = self.target_binary {
            info!("Loading binary from executable path: {}", binary_path);
            Some(DwarfAnalyzer::from_exec_path(binary_path).await?)
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

        let process_analyzer = if let Some(pid) = self.target_pid {
            info!("Loading binary from PID: {} (parallel with progress)", pid);
            Some(DwarfAnalyzer::from_pid_parallel_with_progress(pid, progress_callback).await?)
        } else if let Some(ref binary_path) = self.target_binary {
            info!("Loading binary from executable path: {}", binary_path);
            // Note: from_exec_path doesn't support progress callbacks yet
            Some(DwarfAnalyzer::from_exec_path(binary_path).await?)
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

    /// Create ghost session with merged config and load binary in one step
    pub async fn new_with_binary_and_config(config: &MergedConfig) -> Result<Self> {
        let mut session = Self::new_with_config(config);
        session.load_binary().await?;
        Ok(session)
    }

    /// Create ghost session and load binary in one step (now uses parallel loading)
    pub async fn new_with_binary(args: &ParsedArgs) -> Result<Self> {
        let mut session = Self::new(args);
        session.load_binary().await?;
        Ok(session)
    }

    /// Create a new session with binary loading in parallel mode with progress callback
    pub async fn new_with_binary_parallel_with_progress<F>(
        args: &ParsedArgs,
        progress_callback: F,
    ) -> Result<Self>
    where
        F: Fn(ghostscope_dwarf::ModuleLoadingEvent) + Send + Sync + 'static,
    {
        let mut session = Self::new(args);
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

    /// Get all traces for save/export operations
    pub fn get_traces(&self) -> Vec<TraceInfo> {
        self.trace_manager
            .get_all_traces()
            .into_iter()
            .map(|trace| TraceInfo {
                trace_id: trace.trace_id,
                target_display: trace.target_display.clone(),
                script: trace.script_content.clone(),
                enabled: trace.is_enabled,
                binary_path: Some(trace.binary_path.clone()),
            })
            .collect()
    }

    /// Get binary path if available
    pub fn binary_path(&self) -> Option<String> {
        self.target_binary.clone()
    }

    /// Get PID if available
    pub fn pid(&self) -> Option<u32> {
        self.target_pid
    }

    /// Check if session was started with target path (target file mode)
    pub fn is_target_mode(&self) -> bool {
        self.target_pid.is_none() && self.target_binary.is_some()
    }
}

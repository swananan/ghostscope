use crate::args::ParsedArgs;
use crate::tracing::TraceManager;
use anyhow::{Context, Result};
use ghostscope_dwarf::{DwarfAnalyzer, ModuleStats};
use ghostscope_loader::GhostScopeLoader;
use tracing::{error, info, warn};

/// Ghost session state - manages binary analysis, process tracking, and trace instances
#[derive(Debug)]
pub struct GhostSession {
    pub process_analyzer: Option<DwarfAnalyzer>,
    pub target_binary: Option<String>,
    pub target_args: Vec<String>,
    pub target_pid: Option<u32>,
    pub debug_file: Option<String>,  // Optional debug file path
    pub trace_manager: TraceManager, // Manages all trace instances with their loaders
    pub is_attached: bool,
}

impl GhostSession {
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

    /// Create ghost session and load binary in one step (now uses parallel loading)
    pub async fn new_with_binary(args: &ParsedArgs) -> Result<Self> {
        let mut session = Self::new(args);
        session.load_binary().await?;
        Ok(session)
    }

    /// Create ghost session and load binary with parallel loading (for TUI mode)
    pub async fn new_with_binary_parallel(args: &ParsedArgs) -> Result<Self> {
        let mut session = Self::new(args);
        session.load_binary_parallel().await?;
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

    /// Get debug information summary
    pub fn get_debug_info(&self) -> Option<String> {
        self.process_analyzer.as_ref().map(|a| {
            if let Some(main_module) = a.get_main_executable() {
                format!("Binary: {}, PID: {}", main_module.path, a.get_pid())
            } else {
                format!("PID: {}", a.get_pid())
            }
        })
    }

    /// List available functions
    pub fn list_functions(&self) -> Vec<String> {
        if let Some(ref analyzer) = self.process_analyzer {
            analyzer.lookup_all_function_names()
        } else {
            Vec::new()
        }
    }

    /// Find function by name pattern
    pub fn find_functions(&self, pattern: &str) -> Vec<String> {
        if let Some(ref analyzer) = self.process_analyzer {
            analyzer.lookup_functions_by_pattern(pattern)
        } else {
            Vec::new()
        }
    }

    /// Check if session was started with PID (process mode)
    pub fn is_process_mode(&self) -> bool {
        self.target_pid.is_some()
    }

    /// Check if session was started with target path (target file mode)
    pub fn is_target_mode(&self) -> bool {
        self.target_pid.is_none() && self.target_binary.is_some()
    }

    /// Get startup mode description for user messages
    pub fn get_startup_mode_description(&self) -> &'static str {
        if self.is_process_mode() {
            "process analysis mode (PID-based)"
        } else if self.is_target_mode() {
            "target file mode (path-based)"
        } else {
            "unknown mode"
        }
    }
}

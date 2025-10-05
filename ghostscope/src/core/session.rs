use crate::config::{MergedConfig, ParsedArgs};
use crate::runtime::source_path_resolver::SourcePathResolver;
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
    pub source_path_resolver: SourcePathResolver, // Resolves DWARF paths to actual filesystem paths
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
            source_path_resolver: SourcePathResolver::new(&config.source),
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
            source_path_resolver: SourcePathResolver::new(&Default::default()),
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

    /// Update source path resolver from merged config
    /// This should be called after setting session.config to ensure resolver has correct config
    pub fn update_source_resolver_from_config(&mut self) {
        if let Some(ref config) = self.config {
            self.source_path_resolver = SourcePathResolver::new(&config.source);
            info!(
                "Source path resolver updated from config: {} substitutions, {} search dirs",
                config.source.substitutions.len(),
                config.source.search_dirs.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::{PathSubstitution, SourceConfig};

    #[test]
    fn test_update_source_resolver_from_config() {
        // Create a session with default (empty) resolver
        let args = ParsedArgs {
            binary_path: None,
            target_path: None,
            binary_args: vec![],
            pid: None,
            log_file: None,
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
            should_save_llvm_ir: false,
            should_save_ebpf: false,
            should_save_ast: false,
            layout_mode: crate::config::LayoutMode::Horizontal,
            force_perf_event_array: false,
        };

        let mut session = GhostSession::new(&args);

        // Initially resolver should have no rules
        let initial_rules = session.source_path_resolver.get_all_rules();
        assert_eq!(initial_rules.config_substitution_count, 0);
        assert_eq!(initial_rules.config_search_dir_count, 0);

        // Create a merged config with source settings
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

        let merged_config = MergedConfig::new(args, config);

        // Set the config on the session
        session.config = Some(merged_config);

        // Update the resolver from config
        session.update_source_resolver_from_config();

        // Now resolver should have the config rules
        let updated_rules = session.source_path_resolver.get_all_rules();
        assert_eq!(updated_rules.config_substitution_count, 2);
        assert_eq!(updated_rules.config_search_dir_count, 1);

        // Verify the substitutions are present
        assert!(updated_rules
            .substitutions
            .iter()
            .any(|s| s.from == "/build/path" && s.to == "/local/path"));
        assert!(updated_rules
            .substitutions
            .iter()
            .any(|s| s.from == "/usr/src" && s.to == "/home/src"));

        // Verify search dir is present
        assert!(updated_rules
            .search_dirs
            .contains(&"/home/user/sources".to_string()));
    }
}

use crate::config::{MergedConfig, ParsedArgs};
use crate::runtime::source_path_resolver::SourcePathResolver;
use crate::tracing::TraceManager;
use anyhow::Result;
use ghostscope_dwarf::{DwarfAnalyzer, ModuleStats};
use tracing::{info, warn};

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
            config: Some(config.clone()),
        }
    }

    /// Create a new ghost session (without binary analysis - call load_binary separately)
    #[allow(dead_code)]
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
            config: None,
        }
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

    /// Load binary and perform DWARF analysis using parallel loading (TUI mode)
    pub async fn load_binary_parallel(&mut self) -> Result<()> {
        info!("Loading binary and performing DWARF analysis (parallel mode)");

        let debug_search_paths = self.get_debug_search_paths();
        let allow_loose = self.get_allow_loose_debug_match();

        let process_analyzer = if let Some(pid) = self.target_pid {
            info!("Loading binary from PID: {} (parallel)", pid);
            Some(
                DwarfAnalyzer::from_pid_parallel_with_config(
                    pid,
                    &debug_search_paths,
                    allow_loose,
                    |_| {},
                )
                .await?,
            )
        } else if let Some(ref binary_path) = self.target_binary {
            info!("Loading binary from executable path: {}", binary_path);
            Some(
                DwarfAnalyzer::from_exec_path_with_config(
                    binary_path,
                    &debug_search_paths,
                    allow_loose,
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

        let process_analyzer = if let Some(pid) = self.target_pid {
            info!("Loading binary from PID: {} (parallel with progress)", pid);
            Some(
                DwarfAnalyzer::from_pid_parallel_with_config(
                    pid,
                    &debug_search_paths,
                    allow_loose,
                    progress_callback,
                )
                .await?,
            )
        } else if let Some(ref binary_path) = self.target_binary {
            info!("Loading binary from executable path: {}", binary_path);
            Some(
                DwarfAnalyzer::from_exec_path_with_config(
                    binary_path,
                    &debug_search_paths,
                    allow_loose,
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

    /// Create ghost session with merged config and load binary in one step
    pub async fn new_with_binary_and_config(config: &MergedConfig) -> Result<Self> {
        let mut session = Self::new_with_config(config);
        session.load_binary().await?;
        Ok(session)
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
        config: &MergedConfig,
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

    /// Get PID if available
    pub fn pid(&self) -> Option<u32> {
        self.target_pid
    }

    /// Check if session was started with target path (target file mode)
    pub fn is_target_mode(&self) -> bool {
        self.target_pid.is_none() && self.target_binary.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::{PathSubstitution, SourceConfig};

    #[test]
    fn test_new_with_config_sets_source_resolver() {
        // Create a merged config with source settings
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
            allow_loose_debug_match: false,
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

        let merged_config = MergedConfig::new(args, config);

        // Create session with config - should automatically set resolver
        let session = GhostSession::new_with_config(&merged_config);

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

use crate::args::ParsedArgs;
use crate::trace_manager::TraceManager;
use anyhow::{Context, Result};
use ghostscope_binary::{BinaryAnalyzer, DebugInfo};
use ghostscope_loader::GhostScopeLoader;
use tracing::{error, info, warn};

/// Ghost session state - manages binary analysis, process tracking, and trace instances
#[derive(Debug)]
pub struct GhostSession {
    pub binary_analyzer: Option<BinaryAnalyzer>,
    pub target_binary: Option<String>,
    pub target_args: Vec<String>,
    pub target_pid: Option<u32>,
    pub debug_file: Option<String>,  // Optional debug file path
    pub trace_manager: TraceManager, // Manages all trace instances with their loaders
    pub command_loaders: Vec<GhostScopeLoader>, // Multiple loaders for command line mode uprobes
    pub is_attached: bool,
}

impl GhostSession {
    /// Create a new ghost session (without binary analysis - call load_binary separately)
    pub fn new(args: &ParsedArgs) -> Self {
        info!("Creating ghost session");

        Self {
            binary_analyzer: None,
            target_binary: args.binary_path.clone(),
            target_args: args.binary_args.clone(),
            target_pid: args.pid,
            debug_file: args
                .debug_file
                .as_ref()
                .map(|p| p.to_string_lossy().to_string()),
            trace_manager: TraceManager::new(),
            command_loaders: Vec::new(),
            is_attached: false,
        }
    }

    /// Load binary and perform DWARF analysis (separated from new)
    pub async fn load_binary(&mut self) -> Result<()> {
        info!("Loading binary and performing DWARF analysis");

        let debug_file_path = self.debug_file.as_deref();

        let binary_analyzer = if let Some(pid) = self.target_pid {
            info!("Loading binary from PID: {}", pid);
            Some(BinaryAnalyzer::from_pid(pid, debug_file_path)?)
        } else if let Some(ref binary_path) = self.target_binary {
            info!("Loading binary from path: {}", binary_path);
            Some(BinaryAnalyzer::new(binary_path, debug_file_path)?)
        } else {
            warn!("No PID or binary path specified - running without binary analysis");
            None
        };

        self.binary_analyzer = binary_analyzer;
        Ok(())
    }

    /// Create ghost session and load binary in one step (for command line mode)
    pub async fn new_with_binary(args: &ParsedArgs) -> Result<Self> {
        let mut session = Self::new(args);
        session.load_binary().await?;
        Ok(session)
    }

    /// Initialize eBPF loader with bytecode
    pub async fn initialize_ebpf(&mut self, bytecode: &[u8]) -> Result<()> {
        let loader = GhostScopeLoader::new(bytecode).context("Failed to create eBPF loader")?;

        self.command_loaders.push(loader);
        info!("eBPF loader initialized successfully");
        Ok(())
    }

    /// Attach multiple uprobes based on configurations
    pub async fn attach_uprobes(
        &mut self,
        uprobe_configs: &[ghostscope_compiler::UProbeConfig],
    ) -> Result<()> {
        info!("Attaching {} uprobes", uprobe_configs.len());

        for (i, config) in uprobe_configs.iter().enumerate() {
            info!(
                "Attaching uprobe {}: {:?}",
                i,
                config
                    .function_name
                    .as_ref()
                    .unwrap_or(&"<address>".to_string())
            );

            match self.attach_single_uprobe(config).await {
                Ok(()) => {
                    info!("  ✓ Successfully attached uprobe {}", i);
                }
                Err(e) => {
                    error!("  ✗ Failed to attach uprobe {}: {}", i, e);
                    // Continue with other uprobes instead of failing completely
                }
            }
        }

        info!("Uprobe attachment process completed");
        Ok(())
    }

    /// Attach a single uprobe configuration
    async fn attach_single_uprobe(
        &mut self,
        config: &ghostscope_compiler::UProbeConfig,
    ) -> Result<()> {
        // Create a new loader for this uprobe configuration
        info!(
            "    Creating new eBPF loader with {} bytes of bytecode",
            config.ebpf_bytecode.len()
        );
        let mut loader = GhostScopeLoader::new(&config.ebpf_bytecode)
            .context("Failed to create eBPF loader for uprobe config")?;

        if let Some(uprobe_offset) = config.uprobe_offset {
            if let Some(ref function_name) = config.function_name {
                // Function-based attachment with calculated offset
                info!("    Attaching to function '{}' at offset 0x{:x} in {} using eBPF function '{}'", 
                      function_name, uprobe_offset, config.binary_path, config.ebpf_function_name);

                loader.attach_uprobe_with_program_name(
                    &config.binary_path,
                    function_name,
                    Some(uprobe_offset),
                    config.target_pid.map(|p| p as i32),
                    Some(&config.ebpf_function_name),
                )?;
            } else {
                // Direct address attachment
                info!(
                    "    Attaching to address 0x{:x} in {} using eBPF function '{}'",
                    uprobe_offset, config.binary_path, config.ebpf_function_name
                );

                loader.attach_uprobe_with_program_name(
                    &config.binary_path,
                    &format!("0x{:x}", uprobe_offset), // Use address as function name
                    Some(uprobe_offset),
                    config.target_pid.map(|p| p as i32),
                    Some(&config.ebpf_function_name),
                )?;
            }
        } else {
            return Err(anyhow::anyhow!("No uprobe offset available in config"));
        }

        // Store the loader for event polling
        self.command_loaders.push(loader);

        Ok(())
    }

    /// Legacy single uprobe attachment (kept for compatibility)
    pub async fn legacy_attach_uprobe(&mut self) -> Result<()> {
        let loader = self
            .command_loaders
            .first_mut()
            .ok_or_else(|| anyhow::anyhow!("eBPF loader not initialized"))?;

        // TODO: do not use hardcoded function_name
        let function_name = "main"; // Default function for legacy compatibility
        warn!("Using legacy attach_uprobe with hardcoded 'main' function. Consider migrating to new trace-based approach.");

        // Determine binary path - prefer from binary analyzer if available
        let binary_path = if let Some(ref analyzer) = self.binary_analyzer {
            analyzer
                .debug_info()
                .binary_path
                .to_string_lossy()
                .to_string()
        } else if let Some(ref binary_path) = self.target_binary {
            binary_path.clone()
        } else {
            return Err(anyhow::anyhow!("No target binary specified"));
        };

        info!("Attaching uprobe to {}:{}", binary_path, function_name);

        // If we have a binary analyzer, verify the function exists and get its offset
        let function_offset = if let Some(ref analyzer) = self.binary_analyzer {
            match analyzer.find_symbol(function_name) {
                Some(symbol) => {
                    info!(
                        "Found target function '{}' at address 0x{:x}",
                        function_name, symbol.address
                    );

                    // Calculate proper uprobe offset
                    if let Some(uprobe_offset) = symbol.uprobe_offset() {
                        info!(
                            "Calculated uprobe offset: 0x{:x} (raw address: 0x{:x})",
                            uprobe_offset, symbol.address
                        );
                        info!(
                            "  Section: {:?}, VirtAddr: {:?}, FileOffset: {:?}",
                            symbol.section_name, symbol.section_viraddr, symbol.section_file_offset
                        );
                        Some(uprobe_offset)
                    } else {
                        warn!("Unable to calculate uprobe offset for function '{}', falling back to raw address", 
                              function_name);
                        Some(symbol.address)
                    }
                }
                None => {
                    warn!("Function '{}' not found in symbol table", function_name);

                    // Show similar function names
                    let similar = analyzer.symbol_table.find_matching(function_name);
                    if !similar.is_empty() {
                        info!("Similar functions found:");
                        for sym in similar.iter().take(5) {
                            info!("  {}", sym.name);
                        }
                    }
                    None
                }
            }
        } else {
            None
        };

        // Attempt to attach uprobe with offset if available
        loader
            .attach_uprobe(
                &binary_path,
                function_name,
                function_offset,
                self.target_pid.map(|pid| pid as i32),
            )
            .context("Failed to attach uprobe")?;

        self.is_attached = true;
        info!("Uprobe attached successfully");
        Ok(())
    }

    /// Monitor events from multiple loaders using futures::select_all
    async fn monitor_multiple_loaders(&mut self) -> Result<()> {
        let mut event_count = 0;

        loop {
            tokio::select! {
                result = {
                    let futures: Vec<_> = self.command_loaders.iter_mut()
                        .enumerate()
                        .map(|(i, loader)| Box::pin(async move {
                            (i, loader.wait_for_events_async().await)
                        }))
                        .collect();

                    futures::future::select_all(futures)
                } => {
                    let ((loader_index, result), _index, _remaining_futures) = result;

                    match result {
                        Ok(events) => {
                            for event in events {
                                event_count += 1;
                                info!("[Loader {}] [Event #{}] {}", loader_index, event_count, event);
                            }
                        }
                        Err(e) => {
                            error!("Loader {} error: {}", loader_index, e);
                        }
                    }
                }

                _ = tokio::signal::ctrl_c() => {
                    info!("Received Ctrl+C, shutting down...");
                    return Ok(());
                }
            }
        }
    }

    /// Start event monitoring loop
    pub async fn start_event_monitoring(&mut self) -> Result<()> {
        if !self.command_loaders.is_empty() {
            info!(
                "Starting event monitoring loop for {} loaders",
                self.command_loaders.len()
            );

            self.monitor_multiple_loaders().await
        } else {
            Err(anyhow::anyhow!(
                "No eBPF loaders initialized - unable to monitor events"
            ))
        }
    }

    /// Get debug information summary
    pub fn get_debug_info(&self) -> Option<&DebugInfo> {
        self.binary_analyzer.as_ref().map(|a| a.debug_info())
    }

    /// List available functions
    pub fn list_functions(&self) -> Vec<String> {
        if let Some(ref analyzer) = self.binary_analyzer {
            analyzer
                .symbol_table
                .get_functions()
                .iter()
                .map(|sym| sym.name.clone())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Find function by name pattern
    pub fn find_functions(&self, pattern: &str) -> Vec<String> {
        if let Some(ref analyzer) = self.binary_analyzer {
            analyzer
                .symbol_table
                .find_matching(pattern)
                .iter()
                .map(|sym| sym.name.clone())
                .collect()
        } else {
            Vec::new()
        }
    }
}

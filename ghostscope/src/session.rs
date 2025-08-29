use crate::args::ParsedArgs;
use anyhow::{Context, Result};
use ghostscope_binary::{BinaryAnalyzer, DebugInfo};
use ghostscope_loader::GhostScopeLoader;
use tracing::{error, info, warn};

/// Debug session state
#[derive(Debug)]
pub struct DebugSession {
    pub binary_analyzer: Option<BinaryAnalyzer>,
    pub loader: Option<GhostScopeLoader>, // Keep for backward compatibility
    pub loaders: Vec<GhostScopeLoader>,   // Multiple loaders for multiple uprobes
    pub target_binary: Option<String>,
    pub target_args: Vec<String>,
    pub target_function: Option<String>,
    pub target_pid: Option<u32>,
    pub is_attached: bool,
}

impl DebugSession {
    /// Create a new debug session from parsed arguments
    pub fn new(args: &ParsedArgs) -> Result<Self> {
        info!("Creating debug session");

        let binary_analyzer = if let Some(pid) = args.pid {
            info!("Loading binary from PID: {}", pid);

            // Create binary analyzer from PID
            let debug_path = args.debug_file.as_ref().map(|p| p.to_str().unwrap());
            match BinaryAnalyzer::from_pid(pid, debug_path) {
                Ok(analyzer) => {
                    let debug_info = analyzer.debug_info();
                    info!("Binary analysis complete:");
                    info!("  Path: {}", debug_info.binary_path.display());
                    info!("  Debug info: {:?}", debug_info.debug_path);
                    info!("  Has symbols: {}", debug_info.has_symbols);
                    info!("  Has debug info: {}", debug_info.has_debug_info);
                    info!("  Entry point: {:?}", debug_info.entry_point);
                    info!("  Base address: 0x{:x}", debug_info.base_address);

                    Some(analyzer)
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to analyze binary for PID {}: {}",
                        pid,
                        e
                    ));
                }
            }
        } else if let Some(ref binary_path) = args.binary_path {
            info!("Loading binary: {}", binary_path);

            // Create binary analyzer
            let debug_path = args.debug_file.as_ref().map(|p| p.to_str().unwrap());
            match BinaryAnalyzer::new(binary_path, debug_path) {
                Ok(analyzer) => {
                    let debug_info = analyzer.debug_info();
                    info!("Binary analysis complete:");
                    info!("  Path: {}", debug_info.binary_path.display());
                    info!("  Debug info: {:?}", debug_info.debug_path);
                    info!("  Has symbols: {}", debug_info.has_symbols);
                    info!("  Has debug info: {}", debug_info.has_debug_info);
                    info!("  Entry point: {:?}", debug_info.entry_point);
                    info!("  Base address: 0x{:x}", debug_info.base_address);

                    Some(analyzer)
                }
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "Failed to analyze binary '{}': {}",
                        binary_path,
                        e
                    ));
                }
            }
        } else {
            info!("No target binary specified");
            None
        };

        Ok(Self {
            binary_analyzer,
            loader: None,
            loaders: Vec::new(),
            target_binary: args.binary_path.clone(),
            target_args: args.binary_args.clone(),
            target_function: None, // Functions will be determined from trace script
            target_pid: args.pid,
            is_attached: false,
        })
    }

    /// Initialize eBPF loader with compiled program
    pub async fn initialize_ebpf(&mut self, bytecode: &[u8]) -> Result<()> {
        info!(
            "Initializing eBPF loader with {} bytes of bytecode",
            bytecode.len()
        );

        let loader = GhostScopeLoader::new(bytecode).context("Failed to create eBPF loader")?;

        self.loader = Some(loader);
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
        self.loaders.push(loader);

        Ok(())
    }

    /// Legacy single uprobe attachment (kept for compatibility)
    pub async fn attach_uprobe(&mut self) -> Result<()> {
        let loader = self
            .loader
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("eBPF loader not initialized"))?;

        let function_name = self.target_function.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Target function extraction from trace script not yet implemented. Use legacy --function parameter temporarily."))?;

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

    /// Start event monitoring loop
    pub async fn start_monitoring(&mut self) -> Result<()> {
        // Check if we have any loaders (new multi-uprobe approach) or fall back to single loader
        if !self.loaders.is_empty() {
            info!(
                "Starting event monitoring loop for {} loaders",
                self.loaders.len()
            );

            let mut event_count = 0;
            loop {
                tokio::select! {
                    // Poll eBPF events from all loaders
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                        for (i, loader) in self.loaders.iter_mut().enumerate() {
                            match loader.poll_events() {
                                Ok(Some(events)) => {
                                    for event in events {
                                        event_count += 1;
                                        info!("[Loader {}] [Event #{}] {}", i, event_count, event);
                                    }
                                }
                                Ok(None) => {
                                    // No events, continue loop
                                }
                                Err(e) => {
                                    error!("Error polling events from loader {}: {}", i, e);
                                    // Continue with other loaders
                                }
                            }
                        }
                    }

                    // Handle Ctrl+C
                    _ = tokio::signal::ctrl_c() => {
                        info!("Received Ctrl+C, shutting down...");
                        break;
                    }
                }
            }
        } else if let Some(ref mut loader) = self.loader {
            info!("Starting event monitoring loop for single legacy loader");

            let mut event_count = 0;
            loop {
                tokio::select! {
                    // Poll eBPF events
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                        match loader.poll_events() {
                            Ok(Some(events)) => {
                                for event in events {
                                    event_count += 1;
                                    info!("[Event #{}] {}", event_count, event);
                                }
                            }
                            Ok(None) => {
                                // No events, continue loop
                            }
                            Err(e) => {
                                error!("Error polling events: {}", e);
                                break;
                            }
                        }
                    }

                    // Handle Ctrl+C
                    _ = tokio::signal::ctrl_c() => {
                        info!("Received Ctrl+C, shutting down...");
                        break;
                    }
                }
            }
        } else {
            return Err(anyhow::anyhow!(
                "No eBPF loaders initialized - unable to monitor events"
            ));
        }

        Ok(())
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

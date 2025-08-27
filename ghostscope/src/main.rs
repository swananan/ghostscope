mod args;
mod session;
mod logging;

use args::ParsedArgs;
use session::DebugSession;
use tracing::{error, info, warn};
use anyhow::Result;
use ghostscope_loader::GhostScopeLoader;

#[tokio::main]
async fn main() {
    // Root check disabled for debugging
    // if !is_root() {
    //     eprintln!("Error: GhostScope requires root privileges to load eBPF programs.");
    //     eprintln!("Please run with sudo:");
    //     eprintln!("  sudo ./target/debug/ghostscope [OPTIONS] <target_binary> [binary_args...]");
    //     eprintln!("Example:");
    //     eprintln!("  sudo ./target/debug/ghostscope --function main /bin/ls -la");
    //     eprintln!("  sudo ./target/debug/ghostscope --args /bin/cat file.txt");
    //     std::process::exit(1);
    // }

    // Parse command line arguments
    let parsed_args = args::Args::parse_args();
    
    // Initialize logging with optional custom log file path
    let log_file_path = parsed_args.log_file.as_ref().and_then(|p| p.to_str());
    if let Err(e) = logging::initialize_logging(log_file_path) {
        eprintln!("Failed to initialize logging: {}", e);
        return;
    }

    // Display startup information
    info!("{}", ghostscope_compiler::hello());
    info!("{}", ghostscope_frontend::hello());
    info!("{}", ghostscope_loader::hello());
    info!("{}", ghostscope_ui::hello());

    // Create debug session
    let mut session = match DebugSession::new(&parsed_args) {
        Ok(session) => session,
        Err(e) => {
            error!("Failed to create debug session: {}", e);
            return;
        }
    };

    // Display parsed arguments and session info
    info!("Debug session created");
    info!("Save LLVM IR files: {}", parsed_args.should_save_llvm_ir);
    info!("Save eBPF bytecode files: {}", parsed_args.should_save_ebpf);
    
    if let Some(ref binary) = session.target_binary {
        info!("Target binary: {}", binary);
        if !session.target_args.is_empty() {
            info!("Binary arguments: {:?}", session.target_args);
        }
    }
    // Check for script parameter
    if parsed_args.script.is_some() || parsed_args.script_file.is_some() {
        info!("Script provided via command line arguments");
    }
    if let Some(pid) = session.target_pid {
        info!("Target PID: {}", pid);
    }

    // Display debug information if available
    if let Some(debug_info) = session.get_debug_info() {
        info!("Binary analysis complete:");
        info!("  Path: {}", debug_info.binary_path.display());
        info!("  Debug info: {:?}", debug_info.debug_path);
        info!("  Has symbols: {}", debug_info.has_symbols);
        info!("  Has debug info: {}", debug_info.has_debug_info);
        info!("  Entry point: {:?}", debug_info.entry_point);
        info!("  Base address: 0x{:x}", debug_info.base_address);
        
        // Show available functions if target function not specified
        if session.target_function.is_none() {
            let functions = session.list_functions();
            if functions.len() > 0 {
                info!("Available functions (showing first 10):");
                for func in functions.iter().take(10) {
                    info!("  {}", func);
                }
                if functions.len() > 10 {
                    info!("  ... and {} more", functions.len() - 10);
                }
            }
        }
    }

    // Get script content from arguments or default
    let script_content = match (&parsed_args.script, &parsed_args.script_file) {
        (Some(script), _) => {
            info!("Using inline script from command line");
            script.clone()
        }
        (None, Some(script_file)) => {
            info!("Loading script from file: {}", script_file.display());
            match std::fs::read_to_string(script_file) {
                Ok(content) => content,
                Err(e) => {
                    error!("Failed to read script file '{}': {}", script_file.display(), e);
                    return;
                }
            }
        }
        (None, None) => {
            warn!("No script provided, using default trace example");
            r#"
                trace main {
                    print "Entering main function";
                    print $arg0;
                    print $arg1;
                }
            "#.to_string()
        }
    };

    info!("Starting GhostScope with script");
    info!("Script content:\n{}", script_content);

    // Note: LLVM IR generation is now unified with eBPF compilation
    // Each trace pattern will save its IR file during eBPF compilation

    // Compile to eBPF uprobe configurations (now includes LLVM IR generation)
    let binary_path_string = if let Some(ref analyzer) = session.binary_analyzer {
        Some(analyzer.debug_info().binary_path.to_string_lossy().to_string())
    } else {
        session.target_binary.clone()
    };
    let binary_path_for_naming = binary_path_string.as_deref();
    
    match ghostscope_compiler::compile_to_uprobe_configs(&script_content, session.target_pid, binary_path_for_naming, parsed_args.should_save_llvm_ir) {
        Ok(mut uprobe_configs) => {
            info!("eBPF compilation successful, generated {} uprobe configurations", uprobe_configs.len());
            if parsed_args.should_save_llvm_ir || parsed_args.should_save_ebpf {
                info!("Files saved with consistent naming: gs_{{pid}}_{{exec}}_{{func}}_{{index}}");
            }
            
            // Save each config's bytecode to individual files with consistent naming (if enabled)
            if parsed_args.should_save_ebpf {
                for (index, config) in uprobe_configs.iter().enumerate() {
                    let file_base_name = ghostscope_compiler::generate_file_name(
                        &config.trace_pattern, 
                        index, 
                        session.target_pid, 
                        binary_path_for_naming
                    );
                    let ebpf_filename = format!("{}.o", file_base_name);
                    
                    if let Err(e) = std::fs::write(&ebpf_filename, &config.ebpf_bytecode) {
                        warn!("Failed to save eBPF bytecode to '{}': {}", ebpf_filename, e);
                    } else {
                        info!("eBPF bytecode saved to '{}'", ebpf_filename);
                    }
                }
            }

            // Resolve addresses for each uprobe configuration
            if !uprobe_configs.is_empty() {
                info!("Processing {} uprobe configurations from script:", uprobe_configs.len());
                let binary_path = if let Some(ref analyzer) = session.binary_analyzer {
                    analyzer.debug_info().binary_path.to_string_lossy().to_string()
                } else if let Some(ref binary_path) = session.target_binary {
                    binary_path.clone()
                } else {
                    error!("No target binary available for address resolution");
                    return;
                };
                
                for (i, config) in uprobe_configs.iter_mut().enumerate() {
                    // Update binary path and target PID for each config
                    config.binary_path = binary_path.clone();
                    config.target_pid = session.target_pid;
                    
                    match &config.trace_pattern {
                        ghostscope_compiler::ast::TracePattern::FunctionName(function_name) => {
                            info!("  {}: Function '{}' - looking up in symbol table", i, function_name);
                            
                            if let Some(ref analyzer) = session.binary_analyzer {
                                match analyzer.find_symbol(function_name) {
                                    Some(symbol) => {
                                        info!("    Found function '{}' at address 0x{:x}", function_name, symbol.address);
                                        
                                        // Calculate uprobe offset
                                        if let Some(uprobe_offset) = symbol.uprobe_offset() {
                                            info!("    Calculated uprobe offset: 0x{:x}", uprobe_offset);
                                            
                                            // Update config with resolved addresses
                                            config.function_name = Some(function_name.clone());
                                            config.function_address = Some(symbol.address);
                                            config.uprobe_offset = Some(uprobe_offset);
                                            
                                            info!("    ✓ UProbe config updated for function '{}'", function_name);
                                        } else {
                                            warn!("    ✗ Unable to calculate uprobe offset for function '{}'", function_name);
                                        }
                                    }
                                    None => {
                                        warn!("    ✗ Function '{}' not found in symbol table", function_name);
                                        
                                        // Show similar function names for debugging
                                        let similar = analyzer.symbol_table.find_matching(function_name);
                                        if !similar.is_empty() {
                                            info!("    Similar functions found:");
                                            for sym in similar.iter().take(5) {
                                                info!("      {}", sym.name);
                                            }
                                        }
                                    }
                                }
                            } else {
                                warn!("    ✗ No binary analyzer available for symbol lookup");
                            }
                        }
                        ghostscope_compiler::ast::TracePattern::Wildcard(pattern) => {
                            info!("  {}: Wildcard '{}' - pattern matching not yet implemented", i, pattern);
                        }
                        ghostscope_compiler::ast::TracePattern::Address(addr) => {
                            info!("  {}: Address 0x{:x} - direct attachment", i, addr);
                            
                            // Update config with address information
                            config.function_name = None;
                            config.function_address = Some(*addr);
                            config.uprobe_offset = Some(*addr); // For direct address, offset equals address
                            
                            info!("    ✓ UProbe config updated for address 0x{:x}", addr);
                        }
                    }
                }
                
                info!("Updated {} uprobe configurations", uprobe_configs.len());
                
                // Attach each uprobe configuration
                if !uprobe_configs.is_empty() {
                    info!("Attaching uprobes using the configurations");
                    for (i, config) in uprobe_configs.iter().enumerate() {
                        info!("  Config {}: {:?} -> 0x{:x}", 
                              i, 
                              config.function_name.as_ref().unwrap_or(&format!("0x{:x}", config.function_address.unwrap_or(0))),
                              config.uprobe_offset.unwrap_or(0));
                    }
                    
                    match session.attach_uprobes(&uprobe_configs).await {
                        Ok(()) => {
                            info!("All uprobes attached successfully! Starting event monitoring...");
                        }
                        Err(e) => {
                            error!("Failed to attach uprobes: {}", e);
                            info!("Possible reasons:");
                            info!("1. Need root permissions (run with sudo)");
                            info!("2. Target binary doesn't exist or lacks debug info");
                            info!("3. Process not running or PID invalid");
                            info!("4. Function addresses not accessible");
                            return;
                        }
                    }
                } else {
                    warn!("No uprobe configurations created - nothing to attach");
                    return;
                }
            } else {
                info!("No trace points found in script - using legacy behavior");
            }
            
            info!("\nNew usage with trace scripts:");
            info!("  sudo ./ghostscope --script 'trace main {{ print \"Hello\"; }}'");
            info!("  sudo ./ghostscope --script-file my_trace.gs");
            info!("  sudo ./ghostscope -s 'trace printf* {{ print $arg0; }}'");
            info!("\nTrace script syntax:");
            info!("  trace <function_name> {{ statements... }}");
            info!("  trace <pattern*> {{ statements... }}");
            info!("  trace 0x<address> {{ statements... }}");
            info!("  Special variables: $arg0, $arg1, $retval, $pc, $sp");
            
            // For now, skip uprobe attachment since we need to implement
            // trace pattern extraction and multiple uprobe support

            // Start event monitoring loop
            if let Err(e) = session.start_monitoring().await {
                error!("Event monitoring failed: {}", e);
            }
        }
        Err(e) => {
            error!("eBPF compilation failed: {:?}", e);
        }
    }
}


/// Check if the program is running with root privileges
fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

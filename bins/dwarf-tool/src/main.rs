//! DWARF Analysis Tool for Ghostscope
//!
//! Simple, intuitive tool for analyzing DWARF debug information

use anyhow::Result;
use clap::{Parser, Subcommand};
use ghostscope_dwarf::{DwarfAnalyzer, ModuleAddress};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "dwarf-tool")]
#[command(version = "0.1.0")]
#[command(about = "DWARF debug information analysis tool")]
#[command(author = "swananan")]
struct Cli {
    /// Process ID to analyze
    pid: u32,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze variables at source file:line (e.g., main.c:42)
    #[command(name = "source-line", alias = "s")]
    SourceLine {
        /// Source location (file:line)
        location: String,
        /// Use parallel loading
        #[arg(long)]
        parallel: bool,
        /// Use sequential loading
        #[arg(long)]
        sequential: bool,
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
        /// Quiet output
        #[arg(short, long)]
        quiet: bool,
        /// JSON output
        #[arg(long)]
        json: bool,
    },
    /// Analyze variables in function (e.g., calculate_something)
    #[command(name = "function", alias = "f")]
    Function {
        /// Function name
        name: String,
        /// Use parallel loading
        #[arg(long)]
        parallel: bool,
        /// Use sequential loading
        #[arg(long)]
        sequential: bool,
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
        /// Quiet output
        #[arg(short, long)]
        quiet: bool,
        /// JSON output
        #[arg(long)]
        json: bool,
    },
    /// Analyze variables at module address (e.g., /lib/libc.so.6 0x1234)
    #[command(name = "module-addr", alias = "m")]
    ModuleAddr {
        /// Module path
        module: String,
        /// Address (hex format: 0x1234 or decimal)
        address: String,
        /// Use parallel loading
        #[arg(long)]
        parallel: bool,
        /// Use sequential loading
        #[arg(long)]
        sequential: bool,
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
        /// Quiet output
        #[arg(short, long)]
        quiet: bool,
        /// JSON output
        #[arg(long)]
        json: bool,
    },
    /// List all loaded modules
    #[command(name = "modules", alias = "ls")]
    ListModules {
        /// Use parallel loading
        #[arg(long)]
        parallel: bool,
        /// Use sequential loading
        #[arg(long)]
        sequential: bool,
        /// Quiet output
        #[arg(short, long)]
        quiet: bool,
        /// JSON output
        #[arg(long)]
        json: bool,
    },
    /// Performance benchmark
    #[command(name = "benchmark", alias = "bench")]
    Benchmark {
        /// Number of runs
        #[arg(long, default_value = "3")]
        runs: usize,
    },
}

#[derive(Debug, serde::Serialize)]
struct VariableInfo {
    name: String,
    type_name: String,
    location: String,
    is_parameter: bool,
    scope_depth: u32,
}

#[derive(Debug, serde::Serialize)]
struct AddressInfo {
    module: String,
    address: String,
    variables: Vec<VariableInfo>,
}

#[derive(Debug, serde::Serialize)]
struct AnalysisResult {
    source_location: String,
    addresses: Vec<AddressInfo>,
    total_variables: usize,
    loading_time_ms: u64,
}

#[derive(Debug, serde::Serialize)]
struct FunctionResult {
    function_name: String,
    modules: Vec<FunctionModuleInfo>,
    total_variables: usize,
}

#[derive(Debug, serde::Serialize)]
struct FunctionModuleInfo {
    module: String,
    addresses: Vec<AddressInfo>,
}

// Helper trait to extract common options from commands
trait CommonOptions {
    fn parallel(&self) -> bool;
    fn sequential(&self) -> bool;
    fn verbose(&self) -> bool;
    fn quiet(&self) -> bool;
    fn json(&self) -> bool;
}

impl CommonOptions for Commands {
    fn parallel(&self) -> bool {
        match self {
            Commands::SourceLine { parallel, .. } => *parallel,
            Commands::Function { parallel, .. } => *parallel,
            Commands::ModuleAddr { parallel, .. } => *parallel,
            Commands::ListModules { parallel, .. } => *parallel,
            Commands::Benchmark { .. } => false,
        }
    }

    fn sequential(&self) -> bool {
        match self {
            Commands::SourceLine { sequential, .. } => *sequential,
            Commands::Function { sequential, .. } => *sequential,
            Commands::ModuleAddr { sequential, .. } => *sequential,
            Commands::ListModules { sequential, .. } => *sequential,
            Commands::Benchmark { .. } => false,
        }
    }

    fn verbose(&self) -> bool {
        match self {
            Commands::SourceLine { verbose, .. } => *verbose,
            Commands::Function { verbose, .. } => *verbose,
            Commands::ModuleAddr { verbose, .. } => *verbose,
            Commands::ListModules { .. } => false,
            Commands::Benchmark { .. } => false,
        }
    }

    fn quiet(&self) -> bool {
        match self {
            Commands::SourceLine { quiet, .. } => *quiet,
            Commands::Function { quiet, .. } => *quiet,
            Commands::ModuleAddr { quiet, .. } => *quiet,
            Commands::ListModules { quiet, .. } => *quiet,
            Commands::Benchmark { .. } => false,
        }
    }

    fn json(&self) -> bool {
        match self {
            Commands::SourceLine { json, .. } => *json,
            Commands::Function { json, .. } => *json,
            Commands::ModuleAddr { json, .. } => *json,
            Commands::ListModules { json, .. } => *json,
            Commands::Benchmark { .. } => false,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli.command);

    // Handle benchmark separately (no need to load modules)
    if let Commands::Benchmark { runs } = &cli.command {
        return run_benchmark(cli.pid, *runs).await;
    }

    // Load analyzer
    let loading_time = load_analyzer_and_execute(cli).await?;

    Ok(())
}

fn init_logging(command: &Commands) {
    // Check if RUST_LOG environment variable is set
    if std::env::var("RUST_LOG").is_ok() {
        // Use environment variable setting
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    } else {
        // Default behavior based on command line flags
        if command.quiet() {
            // Quiet mode: no logs
            tracing_subscriber::fmt().with_env_filter("off").init();
        } else if command.verbose() {
            // Verbose mode: debug level
            tracing_subscriber::fmt().with_env_filter("debug").init();
        } else {
            // Default: no logs (silent by default)
            tracing_subscriber::fmt().with_env_filter("off").init();
        }
    }
}

async fn load_analyzer_and_execute(cli: Cli) -> Result<std::time::Duration> {
    let use_parallel = if cli.command.sequential() {
        false
    } else {
        true // Default to parallel
    };

    if !cli.command.quiet() {
        let mode = if use_parallel {
            "Parallel"
        } else {
            "Sequential"
        };
        println!("Loading modules... [{}]", mode);
    }

    let start = Instant::now();
    let mut analyzer = if use_parallel {
        DwarfAnalyzer::from_pid_parallel(cli.pid).await?
    } else {
        DwarfAnalyzer::from_pid_sequential(cli.pid)?
    };
    let loading_time = start.elapsed();

    if !cli.command.quiet() && !cli.command.json() {
        println!("Loaded in {}ms", loading_time.as_millis());
    }

    // Execute command
    match &cli.command {
        Commands::SourceLine { location, .. } => {
            analyze_source_location(&mut analyzer, location, &cli.command, loading_time).await?;
        }
        Commands::Function { name, .. } => {
            analyze_function(&mut analyzer, name, &cli.command).await?;
        }
        Commands::ModuleAddr {
            module, address, ..
        } => {
            analyze_module_address(&mut analyzer, module, address, &cli.command).await?;
        }
        Commands::ListModules { .. } => {
            list_modules(&analyzer, &cli.command);
        }
        Commands::Benchmark { .. } => unreachable!(), // Handled earlier
    }

    Ok(loading_time)
}

async fn analyze_source_location(
    analyzer: &mut DwarfAnalyzer,
    source: &str,
    options: &Commands,
    loading_time: std::time::Duration,
) -> Result<()> {
    let (file_path, line_number) = parse_source_line(source)?;
    let addresses = analyzer.lookup_addresses_by_source_line(file_path, line_number);

    if addresses.is_empty() {
        if options.json() {
            let result = AnalysisResult {
                source_location: source.to_string(),
                addresses: vec![],
                total_variables: 0,
                loading_time_ms: loading_time.as_millis() as u64,
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else if !options.quiet() {
            println!("No addresses found for {}", source);
        }
        return Ok(());
    }

    let mut address_infos = Vec::new();
    let mut total_variables = 0;

    if options.json() {
        for module_address in &addresses {
            let variables = analyzer.get_all_variables_at_address(module_address)?;

            let var_infos: Vec<VariableInfo> = variables
                .iter()
                .map(|var| VariableInfo {
                    name: var.name.clone(),
                    type_name: var.type_name.clone(),
                    location: format!("{}", var.evaluation_result),
                    is_parameter: var.is_parameter,
                    scope_depth: var.scope_depth as u32,
                })
                .collect();

            total_variables += var_infos.len();

            address_infos.push(AddressInfo {
                module: module_address.module_display().to_string(),
                address: format!("0x{:x}", module_address.address),
                variables: var_infos,
            });
        }

        let result = AnalysisResult {
            source_location: source.to_string(),
            addresses: address_infos,
            total_variables,
            loading_time_ms: loading_time.as_millis() as u64,
        };
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        // Print results for each address
        for module_address in addresses {
            let variables = analyzer.get_all_variables_at_address(&module_address)?;

            if !options.quiet() {
                println!(
                    "\n=== {} @ {}:{} → 0x{:x} ===",
                    module_address.module_display(),
                    file_path,
                    line_number,
                    module_address.address
                );
                if variables.is_empty() {
                    println!("No variables found");
                } else {
                    print_variables_with_style(&variables, options);
                }
            }
        }
    }

    Ok(())
}

async fn analyze_function(
    analyzer: &mut DwarfAnalyzer,
    func_name: &str,
    options: &Commands,
) -> Result<()> {
    let addresses = analyzer.lookup_function_addresses(func_name);

    if addresses.is_empty() {
        if !options.quiet() {
            if options.json() {
                let result = FunctionResult {
                    function_name: func_name.to_string(),
                    modules: vec![],
                    total_variables: 0,
                };
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Function '{}' not found", func_name);
            }
        }
        return Ok(());
    }

    if options.json() {
        let mut modules = Vec::new();
        let mut total_variables = 0;

        // Group module addresses by module path
        use std::collections::HashMap;
        let mut grouped_by_module: HashMap<std::path::PathBuf, Vec<u64>> = HashMap::new();
        for module_address in &addresses {
            grouped_by_module
                .entry(module_address.module_path.clone())
                .or_insert_with(Vec::new)
                .push(module_address.address);
        }

        for (module_path, addrs) in grouped_by_module {
            let mut address_infos = Vec::new();

            for addr in &addrs {
                let module_address = ModuleAddress::new(module_path.clone(), *addr);
                let variables = analyzer.get_all_variables_at_address(&module_address)?;

                let var_infos: Vec<VariableInfo> = variables
                    .iter()
                    .map(|var| VariableInfo {
                        name: var.name.clone(),
                        type_name: var.type_name.clone(),
                        location: format!("{}", var.evaluation_result),
                        is_parameter: var.is_parameter,
                        scope_depth: var.scope_depth as u32,
                    })
                    .collect();

                total_variables += var_infos.len();

                address_infos.push(AddressInfo {
                    module: module_path.display().to_string(),
                    address: format!("0x{:x}", addr),
                    variables: var_infos,
                });
            }

            modules.push(FunctionModuleInfo {
                module: module_path.display().to_string(),
                addresses: address_infos,
            });
        }

        let result = FunctionResult {
            function_name: func_name.to_string(),
            modules,
            total_variables,
        };

        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        // Text output
        if !options.quiet() {
            println!("\n=== Function: {} ===", func_name);
        }

        for module_address in &addresses {
            if !options.quiet() {
                println!("\nModule: {}", module_address.module_display());
            }

            let variables = analyzer.get_all_variables_at_address(module_address)?;

            if options.quiet() {
                for var in &variables {
                    // Use DWARF type if available, otherwise fall back to type name
                    let type_str = if let Some(dwarf_type) = &var.dwarf_type {
                        dwarf_type.to_string()
                    } else {
                        format!("{} (no DWARF info)", var.type_name)
                    };

                    println!("{}: {} = {}", var.name, type_str, var.evaluation_result);
                }
            } else {
                println!("  Address: 0x{:x}", module_address.address);
                if variables.is_empty() {
                    println!("    No variables found");
                } else {
                    print_variables_with_indent(&variables, "    ");
                }
            }
        }
    }

    Ok(())
}

async fn analyze_module_address(
    analyzer: &mut DwarfAnalyzer,
    module_path: &str,
    address_str: &str,
    options: &Commands,
) -> Result<()> {
    let address = parse_address(address_str)?;
    let module_pathbuf = std::path::PathBuf::from(module_path);
    let module_address = ModuleAddress::new(module_pathbuf, address);

    match analyzer.get_all_variables_at_address(&module_address) {
        Ok(variables) => {
            if options.json() {
                let var_infos: Vec<VariableInfo> = variables
                    .iter()
                    .map(|var| VariableInfo {
                        name: var.name.clone(),
                        type_name: var.type_name.clone(),
                        location: format!("{}", var.evaluation_result),
                        is_parameter: var.is_parameter,
                        scope_depth: var.scope_depth as u32,
                    })
                    .collect();

                let result = AddressInfo {
                    module: module_path.to_string(),
                    address: format!("0x{:x}", address),
                    variables: var_infos,
                };
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else if options.quiet() {
                for var in &variables {
                    println!(
                        "{}: {} = {}",
                        var.name, var.type_name, var.evaluation_result
                    );
                }
            } else {
                println!("\n=== {} @ 0x{:x} ===", module_path, address);
                if variables.is_empty() {
                    println!("No variables found");
                } else {
                    print_variables_with_style(&variables, options);
                }
            }
        }
        Err(e) => {
            if !options.quiet() {
                eprintln!("Failed to get variables: {}", e);
            }
        }
    }

    Ok(())
}

fn list_modules(analyzer: &DwarfAnalyzer, options: &Commands) {
    let modules = analyzer.get_loaded_modules();

    if options.json() {
        let module_list: Vec<String> = modules
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        println!("{}", serde_json::to_string_pretty(&module_list).unwrap());
    } else if options.quiet() {
        for module in modules {
            println!("{}", module.display());
        }
    } else {
        println!("Loaded modules ({}):", modules.len());
        for (i, module) in modules.iter().enumerate() {
            println!("  [{}] {}", i + 1, module.display());
        }
    }
}

async fn run_benchmark(pid: u32, runs: usize) -> Result<()> {
    println!(
        "Benchmarking module loading for PID {} ({} runs)...\n",
        pid, runs
    );

    print!("Sequential: ");
    let mut seq_times = Vec::new();

    for _ in 0..runs {
        print!(".");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        let start = Instant::now();
        let _analyzer = DwarfAnalyzer::from_pid_sequential(pid)?;
        seq_times.push(start.elapsed());
    }
    println!();

    print!("Parallel:   ");
    let mut par_times = Vec::new();

    for _ in 0..runs {
        print!(".");
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        let start = Instant::now();
        let _analyzer = DwarfAnalyzer::from_pid_parallel(pid).await?;
        par_times.push(start.elapsed());
    }
    println!();

    let seq_avg = seq_times.iter().sum::<std::time::Duration>() / runs as u32;
    let par_avg = par_times.iter().sum::<std::time::Duration>() / runs as u32;
    let speedup = seq_avg.as_secs_f64() / par_avg.as_secs_f64();

    println!("\nResults:");
    println!("  Sequential: {}ms (avg)", seq_avg.as_millis());
    println!("  Parallel:   {}ms (avg)", par_avg.as_millis());

    if speedup > 1.0 {
        println!(
            "  Speedup: {:.2}x ({:.0}% faster)",
            speedup,
            (speedup - 1.0) * 100.0
        );
    } else {
        println!(
            "  Sequential is {:.0}% faster",
            (1.0 / speedup - 1.0) * 100.0
        );
    }

    Ok(())
}

fn print_source_analysis(
    address_infos: &[AddressInfo],
    source: &str,
    total_variables: usize,
    options: &Commands,
) {
    if options.quiet() {
        for addr_info in address_infos {
            for var in &addr_info.variables {
                println!("{}: {} = {}", var.name, var.type_name, var.location);
            }
        }
        return;
    }

    println!("\n=== {} ===", source);

    if options.verbose() {
        println!(
            "Found {} addresses with {} total variables\n",
            address_infos.len(),
            total_variables
        );
    }

    for (i, addr_info) in address_infos.iter().enumerate() {
        if address_infos.len() > 1 {
            println!(
                "Address {}: {} → {}",
                i + 1,
                addr_info.address,
                addr_info.module
            );
        } else {
            println!("Address: {} → {}", addr_info.address, addr_info.module);
        }

        if addr_info.variables.is_empty() {
            println!("  No variables found");
        } else {
            for var in &addr_info.variables {
                let param_marker = if var.is_parameter { " (param)" } else { "" };
                println!(
                    "  ├─ {}: {} = {}{}",
                    var.name, var.type_name, var.location, param_marker
                );
            }
        }

        if i < address_infos.len() - 1 {
            println!();
        }
    }
}

fn print_variables_with_style(
    variables: &[ghostscope_dwarf::VariableWithEvaluation],
    options: &Commands,
) {
    for (i, var) in variables.iter().enumerate() {
        if options.verbose() {
            println!("═══════════════════════════════════════");
            println!("Variable #{}", i + 1);
            println!("───────────────────────────────────────");
            println!("  Name:          {}", var.name);

            // Prioritize DWARF type info over simple type name
            if let Some(dwarf_type) = &var.dwarf_type {
                println!("  Type:          {}", dwarf_type);
            } else {
                println!("  Type:          {} (no DWARF type info)", var.type_name);
            }
            println!("  Scope Depth:   {}", var.scope_depth);
            println!("  Is Parameter:  {}", var.is_parameter);
            println!("  Is Artificial: {}", var.is_artificial);
            println!("  Location:      {}", var.evaluation_result);
            println!();
        } else {
            let param_marker = if var.is_parameter { " (param)" } else { "" };
            let artificial_marker = if var.is_artificial {
                " (artificial)"
            } else {
                ""
            };

            // Use DWARF type if available, otherwise fall back to type name
            let type_str = if let Some(dwarf_type) = &var.dwarf_type {
                dwarf_type.to_string()
            } else {
                format!("{} (no DWARF info)", var.type_name)
            };

            println!(
                "  ├─ {}: {} = {}{}{}",
                var.name, type_str, var.evaluation_result, param_marker, artificial_marker
            );
        }
    }
}

fn print_variables_with_indent(
    variables: &[ghostscope_dwarf::VariableWithEvaluation],
    indent: &str,
) {
    for var in variables {
        let param_marker = if var.is_parameter { " (param)" } else { "" };
        let artificial_marker = if var.is_artificial {
            " (artificial)"
        } else {
            ""
        };

        // Use DWARF type if available, otherwise fall back to type name
        let type_str = if let Some(dwarf_type) = &var.dwarf_type {
            dwarf_type.to_string()
        } else {
            format!("{} (no DWARF info)", var.type_name)
        };

        println!(
            "{}├─ {}: {} = {}{}{}",
            indent, var.name, type_str, var.evaluation_result, param_marker, artificial_marker
        );
    }
}

fn parse_source_line(source_str: &str) -> Result<(&str, u32)> {
    let parts: Vec<&str> = source_str.rsplitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(anyhow::anyhow!(
            "Invalid source format. Expected 'file:line', got '{}'",
            source_str
        ));
    }

    let line_str = parts[0];
    let file_path = parts[1];

    let line_number: u32 = line_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid line number: {}", line_str))?;

    Ok((file_path, line_number))
}

fn parse_address(address_str: &str) -> Result<u64> {
    if address_str.starts_with("0x") || address_str.starts_with("0X") {
        u64::from_str_radix(&address_str[2..], 16)
    } else {
        address_str.parse::<u64>()
    }
    .map_err(|_| anyhow::anyhow!("Invalid address format: {}", address_str))
}

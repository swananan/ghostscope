#![allow(clippy::uninlined_format_args)]

// New modular organization
pub mod ebpf;
pub mod script; // New instruction generator
                // Legacy codegen - kept for reference, not compiled
                // pub mod codegen_legacy;
                // pub mod codegen_new;

use crate::script::compiler::AstCompiler;
use ebpf::context::CodeGenError;
use script::parser::ParseError;
use tracing::info;

pub fn hello() -> &'static str {
    "Hello from ghostscope-compiler!"
}

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("Parse error: {0}")]
    Parse(#[from] Box<ParseError>),

    #[error("Code generation error: {0}")]
    CodeGen(#[from] CodeGenError),

    #[error("LLVM error: {0}")]
    LLVM(String),

    #[error("Error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CompileError>;

impl From<ParseError> for CompileError {
    fn from(err: ParseError) -> Self {
        CompileError::Parse(Box::new(err))
    }
}

// Public re-exports from script::compiler module
pub use script::compiler::{CompilationResult, UProbeConfig};

/// Save options for compilation output
#[derive(Debug, Clone, Default)]
pub struct SaveOptions {
    pub save_llvm_ir: bool,
    pub save_ebpf: bool,
    pub save_ast: bool,
    pub binary_path_hint: Option<String>,
}

/// Main compilation interface with DwarfAnalyzer (multi-module support)
///
/// This is the new multi-module interface that uses DwarfAnalyzer
/// to perform compilation across main executable and dynamic libraries
pub fn compile_script(
    script_source: &str,
    process_analyzer: &mut ghostscope_dwarf::DwarfAnalyzer,
    pid: Option<u32>,
    trace_id: Option<u32>,
    save_options: &SaveOptions,
) -> Result<CompilationResult> {
    info!("Starting unified script compilation with DwarfAnalyzer (multi-module support)");

    // Step 1: Parse script to AST
    let program = script::parser::parse(script_source)?;
    info!("Parsed script with {} statements", program.statements.len());

    // Step 2: Use AstCompiler with full DwarfAnalyzer integration
    let mut compiler = AstCompiler::new(
        Some(process_analyzer),
        save_options.binary_path_hint.clone(),
        trace_id.unwrap_or(0), // Default starting trace_id is 0 if not provided
        save_options.clone(),
    );

    // Step 3: Compile using unified interface
    let result = compiler.compile_program(&program, pid)?;

    info!(
        "Successfully compiled script: {} trace points, {} uprobe configs",
        result.trace_count,
        result.uprobe_configs.len()
    );

    Ok(result)
}

/// Print AST for debugging
pub fn print_ast(program: &crate::script::Program) {
    info!("\n=== AST Tree ===");
    info!("Program:");
    for (i, stmt) in program.statements.iter().enumerate() {
        info!("  Statement {}: {:?}", i, stmt);
    }
    info!("=== End AST Tree ===\n");
}

/// Save AST to file
pub fn save_ast_to_file(program: &crate::script::Program, filename: &str) -> Result<()> {
    let mut ast_content = String::new();
    ast_content.push_str("=== AST Tree ===\n");
    ast_content.push_str("Program:\n");
    for (i, stmt) in program.statements.iter().enumerate() {
        ast_content.push_str(&format!("  Statement {i}: {stmt:?}\n"));
    }
    ast_content.push_str("=== End AST Tree ===\n");

    let file_path = format!("{filename}.txt");
    std::fs::write(&file_path, ast_content)
        .map_err(|e| CompileError::Other(format!("Failed to save AST file '{file_path}': {e}")))?;

    Ok(())
}

/// Format eBPF bytecode as hexadecimal string for inspection
pub fn format_ebpf_bytecode(bytecode: &[u8]) -> String {
    bytecode
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<String>>()
        .join(" ")
}

/// Generate filename for AST files
pub fn generate_file_name_for_ast(pid: Option<u32>, binary_path: Option<&str>) -> String {
    let pid_part = pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let exec_part = binary_path
        .and_then(|path| std::path::Path::new(path).file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("unknown");

    format!("gs_{pid_part}_{exec_part}_ast")
}

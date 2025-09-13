pub mod ast;
pub mod ast_compiler;
pub mod codegen;
pub mod debug_logger;
pub mod map;
pub mod parser;

use crate::ast_compiler::AstCompiler;
use codegen::CodeGenError;
use parser::ParseError;
use tracing::info;

pub fn hello() -> &'static str {
    "Hello from ghostscope-compiler!"
}

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),

    #[error("Code generation error: {0}")]
    CodeGen(#[from] CodeGenError),

    #[error("LLVM error: {0}")]
    LLVM(String),

    #[error("Error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CompileError>;

// Public re-exports from ast_compiler module
pub use ast_compiler::{CompilationResult, PCCompilationResult, UProbeConfig};

/// Save options for compilation output
#[derive(Debug, Clone)]
pub struct SaveOptions {
    pub save_llvm_ir: bool,
    pub save_ebpf: bool,
    pub save_ast: bool,
    pub binary_path_hint: Option<String>,
}

impl Default for SaveOptions {
    fn default() -> Self {
        Self {
            save_llvm_ir: false,
            save_ebpf: false,
            save_ast: false,
            binary_path_hint: None,
        }
    }
}

/// Main compilation interface - replaces all the old messy functions
///
/// This is the new unified interface that uses AstCompiler internally
/// to perform single-pass AST traversal with integrated DWARF queries and code generation
pub fn compile_script(
    script_source: &str,
    binary_analyzer: &mut ghostscope_binary::BinaryAnalyzer,
    pid: Option<u32>,
    trace_id: Option<u32>,
    save_options: &SaveOptions,
) -> Result<CompilationResult> {
    info!("Starting unified script compilation with new AstCompiler");

    // Step 1: Parse script to AST
    let program = parser::parse(script_source)?;
    info!("Parsed script with {} statements", program.statements.len());

    // Step 2: Use new AstCompiler for unified compilation
    let mut compiler = AstCompiler::new(
        Some(binary_analyzer),
        save_options.binary_path_hint.clone(),
        trace_id,
    );

    let result = compiler.compile_program(&program, pid)?;
    info!(
        "Compilation completed: {} uprobe configs generated",
        result.uprobe_configs.len()
    );

    Ok(result)
}

/// Legacy interface for backward compatibility - parses source and compiles
pub fn compile_source_to_ebpf(source: &str) -> Result<Vec<u8>> {
    let program = parser::parse(source)?;

    let mut compiler = AstCompiler::new(None, None, None);
    let result = compiler.compile_program(&program, None)?;

    if result.uprobe_configs.is_empty() {
        return Err(CompileError::LLVM(
            "No uprobe configurations generated".to_string(),
        ));
    }

    Ok(result.uprobe_configs[0].ebpf_bytecode.clone())
}

/// Print AST for debugging
pub fn print_ast(program: &crate::ast::Program) {
    info!("\n=== AST Tree ===");
    info!("Program:");
    for (i, stmt) in program.statements.iter().enumerate() {
        info!("  Statement {}: {:?}", i, stmt);
    }
    info!("=== End AST Tree ===\n");
}

/// Format eBPF bytecode as hexadecimal string for inspection
pub fn format_ebpf_bytecode(bytecode: &[u8]) -> String {
    bytecode
        .iter()
        .map(|byte| format!("{:02x}", byte))
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

    format!("gs_{}_{}_{}", pid_part, exec_part, "ast")
}

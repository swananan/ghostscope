//! eBPF LLVM context and core infrastructure
//!
//! This module provides the main code generation context and basic LLVM
//! infrastructure for eBPF program generation.

use super::maps::MapManager;
use crate::script::{VarType, VariableContext};
use aya_ebpf_bindings::bindings::bpf_func_id::BPF_FUNC_get_current_pid_tgid;
use ghostscope_dwarf::DwarfAnalyzer;
use inkwell::builder::Builder;
use inkwell::context::Context;
use inkwell::debug_info::DebugInfoBuilder;
use inkwell::module::Module;
use inkwell::targets::{Target, TargetTriple};
use inkwell::types::{BasicTypeEnum, IntType};
use inkwell::values::{
    BasicMetadataValueEnum, BasicValue, BasicValueEnum, FunctionValue, IntValue, PointerValue,
};
use inkwell::AddressSpace;
use inkwell::OptimizationLevel;
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Compile-time context containing PC address and module information for DWARF queries
#[derive(Debug, Clone)]
pub struct CompileTimeContext {
    pub pc_address: u64,
    pub module_path: String,
}

#[derive(Error, Debug)]
pub enum CodeGenError {
    #[error("LLVM compilation error: {0}")]
    LLVMError(String),
    #[error("Unsupported evaluation result: {0}")]
    UnsupportedEvaluation(String),
    #[error("Register mapping error: {0}")]
    RegisterMappingError(String),
    #[error("Memory access error: {0}")]
    MemoryAccessError(String),
    #[error("Builder error: {0}")]
    Builder(String),

    // === Legacy variable management errors ===
    #[error("Variable not found: {0}")]
    VariableNotFound(String),
    #[error("Variable not in scope: {0}")]
    VariableNotInScope(String),
    #[error("Type error: {0}")]
    TypeError(String),
    #[error("Not implemented: {0}")]
    NotImplemented(String),
    #[error("DWARF expression error: {0}")]
    DwarfError(String),
    #[error("Type size not available for variable: {0}")]
    TypeSizeNotAvailable(String),
}

pub type Result<T> = std::result::Result<T, CodeGenError>;

/// eBPF LLVM code generation context
pub struct EbpfContext<'ctx> {
    pub context: &'ctx Context,
    pub module: Module<'ctx>,
    pub builder: Builder<'ctx>,

    // eBPF-specific function declarations
    pub trace_printk_fn: FunctionValue<'ctx>,

    // Map manager for eBPF maps
    pub map_manager: MapManager<'ctx>,

    // Debug infrastructure
    pub di_builder: DebugInfoBuilder<'ctx>,
    pub compile_unit: inkwell::debug_info::DICompileUnit<'ctx>,

    // Register cache for pt_regs access
    pub register_cache: HashMap<u16, IntValue<'ctx>>,

    // === Complete Variable Management System ===
    pub variables: HashMap<String, PointerValue<'ctx>>, // Variable name -> LLVM pointer
    pub var_types: HashMap<String, VarType>,            // Variable name -> type
    pub optimized_out_vars: HashMap<String, bool>,      // Optimized out variables
    pub var_pc_addresses: HashMap<String, u64>,         // Variable -> PC address
    pub variable_context: Option<VariableContext>,      // Scope validation context
    pub process_analyzer: Option<*mut DwarfAnalyzer>,   // Multi-module DWARF analyzer
    pub current_trace_id: Option<u32>,                  // Current trace_id being compiled
    pub current_compile_time_context: Option<CompileTimeContext>, // PC address and module for DWARF queries

    // === New instruction-based compilation system ===
    pub string_table: ghostscope_protocol::StringTable, // String table for optimized transmission
}

// Temporary alias for backward compatibility during refactoring
pub type NewCodeGen<'ctx> = EbpfContext<'ctx>;

impl<'ctx> EbpfContext<'ctx> {
    /// Create a new eBPF code generation context
    pub fn new(context: &'ctx Context, module_name: &str, trace_id: Option<u32>) -> Result<Self> {
        let module = context.create_module(module_name);
        let builder = context.create_builder();

        // Initialize standard BPF target
        Target::initialize_bpf(&Default::default());

        // Create BPF target triple
        let triple = TargetTriple::create("bpf-pc-linux");

        // Get target and create target machine
        let target = Target::from_triple(&triple).map_err(|e| {
            CodeGenError::LLVMError(format!("Failed to get target from triple: {}", e))
        })?;
        let target_machine = target
            .create_target_machine(
                &triple,
                "generic",
                "+alu32",
                OptimizationLevel::Default,
                inkwell::targets::RelocMode::PIC,
                inkwell::targets::CodeModel::Small,
            )
            .ok_or_else(|| {
                CodeGenError::LLVMError("Failed to create target machine".to_string())
            })?;

        // Set module data layout and triple
        let data_layout = target_machine.get_target_data().get_data_layout();
        module.set_data_layout(&data_layout);
        module.set_triple(&triple);

        // Initialize debug info
        let (di_builder, compile_unit) = module.create_debug_info_builder(
            true,                                         // allow_unresolved
            inkwell::debug_info::DWARFSourceLanguage::C,  // language
            "ghostscope_generated.c",                     // filename
            ".",                                          // directory
            "ghostscope-compiler",                        // producer
            false,                                        // is_optimized
            "",                                           // flags
            1,                                            // runtime_version
            "",                                           // split_name
            inkwell::debug_info::DWARFEmissionKind::Full, // kind
            0,                                            // dwo_id
            false,                                        // split_debug_inlining
            false,                                        // debug_info_for_profiling
            "",                                           // sysroot
            "",                                           // sdk
        );

        let map_manager = MapManager::new(context);

        // Declare eBPF helper functions
        let trace_printk_fn = Self::declare_trace_printk(context, &module);

        Ok(Self {
            context,
            module,
            builder,
            trace_printk_fn,
            map_manager,
            di_builder,
            compile_unit,
            register_cache: HashMap::new(),

            // Initialize variable management system
            variables: HashMap::new(),
            var_types: HashMap::new(),
            optimized_out_vars: HashMap::new(),
            var_pc_addresses: HashMap::new(),
            variable_context: None,
            process_analyzer: None,
            current_trace_id: trace_id,
            current_compile_time_context: None,

            // Initialize new instruction-based compilation system
            string_table: ghostscope_protocol::StringTable::new(),
        })
    }

    /// Create a new code generator with DWARF analyzer support
    pub fn new_with_process_analyzer(
        context: &'ctx Context,
        module_name: &str,
        process_analyzer: Option<&mut DwarfAnalyzer>,
        trace_id: Option<u32>,
    ) -> Result<Self> {
        let mut codegen = Self::new(context, module_name, trace_id)?;
        codegen.process_analyzer = process_analyzer.map(|pa| pa as *const _ as *mut _);
        Ok(codegen)
    }

    /// Set compile-time context for DWARF queries
    pub fn set_compile_time_context(&mut self, pc_address: u64, module_path: String) {
        self.current_compile_time_context = Some(CompileTimeContext {
            pc_address,
            module_path,
        });
    }

    /// Get compile-time context for DWARF queries
    pub fn get_compile_time_context(&self) -> Result<&CompileTimeContext> {
        self.current_compile_time_context
            .as_ref()
            .ok_or_else(|| CodeGenError::DwarfError("No compile-time context set".to_string()))
    }

    /// Declare trace_printk eBPF helper function
    fn declare_trace_printk(context: &'ctx Context, module: &Module<'ctx>) -> FunctionValue<'ctx> {
        let i32_type = context.i32_type();
        let ptr_type = context.ptr_type(AddressSpace::default());
        let i64_type = context.i64_type();

        // int bpf_trace_printk(const char *fmt, u32 fmt_size, ...)
        let fn_type = i32_type.fn_type(&[ptr_type.into(), i64_type.into()], true);

        module.add_function("bpf_trace_printk", fn_type, None)
    }

    /// Create basic eBPF function with proper signature
    pub fn create_basic_ebpf_function(&mut self, function_name: &str) -> Result<()> {
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        // eBPF function signature: int function(struct pt_regs *ctx)
        let fn_type = i32_type.fn_type(&[ptr_type.into()], false);

        let function = self.module.add_function(function_name, fn_type, None);

        // Set section attribute for uprobe
        function.add_attribute(
            inkwell::attributes::AttributeLoc::Function,
            self.context.create_string_attribute("section", "uprobe"),
        );

        // Create basic block
        let basic_block = self.context.append_basic_block(function, "entry");
        self.builder.position_at_end(basic_block);

        info!("Created eBPF function: {}", function_name);
        Ok(())
    }

    /// Get the LLVM module reference
    pub fn get_module(&self) -> &Module<'ctx> {
        &self.module
    }

    /// Get the string table after compilation
    pub fn get_string_table(&self) -> ghostscope_protocol::StringTable {
        self.string_table.clone()
    }

    /// Get pt_regs parameter from current function
    pub fn get_pt_regs_parameter(&self) -> Result<PointerValue<'ctx>> {
        let current_function = self
            .builder
            .get_insert_block()
            .ok_or_else(|| CodeGenError::Builder("No current basic block".to_string()))?
            .get_parent()
            .ok_or_else(|| CodeGenError::Builder("No parent function".to_string()))?;

        let pt_regs_param = current_function
            .get_first_param()
            .ok_or_else(|| CodeGenError::Builder("Function has no parameters".to_string()))?
            .into_pointer_value();

        Ok(pt_regs_param)
    }

    /// Compile a complete program with statements
    pub fn compile_program(
        &mut self,
        program: &crate::script::Program,
        function_name: &str,
        trace_statements: &[crate::script::Statement],
        target_pid: Option<u32>,
        compile_time_pc: Option<u64>,
        module_path: Option<&str>,
    ) -> Result<(FunctionValue<'ctx>, ghostscope_protocol::StringTable)> {
        info!(
            "Starting program compilation with function: {}",
            function_name
        );

        // Set the current trace_id and compile-time context for code generation
        self.current_compile_time_context =
            if let (Some(pc), Some(path)) = (compile_time_pc, module_path) {
                Some(CompileTimeContext {
                    pc_address: pc,
                    module_path: path.to_string(),
                })
            } else {
                None
            };

        // Create required maps - critical for eBPF loader
        self.map_manager
            .create_ringbuf_map(
                &self.module,
                &self.di_builder,
                &self.compile_unit,
                "ringbuf",
                8,
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to create ringbuf map: {}", e)))?;

        // Variables are now queried on-demand when accessed in expressions
        // No need to pre-populate DWARF variables

        // Create main function
        let main_function = self.create_main_function(function_name)?;

        // Add PID filtering if target_pid is specified
        if let Some(pid) = target_pid {
            self.add_pid_filter(pid)?;
        }

        // Use new staged transmission system for all statements
        let program = crate::script::ast::Program {
            statements: trace_statements.to_vec(),
        };

        // Collect variable types from DWARF analysis
        let variable_types = std::collections::HashMap::new(); // Empty for now, will be populated by codegen

        // Generate staged transmission code using new architecture
        let string_table =
            self.compile_program_with_staged_transmission(&program, variable_types)?;
        info!(
            "Generated StringTable with {} strings",
            string_table.string_count()
        );

        // Return success
        let i32_type = self.context.i32_type();
        let return_value = i32_type.const_int(0, false);
        self.builder
            .build_return(Some(&return_value))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        info!(
            "Successfully compiled program with function: {} and StringTable",
            function_name
        );
        Ok((main_function, string_table))
    }

    /// Create the main eBPF function
    fn create_main_function(&mut self, function_name: &str) -> Result<FunctionValue<'ctx>> {
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        // Create function type: int function_name(void *ctx)
        let fn_type = i32_type.fn_type(&[ptr_type.into()], false);
        let function = self.module.add_function(function_name, fn_type, None);

        // CRITICAL: Set section name for eBPF loader to find the function
        function.set_section(Some("uprobe"));

        // Create basic block and position builder
        let basic_block = self.context.append_basic_block(function, "entry");
        self.builder.position_at_end(basic_block);

        info!("Created main function: {}", function_name);
        Ok(function)
    }

    /// Add PID filtering logic to the current function
    /// This generates LLVM IR to check current PID against target PID and early return if not matching
    fn add_pid_filter(&mut self, target_pid: u32) -> Result<()> {
        info!("Adding PID filter for target PID: {}", target_pid);

        // Get current function and entry block
        let current_fn = self
            .builder
            .get_insert_block()
            .unwrap()
            .get_parent()
            .unwrap();

        // Create basic blocks for control flow
        let continue_block = self
            .context
            .append_basic_block(current_fn, "continue_execution");
        let early_return_block = self
            .context
            .append_basic_block(current_fn, "pid_mismatch_return");

        // Get current PID/TID using bpf_get_current_pid_tgid helper
        let pid_tgid_value = self.get_current_pid_tgid()?;

        // Extract TGID (high 32 bits) by right shifting 32 bits
        let shift_amount = self.context.i64_type().const_int(32, false);
        let current_tgid = self
            .builder
            .build_right_shift(pid_tgid_value, shift_amount, false, "current_tgid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Convert target_pid to i64 and compare
        let target_pid_value = self.context.i64_type().const_int(target_pid as u64, false);
        let pid_matches = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                current_tgid,
                target_pid_value,
                "pid_matches",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Conditional branch: if pid matches, continue; else early return
        self.builder
            .build_conditional_branch(pid_matches, continue_block, early_return_block)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Early return block - just return 0
        self.builder.position_at_end(early_return_block);
        self.builder
            .build_return(Some(&self.context.i32_type().const_int(0, false)))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Position at continue block for the rest of the function
        self.builder.position_at_end(continue_block);

        info!(
            "PID filter added successfully for target PID: {}",
            target_pid
        );
        Ok(())
    }
}

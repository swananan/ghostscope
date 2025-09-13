use aya_ebpf_bindings::bindings::bpf_func_id::{
    BPF_FUNC_get_current_pid_tgid, BPF_FUNC_ktime_get_ns, BPF_FUNC_probe_read_user,
    BPF_FUNC_ringbuf_output, BPF_FUNC_trace_printk,
};
use inkwell::builder::Builder;
use inkwell::context::Context;
use inkwell::debug_info::{AsDIScope, DebugInfoBuilder};
use inkwell::module::Module;
use inkwell::targets::{Target, TargetTriple};
use inkwell::types::BasicTypeEnum;
use inkwell::values::{
    BasicMetadataValueEnum, BasicValue, BasicValueEnum, FunctionValue, IntValue, PointerValue,
};
use inkwell::AddressSpace;
use inkwell::Either;
use inkwell::OptimizationLevel;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

use crate::ast::{BinaryOp, Expr, Program, Statement, VarType, VariableContext};
use crate::debug_logger::DebugLogger;
use crate::map::MapManager;
use ghostscope_binary::dwarf::{DwarfEncoding, DwarfType};
use ghostscope_binary::expression::AccessStep;
use ghostscope_protocol::platform;
use ghostscope_protocol::{consts, MessageType, TypeEncoding};

pub struct CodeGen<'ctx> {
    context: &'ctx Context,
    module: Module<'ctx>,
    builder: Builder<'ctx>,
    di_builder: DebugInfoBuilder<'ctx>,
    compile_unit: inkwell::debug_info::DICompileUnit<'ctx>,
    // TODO: Remove these legacy fields after migration to runtime access
    variables: HashMap<String, PointerValue<'ctx>>,
    var_types: HashMap<String, VarType>,
    optimized_out_vars: HashMap<String, bool>,
    var_pc_addresses: HashMap<String, u64>,
    map_manager: MapManager<'ctx>,
    variable_context: Option<VariableContext>, // Variable scope context for validation
    pending_dwarf_variables: Option<Vec<ghostscope_binary::EnhancedVariableLocation>>, // DWARF variables awaiting population
    debug_logger: DebugLogger<'ctx>,
    binary_analyzer: Option<*mut ghostscope_binary::BinaryAnalyzer>, // CFI and DWARF information access
    current_trace_id: Option<u32>, // Current trace_id being compiled
    current_compile_time_pc: Option<u64>, // PC address from source line for DWARF queries
}

#[derive(Debug, thiserror::Error)]
pub enum CodeGenError {
    #[error("Variable not found: {0}")]
    VariableNotFound(String),

    #[error("Variable not in scope: {0}")]
    VariableNotInScope(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Builder error: {0}")]
    Builder(String),

    #[error("Type error: {0}")]
    TypeError(String),

    #[error("Map error: {0}")]
    MapError(String),

    #[error("DWARF expression error: {0}")]
    DwarfError(String),
    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
    #[error("Invalid expression: {0}")]
    InvalidExpression(String),

    #[error("Debug info error: {0}")]
    DebugInfo(String),

    #[error("Unsupported DWARF register: {0}")]
    UnsupportedRegister(u16),
}

pub type Result<T> = std::result::Result<T, CodeGenError>;

impl<'ctx> CodeGen<'ctx> {
    pub fn new(context: &'ctx Context, module_name: &str) -> Self {
        Self::new_with_binary_analyzer(context, module_name, None)
    }

    pub fn new_with_binary_analyzer(
        context: &'ctx Context,
        module_name: &str,
        binary_analyzer: Option<&mut ghostscope_binary::BinaryAnalyzer>,
    ) -> Self {
        let module = context.create_module(module_name);
        let builder = context.create_builder();
        let map_manager = MapManager::new(context);

        // Initialize standard BPF target
        Target::initialize_bpf(&Default::default());

        // Create BPF target triple
        let triple = TargetTriple::create("bpf-pc-linux");

        // Get target and create target machine
        let target = Target::from_triple(&triple).expect("Failed to get target from triple");
        let target_machine = target
            .create_target_machine(
                &triple,
                "generic",
                "+alu32",
                OptimizationLevel::Default,
                inkwell::targets::RelocMode::PIC,
                inkwell::targets::CodeModel::Small,
            )
            .expect("Failed to create target machine");

        // Get data layout from target machine
        let data_layout = target_machine.get_target_data().get_data_layout();

        // Set module target data layout and triple
        module.set_data_layout(&data_layout);
        module.set_triple(&triple);

        // Set debug info version for BTF compatibility
        let debug_version = context.i32_type().const_int(3, false); // DWARF version 3 for BTF
        let debug_version_md = context.metadata_node(&[debug_version.into()]);
        module.add_metadata_flag(
            "Debug Info Version",
            inkwell::module::FlagBehavior::Warning,
            debug_version_md,
        );

        // Create debug info builder for BTF/DWARF generation
        let (di_builder, compile_unit) = module.create_debug_info_builder(
            true,                                         // allow_unresolved
            inkwell::debug_info::DWARFSourceLanguage::C,  // Use C language for BPF compatibility
            "ghostscope_generated",                       // filename
            "/",                                          // directory
            "GhostScope Compiler v0.1.0",                 // producer
            false,                                        // is_optimized
            "-g",                                         // flags - enable debug info generation
            5,  // runtime_version - use DWARF version 5 for BTF compatibility
            "", // split_name
            inkwell::debug_info::DWARFEmissionKind::Full, // kind
            0,  // dwo_id
            false, // split_debug_inlining
            false, // debug_info_for_profiling
            "", // sys_root
            "", // sdk
        );

        CodeGen {
            context,
            module,
            builder,
            di_builder,
            compile_unit,
            // TODO: Remove these legacy fields after migration to runtime access
            variables: HashMap::new(),
            var_types: HashMap::new(),
            optimized_out_vars: HashMap::new(),
            var_pc_addresses: HashMap::new(),
            map_manager,
            variable_context: None, // Will be set later when trace point context is available
            pending_dwarf_variables: None, // Will be set when DWARF variables are prepared
            debug_logger: DebugLogger::new(context),
            binary_analyzer: binary_analyzer.map(|ba| ba as *const _ as *mut _),
            current_trace_id: None,        // Will be set during compilation
            current_compile_time_pc: None, // Will be set when processing trace statements
        }
    }

    /// Set the variable context for scope validation
    pub fn set_variable_context(&mut self, context: VariableContext) {
        self.variable_context = Some(context);
    }

    /// Set the binary analyzer for DWARF and CFI information access
    pub fn set_binary_analyzer(
        &mut self,
        binary_analyzer: Option<&mut ghostscope_binary::BinaryAnalyzer>,
    ) {
        self.binary_analyzer = binary_analyzer.map(|ba| ba as *const _ as *mut _);
    }

    /// Prepare DWARF variables for later population during compilation
    pub fn prepare_dwarf_variables(
        &mut self,
        enhanced_variables: &[ghostscope_binary::EnhancedVariableLocation],
    ) -> Result<()> {
        // Store the enhanced variables for later use when we have the ctx parameter
        // For now, we'll store them in a temporary field and populate them in compile_with_function_name
        self.pending_dwarf_variables = Some(enhanced_variables.to_vec());
        info!(
            "Prepared {} DWARF variables for code generation integration",
            enhanced_variables.len()
        );
        Ok(())
    }

    /// Create register access for DWARF variables stored in CPU registers
    fn create_register_access(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        register: u16,
        var_name: &str,
    ) -> Result<PointerValue<'ctx>> {
        debug!(
            "Creating register access for variable '{}' in register {}",
            var_name, register
        );

        // For eBPF uprobes, we need to read from the pt_regs structure
        // Convert DWARF register number to pt_regs byte offset
        let pt_regs_byte_offset =
            platform::dwarf_reg_to_pt_regs_byte_offset(register).ok_or_else(|| {
                CodeGenError::InvalidExpression(format!(
                    "Unsupported DWARF register {} for current platform",
                    register
                ))
            })?;

        let i64_type = self.context.i64_type();
        let _ptr_type = self.context.ptr_type(AddressSpace::default());

        // For eBPF, access register values from pt_regs safely using i64 array index
        // pt_regs byte offset / 8 = i64 array index
        let i64_index = pt_regs_byte_offset / 8;
        let reg_index_const = i64_type.const_int(i64_index as u64, false);

        // Get pointer to the register in pt_regs (pt_regs as i64 array)
        let reg_ptr = unsafe {
            self.builder
                .build_gep(
                    i64_type,
                    ctx_param,
                    &[reg_index_const],
                    &format!("{}_reg_ptr", var_name),
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        // Register values can be read directly from pt_regs (kernel memory)
        Ok(reg_ptr)
    }

    /// Get register value from eBPF context using platform-specific mappings
    fn get_register_value(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        register: u16,
    ) -> Result<IntValue<'ctx>> {
        debug!("Getting value for DWARF register {}", register);

        // Use platform-specific DWARF register to pt_regs offset mapping
        let reg_offset =
            platform::dwarf_reg_to_pt_regs_byte_offset_x86_64(register).ok_or_else(|| {
                warn!("Unsupported DWARF register {}", register);
                CodeGenError::UnsupportedRegister(register)
            })?;

        let i64_type = self.context.i64_type();
        let offset_value = i64_type.const_int(reg_offset as u64, false);

        // Get pointer to register in context
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let reg_ptr = unsafe {
            self.builder
                .build_gep(
                    i64_type,
                    ctx_param,
                    &[offset_value],
                    &format!("reg_{}_ptr", register),
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        // Load register value
        let reg_value = self
            .builder
            .build_load(i64_type, reg_ptr, &format!("reg_{}_value", register))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        if let BasicValueEnum::IntValue(int_val) = reg_value {
            Ok(int_val)
        } else {
            Err(CodeGenError::Builder(
                "Expected integer value from register load".to_string(),
            ))
        }
    }

    /// Extract variable names used in the trace statements
    fn extract_used_variables(
        &self,
        trace_statements: &[Statement],
    ) -> std::collections::HashSet<String> {
        let mut used_vars = std::collections::HashSet::new();

        for statement in trace_statements {
            self.extract_variables_from_statement(statement, &mut used_vars);
        }

        used_vars
    }

    /// Recursively extract variable names from a statement
    fn extract_variables_from_statement(
        &self,
        statement: &Statement,
        used_vars: &mut std::collections::HashSet<String>,
    ) {
        match statement {
            Statement::Print(expr) => {
                self.extract_variables_from_expr(expr, used_vars);
            }
            Statement::Expr(expr) => {
                self.extract_variables_from_expr(expr, used_vars);
            }
            Statement::VarDeclaration { name: _, value } => {
                self.extract_variables_from_expr(value, used_vars);
            }
            Statement::TracePoint { pattern: _, body } => {
                for stmt in body {
                    self.extract_variables_from_statement(stmt, used_vars);
                }
            }
            Statement::Backtrace => {}
        }
    }

    /// Recursively extract variable names from an expression
    fn extract_variables_from_expr(
        &self,
        expr: &Expr,
        used_vars: &mut std::collections::HashSet<String>,
    ) {
        match expr {
            Expr::Variable(name) => {
                debug!("Found used variable in script: '{}'", name);
                used_vars.insert(name.clone());
            }
            Expr::SpecialVar(name) => {
                debug!("Found used special variable in script: '{}'", name);
                used_vars.insert(name.clone());
            }
            Expr::BinaryOp { left, op: _, right } => {
                self.extract_variables_from_expr(left, used_vars);
                self.extract_variables_from_expr(right, used_vars);
            }
            Expr::MemberAccess(obj, _field) => {
                self.extract_variables_from_expr(obj, used_vars);
            }
            Expr::PointerDeref(expr) => {
                self.extract_variables_from_expr(expr, used_vars);
            }
            // Literals don't contain variables
            Expr::Int(_) | Expr::Float(_) | Expr::String(_) => {}
        }
    }

    /// Determine VarType from DWARF type information
    fn determine_var_type_from_dwarf(&self, dwarf_type: &Option<DwarfType>) -> VarType {
        match dwarf_type {
            Some(DwarfType::BaseType {
                encoding,
                size,
                name,
            }) => {
                match encoding {
                    DwarfEncoding::Signed | DwarfEncoding::Unsigned => {
                        // Support different integer sizes
                        VarType::Int
                    }
                    DwarfEncoding::Float => {
                        // Properly support floating point types
                        VarType::Float
                    }
                    DwarfEncoding::Boolean => VarType::Int, // Treat boolean as int
                    DwarfEncoding::Address => VarType::Int, // Address as int
                    DwarfEncoding::Unknown => {
                        // Fallback: try to infer from type name
                        if name.contains("char") {
                            VarType::String
                        } else {
                            VarType::Int
                        }
                    }
                }
            }
            Some(DwarfType::PointerType { target_type, .. }) => {
                // Check if it's a pointer to char (string)
                if let DwarfType::BaseType { name, .. } = target_type.as_ref() {
                    if name.contains("char") {
                        VarType::String
                    } else {
                        VarType::Int // Pointers to other types as int
                    }
                } else {
                    VarType::Int // Generic pointer as int
                }
            }
            Some(DwarfType::ArrayType { element_type, .. }) => {
                // Arrays typically treated as addresses
                if let DwarfType::BaseType { name, .. } = element_type.as_ref() {
                    if name.contains("char") {
                        VarType::String // char arrays as strings
                    } else {
                        VarType::Int // Other arrays as int (address)
                    }
                } else {
                    VarType::Int
                }
            }
            Some(DwarfType::StructType { .. }) => {
                // Structs are typically accessed by address
                VarType::Int
            }
            Some(DwarfType::UnknownType { name }) => {
                // Try to infer from type name as fallback
                if name.contains("float") || name.contains("double") {
                    VarType::Float
                } else if name.contains("char") {
                    VarType::String
                } else {
                    VarType::Int
                }
            }
            None => VarType::Int, // Default to int for missing type info
        }
    }

    /// Validate if a variable is available in the current scope
    fn validate_variable_access(&self, var_name: &str) -> Result<()> {
        // Check if we have a variable context for validation
        if let Some(ref ctx) = self.variable_context {
            if !ctx.is_variable_available(var_name) {
                return Err(CodeGenError::VariableNotInScope(var_name.to_string()));
            }
        } else {
            // If no variable context is set, we should have one for proper validation
            debug!(
                "No variable context available for validation of '{}'",
                var_name
            );
        }
        Ok(())
    }

    pub fn compile_with_function_name(
        &mut self,
        program: &Program,
        function_name: &str,
        trace_statements: &[Statement],
        target_pid: Option<u32>,
        trace_id: Option<u32>,
        compile_time_pc: Option<u64>, // PC address for compile-time DWARF queries
        save_ir_path: Option<&str>,
    ) -> Result<&Module<'ctx>> {
        // Set the current trace_id and compile-time PC for code generation
        self.current_trace_id = trace_id;
        self.current_compile_time_pc = compile_time_pc;

        // Declare all external functions
        self.declare_external_functions();

        // Create function with ctx parameter (standard uprobe signature)
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let fn_type = self.context.i32_type().fn_type(&[ptr_type.into()], false);
        let main_fn = self.module.add_function(function_name, fn_type, None);

        // Set the function section to uprobe for aya compatibility
        // UProbe programs use BPF_PROG_TYPE_KPROBE but need "uprobe" section name
        main_fn.set_section(Some("uprobe"));

        let entry = self.context.append_basic_block(main_fn, "entry");
        self.builder.position_at_end(entry);

        // Create a simple function debug info as scope
        // Create i32 return type for the main function
        let i32_di_type = self
            .di_builder
            .create_basic_type("int", 32, 0x05, 0)
            .map_err(|e| CodeGenError::DebugInfo(e.to_string()))?;

        // Create void pointer type for ctx parameter
        let void_di_type = self
            .di_builder
            .create_basic_type("void", 0, 0, 0)
            .map_err(|e| CodeGenError::DebugInfo(e.to_string()))?;
        let void_ptr_di_type = self.di_builder.create_pointer_type(
            "",
            void_di_type.as_type(),
            64,
            64,
            AddressSpace::default(),
        );

        let di_function_type = self.di_builder.create_subroutine_type(
            self.compile_unit.get_file(),
            Some(i32_di_type.as_type()), // return type - i32 instead of None
            &[void_ptr_di_type.as_type()], // parameter types - void *ctx
            0,                           // flags
        );

        let di_function = self.di_builder.create_function(
            self.compile_unit.as_debug_info_scope(), // scope
            function_name,                           // name
            Some(function_name),                     // linkage_name
            self.compile_unit.get_file(),            // file
            1,                                       // line_no
            di_function_type,                        // ty
            false, // is_local_to_unit - set to false for global linkage
            true,  // is_definition
            1,     // scope_line
            0,     // flags
            false, // is_optimized
        );

        // Set the subprogram for the function
        main_fn.set_subprogram(di_function);

        // Now create debug location with the function as scope
        let debug_loc = self.di_builder.create_debug_location(
            self.context,
            1, // line
            0, // column
            di_function.as_debug_info_scope(),
            None,
        );
        self.builder.set_current_debug_location(debug_loc);

        // Add PID filtering FIRST if target_pid is specified - this should be at the very beginning
        if let Some(target_pid) = target_pid {
            self.add_pid_filter(target_pid)?;
        }

        // Get the ctx parameter for DWARF variable population
        let ctx_param = main_fn.get_nth_param(0).unwrap().into_pointer_value();

        // Populate DWARF variables if prepared - only for variables used in the script
        if let Some(dwarf_variables) = self.pending_dwarf_variables.take() {
            info!(
                "Analyzing {} DWARF variables to find used variables",
                dwarf_variables.len()
            );

            // Extract variables used in the trace statements
            let used_variables = self.extract_used_variables(trace_statements);
            info!(
                "Found {} variables used in script: {:?}",
                used_variables.len(),
                used_variables
            );

            // Create required maps BEFORE processing variables since they might need logging
            // Use 8 pages (32KB) for ringbuf map
            self.map_manager
                .create_ringbuf_map(
                    &self.module,
                    &self.di_builder,
                    &self.compile_unit,
                    "ringbuf",
                    8,
                )
                .map_err(|e| CodeGenError::MapError(e.to_string()))?;

            // Pre-calculate variable access using DWARF expression evaluation
            // This avoids runtime DWARF lookups which are not possible
            // Variables will be queried and compiled just-in-time during send_variable_data
            debug!(
                "Pre-calculated {} DWARF variables for compile-time use",
                dwarf_variables.len()
            );
        } else {
            // Create required maps even if no DWARF variables
            // Use 8 pages (32KB) for ringbuf map
            self.map_manager
                .create_ringbuf_map(
                    &self.module,
                    &self.di_builder,
                    &self.compile_unit,
                    "ringbuf",
                    8,
                )
                .map_err(|e| CodeGenError::MapError(e.to_string()))?;
        }
        // Temporarily disable event_loss_counter for POC testing
        // self.map_manager
        //     .create_event_loss_counter_map(&self.module, &self.di_builder, &self.compile_unit, "event_loss_counter", 1)?;

        // Compile trace statements
        for statement in trace_statements {
            self.compile_statement(statement)?;
        }

        // Return 0
        let _ = self
            .builder
            .build_return(Some(&self.context.i32_type().const_int(0, false)));

        // Add GPL license section (required for BPF programs)
        self.create_license_section()?;

        // Finalize debug information for BTF generation
        self.di_builder.finalize();

        // Save IR to file if path is provided
        if let Some(ir_path) = save_ir_path {
            info!("Saving LLVM IR to: {}", ir_path);
            self.module
                .print_to_file(ir_path)
                .map_err(|e| CodeGenError::Builder(format!("Failed to save IR to file: {}", e)))?;
        }

        // Ensure module verification passes
        if let Err(e) = self.module.verify() {
            return Err(CodeGenError::Builder(format!(
                "Module verification failed: {}",
                e
            )));
        }

        Ok(&self.module)
    }

    // Keep original compile method for backward compatibility
    pub fn compile(&mut self, program: &Program) -> Result<&Module<'ctx>> {
        // For backward compatibility, use "main" as function name and compile all statements
        self.compile_with_function_name(
            program,
            "main",
            &program.statements,
            None,
            None,
            None,
            None,
        )
    }

    fn declare_external_functions(&mut self) {
        let i64_type = self.context.i64_type();
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let fn_type = i64_type.fn_type(
            &[
                ptr_type.into(),
                ptr_type.into(),
                i64_type.into(),
                i64_type.into(),
            ],
            false,
        );
        let ringbuf_output_fn = self.module.add_function("ringbuf_output", fn_type, None);
        ringbuf_output_fn.set_linkage(inkwell::module::Linkage::External);

        // Declare llvm.bpf.pseudo function - used for handling BPF maps
        let pseudo_fn_type = i64_type.fn_type(&[i64_type.into(), i64_type.into()], false);
        let pseudo_fn = self
            .module
            .add_function("llvm.bpf.pseudo", pseudo_fn_type, None);
        pseudo_fn.set_linkage(inkwell::module::Linkage::External);

        // Declare bpf_get_current_pid_tgid helper function
        let pid_tgid_fn_type = i64_type.fn_type(&[], false);
        let pid_tgid_fn =
            self.module
                .add_function("bpf_get_current_pid_tgid", pid_tgid_fn_type, None);
        pid_tgid_fn.set_linkage(inkwell::module::Linkage::External);

        // Note: bpf_probe_read_user is called via indirect call with helper ID 113
        // We don't declare it as an external function since eBPF helpers are accessed by ID

        // Declare bpf_ktime_get_ns helper function for timestamp
        // u64 bpf_ktime_get_ns(void)
        let ktime_fn_type = i64_type.fn_type(&[], false);
        let ktime_fn = self
            .module
            .add_function("bpf_ktime_get_ns", ktime_fn_type, None);
        ktime_fn.set_linkage(inkwell::module::Linkage::External);

        // Declare bpf_trace_printk helper function for debug output
        // long bpf_trace_printk(const char *fmt, u32 fmt_size, ...)
        let trace_printk_fn_type = i64_type.fn_type(
            &[
                ptr_type.into(), // fmt
                i32_type.into(), // fmt_size
                i64_type.into(), // variadic arg (u64)
            ],
            false,
        );
        let trace_printk_fn =
            self.module
                .add_function("bpf_trace_printk", trace_printk_fn_type, None);
        trace_printk_fn.set_linkage(inkwell::module::Linkage::External);
    }

    fn get_seq_printf_fn(&self) -> FunctionValue<'ctx> {
        // Check if function already exists
        if let Some(fn_val) = self.module.get_function("bpf_seq_printf") {
            return fn_val;
        }

        // Create function type for bpf_seq_printf
        let i64_type = self.context.i64_type();
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        let seq_printf_type = i64_type.fn_type(
            &[
                i64_type.into(),
                ptr_type.into(),
                i32_type.into(),
                ptr_type.into(),
                i32_type.into(),
            ],
            false,
        );

        // Create the function
        let seq_printf_fn = self
            .module
            .add_function("bpf_seq_printf", seq_printf_type, None);
        seq_printf_fn.set_linkage(inkwell::module::Linkage::External);
        seq_printf_fn
    }

    fn get_trace_printk_fn(&self) -> FunctionValue<'ctx> {
        // Check if function already exists
        if let Some(fn_val) = self.module.get_function("bpf_trace_printk") {
            return fn_val;
        }

        // Create function type for bpf_trace_printk
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let trace_printk_type = i32_type.fn_type(&[ptr_type.into()], true);

        // Create the function
        let trace_printk_fn = self
            .module
            .add_function("bpf_trace_printk", trace_printk_type, None);
        trace_printk_fn.set_linkage(inkwell::module::Linkage::External);
        trace_printk_fn
    }

    fn get_backtrace_fn(&self) -> FunctionValue<'ctx> {
        // Check if function already exists
        if let Some(fn_val) = self.module.get_function("backtrace") {
            return fn_val;
        }

        // Create function type for backtrace
        let backtrace_type = self.context.void_type().fn_type(&[], false);
        let backtrace_fn = self.module.add_function("backtrace", backtrace_type, None);
        backtrace_fn
    }

    /* fn get_ringbuf_output_fn(&self) -> FunctionValue<'ctx> {
        // Check if function already exists
        if let Some(fn_val) = self.module.get_function("bpf_ringbuf_output") {
            return fn_val;
        }

        // Create function type for bpf_ringbuf_output
        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        let ringbuf_output_type = i64_type.fn_type(
            &[
                ptr_type.into(),
                ptr_type.into(),
                i64_type.into(),
                i64_type.into(),
            ],
            false,
        );

        // Create the function with BPF helper function ID attribute
        let ringbuf_output_fn =
            self.module
                .add_function("bpf_ringbuf_output", ringbuf_output_type, None);
        ringbuf_output_fn.set_linkage(inkwell::module::Linkage::External);

        // Can add BPF helper function ID as function attribute
        // BPF_FUNC_RINGBUF_OUTPUT = 129

        ringbuf_output_fn
    } */

    fn compile_statement(&mut self, statement: &Statement) -> Result<()> {
        match statement {
            Statement::Print(expr) => self.compile_print(expr),
            Statement::Backtrace => {
                let backtrace_fn = self.get_backtrace_fn();
                let _ = self.builder.build_call(backtrace_fn, &[], "backtrace");
                Ok(())
            }
            Statement::Expr(expr) => {
                self.compile_expr(expr)?;
                Ok(())
            }
            Statement::VarDeclaration { name, value } => {
                let value_expr = self.compile_expr(value)?;

                // Determine and store variable type
                let var_type = match value_expr {
                    BasicValueEnum::IntValue(_) => VarType::Int,
                    BasicValueEnum::FloatValue(_) => VarType::Float,
                    BasicValueEnum::PointerValue(_) => VarType::String, // Strings are pointers
                    _ => {
                        return Err(CodeGenError::NotImplemented(
                            "Unsupported variable type".to_string(),
                        ))
                    }
                };

                // Check if variable already exists
                if self.variables.contains_key(name) {
                    return Err(CodeGenError::TypeError(format!(
                        "Variable '{}' is already defined",
                        name
                    )));
                }

                // Create global variable storage (eBPF compatible)
                let global_var = self.module.add_global(
                    value_expr.get_type(),
                    Some(AddressSpace::default()),
                    &format!("_local_var_{}", name),
                );

                // Initialize with zero value
                match value_expr {
                    BasicValueEnum::IntValue(_) => {
                        global_var.set_initializer(&self.context.i64_type().const_zero());
                    }
                    BasicValueEnum::FloatValue(_) => {
                        global_var.set_initializer(&self.context.f64_type().const_zero());
                    }
                    BasicValueEnum::PointerValue(_) => {
                        global_var.set_initializer(
                            &self.context.ptr_type(AddressSpace::default()).const_null(),
                        );
                    }
                    _ => {}
                }

                // Store the initial value
                self.builder
                    .build_store(global_var.as_pointer_value(), value_expr)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                self.variables
                    .insert(name.clone(), global_var.as_pointer_value());

                // Store variable type
                self.var_types.insert(name.clone(), var_type);

                // Add variable to the scope context for future validation
                if let Some(ref mut ctx) = self.variable_context {
                    ctx.add_variable(name.clone());
                }

                Ok(())
            }
            Statement::TracePoint { pattern: _, body } => {
                // For now, just compile the body as normal statements
                // TODO: Implement proper trace point handling with multiple uprobe attachment
                for stmt in body {
                    self.compile_statement(stmt)?;
                }
                Ok(())
            }
        }
    }

    fn compile_print(&mut self, expr: &Expr) -> Result<()> {
        match expr {
            Expr::Variable(var_name) => {
                // For variable printing, send structured data using our protocol
                self.send_variable_data(var_name)
            }
            Expr::String(value) => {
                // Handle string literals - send as string data
                let str_ptr = self.compile_expr(expr)?;
                if let BasicValueEnum::PointerValue(ptr) = str_ptr {
                    self.send_string_literal(ptr, value.len() as u64)
                } else {
                    Err(CodeGenError::TypeError(
                        "Expected string pointer".to_string(),
                    ))
                }
            }
            _ => {
                let value = self.compile_expr(expr)?;
                match value {
                    BasicValueEnum::IntValue(int_val) => {
                        // Send integer as structured data
                        self.send_anonymous_integer(int_val)
                    }
                    BasicValueEnum::FloatValue(float_val) => {
                        // Send float as structured data
                        self.send_anonymous_float(float_val)
                    }
                    _ => Err(CodeGenError::NotImplemented(
                        "Unsupported print type".to_string(),
                    )),
                }
            }
        }
    }

    fn compile_expr(&mut self, expr: &Expr) -> Result<BasicValueEnum<'ctx>> {
        match expr {
            Expr::Int(value) => {
                let int_value = self.context.i64_type().const_int(*value as u64, false);
                Ok(int_value.into())
            }
            Expr::Float(value) => {
                let float_value = self.context.f64_type().const_float(*value);
                Ok(float_value.into())
            }
            Expr::String(value) => {
                // Create string constant
                let char_arr_type = self.context.i8_type().array_type((value.len() + 1) as u32);
                let global = self.module.add_global(char_arr_type, None, "str_const");

                // Set string content (including null terminator)
                let mut str_with_null = value.clone();
                str_with_null.push('\0');
                let string_bytes = str_with_null.as_bytes();

                global.set_initializer(&self.context.const_string(string_bytes, false));

                // Return string pointer
                Ok(self
                    .builder
                    .build_pointer_cast(
                        global.as_pointer_value(),
                        self.context.ptr_type(AddressSpace::default()),
                        "str_ptr",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    .into())
            }
            Expr::Variable(name) => {
                // Validate variable access scope
                self.validate_variable_access(name)?;

                if let Some(ptr) = self.variables.get(name) {
                    debug!("Loading variable: {}", name);

                    // Load the correct value based on variable type
                    match self.var_types.get(name) {
                        Some(VarType::Int) => {
                            let i64_type = self.context.i64_type();
                            self.builder
                                .build_load(i64_type, *ptr, name)
                                .map_err(|e| CodeGenError::Builder(e.to_string()))
                        }
                        Some(VarType::Float) => {
                            let f64_type = self.context.f64_type();
                            self.builder
                                .build_load(f64_type, *ptr, name)
                                .map_err(|e| CodeGenError::Builder(e.to_string()))
                        }
                        Some(VarType::String) => {
                            // Strings are pointer type
                            let ptr_type = self.context.ptr_type(AddressSpace::default());
                            self.builder
                                .build_load(ptr_type, *ptr, name)
                                .map_err(|e| CodeGenError::Builder(e.to_string()))
                        }
                        None => Err(CodeGenError::NotImplemented(
                            "Unknown variable type".to_string(),
                        )),
                    }
                } else {
                    Err(CodeGenError::VariableNotFound(name.clone()))
                }
            }
            Expr::MemberAccess(_obj, _field) => {
                // This is a simplified implementation, assuming struct types are predefined
                Err(CodeGenError::NotImplemented(
                    "Member access not fully implemented".to_string(),
                ))
            }
            Expr::PointerDeref(expr) => {
                let ptr = self.compile_expr(expr)?;
                if let BasicValueEnum::PointerValue(ptr) = ptr {
                    let ptr_type = self.context.ptr_type(AddressSpace::default());
                    self.builder
                        .build_load(ptr_type, ptr, "deref")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))
                } else {
                    Err(CodeGenError::NotImplemented(
                        "Cannot dereference non-pointer".to_string(),
                    ))
                }
            }
            Expr::SpecialVar(var_name) => {
                // Validate special variable access scope
                self.validate_variable_access(var_name)?;

                // Handle special variables like $arg0, $arg1, $retval, $pc, $sp
                // For now, return a placeholder integer value
                // TODO: Implement proper special variable handling based on eBPF context
                match var_name.as_str() {
                    "$arg0" | "$arg1" | "$arg2" | "$arg3" => {
                        // For now, return 0 as placeholder for function arguments
                        let int_value = self.context.i64_type().const_int(0, false);
                        Ok(int_value.into())
                    }
                    "$retval" => {
                        // For now, return 0 as placeholder for return value
                        let int_value = self.context.i64_type().const_int(0, false);
                        Ok(int_value.into())
                    }
                    "$pc" | "$sp" => {
                        // For now, return 0 as placeholder for registers
                        let int_value = self.context.i64_type().const_int(0, false);
                        Ok(int_value.into())
                    }
                    _ => Err(CodeGenError::NotImplemented(format!(
                        "Unsupported special variable: {}",
                        var_name
                    ))),
                }
            }
            Expr::BinaryOp { left, op, right } => self.compile_binary_op(left, op, right),
        }
    }

    fn create_string_constant(&self, s: &str) -> Result<inkwell::values::PointerValue<'ctx>> {
        // Ensure array type size includes string content and null terminator
        // s.len() is the byte length of the string, when const_string second parameter is true, it will automatically add a null terminator
        let string_type = self.context.i8_type().array_type((s.len() + 1) as u32);
        let global = self.module.add_global(string_type, None, "str");
        global.set_initializer(&self.context.const_string(s.as_bytes(), true));
        self.builder
            .build_pointer_cast(
                global.as_pointer_value(),
                self.context.ptr_type(AddressSpace::default()),
                "str_ptr",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))
    }

    // create_entry_block_alloca method removed - eBPF doesn't support dynamic stack allocation
    // All variables now use global storage instead

    fn compile_print_string(&mut self, str_ptr: PointerValue<'ctx>) -> Result<()> {
        // For string printing, calculate actual string length and send to ringbuf
        // This is a simplified implementation for POC

        // For constant strings, we can calculate length at compile time
        // For now, we'll use a fixed small buffer size
        let string_len = 32u64; // Reasonable default for POC

        // Send string data to ringbuf
        self.create_ringbuf_output(str_ptr, string_len)?;

        Ok(())
    }

    fn compile_print_string_with_length(
        &mut self,
        str_ptr: PointerValue<'ctx>,
        length: u64,
    ) -> Result<()> {
        // Send string data to ringbuf with the specified length
        self.create_ringbuf_output(str_ptr, length)?;
        Ok(())
    }

    fn compile_print_integer(&mut self, int_val: IntValue<'ctx>) -> Result<()> {
        // Convert integer to bytes and send to ringbuf
        // Create global storage for the integer (eBPF compatible)
        let i64_type = self.context.i64_type();
        let int_storage =
            self.module
                .add_global(i64_type, Some(AddressSpace::default()), "_int_storage");
        int_storage.set_initializer(&i64_type.const_zero());

        // Store the integer value in global storage
        self.builder
            .build_store(int_storage.as_pointer_value(), int_val)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Send 8 bytes (i64) to ringbuf
        self.create_ringbuf_output(int_storage.as_pointer_value(), 8)?;

        Ok(())
    }

    /// Get compile-time PC address for DWARF queries
    fn get_compile_time_pc_address(&self) -> Result<u64> {
        self.current_compile_time_pc.ok_or_else(|| {
            CodeGenError::InvalidExpression(
                "No compile-time PC address available for DWARF query".to_string(),
            )
        })
    }

    /// Query DWARF for variable location at compile-time PC
    fn query_dwarf_for_variable(
        &self,
        var_name: &str,
        pc: u64,
    ) -> Result<ghostscope_binary::dwarf::EnhancedVariableLocation> {
        if let Some(analyzer_ptr) = self.binary_analyzer {
            unsafe {
                let analyzer = &mut *analyzer_ptr;
                if let Some(dwarf_context) = analyzer.dwarf_context_mut() {
                    let enhanced_vars = dwarf_context.get_enhanced_variable_locations(pc);

                    for mut var_info in enhanced_vars {
                        if var_info.variable.name == var_name {
                            // Compute new evaluation result on-the-fly
                            if var_info.evaluation_result.is_none() {
                                let context = ghostscope_binary::expression::EvaluationContext {
                                    pc_address: pc,
                                    address_size: 8,
                                };

                                match dwarf_context
                                    .get_expression_evaluator()
                                    .ok_or_else(|| {
                                        CodeGenError::InvalidExpression(
                                            "Expression evaluator not available".to_string(),
                                        )
                                    })?
                                    .evaluate_location_with_enhanced_types(
                                        &var_info.location_at_address,
                                        pc,
                                        &context,
                                        None, // Pass None to avoid borrowing conflicts
                                    ) {
                                    Ok(new_result) => {
                                        debug!(
                                            "Computed new evaluation result for '{}': {:?}",
                                            var_name, new_result
                                        );
                                        var_info.evaluation_result = Some(new_result);
                                    }
                                    Err(e) => {
                                        debug!(
                                            "Failed to compute new evaluation result for '{}': {}",
                                            var_name, e
                                        );
                                    }
                                }
                            }
                            return Ok(var_info);
                        }
                    }
                }
            }
        }

        Err(CodeGenError::VariableNotFound(format!(
            "Variable '{}' not found in DWARF at compile-time PC 0x{:x}",
            var_name, pc
        )))
    }

    /// Send variable data using protocol format - compile-time DWARF query + LLVM IR generation
    fn send_variable_data(&mut self, var_name: &str) -> Result<()> {
        debug!("Generating LLVM IR for variable: {}", var_name);

        // Get compile-time PC address for DWARF query
        let compile_time_pc = self.get_compile_time_pc_address()?;
        debug!(
            "Using compile-time PC 0x{:x} for DWARF query of '{}'",
            compile_time_pc, var_name
        );

        // Query DWARF for complete variable information at compile-time
        match self.query_dwarf_for_variable(var_name, compile_time_pc) {
            Ok(var_info) => {
                debug!(
                    "DWARF query successful for '{}': evaluation_result={:?}, size={:?}",
                    var_name, var_info.evaluation_result, var_info.size
                );

                // Extract variable size with fallback
                let ctx_param = self.get_current_function_ctx_param()?;

                // First try to use new evaluation system
                if let Some(evaluation_result) = var_info.evaluation_result {
                    let var_type = self
                        .get_variable_type_from_dwarf(var_name, compile_time_pc)
                        .ok_or_else(|| {
                            CodeGenError::InvalidExpression(format!(
                                "Failed to determine type for variable '{}' at PC 0x{:x}",
                                var_name, compile_time_pc
                            ))
                        })?;

                    // Use new type-safe evaluation system - no runtime type checking needed!
                    let var_ptr = self.execute_evaluation_result(
                        ctx_param,
                        &evaluation_result,
                        var_name,
                        compile_time_pc,
                    )?;

                    self.build_and_send_protocol_message(
                        var_name,
                        &var_type,
                        var_ptr,
                        compile_time_pc,
                    )
                } else {
                    debug!(
                        "Variable '{}' has no evaluation result, treating as optimized out",
                        var_name
                    );
                    let var_type = VarType::Int;
                    self.build_and_send_optimized_out_message(var_name, &var_type, compile_time_pc)
                }
            }
            Err(CodeGenError::VariableNotFound(_)) => {
                Err(CodeGenError::InvalidExpression(format!(
                    "Variable '{}' not found in DWARF at PC 0x{:x}",
                    var_name, compile_time_pc
                )))
            }
            Err(e) => Err(e), // Other errors should propagate
        }
    }

    /// Execute complex computed access steps to get final memory address
    fn execute_computed_access_steps(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        steps: &[ghostscope_binary::expression::AccessStep],
        var_name: &str,
        pc_address: u64,
    ) -> Result<IntValue<'ctx>> {
        use ghostscope_binary::expression::{AccessStep, ArithOp};

        // Initialize computation stack
        let mut stack: Vec<IntValue<'ctx>> = Vec::new();
        let i64_type = self.context.i64_type();

        debug!("Executing {} access steps for '{}'", steps.len(), var_name);

        for (i, step) in steps.iter().enumerate() {
            debug!("  Step {}: {:?}", i, step);

            match step {
                AccessStep::LoadRegister(reg) => {
                    let reg_value = self.get_register_value(ctx_param, *reg)?;
                    stack.push(reg_value);
                }
                AccessStep::AddConstant(constant) => {
                    if stack.is_empty() {
                        return Err(CodeGenError::DwarfError(
                            "Stack underflow in AddConstant".to_string(),
                        ));
                    }
                    let top = stack.pop().unwrap();
                    let const_val = i64_type.const_int(constant.abs() as u64, *constant < 0);
                    let result = if *constant >= 0 {
                        self.builder.build_int_add(
                            top,
                            const_val,
                            &format!("{}_add_{}", var_name, i),
                        )
                    } else {
                        self.builder.build_int_sub(
                            top,
                            const_val,
                            &format!("{}_sub_{}", var_name, i),
                        )
                    }
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    stack.push(result);
                }
                AccessStep::LoadFrameBase => {
                    let compile_time_pc = self.get_compile_time_pc_address()?;
                    let frame_base =
                        self.get_frame_base_from_pt_regs(ctx_param, compile_time_pc)?;
                    let frame_base_value = self
                        .builder
                        .build_ptr_to_int(frame_base, i64_type, &format!("{}_frame_base", var_name))
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    stack.push(frame_base_value);
                }
                AccessStep::LoadCallFrameCFA => {
                    debug!("LoadCallFrameCFA step - using CFA evaluation");

                    // Use our new CFA evaluation from DwarfContext
                    if let Some(analyzer_ptr) = self.binary_analyzer {
                        let analyzer = unsafe { &mut *analyzer_ptr };
                        if let Some(dwarf_context) = analyzer.dwarf_context_mut() {
                            if let Some(cfa_result) =
                                dwarf_context.get_cfa_evaluation_result(pc_address)
                            {
                                debug!(
                                    "Successfully got CFA evaluation result in LoadCallFrameCFA"
                                );
                                // Execute the CFA result to get the address
                                match self.execute_evaluation_result(
                                    ctx_param,
                                    &cfa_result,
                                    "cfa_step",
                                    pc_address,
                                ) {
                                    Ok(ptr_val) => {
                                        // Convert pointer to integer and push to stack
                                        let cfa_addr = self
                                            .builder
                                            .build_ptr_to_int(ptr_val, i64_type, "cfa_addr")
                                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                                        stack.push(cfa_addr);
                                    }
                                    Err(e) => {
                                        debug!("Failed to execute CFA evaluation result: {}", e);
                                        return Err(CodeGenError::DwarfError(format!(
                                            "CFA evaluation failed: {}",
                                            e
                                        )));
                                    }
                                }
                            } else {
                                debug!("No CFA evaluation result, using fallback");
                                return Err(CodeGenError::DwarfError(
                                    "CFA evaluation returned no result".to_string(),
                                ));
                            }
                        } else {
                            return Err(CodeGenError::DwarfError(
                                "No DWARF context available for CFA".to_string(),
                            ));
                        }
                    } else {
                        return Err(CodeGenError::DwarfError(
                            "No binary analyzer available for CFA".to_string(),
                        ));
                    }
                }
                AccessStep::Dereference { size: _ } => {
                    // Dereference step - this doesn't change the address computation,
                    // just marks that the final address should be dereferenced
                    // The actual memory read will happen in create_variable_memory_read
                    debug!("Dereference step noted for final memory read");
                }
                AccessStep::ArithmeticOp(op) => match op {
                    ArithOp::Add => {
                        if stack.len() < 2 {
                            return Err(CodeGenError::DwarfError(
                                "Stack underflow in Add".to_string(),
                            ));
                        }
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();
                        let result = self
                            .builder
                            .build_int_add(a, b, &format!("{}_add_{}", var_name, i))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        stack.push(result);
                    }
                    ArithOp::Sub => {
                        if stack.len() < 2 {
                            return Err(CodeGenError::DwarfError(
                                "Stack underflow in Sub".to_string(),
                            ));
                        }
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();
                        let result = self
                            .builder
                            .build_int_sub(a, b, &format!("{}_sub_{}", var_name, i))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        stack.push(result);
                    }
                    ArithOp::Mul => {
                        if stack.len() < 2 {
                            return Err(CodeGenError::DwarfError(
                                "Stack underflow in Mul".to_string(),
                            ));
                        }
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();
                        let result = self
                            .builder
                            .build_int_mul(a, b, &format!("{}_mul_{}", var_name, i))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        stack.push(result);
                    }
                    ArithOp::Div => {
                        if stack.len() < 2 {
                            return Err(CodeGenError::DwarfError(
                                "Stack underflow in Div".to_string(),
                            ));
                        }
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();
                        let result = self
                            .builder
                            .build_int_signed_div(a, b, &format!("{}_div_{}", var_name, i))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        stack.push(result);
                    }
                    ArithOp::Mod => {
                        if stack.len() < 2 {
                            return Err(CodeGenError::DwarfError(
                                "Stack underflow in Mod".to_string(),
                            ));
                        }
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();
                        let result = self
                            .builder
                            .build_int_signed_rem(a, b, &format!("{}_mod_{}", var_name, i))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        stack.push(result);
                    }
                    ArithOp::Neg => {
                        if stack.is_empty() {
                            return Err(CodeGenError::DwarfError(
                                "Stack underflow in Neg".to_string(),
                            ));
                        }
                        let a = stack.pop().unwrap();
                        let result = self
                            .builder
                            .build_int_neg(a, &format!("{}_neg_{}", var_name, i))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        stack.push(result);
                    }
                    _ => {
                        return Err(CodeGenError::DwarfError(format!(
                            "Arithmetic operation {:?} not yet implemented",
                            op
                        )));
                    }
                },
                AccessStep::Conditional {
                    condition: _,
                    then_steps: _,
                    else_steps: _,
                } => {
                    return Err(CodeGenError::DwarfError(
                        "Conditional access steps not yet implemented".to_string(),
                    ));
                }
                AccessStep::Piece { size: _, offset: _ } => {
                    return Err(CodeGenError::DwarfError(
                        "Piece access steps not yet implemented".to_string(),
                    ));
                }
            }
        }

        // Final result should be the computed address
        if stack.len() != 1 {
            return Err(CodeGenError::DwarfError(format!(
                "Invalid stack state after computed access: {} elements (expected 1)",
                stack.len()
            )));
        }

        Ok(stack.pop().unwrap())
    }

    /// Compute memory address for frame-based access
    fn compute_frame_based_address(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        offset: i64,
        var_name: &str,
    ) -> Result<IntValue<'ctx>> {
        let compile_time_pc = self.get_compile_time_pc_address()?;
        let frame_base_ptr = self.get_frame_base_from_pt_regs(ctx_param, compile_time_pc)?;

        // Convert frame base pointer to integer
        let i64_type = self.context.i64_type();
        let frame_base_value = self
            .builder
            .build_ptr_to_int(frame_base_ptr, i64_type, "frame_base")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Add offset
        let offset_const = i64_type.const_int(offset.abs() as u64, offset < 0);
        let result = if offset >= 0 {
            self.builder.build_int_add(
                frame_base_value,
                offset_const,
                &format!("{}_frame_addr", var_name),
            )
        } else {
            self.builder.build_int_sub(
                frame_base_value,
                offset_const,
                &format!("{}_frame_addr", var_name),
            )
        }
        .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        Ok(result)
    }

    /// Compute memory address for CFA-based access
    fn compute_cfa_based_address(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        offset: i64,
        var_name: &str,
    ) -> Result<IntValue<'ctx>> {
        // CFA computation would require CFI evaluation at compile time
        // For now, we'll use a simplified approach assuming CFA = RSP + constant
        debug!("CFA-based access not fully implemented, using RSP-based fallback");

        let rsp_reg_access = ghostscope_binary::expression::RegisterAccess {
            register: 7, // RSP
            offset: Some(offset),
            dereference: false,
            size: None,
        };
        self.compute_register_memory_address(ctx_param, &rsp_reg_access, var_name)
    }

    /// Generate LLVM IR for frame-based variable access
    fn generate_frame_based_access_ir(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        offset: i64,
        var_name: &str,
    ) -> Result<PointerValue<'ctx>> {
        debug!(
            "Generating frame-based access IR for '{}' with offset {}",
            var_name, offset
        );

        // Get compile-time PC address for CFI query
        let compile_time_pc = self.get_compile_time_pc_address()?;

        // Get frame base using CFI information
        // This generates LLVM IR to calculate frame_base + offset at runtime
        let frame_base_ptr = self.get_frame_base_from_pt_regs(ctx_param, compile_time_pc)?;

        // Generate address calculation IR
        let i64_type = self.context.i64_type();
        let offset_const = i64_type.const_int(offset.abs() as u64, false);

        // frame_base_ptr is already the frame base address value, convert it to integer
        let frame_base_value = self
            .builder
            .build_ptr_to_int(frame_base_ptr, i64_type, "frame_base")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let var_addr = if offset >= 0 {
            self.builder
                .build_int_add(frame_base_value, offset_const, "var_addr")
        } else {
            self.builder
                .build_int_sub(frame_base_value, offset_const, "var_addr")
        }
        .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Step 2: Unified memory read with DWARF type info (8 bytes default for frame access)
        self.create_variable_memory_read(var_addr, var_name, 8)
    }

    /// Generate LLVM IR for register-based variable access - unified approach
    fn generate_register_access_ir(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        reg_access: &ghostscope_binary::expression::RegisterAccess,
        var_name: &str,
        var_size: usize,
    ) -> Result<PointerValue<'ctx>> {
        debug!(
            "Generating register access IR for '{}': reg={}, offset={:?}, size={}",
            var_name, reg_access.register, reg_access.offset, var_size
        );

        // Step 1: Compute memory address from register + offset
        let memory_address =
            self.compute_register_memory_address(ctx_param, reg_access, var_name)?;

        // Step 2: Unified memory read with specified size
        self.create_variable_memory_read(memory_address, var_name, var_size)
    }

    /// Compute memory address from register access (register + offset)
    fn compute_register_memory_address(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        reg_access: &ghostscope_binary::expression::RegisterAccess,
        var_name: &str,
    ) -> Result<IntValue<'ctx>> {
        let i64_type = self.context.i64_type();
        let i8_type = self.context.i8_type();

        // Convert DWARF register number to pt_regs byte offset
        let byte_offset = platform::dwarf_reg_to_pt_regs_byte_offset(reg_access.register)
            .ok_or_else(|| CodeGenError::UnsupportedRegister(reg_access.register))?;

        debug!(
            "Computing register address: DWARF reg {} -> pt_regs offset {} bytes",
            reg_access.register, byte_offset
        );

        // Get register value from pt_regs using platform conversion
        let ctx_as_i8_ptr = self
            .builder
            .build_bit_cast(
                ctx_param,
                self.context.ptr_type(AddressSpace::default()),
                &format!("{}_ctx_bytes", var_name),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_pointer_value();

        let byte_offset_const = i64_type.const_int(byte_offset as u64, false);
        let reg_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    ctx_as_i8_ptr,
                    &[byte_offset_const],
                    &format!("reg_{}_ptr", reg_access.register),
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        let reg_u64_ptr = self
            .builder
            .build_bit_cast(
                reg_ptr,
                self.context.ptr_type(AddressSpace::default()),
                &format!("reg_{}_u64_ptr", reg_access.register),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_pointer_value();

        let mut reg_value = self
            .builder
            .build_load(
                i64_type,
                reg_u64_ptr,
                &format!("reg_{}_value", reg_access.register),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();

        // Apply offset if present
        if let Some(offset) = reg_access.offset {
            let offset_const = i64_type.const_int(offset.unsigned_abs(), offset < 0);
            reg_value = if offset >= 0 {
                self.builder
                    .build_int_add(reg_value, offset_const, &format!("{}_addr_add", var_name))
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            } else {
                self.builder
                    .build_int_sub(reg_value, offset_const, &format!("{}_addr_sub", var_name))
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            };
        }

        Ok(reg_value)
    }

    /// Unified memory read with specified size
    fn create_variable_memory_read(
        &mut self,
        memory_address: IntValue<'ctx>,
        var_name: &str,
        var_size: usize,
    ) -> Result<PointerValue<'ctx>> {
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        // Convert address to pointer
        let user_ptr = self
            .builder
            .build_int_to_ptr(memory_address, ptr_type, &format!("{}_ptr", var_name))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        debug!(
            "Reading variable '{}' from memory: size={} bytes",
            var_name, var_size
        );

        // Unified safe memory read
        self.create_safe_user_memory_read(user_ptr, var_size, var_name)
    }

    /// Generate LLVM IR for absolute address variable access - unified approach
    fn generate_absolute_address_access_ir(
        &mut self,
        addr: u64,
        var_name: &str,
        var_size: usize,
    ) -> Result<PointerValue<'ctx>> {
        debug!(
            "Generating absolute address access IR for '{}' at 0x{:x}, size={}",
            var_name, addr, var_size
        );

        // Step 1: Convert absolute address to IntValue
        let memory_address = self.context.i64_type().const_int(addr, false);

        // Step 2: Unified memory read with specified size
        self.create_variable_memory_read(memory_address, var_name, var_size)
    }

    /// Get frame base pointer from pt_regs context based on CFI information
    fn get_frame_base_from_pt_regs(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        pc_address: u64,
    ) -> Result<PointerValue<'ctx>> {
        let i64_type = self.context.i64_type();

        // Simplified frame base calculation using RBP register
        // TODO: Implement proper CFI-based frame base calculation
        debug!(
            "Using simplified frame base calculation for PC 0x{:x}",
            pc_address
        );

        // Use RBP register as frame base (DWARF register 6)
        let rbp_byte_offset = platform::dwarf_reg_to_pt_regs_byte_offset(6).ok_or_else(|| {
            CodeGenError::InvalidExpression(
                "RBP register not supported on current platform".to_string(),
            )
        })?;

        // Calculate i64 index for GEP (pt_regs is array of i64)
        let i64_index = rbp_byte_offset / 8;
        let reg_index_const = i64_type.const_int(i64_index as u64, false);

        let rbp_ptr = unsafe {
            self.builder
                .build_gep(
                    i64_type,
                    ctx_param,
                    &[reg_index_const],
                    "frame_base_rbp_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        // Load RBP value and convert to pointer
        let rbp_value = self
            .builder
            .build_load(i64_type, rbp_ptr, "frame_base_rbp_value")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();

        // Convert register value to pointer
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        self.builder
            .build_int_to_ptr(rbp_value, ptr_type, "frame_base_ptr")
            .map_err(|e| CodeGenError::Builder(e.to_string()))
    }

    /// Build and send protocol format message
    fn build_and_send_protocol_message(
        &mut self,
        var_name: &str,
        var_type: &VarType,
        var_ptr: PointerValue<'ctx>,
        pc_address: u64,
    ) -> Result<()> {
        // Create protocol message storage area
        let msg_storage = self.create_protocol_message_storage();

        // Build message header (MessageHeader: 8 bytes)
        self.build_message_header(msg_storage)?;

        // Build variable data message body (VariableDataMessage: 24 bytes)
        self.build_variable_data_header(msg_storage)?;

        // Build variable entry (VariableEntry + variable name + data)
        self.build_variable_entry(msg_storage, var_name, var_type, var_ptr, pc_address)?;

        // Calculate actual message length and update header
        let total_len = self.calculate_message_length(var_name, var_type, pc_address);
        self.update_message_length(msg_storage, total_len)?;

        // Send to ringbuf
        self.create_ringbuf_output(msg_storage, total_len as u64)?;

        Ok(())
    }

    /// Build and send optimized-out variable message (no bpf_probe_read_user calls)
    fn build_and_send_optimized_out_message(
        &mut self,
        var_name: &str,
        var_type: &VarType,
        pc_address: u64,
    ) -> Result<()> {
        // Create protocol message storage area
        let msg_storage = self.create_protocol_message_storage();

        // Build message header (MessageHeader: 8 bytes)
        self.build_message_header(msg_storage)?;

        // Build variable data message body (VariableDataMessage: 28 bytes)
        self.build_variable_data_header(msg_storage)?;

        // Build variable entry for optimized-out variable (no memory read)
        self.build_optimized_out_variable_entry(msg_storage, var_name, var_type)?;

        // Calculate actual message length and update header
        let total_len = self.calculate_message_length(var_name, var_type, pc_address);
        self.update_message_length(msg_storage, total_len)?;

        // Send to ringbuf
        self.create_ringbuf_output(msg_storage, total_len as u64)?;

        Ok(())
    }

    /// Create storage area for protocol message
    fn create_protocol_message_storage(&mut self) -> PointerValue<'ctx> {
        // Create large enough global buffer to store protocol message (max 4KB)
        let buffer_size = 4096;
        let i8_type = self.context.i8_type();
        let buffer_type = i8_type.array_type(buffer_size);

        let msg_buffer = self.module.add_global(
            buffer_type,
            Some(AddressSpace::default()),
            "_protocol_msg_buffer",
        );
        msg_buffer.set_initializer(&buffer_type.const_zero());

        msg_buffer.as_pointer_value()
    }

    /// Build message header
    fn build_message_header(&mut self, buffer: PointerValue<'ctx>) -> Result<()> {
        let i32_type = self.context.i32_type();
        let i8_type = self.context.i8_type();
        let i16_type = self.context.i16_type();

        // MessageHeader structure: [magic:u32, msg_type:u8, flags:u8, length:u16]
        let magic = i32_type.const_int(0x47534350, false); // "GSCP"
        let msg_type = i8_type.const_int(0x01, false); // VariableData
        let flags = i8_type.const_int(0x00, false); // No flags
        let _length = i16_type.const_int(0, false); // Update later

        // Write magic (offset 0) - cast buffer to u32* for proper alignment
        let magic_u32_ptr = self
            .builder
            .build_pointer_cast(
                buffer,
                self.context.ptr_type(AddressSpace::default()),
                "magic_u32_ptr",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_store(magic_u32_ptr, magic)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write msg_type (offset 4)
        let msg_type_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[self.context.i32_type().const_int(4, false)],
                    "msg_type_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        self.builder
            .build_store(msg_type_ptr, msg_type)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write flags (offset 5)
        let flags_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[self.context.i32_type().const_int(5, false)],
                    "flags_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        self.builder
            .build_store(flags_ptr, flags)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        Ok(())
    }

    /// Build variable data message header
    fn build_variable_data_header(&mut self, buffer: PointerValue<'ctx>) -> Result<()> {
        let i64_type = self.context.i64_type();
        let i32_type = self.context.i32_type();
        let i16_type = self.context.i16_type();

        let offset = 8; // Message header length

        // VariableDataMessage: [trace_id:u64, timestamp:u64, pid:u32, tid:u32, var_count:u16, reserved:u16]
        let trace_id_value = self
            .current_trace_id
            .unwrap_or(consts::DEFAULT_TRACE_ID as u32) as u64;
        let trace_id = i64_type.const_int(trace_id_value, false);
        let timestamp = self.get_current_timestamp()?; // Get real timestamp from bpf_ktime_get_ns

        // Get real PID/TID using bpf_get_current_pid_tgid()
        let pid_tgid_result = self.get_current_pid_tgid()?;
        let pid = self
            .builder
            .build_int_truncate(pid_tgid_result, i32_type, "pid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let shift_32 = self.context.i64_type().const_int(32, false);
        let tgid_64 = self
            .builder
            .build_right_shift(pid_tgid_result, shift_32, false, "tgid_64")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let tid = self
            .builder
            .build_int_truncate(tgid_64, i32_type, "tid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let var_count = i16_type.const_int(1, false); // 1 variable
        let reserved = i16_type.const_int(0, false);

        // Write trace_id (offset 8)
        let trace_id_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(offset, false)],
                    "trace_id_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let trace_id_cast = self
            .builder
            .build_pointer_cast(
                trace_id_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "trace_id_cast",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_store(trace_id_cast, trace_id)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write timestamp (offset 16)
        let timestamp_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(16, false)],
                    "timestamp_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let timestamp_cast = self
            .builder
            .build_pointer_cast(
                timestamp_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "timestamp_cast",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_store(timestamp_cast, timestamp)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write pid (offset 24)
        let pid_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(24, false)],
                    "pid_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let pid_cast = self
            .builder
            .build_pointer_cast(
                pid_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "pid_cast",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_store(pid_cast, pid)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write tid (offset 28)
        let tid_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(28, false)],
                    "tid_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let tid_cast = self
            .builder
            .build_pointer_cast(
                tid_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "tid_cast",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_store(tid_cast, tid)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write var_count (offset 32)
        let var_count_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(32, false)],
                    "var_count_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let var_count_cast = self
            .builder
            .build_pointer_cast(
                var_count_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "var_count_cast",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_store(var_count_cast, var_count)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        Ok(())
    }

    /// Build variable entry
    fn build_variable_entry(
        &mut self,
        buffer: PointerValue<'ctx>,
        var_name: &str,
        var_type: &VarType,
        var_ptr: PointerValue<'ctx>,
        pc_address: u64,
    ) -> Result<()> {
        let i8_type = self.context.i8_type();
        let i16_type = self.context.i16_type();
        let i64_type = self.context.i64_type();

        let entry_offset: usize = 36; // MessageHeader(8) + VariableDataMessage(28)

        // VariableEntry: [name_len:u8, type_encoding:u8, data_len:u16]
        let name_len = i8_type.const_int(var_name.len() as u64, false);
        let type_encoding = i8_type.const_int(
            self.get_type_encoding(var_name, var_type, pc_address),
            false,
        );
        // Set data length based on whether variable is optimized out
        let data_len = if *self.optimized_out_vars.get(var_name).unwrap_or(&false) {
            i16_type.const_int(0, false) // Optimized out variables have no data
        } else {
            // Use actual variable size from DWARF information
            let var_size = self.get_variable_size(pc_address, var_name);
            i16_type.const_int(var_size, false)
        };

        // Write name_len
        let name_len_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(entry_offset as u64, false)],
                    "name_len_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        self.builder
            .build_store(name_len_ptr, name_len)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write type_encoding
        let type_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int((entry_offset + 1) as u64, false)],
                    "type_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        self.builder
            .build_store(type_ptr, type_encoding)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write data_len
        let data_len_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int((entry_offset + 2) as u64, false)],
                    "data_len_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let data_len_cast = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_cast",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_store(data_len_cast, data_len)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write variable name
        let name_offset: usize = entry_offset + 4;
        for (i, byte) in var_name.as_bytes().iter().enumerate() {
            let char_ptr = unsafe {
                self.builder
                    .build_gep(
                        i8_type,
                        buffer,
                        &[self
                            .context
                            .i32_type()
                            .const_int((name_offset + i) as u64, false)],
                        &format!("name_char_{}", i),
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            };
            let char_val = i8_type.const_int(*byte as u64, false);
            self.builder
                .build_store(char_ptr, char_val)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        }

        // Write variable data (read from DWARF storage location)
        // Skip data writing for optimized-out variables
        if !*self.optimized_out_vars.get(var_name).unwrap_or(&false) {
            let data_offset: usize = name_offset + var_name.len();
            // Use actual variable size to determine load type
            let var_size = self.get_variable_size(pc_address, var_name);
            let load_type: inkwell::types::BasicTypeEnum = match var_size {
                1 => self.context.i8_type().into(),
                2 => self.context.i16_type().into(),
                4 => self.context.i32_type().into(),
                8 => self.context.i64_type().into(),
                _ => {
                    debug!(
                        "Unusual variable size {} for '{}', using i64",
                        var_size, var_name
                    );
                    self.context.i64_type().into()
                }
            };

            let var_value = self
                .builder
                .build_load(load_type, var_ptr, "var_value")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            let data_ptr = unsafe {
                self.builder
                    .build_gep(
                        i8_type,
                        buffer,
                        &[self.context.i32_type().const_int(data_offset as u64, false)],
                        "data_ptr",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            };
            let data_cast = self
                .builder
                .build_pointer_cast(
                    data_ptr,
                    self.context.ptr_type(AddressSpace::default()),
                    "data_cast",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder
                .build_store(data_cast, var_value)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        }

        Ok(())
    }

    /// Build variable entry for optimized-out variables (no memory access)
    fn build_optimized_out_variable_entry(
        &mut self,
        buffer: PointerValue<'ctx>,
        var_name: &str,
        _var_type: &VarType,
    ) -> Result<()> {
        let i8_type = self.context.i8_type();
        let i16_type = self.context.i16_type();

        let entry_offset: usize = 36; // MessageHeader(8) + VariableDataMessage(28)

        // VariableEntry: [name_len:u8, type_encoding:u8, data_len:u16]
        let name_len = i8_type.const_int(var_name.len() as u64, false);
        let type_encoding = i8_type.const_int(TypeEncoding::OptimizedOut as u64, false);
        let data_len = i16_type.const_int(0, false); // Optimized out variables have no data

        // Write name_len
        let name_len_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(entry_offset as u64, false)],
                    "name_len_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        self.builder
            .build_store(name_len_ptr, name_len)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write type_encoding
        let type_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int((entry_offset + 1) as u64, false)],
                    "type_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        self.builder
            .build_store(type_ptr, type_encoding)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write data_len
        let data_len_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int((entry_offset + 2) as u64, false)],
                    "data_len_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let data_len_cast = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_cast",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_store(data_len_cast, data_len)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write variable name
        let name_offset: usize = entry_offset + 4;
        for (i, byte) in var_name.as_bytes().iter().enumerate() {
            let char_ptr = unsafe {
                self.builder
                    .build_gep(
                        i8_type,
                        buffer,
                        &[self
                            .context
                            .i32_type()
                            .const_int((name_offset + i) as u64, false)],
                        &format!("name_char_{}", i),
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            };
            let char_val = i8_type.const_int(*byte as u64, false);
            self.builder
                .build_store(char_ptr, char_val)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        }

        // No data section for optimized-out variables

        Ok(())
    }

    /// Calculate total message length
    fn calculate_message_length(
        &self,
        var_name: &str,
        _var_type: &VarType,
        pc_address: u64,
    ) -> u32 {
        let header_len: usize = 8; // MessageHeader
        let msg_body_len: usize = 28; // VariableDataMessage
        let entry_len: usize = 4; // VariableEntry
        let name_len: usize = var_name.len(); // Variable name
                                              // Optimized-out variables have 0 data length, normal variables use actual size
        let data_len: usize = if *self.optimized_out_vars.get(var_name).unwrap_or(&false) {
            0
        } else {
            self.get_variable_size(pc_address, var_name) as usize
        };

        (header_len + msg_body_len + entry_len + name_len + data_len) as u32
    }

    /// Update message length field
    fn update_message_length(&mut self, buffer: PointerValue<'ctx>, total_len: u32) -> Result<()> {
        let i16_type = self.context.i16_type();
        let length_val = i16_type.const_int(total_len as u64, false);

        // Write length field (offset 6)
        let length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(6, false)],
                    "length_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let length_cast = self
            .builder
            .build_pointer_cast(
                length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "length_cast",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_store(length_cast, length_val)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        Ok(())
    }

    /// Get type encoding based on variable size
    fn get_type_encoding(&self, var_name: &str, var_type: &VarType, pc_address: u64) -> u64 {
        // Check if this variable is optimized out
        if *self.optimized_out_vars.get(var_name).unwrap_or(&false) {
            return TypeEncoding::OptimizedOut as u64;
        }

        match var_type {
            VarType::Int => {
                // Use actual variable size to determine encoding
                let var_size = self.get_variable_size(pc_address, var_name);
                match var_size {
                    1 => TypeEncoding::I8 as u64,
                    2 => TypeEncoding::I16 as u64,
                    4 => TypeEncoding::I32 as u64,
                    8 => TypeEncoding::I64 as u64,
                    _ => {
                        debug!(
                            "Unusual integer size {} for variable '{}', using I64",
                            var_size, var_name
                        );
                        TypeEncoding::I64 as u64
                    }
                }
            }
            VarType::Float => {
                // Use actual variable size for float types too
                let var_size = self.get_variable_size(pc_address, var_name);
                match var_size {
                    4 => TypeEncoding::F32 as u64,
                    8 => TypeEncoding::F64 as u64,
                    _ => {
                        debug!(
                            "Unusual float size {} for variable '{}', using F64",
                            var_size, var_name
                        );
                        TypeEncoding::F64 as u64
                    }
                }
            }
            VarType::String => TypeEncoding::String as u64,
        }
    }

    /// Send string literal
    fn send_string_literal(&mut self, _str_ptr: PointerValue<'ctx>, _len: u64) -> Result<()> {
        // TODO: Implement protocol format sending for string literals
        info!("Sending string literal (not implemented yet)");
        Ok(())
    }

    /// Send anonymous integer
    fn send_anonymous_integer(&mut self, int_val: IntValue<'ctx>) -> Result<()> {
        // Create temporary storage and send using protocol format
        let temp_storage = self.module.add_global(
            self.context.i64_type(),
            Some(AddressSpace::default()),
            "_temp_int",
        );
        temp_storage.set_initializer(&self.context.i64_type().const_zero());

        self.builder
            .build_store(temp_storage.as_pointer_value(), int_val)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.build_and_send_protocol_message(
            "<anonymous>",
            &VarType::Int,
            temp_storage.as_pointer_value(),
            0, // Anonymous variables don't have PC address
        )
    }

    /// Send anonymous float
    fn send_anonymous_float(&mut self, float_val: inkwell::values::FloatValue<'ctx>) -> Result<()> {
        // Create temporary storage and send using protocol format
        let temp_storage = self.module.add_global(
            self.context.f64_type(),
            Some(AddressSpace::default()),
            "_temp_float",
        );
        temp_storage.set_initializer(&self.context.f64_type().const_zero());

        self.builder
            .build_store(temp_storage.as_pointer_value(), float_val)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.build_and_send_protocol_message(
            "<anonymous>",
            &VarType::Float,
            temp_storage.as_pointer_value(),
            0, // Anonymous variables don't have PC address
        )
    }

    fn create_ringbuf_output(&mut self, data: PointerValue<'ctx>, size: u64) -> Result<()> {
        // Get ringbuf map
        let map_ptr = self
            .map_manager
            .get_map(&self.module, "ringbuf")
            .map_err(|e| CodeGenError::MapError(e.to_string()))?;

        // Create parameters
        let size_val = self.context.i64_type().const_int(size, false);
        let flags_val = self.context.i64_type().const_int(0, false);

        // Create function type
        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let fn_type = i64_type.fn_type(
            &[
                ptr_type.into(),
                ptr_type.into(),
                i64_type.into(),
                i64_type.into(),
            ],
            false,
        );

        // Create function pointer type
        let fn_ptr_type = fn_type.ptr_type(AddressSpace::default());

        // Convert function ID to function pointer
        let func_id_val = self
            .context
            .i64_type()
            .const_int(BPF_FUNC_ringbuf_output as u64, false);
        let func_ptr = self
            .builder
            .build_int_to_ptr(func_id_val, fn_ptr_type, "ringbuf_output_fn_ptr")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Build parameter array
        let args: &[BasicMetadataValueEnum] = &[
            map_ptr.into(),
            data.into(),
            size_val.into(),
            flags_val.into(),
        ];

        // Use build_indirect_call to create call from function pointer
        let _ = self
            .builder
            .build_indirect_call(fn_type, func_ptr, args, "ringbuf_output")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        Ok(())
    }

    fn compile_binary_op(
        &mut self,
        left: &Expr,
        op: &BinaryOp,
        right: &Expr,
    ) -> Result<BasicValueEnum<'ctx>> {
        debug!("Compiling binary op: {:?} {:?} {:?}", left, op, right);
        let lhs = self.compile_expr(left)?;
        let rhs = self.compile_expr(right)?;

        debug!(
            "Left type: {:?}, Right type: {:?}",
            lhs.get_type(),
            rhs.get_type()
        );

        match (lhs, rhs) {
            (BasicValueEnum::IntValue(lhs), BasicValueEnum::IntValue(rhs)) => {
                debug!("Both operands are integers");
                let result = match op {
                    BinaryOp::Add => self
                        .builder
                        .build_int_add(lhs, rhs, "add")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    BinaryOp::Subtract => self
                        .builder
                        .build_int_sub(lhs, rhs, "sub")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    BinaryOp::Multiply => self
                        .builder
                        .build_int_mul(lhs, rhs, "mul")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    BinaryOp::Divide => self
                        .builder
                        .build_int_signed_div(lhs, rhs, "div")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                };
                Ok(result.into())
            }
            (BasicValueEnum::FloatValue(lhs), BasicValueEnum::FloatValue(rhs)) => {
                debug!("Both operands are floats");
                let result = match op {
                    BinaryOp::Add => self
                        .builder
                        .build_float_add(lhs, rhs, "add")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    BinaryOp::Subtract => self
                        .builder
                        .build_float_sub(lhs, rhs, "sub")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    BinaryOp::Multiply => self
                        .builder
                        .build_float_mul(lhs, rhs, "mul")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    BinaryOp::Divide => self
                        .builder
                        .build_float_div(lhs, rhs, "div")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                };
                Ok(result.into())
            }
            (BasicValueEnum::PointerValue(_lhs), BasicValueEnum::PointerValue(_rhs)) => {
                // Only string addition is supported
                if *op != BinaryOp::Add {
                    return Err(CodeGenError::TypeError(
                        "String type only supports addition operation".to_string(),
                    ));
                }

                // Use strcat function to concatenate strings
                Err(CodeGenError::NotImplemented(
                    "String concatenation not implemented".to_string(),
                ))
            }
            _ => {
                error!(
                    "Unsupported operation between types: {:?} and {:?}",
                    lhs, rhs
                );
                Err(CodeGenError::TypeError(
                    "Operations between different types are not allowed".to_string(),
                ))
            }
        }
    }

    /// Create GPL license section for BPF program
    fn create_license_section(&mut self) -> Result<()> {
        // Create "GPL" string as null-terminated char array
        let license_str = "GPL\0"; // Add null terminator
        let license_bytes = license_str.as_bytes();

        // Create array type for license string
        let i8_type = self.context.i8_type();
        let license_array_type = i8_type.array_type(license_bytes.len() as u32);

        // Create constant initializer
        let license_values: Vec<_> = license_bytes
            .iter()
            .map(|&b| i8_type.const_int(b as u64, false))
            .collect();
        let license_initializer = i8_type.const_array(&license_values);

        // Create global variable for license
        let license_global = self.module.add_global(license_array_type, None, "_license");
        license_global.set_initializer(&license_initializer);
        license_global.set_section(Some("license"));
        license_global.set_linkage(inkwell::module::Linkage::External);

        // Create BTF debug info for license
        let char_di_type = self
            .di_builder
            .create_basic_type("char", 8, 0x06, 0) // DW_ATE_signed_char
            .map_err(|e| CodeGenError::DebugInfo(e.to_string()))?;

        let license_array_di_type = self.di_builder.create_array_type(
            char_di_type.as_type(),
            (license_bytes.len() * 8) as u64, // size in bits
            8,                                // align in bits
            &[0..license_bytes.len() as i64],
        );

        let file = self.compile_unit.get_file();
        let license_di_global = self.di_builder.create_global_variable_expression(
            self.compile_unit.as_debug_info_scope(),
            "_license",
            "_license",
            file,
            1,
            license_array_di_type.as_type(),
            false,                          // is_local_to_unit
            None,                           // expr
            None,                           // decl
            license_global.get_alignment(), // align_in_bits
        );

        // Attach debug info to global
        license_global.set_metadata(license_di_global.as_metadata_value(self.context), 0);

        info!("Created GPL license section");
        Ok(())
    }

    /// Add PID filtering logic to the current function
    /// Get current PID/TID using bpf_get_current_pid_tgid helper
    fn get_current_pid_tgid(&mut self) -> Result<IntValue<'ctx>> {
        // Use aya binding for bpf_get_current_pid_tgid helper function ID
        let func_id_val = self
            .context
            .i64_type()
            .const_int(BPF_FUNC_get_current_pid_tgid as u64, false);
        let i64_type = self.context.i64_type();
        let fn_type = i64_type.fn_type(&[], false);
        let fn_ptr_type = self.context.ptr_type(AddressSpace::default());

        let func_ptr = self
            .builder
            .build_int_to_ptr(func_id_val, fn_ptr_type, "pid_tgid_fn_ptr")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let pid_tgid_result = self
            .builder
            .build_indirect_call(fn_type, func_ptr, &[], "pid_tgid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let pid_tgid_value = pid_tgid_result.try_as_basic_value().left().ok_or_else(|| {
            CodeGenError::Builder("Failed to get pid_tgid return value".to_string())
        })?;

        if let BasicValueEnum::IntValue(pid_tgid_int) = pid_tgid_value {
            Ok(pid_tgid_int)
        } else {
            Err(CodeGenError::Builder(
                "Expected integer value from pid_tgid".to_string(),
            ))
        }
    }

    /// Get current timestamp using bpf_ktime_get_ns helper
    fn get_current_timestamp(&mut self) -> Result<IntValue<'ctx>> {
        // Use aya binding for bpf_ktime_get_ns helper function ID
        let func_id_val = self
            .context
            .i64_type()
            .const_int(BPF_FUNC_ktime_get_ns as u64, false);
        let i64_type = self.context.i64_type();
        let fn_type = i64_type.fn_type(&[], false);
        let fn_ptr_type = self.context.ptr_type(AddressSpace::default());

        let func_ptr = self
            .builder
            .build_int_to_ptr(func_id_val, fn_ptr_type, "ktime_fn_ptr")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let timestamp_result = self
            .builder
            .build_indirect_call(fn_type, func_ptr, &[], "timestamp")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let timestamp_value = timestamp_result
            .try_as_basic_value()
            .left()
            .ok_or_else(|| {
                CodeGenError::Builder("Failed to get timestamp return value".to_string())
            })?;

        if let BasicValueEnum::IntValue(timestamp_int) = timestamp_value {
            Ok(timestamp_int)
        } else {
            Err(CodeGenError::Builder(
                "Expected integer value from timestamp".to_string(),
            ))
        }
    }

    /// Send execution failure message
    fn send_execution_failure(
        &mut self,
        function_id: u32,
        error_code_value: IntValue<'ctx>, // Changed to accept runtime LLVM value
        message: &str,
    ) -> Result<()> {
        let msg_storage = self.create_execution_failure_message_storage();
        self.build_execution_failure_header(
            msg_storage,
            function_id,
            error_code_value,
            message.len() as u16,
        )?;
        self.write_message_string(
            msg_storage,
            message,
            consts::MESSAGE_HEADER_SIZE + consts::EXECUTION_FAILURE_MESSAGE_SIZE,
        )?; // After MessageHeader + ExecutionFailureMessage
        let total_len =
            consts::MESSAGE_HEADER_SIZE + consts::EXECUTION_FAILURE_MESSAGE_SIZE + message.len(); // Header + ExecutionFailureMessage + message
        self.create_ringbuf_output(msg_storage, total_len as u64)?;
        Ok(())
    }

    /// Create storage area for log message
    fn create_log_message_storage(&mut self) -> PointerValue<'ctx> {
        let msg_size =
            consts::MESSAGE_HEADER_SIZE + consts::LOG_MESSAGE_SIZE + consts::MAX_STRING_LENGTH;
        let array_type = self.context.i8_type().array_type(msg_size as u32);
        let msg_storage =
            self.module
                .add_global(array_type, Some(AddressSpace::default()), "_log_msg");
        msg_storage.set_initializer(&array_type.const_zero());
        msg_storage.as_pointer_value()
    }

    /// Create storage area for execution failure message
    fn create_execution_failure_message_storage(&mut self) -> PointerValue<'ctx> {
        let msg_size = consts::MESSAGE_HEADER_SIZE
            + consts::EXECUTION_FAILURE_MESSAGE_SIZE
            + consts::MAX_STRING_LENGTH;
        let array_type = self.context.i8_type().array_type(msg_size as u32);
        let msg_storage =
            self.module
                .add_global(array_type, Some(AddressSpace::default()), "_failure_msg");
        msg_storage.set_initializer(&array_type.const_zero());
        msg_storage.as_pointer_value()
    }

    /// Build log message header
    fn build_log_message_header(
        &mut self,
        buffer: PointerValue<'ctx>,
        log_level: u8,
        message_len: u16,
    ) -> Result<()> {
        let i8_type = self.context.i8_type();
        let i16_type = self.context.i16_type();
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();

        // Build MessageHeader
        self.write_message_header(
            buffer,
            MessageType::Log as u8,
            (consts::MESSAGE_HEADER_SIZE + consts::LOG_MESSAGE_SIZE + message_len as usize) as u16,
        )?;

        // Build LogMessage
        let log_msg_offset = consts::MESSAGE_HEADER_SIZE;

        // trace_id (8 bytes) - use current trace_id or default
        let trace_id_value = self
            .current_trace_id
            .unwrap_or(consts::DEFAULT_TRACE_ID as u32) as u64;
        let trace_id = i64_type.const_int(trace_id_value, false);
        self.write_u64_at_offset(buffer, log_msg_offset, trace_id)?;

        // timestamp (8 bytes)
        let timestamp = self.get_current_timestamp()?;
        self.write_u64_at_offset(buffer, log_msg_offset + 8, timestamp)?;

        // pid and tid (8 bytes total)
        let pid_tgid = self.get_current_pid_tgid()?;
        let tid = self
            .builder
            .build_int_truncate(pid_tgid, i32_type, "tid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let pid = self
            .builder
            .build_right_shift(pid_tgid, i64_type.const_int(32, false), false, "pid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let pid_truncated = self
            .builder
            .build_int_truncate(pid, i32_type, "pid_truncated")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.write_u32_at_offset(buffer, log_msg_offset + 16, pid_truncated)?;
        self.write_u32_at_offset(buffer, log_msg_offset + 20, tid)?;

        // log_level (1 byte) + reserved (3 bytes)
        self.write_u8_at_offset(
            buffer,
            log_msg_offset + 24,
            i8_type.const_int(log_level as u64, false),
        )?;

        // message_len (2 bytes) + reserved2 (2 bytes)
        self.write_u16_at_offset(
            buffer,
            log_msg_offset + 28,
            i16_type.const_int(message_len as u64, false),
        )?;

        Ok(())
    }

    /// Build execution failure message header
    fn build_execution_failure_header(
        &mut self,
        buffer: PointerValue<'ctx>,
        function_id: u32,
        error_code_value: IntValue<'ctx>, // Changed to accept runtime LLVM value
        message_len: u16,
    ) -> Result<()> {
        let i16_type = self.context.i16_type();
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();

        // Build MessageHeader
        self.write_message_header(
            buffer,
            MessageType::ExecutionFailure as u8,
            (consts::MESSAGE_HEADER_SIZE
                + consts::EXECUTION_FAILURE_MESSAGE_SIZE
                + message_len as usize) as u16,
        )?;

        // Build ExecutionFailureMessage
        let failure_msg_offset = consts::MESSAGE_HEADER_SIZE;

        // trace_id (8 bytes) - use current trace_id or default
        let trace_id_value = self
            .current_trace_id
            .unwrap_or(consts::DEFAULT_TRACE_ID as u32) as u64;
        let trace_id = i64_type.const_int(trace_id_value, false);
        self.write_u64_at_offset(buffer, failure_msg_offset, trace_id)?;

        // timestamp (8 bytes)
        let timestamp = self.get_current_timestamp()?;
        self.write_u64_at_offset(buffer, failure_msg_offset + 8, timestamp)?;

        // pid and tid (8 bytes total)
        let pid_tgid = self.get_current_pid_tgid()?;
        let tid = self
            .builder
            .build_int_truncate(pid_tgid, i32_type, "tid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let pid = self
            .builder
            .build_right_shift(pid_tgid, i64_type.const_int(32, false), false, "pid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let pid_truncated = self
            .builder
            .build_int_truncate(pid, i32_type, "pid_truncated")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.write_u32_at_offset(buffer, failure_msg_offset + 16, pid_truncated)?;
        self.write_u32_at_offset(buffer, failure_msg_offset + 20, tid)?;

        // function_id (4 bytes)
        self.write_u32_at_offset(
            buffer,
            failure_msg_offset + 24,
            i32_type.const_int(function_id as u64, false),
        )?;

        // error_code (8 bytes) - use runtime value
        self.write_u64_at_offset(buffer, failure_msg_offset + 28, error_code_value)?;

        // message_len (2 bytes) + reserved (2 bytes)
        self.write_u16_at_offset(
            buffer,
            failure_msg_offset + 36,
            i16_type.const_int(message_len as u64, false),
        )?;

        Ok(())
    }

    /// Helper function to write message header
    fn write_message_header(
        &mut self,
        buffer: PointerValue<'ctx>,
        msg_type: u8,
        length: u16,
    ) -> Result<()> {
        let i8_type = self.context.i8_type();
        let i16_type = self.context.i16_type();
        let i32_type = self.context.i32_type();

        // magic (4 bytes) = "GSCP"
        let magic = i32_type.const_int(consts::MAGIC as u64, false);
        self.write_u32_at_offset(buffer, 0, magic)?;

        // msg_type (1 byte)
        self.write_u8_at_offset(buffer, 4, i8_type.const_int(msg_type as u64, false))?;

        // flags (1 byte) = 0
        self.write_u8_at_offset(buffer, 5, i8_type.const_int(0, false))?;

        // length (2 bytes)
        self.write_u16_at_offset(buffer, 6, i16_type.const_int(length as u64, false))?;

        Ok(())
    }

    /// Helper functions for writing different data types at offsets
    fn write_u8_at_offset(
        &mut self,
        buffer: PointerValue<'ctx>,
        offset: usize,
        value: IntValue<'ctx>,
    ) -> Result<()> {
        let i8_type = self.context.i8_type();
        let ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[self.context.i32_type().const_int(offset as u64, false)],
                    &format!("ptr_offset_{}", offset),
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        // Ensure value is truncated to i8 if necessary
        let i8_value = if value.get_type() == i8_type {
            value
        } else {
            self.builder
                .build_int_truncate(value, i8_type, "truncate_to_i8")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        self.builder
            .build_store(ptr, i8_value)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        Ok(())
    }

    fn write_u16_at_offset(
        &mut self,
        buffer: PointerValue<'ctx>,
        offset: usize,
        value: IntValue<'ctx>,
    ) -> Result<()> {
        let i8_type = self.context.i8_type();
        let i16_type = self.context.i16_type();
        let ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[self.context.i32_type().const_int(offset as u64, false)],
                    &format!("ptr_offset_{}", offset),
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let ptr_cast = self
            .builder
            .build_pointer_cast(
                ptr,
                self.context.ptr_type(AddressSpace::default()),
                "ptr_cast",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Ensure value is truncated to i16 if necessary
        let i16_value = if value.get_type() == i16_type {
            value
        } else {
            self.builder
                .build_int_truncate(value, i16_type, "truncate_to_i16")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        self.builder
            .build_store(ptr_cast, i16_value)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        Ok(())
    }

    fn write_u32_at_offset(
        &mut self,
        buffer: PointerValue<'ctx>,
        offset: usize,
        value: IntValue<'ctx>,
    ) -> Result<()> {
        let i8_type = self.context.i8_type();
        let i32_type = self.context.i32_type();
        let ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[self.context.i32_type().const_int(offset as u64, false)],
                    &format!("ptr_offset_{}", offset),
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let ptr_cast = self
            .builder
            .build_pointer_cast(
                ptr,
                self.context.ptr_type(AddressSpace::default()),
                "ptr_cast",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Ensure value is truncated to i32 if necessary
        let i32_value = if value.get_type() == i32_type {
            value
        } else {
            self.builder
                .build_int_truncate(value, i32_type, "truncate_to_i32")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        self.builder
            .build_store(ptr_cast, i32_value)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        Ok(())
    }

    fn write_u64_at_offset(
        &mut self,
        buffer: PointerValue<'ctx>,
        offset: usize,
        value: IntValue<'ctx>,
    ) -> Result<()> {
        let i8_type = self.context.i8_type();
        let ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[self.context.i32_type().const_int(offset as u64, false)],
                    &format!("ptr_offset_{}", offset),
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let ptr_cast = self
            .builder
            .build_pointer_cast(
                ptr,
                self.context.ptr_type(AddressSpace::default()),
                "ptr_cast",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_store(ptr_cast, value)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        Ok(())
    }

    /// Write message string at specified offset
    fn write_message_string(
        &mut self,
        buffer: PointerValue<'ctx>,
        message: &str,
        offset: usize,
    ) -> Result<()> {
        let i8_type = self.context.i8_type();
        for (i, byte) in message.as_bytes().iter().enumerate() {
            let char_ptr = unsafe {
                self.builder
                    .build_gep(
                        i8_type,
                        buffer,
                        &[self
                            .context
                            .i32_type()
                            .const_int((offset + i) as u64, false)],
                        &format!("msg_char_{}", i),
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            };
            let char_val = i8_type.const_int(*byte as u64, false);
            self.builder
                .build_store(char_ptr, char_val)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        }
        Ok(())
    }

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

        // Get current PID/TID
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

    /// Generate eBPF bpf_trace_printk instruction for RBP debugging
    /// This directly generates eBPF bytecode without complex borrowing
    /// Get CFI offset for a specific PC address by querying the binary analyzer
    /// This delegates all DWARF/CFI logic to the binary crate
    fn get_cfi_offset_for_pc(&self, pc_address: u64) -> i64 {
        // Query the binary analyzer for frame base offset
        if let Some(analyzer_ptr) = self.binary_analyzer {
            unsafe {
                let analyzer = &mut *analyzer_ptr;
                if let Some(offset) = analyzer.get_frame_base_offset(pc_address) {
                    debug!(
                        "Binary analyzer returned frame base offset {} for PC 0x{:x}",
                        offset, pc_address
                    );
                    offset
                } else {
                    debug!(
                        "Binary analyzer found no CFI info for PC 0x{:x}: using default RBP + 16",
                        pc_address
                    );
                    16 // Default fallback
                }
            }
        } else {
            debug!("No binary analyzer available: using default RBP + 16");
            16 // Default fallback
        }
    }

    /// Get variable size from binary analyzer
    /// Returns size in bytes for bpf_probe_read_user, defaults to 8 bytes if not found
    fn get_variable_size(&self, pc_address: u64, var_name: &str) -> u64 {
        if let Some(analyzer_ptr) = self.binary_analyzer {
            unsafe {
                let analyzer = &mut *analyzer_ptr;
                if let Some(size) = analyzer.get_variable_size(pc_address, var_name) {
                    debug!(
                        "Binary analyzer returned size {} bytes for variable '{}' at PC 0x{:x}",
                        size, var_name, pc_address
                    );
                    size
                } else {
                    debug!(
                        "Binary analyzer found no size info for variable '{}' at PC 0x{:x}: using default 8 bytes",
                        var_name, pc_address
                    );
                    8 // Default fallback
                }
            }
        } else {
            debug!(
                "No binary analyzer available: using default 8 bytes for variable '{}'",
                var_name
            );
            8 // Default fallback
        }
    }

    /// Get LLVM type based on variable size
    fn get_llvm_type_for_size(&self, size: u64) -> inkwell::types::BasicTypeEnum<'ctx> {
        match size {
            1 => self.context.i8_type().into(),
            2 => self.context.i16_type().into(),
            4 => self.context.i32_type().into(),
            8 => self.context.i64_type().into(),
            _ => {
                debug!("Unusual variable size {}, using i64", size);
                self.context.i64_type().into()
            }
        }
    }

    fn generate_rbp_trace_printk(
        &mut self,
        var_name: &str,
        rbp_value: IntValue<'ctx>,
    ) -> Result<()> {
        debug!("Generating RBP trace_printk for variable: {}", var_name);

        let i64_type = self.context.i64_type();
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        // Create simplified format string for RBP debug output
        let format_str = "RBP_DEBUG rbp:0x%llx\n\0";
        let format_bytes = format_str.as_bytes();

        // Create global format string with unique name
        let array_type = self.context.i8_type().array_type(format_bytes.len() as u32);
        let format_global_name = format!("rbp_debug_fmt_{}", var_name.replace(".", "_"));

        debug!("Creating global format string: {}", format_global_name);

        let format_global = self
            .module
            .add_global(array_type, None, &format_global_name);
        format_global.set_initializer(&self.context.const_string(format_bytes, false));
        format_global.set_constant(true);

        // Create function type for bpf_trace_printk
        let trace_printk_fn_type = i64_type.fn_type(
            &[
                ptr_type.into(), // fmt
                i32_type.into(), // fmt_size
                i64_type.into(), // rbp_value
            ],
            false,
        );

        // Create function pointer type
        let fn_ptr_type = trace_printk_fn_type.ptr_type(AddressSpace::default());

        // Use aya binding for bpf_trace_printk helper function ID
        let func_id_val = i64_type.const_int(BPF_FUNC_trace_printk as u64, false);
        let func_ptr = self
            .builder
            .build_int_to_ptr(func_id_val, fn_ptr_type, "trace_printk_fn_ptr")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Cast format string to pointer
        let format_ptr = self
            .builder
            .build_pointer_cast(format_global.as_pointer_value(), ptr_type, "rbp_format_ptr")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let format_size = i32_type.const_int(format_bytes.len() as u64, false);

        debug!(
            "Calling bpf_trace_printk (helper ID 6) with format_size: {}",
            format_bytes.len()
        );

        // Use build_indirect_call like other BPF helper functions
        let _result = self
            .builder
            .build_indirect_call(
                trace_printk_fn_type,
                func_ptr,
                &[format_ptr.into(), format_size.into(), rbp_value.into()],
                "rbp_debug_call",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        debug!("RBP trace_printk call generated successfully");
        Ok(())
    }

    /// Create computed access from a sequence of access steps
    fn create_computed_access_from_steps(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        steps: &[AccessStep],
        var_name: &str,
        pc_address: u64,
    ) -> Result<PointerValue<'ctx>> {
        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        let mut current_value: Option<BasicValueEnum<'ctx>> = None;

        for (i, step) in steps.iter().enumerate() {
            debug!(
                "Processing step {} for variable '{}': {:?}",
                i, var_name, step
            );

            current_value = Some(match step {
                AccessStep::LoadRegister(reg) => {
                    let reg_ptr = self.create_register_access(
                        ctx_param,
                        *reg,
                        &format!("{}_step{}", var_name, i),
                    )?;
                    self.builder
                        .build_load(i64_type, reg_ptr, &format!("{}_reg{}_value", var_name, reg))
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?
                }

                AccessStep::AddConstant(constant) => {
                    let base = current_value.ok_or_else(|| {
                        CodeGenError::InvalidExpression("No base value for AddConstant".to_string())
                    })?;

                    let base_int = if let BasicValueEnum::IntValue(int_val) = base {
                        int_val
                    } else if let BasicValueEnum::PointerValue(ptr_val) = base {
                        self.builder
                            .build_ptr_to_int(
                                ptr_val,
                                i64_type,
                                &format!("{}_ptr_to_int", var_name),
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    } else {
                        return Err(CodeGenError::InvalidExpression(
                            "Invalid base type for AddConstant".to_string(),
                        ));
                    };

                    let constant_val =
                        i64_type.const_int(constant.unsigned_abs() as u64, *constant < 0);

                    if *constant >= 0 {
                        self.builder.build_int_add(
                            base_int,
                            constant_val,
                            &format!("{}_add_const", var_name),
                        )
                    } else {
                        self.builder.build_int_sub(
                            base_int,
                            constant_val,
                            &format!("{}_sub_const", var_name),
                        )
                    }
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    .into()
                }

                AccessStep::LoadFrameBase => {
                    // This would require CFI context to resolve frame base
                    // For now, fall back to RSP-based frame base estimation
                    warn!("LoadFrameBase step encountered, using RSP-based fallback for variable '{}'", var_name);
                    let rsp_index =
                        i64_type.const_int(platform::pt_regs_indices::RSP as u64, false);
                    let rsp_ptr = unsafe {
                        self.builder
                            .build_gep(i64_type, ctx_param, &[rsp_index], "frame_base_rsp")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    };
                    self.builder
                        .build_load(i64_type, rsp_ptr, "frame_base_value")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?
                }

                AccessStep::Dereference { size } => {
                    let addr = current_value.ok_or_else(|| {
                        CodeGenError::InvalidExpression(
                            "No address value for Dereference".to_string(),
                        )
                    })?;

                    let addr_int = if let BasicValueEnum::IntValue(int_val) = addr {
                        int_val
                    } else if let BasicValueEnum::PointerValue(ptr_val) = addr {
                        self.builder
                            .build_ptr_to_int(
                                ptr_val,
                                i64_type,
                                &format!("{}_deref_addr", var_name),
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    } else {
                        return Err(CodeGenError::InvalidExpression(
                            "Invalid address type for Dereference".to_string(),
                        ));
                    };

                    // Use bpf_probe_read_user to safely read user memory
                    let addr_ptr = self
                        .builder
                        .build_int_to_ptr(addr_int, ptr_type, &format!("{}_deref_ptr", var_name))
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                    self.create_safe_user_memory_read(
                        addr_ptr,
                        *size,
                        &format!("{}_deref", var_name),
                    )?
                    .into()
                }

                AccessStep::LoadCallFrameCFA => {
                    debug!("LoadCallFrameCFA step in create_computed_access_from_steps for variable '{}'", var_name);

                    // Use our new CFA evaluation from DwarfContext
                    if let Some(analyzer_ptr) = self.binary_analyzer {
                        let analyzer = unsafe { &mut *analyzer_ptr };
                        if let Some(dwarf_context) = analyzer.dwarf_context_mut() {
                            if let Some(cfa_result) =
                                dwarf_context.get_cfa_evaluation_result(pc_address)
                            {
                                debug!("Successfully got CFA evaluation result");
                                // Execute the CFA result to get the address
                                match self.execute_evaluation_result(
                                    ctx_param,
                                    &cfa_result,
                                    var_name,
                                    pc_address,
                                ) {
                                    Ok(ptr_val) => {
                                        // Convert pointer to integer value for address computation
                                        self.builder
                                            .build_ptr_to_int(ptr_val, i64_type, "cfa_addr_value")
                                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                                            .into()
                                    }
                                    Err(e) => {
                                        warn!("Failed to execute CFA evaluation result: {}, using RSP fallback", e);
                                        // Fallback to RSP-based approach
                                        let rsp_index = i64_type.const_int(
                                            platform::pt_regs_indices::RSP as u64,
                                            false,
                                        );
                                        let rsp_ptr = unsafe {
                                            self.builder
                                                .build_gep(
                                                    i64_type,
                                                    ctx_param,
                                                    &[rsp_index],
                                                    "cfa_rsp_fallback",
                                                )
                                                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                                        };
                                        self.builder
                                            .build_load(i64_type, rsp_ptr, "cfa_value_fallback")
                                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                                    }
                                }
                            } else {
                                warn!("No CFA evaluation result for variable '{}', using RSP fallback", var_name);
                                // Fallback to RSP-based approach
                                let rsp_index = i64_type
                                    .const_int(platform::pt_regs_indices::RSP as u64, false);
                                let rsp_ptr = unsafe {
                                    self.builder
                                        .build_gep(
                                            i64_type,
                                            ctx_param,
                                            &[rsp_index],
                                            "cfa_rsp_fallback",
                                        )
                                        .map_err(|e| CodeGenError::Builder(e.to_string()))?
                                };
                                self.builder
                                    .build_load(i64_type, rsp_ptr, "cfa_value_fallback")
                                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
                            }
                        } else {
                            warn!(
                                "No DWARF context for CFA in variable '{}', using RSP fallback",
                                var_name
                            );
                            // Fallback to RSP-based approach
                            let rsp_index =
                                i64_type.const_int(platform::pt_regs_indices::RSP as u64, false);
                            let rsp_ptr = unsafe {
                                self.builder
                                    .build_gep(
                                        i64_type,
                                        ctx_param,
                                        &[rsp_index],
                                        "cfa_rsp_fallback",
                                    )
                                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
                            };
                            self.builder
                                .build_load(i64_type, rsp_ptr, "cfa_value_fallback")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                        }
                    } else {
                        warn!(
                            "No binary analyzer for CFA in variable '{}', using RSP fallback",
                            var_name
                        );
                        // Fallback to RSP-based approach
                        let rsp_index =
                            i64_type.const_int(platform::pt_regs_indices::RSP as u64, false);
                        let rsp_ptr = unsafe {
                            self.builder
                                .build_gep(i64_type, ctx_param, &[rsp_index], "cfa_rsp_fallback")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                        };
                        self.builder
                            .build_load(i64_type, rsp_ptr, "cfa_value_fallback")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    }
                }

                AccessStep::Conditional { .. } => {
                    return Err(CodeGenError::UnsupportedOperation(
                        "Conditional access steps not yet implemented".to_string(),
                    ));
                }

                AccessStep::Piece { .. } => {
                    return Err(CodeGenError::UnsupportedOperation(
                        "Piece access steps not yet implemented".to_string(),
                    ));
                }

                AccessStep::ArithmeticOp(op) => {
                    // Complex arithmetic operations in computed access - should use the main implementation
                    return Err(CodeGenError::DwarfError(format!(
                        "ArithmeticOp {:?} should be handled in the main computed access path",
                        op
                    )));
                }
            });
        }

        // Convert final result to pointer
        let final_value = current_value.ok_or_else(|| {
            CodeGenError::InvalidExpression("Computed access produced no result".to_string())
        })?;

        match final_value {
            BasicValueEnum::IntValue(int_val) => {
                let ptr_type = self.context.ptr_type(AddressSpace::default());
                self.builder
                    .build_int_to_ptr(int_val, ptr_type, &format!("{}_final_ptr", var_name))
                    .map_err(|e| CodeGenError::Builder(e.to_string()))
            }
            BasicValueEnum::PointerValue(ptr_val) => Ok(ptr_val),
            _ => Err(CodeGenError::InvalidExpression(
                "Invalid final result type".to_string(),
            )),
        }
    }

    /// Create access for immediate values by storing them in a global variable
    fn create_immediate_value_access(
        &mut self,
        value: i64,
        var_name: &str,
    ) -> Result<PointerValue<'ctx>> {
        let i64_type = self.context.i64_type();
        let global_name = format!("immediate_value_{}", var_name);

        debug!(
            "Creating immediate value global '{}' with value {}",
            global_name, value
        );

        let global_var = self.module.add_global(i64_type, None, &global_name);
        global_var.set_initializer(&i64_type.const_int(value as u64, value < 0));
        global_var.set_constant(true);

        Ok(global_var.as_pointer_value())
    }

    /// Create memory dereference from a pointer value using bpf_probe_read_user
    fn create_memory_dereference_from_ptr(
        &mut self,
        ptr: PointerValue<'ctx>,
        var_name: &str,
    ) -> Result<PointerValue<'ctx>> {
        // Default to 8 bytes for pointer dereference
        self.create_safe_user_memory_read(ptr, 8, var_name)
    }

    /// Create safe user memory read using bpf_probe_read_user helper
    fn create_safe_user_memory_read(
        &mut self,
        src_ptr: PointerValue<'ctx>,
        size: usize,
        var_name: &str,
    ) -> Result<PointerValue<'ctx>> {
        let i64_type = self.context.i64_type();
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        // Create a global variable to store the read result
        let result_type: BasicTypeEnum = match size {
            1 => self.context.i8_type().into(),
            2 => self.context.i16_type().into(),
            4 => i32_type.into(),
            8 => i64_type.into(),
            _ => self.context.i8_type().array_type(size as u32).into(),
        };

        let global_name = format!("deref_result_{}", var_name);
        let result_global = self.module.add_global(result_type, None, &global_name);
        result_global.set_initializer(&result_type.const_zero());
        let result_ptr = result_global.as_pointer_value();

        // Use bpf_probe_read_user to safely read from user space
        let helper_id = i64_type.const_int(BPF_FUNC_probe_read_user as u64, false);
        let helper_fn_type = i64_type.fn_type(
            &[
                ptr_type.into(), // dst
                i32_type.into(), // size
                ptr_type.into(), // src
            ],
            false,
        );
        let helper_fn_ptr = self
            .builder
            .build_int_to_ptr(
                helper_id,
                self.context.ptr_type(AddressSpace::default()),
                "probe_read_user_fn",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let size_val = i32_type.const_int(size as u64, false);
        let _result = self
            .builder
            .build_indirect_call(
                helper_fn_type,
                helper_fn_ptr,
                &[result_ptr.into(), size_val.into(), src_ptr.into()],
                &format!("probe_read_{}", var_name),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        debug!(
            "Created safe user memory read for variable '{}', size: {}",
            var_name, size
        );
        Ok(result_ptr)
    }

    /// Create access for implicit values from DWARF expressions
    fn create_implicit_value_access(
        &mut self,
        bytes: &[u8],
        var_name: &str,
    ) -> Result<PointerValue<'ctx>> {
        let global_name = format!("implicit_value_{}", var_name);

        debug!(
            "Creating implicit value global '{}' with {} bytes",
            global_name,
            bytes.len()
        );

        // Create an array type for the bytes
        let byte_array_type = self.context.i8_type().array_type(bytes.len() as u32);
        let global_var = self.module.add_global(byte_array_type, None, &global_name);

        // Create array constant from bytes
        let byte_constants: Vec<_> = bytes
            .iter()
            .map(|&b| self.context.i8_type().const_int(b as u64, false))
            .collect();
        let array_const = self.context.i8_type().const_array(&byte_constants);

        global_var.set_initializer(&array_const);
        global_var.set_constant(true);

        Ok(global_var.as_pointer_value())
    }

    /// Get the current function's ctx parameter (uprobe context)
    fn get_current_function_ctx_param(&self) -> Result<PointerValue<'ctx>> {
        let current_fn = self
            .builder
            .get_insert_block()
            .ok_or_else(|| CodeGenError::Builder("No current basic block".to_string()))?
            .get_parent()
            .ok_or_else(|| CodeGenError::Builder("No parent function".to_string()))?;

        let ctx_param = current_fn
            .get_first_param()
            .ok_or_else(|| CodeGenError::Builder("No ctx parameter found".to_string()))?
            .into_pointer_value();

        Ok(ctx_param)
    }

    /// Get current PC address from pt_regs context
    fn get_current_pc_address(&mut self, ctx_param: PointerValue<'ctx>) -> Result<IntValue<'ctx>> {
        let i64_type = self.context.i64_type();

        // Get RIP (PC) from pt_regs - it's at offset for x86_64
        // For uprobe, RIP contains the current instruction address
        let rip_index = self
            .context
            .i64_type()
            .const_int(platform::pt_regs_indices::RIP as u64, false);
        let rip_ptr = unsafe {
            self.builder
                .build_gep(i64_type, ctx_param, &[rip_index], "rip_ptr")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        let pc_address = self
            .builder
            .build_load(i64_type, rip_ptr, "pc_address")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();

        Ok(pc_address)
    }

    /// DEPRECATED: Create runtime variable access using DWARF expression evaluation
    /// This function is deprecated and should not be used in the new architecture.
    /// Use compile-time PC addresses with send_variable_data instead.
    fn create_runtime_variable_access(
        &mut self,
        var_name: &str,
        _pc_address: IntValue<'ctx>,
        _ctx_param: PointerValue<'ctx>,
    ) -> Result<PointerValue<'ctx>> {
        // This function is deprecated in the new architecture
        // All variable access should use compile-time DWARF queries
        Err(CodeGenError::InvalidExpression(
            format!("DEPRECATED: Runtime DWARF queries are no longer supported. Variable '{}' should be accessed via compile-time PC queries in send_variable_data.", var_name),
        ))
    }

    /// Create register-based variable access
    fn create_register_variable_access(
        &mut self,
        reg_access: &ghostscope_binary::expression::RegisterAccess,
        var_name: &str,
        ctx_param: PointerValue<'ctx>,
    ) -> Result<PointerValue<'ctx>> {
        let i64_type = self.context.i64_type();
        let i8_type = self.context.i8_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        // Convert DWARF register number to pt_regs byte offset
        let byte_offset = platform::dwarf_reg_to_pt_regs_byte_offset(reg_access.register)
            .ok_or_else(|| CodeGenError::UnsupportedRegister(reg_access.register))?;

        debug!(
            "Converting DWARF register {} to pt_regs byte offset {}",
            reg_access.register, byte_offset
        );

        // Cast pt_regs ctx to i8* for byte-level access
        let ctx_as_i8_ptr = self
            .builder
            .build_bit_cast(
                ctx_param,
                self.context.ptr_type(AddressSpace::default()),
                &format!("{}_ctx_as_bytes", var_name),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_pointer_value();

        // Get pointer to register using byte offset
        let byte_offset_const = self.context.i64_type().const_int(byte_offset as u64, false);
        let reg_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    ctx_as_i8_ptr,
                    &[byte_offset_const],
                    &format!("reg_{}_ptr", reg_access.register),
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        // Cast back to u64 pointer and load register value
        let reg_u64_ptr = self
            .builder
            .build_bit_cast(
                reg_ptr,
                self.context.ptr_type(AddressSpace::default()),
                &format!("reg_{}_u64_ptr", reg_access.register),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_pointer_value();

        let mut reg_value = self
            .builder
            .build_load(
                i64_type,
                reg_u64_ptr,
                &format!("reg_{}_value", reg_access.register),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();

        // Apply offset if present
        if let Some(offset) = reg_access.offset {
            let offset_const = self
                .context
                .i64_type()
                .const_int(offset.unsigned_abs(), offset < 0);
            reg_value = if offset >= 0 {
                self.builder
                    .build_int_add(
                        reg_value,
                        offset_const,
                        &format!("{}_reg_offset_add", var_name),
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            } else {
                self.builder
                    .build_int_sub(
                        reg_value,
                        offset_const,
                        &format!("{}_reg_offset_sub", var_name),
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            };
        }

        if reg_access.dereference {
            // Convert to pointer and use safe memory read
            let user_ptr = self
                .builder
                .build_int_to_ptr(reg_value, ptr_type, &format!("{}_reg_ptr", var_name))
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Get variable size (default to 8 bytes)
            let var_size = 8; // Default size, could be enhanced with DWARF type info

            // Use existing safe memory read implementation
            self.create_safe_user_memory_read(user_ptr, var_size, var_name)
        } else {
            // Direct register access - create global storage for the value
            let storage_global = self.module.add_global(
                i64_type,
                Some(AddressSpace::default()),
                &format!("reg_var_{}", var_name),
            );
            storage_global.set_initializer(&i64_type.const_zero());

            // Store register value
            self.builder
                .build_store(storage_global.as_pointer_value(), reg_value)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            Ok(storage_global.as_pointer_value())
        }
    }

    /// Create computed access-based variable access
    fn create_computed_variable_access(
        &mut self,
        steps: &[ghostscope_binary::expression::AccessStep],
        var_name: &str,
        ctx_param: PointerValue<'ctx>,
    ) -> Result<PointerValue<'ctx>> {
        use ghostscope_binary::expression::{AccessStep, ArithOp};

        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        // Use stack-based approach like execute_computed_access_steps for complex operations
        let mut stack: Vec<IntValue<'ctx>> = Vec::new();

        for (i, step) in steps.iter().enumerate() {
            debug!("  Variable access step {}: {:?}", i, step);

            match step {
                AccessStep::LoadRegister(reg_num) => {
                    // Convert DWARF register number to pt_regs byte offset
                    let pt_regs_byte_offset = platform::dwarf_reg_to_pt_regs_byte_offset(*reg_num)
                        .ok_or_else(|| {
                            CodeGenError::InvalidExpression(format!(
                                "Unsupported DWARF register {} for current platform",
                                reg_num
                            ))
                        })?;

                    // Calculate pt_regs array index (byte_offset / 8)
                    let reg_index = self
                        .context
                        .i64_type()
                        .const_int((pt_regs_byte_offset / 8) as u64, false);
                    let reg_ptr = unsafe {
                        self.builder
                            .build_gep(
                                i64_type,
                                ctx_param,
                                &[reg_index],
                                &format!("step_reg_{}_ptr", reg_num),
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    };

                    let reg_value = self
                        .builder
                        .build_load(i64_type, reg_ptr, &format!("step_reg_{}_value", reg_num))
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?
                        .into_int_value();

                    stack.push(reg_value);
                }
                AccessStep::AddConstant(offset) => {
                    if stack.is_empty() {
                        return Err(CodeGenError::DwarfError(
                            "Stack underflow in AddConstant".to_string(),
                        ));
                    }
                    let base = stack.pop().unwrap();

                    let offset_const = self
                        .context
                        .i64_type()
                        .const_int(offset.unsigned_abs(), *offset < 0);
                    let result = if *offset >= 0 {
                        self.builder
                            .build_int_add(base, offset_const, &format!("{}_step_add", var_name))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    } else {
                        self.builder
                            .build_int_sub(base, offset_const, &format!("{}_step_sub", var_name))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    };

                    stack.push(result);
                }
                AccessStep::ArithmeticOp(op) => match op {
                    ArithOp::Add => {
                        if stack.len() < 2 {
                            return Err(CodeGenError::DwarfError(
                                "Stack underflow in Add".to_string(),
                            ));
                        }
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();
                        let result = self
                            .builder
                            .build_int_add(a, b, &format!("{}_add_{}", var_name, i))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        stack.push(result);
                    }
                    ArithOp::Sub => {
                        if stack.len() < 2 {
                            return Err(CodeGenError::DwarfError(
                                "Stack underflow in Sub".to_string(),
                            ));
                        }
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();
                        let result = self
                            .builder
                            .build_int_sub(a, b, &format!("{}_sub_{}", var_name, i))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        stack.push(result);
                    }
                    ArithOp::Mul => {
                        if stack.len() < 2 {
                            return Err(CodeGenError::DwarfError(
                                "Stack underflow in Mul".to_string(),
                            ));
                        }
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();
                        let result = self
                            .builder
                            .build_int_mul(a, b, &format!("{}_mul_{}", var_name, i))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        stack.push(result);
                    }
                    ArithOp::Div => {
                        if stack.len() < 2 {
                            return Err(CodeGenError::DwarfError(
                                "Stack underflow in Div".to_string(),
                            ));
                        }
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();
                        let result = self
                            .builder
                            .build_int_signed_div(a, b, &format!("{}_div_{}", var_name, i))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        stack.push(result);
                    }
                    ArithOp::Mod => {
                        if stack.len() < 2 {
                            return Err(CodeGenError::DwarfError(
                                "Stack underflow in Mod".to_string(),
                            ));
                        }
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();
                        let result = self
                            .builder
                            .build_int_signed_rem(a, b, &format!("{}_mod_{}", var_name, i))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        stack.push(result);
                    }
                    ArithOp::Neg => {
                        if stack.is_empty() {
                            return Err(CodeGenError::DwarfError(
                                "Stack underflow in Neg".to_string(),
                            ));
                        }
                        let a = stack.pop().unwrap();
                        let result = self
                            .builder
                            .build_int_neg(a, &format!("{}_neg_{}", var_name, i))
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        stack.push(result);
                    }
                    _ => {
                        return Err(CodeGenError::DwarfError(format!(
                            "Arithmetic operation {:?} not yet implemented",
                            op
                        )));
                    }
                },
                AccessStep::Dereference { size } => {
                    if stack.is_empty() {
                        return Err(CodeGenError::InvalidExpression(
                            "No address to dereference".to_string(),
                        ));
                    }
                    let addr = stack.pop().unwrap();

                    let user_ptr = self
                        .builder
                        .build_int_to_ptr(addr, ptr_type, &format!("{}_step_deref_ptr", var_name))
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                    // Use safe memory read and return early since this produces a pointer
                    return self.create_safe_user_memory_read(user_ptr, *size, var_name);
                }
                _ => {
                    return Err(CodeGenError::NotImplemented(format!(
                        "Access step {:?} not implemented",
                        step
                    )));
                }
            }
        }

        // If we get here without a dereference, create a global storage for the final value
        if let Some(final_value) = stack.pop() {
            let storage_global = self.module.add_global(
                i64_type,
                Some(AddressSpace::default()),
                &format!("computed_var_{}", var_name),
            );
            storage_global.set_initializer(&i64_type.const_zero());

            self.builder
                .build_store(storage_global.as_pointer_value(), final_value)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            Ok(storage_global.as_pointer_value())
        } else {
            Err(CodeGenError::InvalidExpression(
                "Computed access produced no result".to_string(),
            ))
        }
    }

    /// Execute EvaluationResult with enhanced type safety
    fn execute_evaluation_result(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        evaluation_result: &ghostscope_binary::expression::EvaluationResult,
        var_name: &str,
        pc_address: u64,
    ) -> Result<inkwell::values::PointerValue<'ctx>> {
        use ghostscope_binary::expression::{DirectValueResult, EvaluationResult, LocationResult};

        debug!(
            "Executing new evaluation result for '{}': {:?}",
            var_name, evaluation_result
        );

        match evaluation_result {
            // Direct values - no memory read needed
            EvaluationResult::DirectValue(direct_value) => {
                match direct_value {
                    DirectValueResult::Constant(value) => {
                        debug!("Direct constant value: {}", value);
                        self.create_immediate_value_access(*value, var_name)
                    }

                    DirectValueResult::RegisterValue(reg) => {
                        debug!("Direct register value from reg{}", reg);
                        // Register contains the variable value directly, not an address
                        self.create_register_value_access(ctx_param, *reg, var_name)
                    }

                    DirectValueResult::ImplicitValue(bytes) => {
                        debug!("Implicit value with {} bytes", bytes.len());
                        self.create_implicit_value_access(bytes, var_name)
                    }

                    DirectValueResult::ComputedValue {
                        steps,
                        requires_registers,
                        requires_frame_base,
                        requires_cfa,
                    } => {
                        debug!(
                            "Computed direct value: {} steps, requires_registers: {:?}, frame_base: {}, cfa: {}",
                            steps.len(), requires_registers, requires_frame_base, requires_cfa
                        );
                        // This computes a value directly, not an address
                        self.create_computed_value_access(
                            ctx_param,
                            steps,
                            requires_registers,
                            requires_frame_base,
                            requires_cfa,
                            var_name,
                        )
                    }
                }
            }

            // Memory locations - need to dereference
            EvaluationResult::MemoryLocation(location) => {
                match location {
                    LocationResult::Address(addr) => {
                        debug!("Memory address: 0x{:x}", addr);
                        let address_val = self.context.i64_type().const_int(*addr, false);
                        self.create_memory_dereference_from_ptr(
                            address_val.as_basic_value_enum().into_pointer_value(),
                            var_name,
                        )
                    }

                    LocationResult::RegisterAddress {
                        register,
                        offset,
                        size: _,
                    } => {
                        debug!("Register-based address: reg{} + {:?}", register, offset);
                        self.create_register_address_access(ctx_param, *register, *offset, var_name)
                    }

                    LocationResult::ComputedLocation {
                        steps,
                        requires_registers,
                    } => {
                        debug!(
                            "Computed memory location: {} steps, requires_registers: {:?}",
                            steps.len(),
                            requires_registers
                        );
                        // Execute computed access steps to get the address
                        let address_int = self.execute_computed_access_steps(
                            ctx_param, steps, var_name, pc_address,
                        )?;
                        let address_ptr = address_int.as_basic_value_enum().into_pointer_value();

                        // Dereference the computed address
                        let var_size = 8; // Default size
                        self.create_safe_user_memory_read(address_ptr, var_size, var_name)
                    }
                }
            }

            EvaluationResult::Optimized => {
                debug!("Variable '{}' was optimized out", var_name);
                // For optimized out variables, create a null pointer
                let null_ptr = self.context.ptr_type(AddressSpace::default()).const_null();
                Ok(null_ptr)
            }

            EvaluationResult::Composite(_components) => {
                debug!(
                    "Composite location for '{}' - not yet fully supported",
                    var_name
                );
                // TODO: Implement full composite location support
                let null_ptr = self.context.ptr_type(AddressSpace::default()).const_null();
                Ok(null_ptr)
            }
        }
    }

    /// Build and send protocol message for direct values (no memory read required)
    fn build_and_send_direct_value_message(
        &mut self,
        var_name: &str,
        var_type: &VarType,
        value: IntValue<'ctx>,
        pc_address: u64,
    ) -> Result<()> {
        debug!(
            "Building direct value message for '{}': {:?}",
            var_name, var_type
        );

        // For direct values, we can send them immediately without memory read
        match var_type {
            VarType::Int => {
                self.send_int_variable(var_name, value, pc_address)?;
            }
            VarType::Float => {
                // Convert int to float representation
                let float_val = self
                    .builder
                    .build_bit_cast(
                        value,
                        self.context.f64_type(),
                        &format!("{}_as_float", var_name),
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    .into_float_value();
                self.send_float_variable(var_name, float_val, pc_address)?;
            }
            VarType::String => {
                // For string types, treat as int for now
                self.send_int_variable(var_name, value, pc_address)?;
            }
        }
        Ok(())
    }

    /// Send integer variable data directly (for direct values)
    fn send_int_variable(
        &mut self,
        var_name: &str,
        value: IntValue<'ctx>,
        _pc_address: u64,
    ) -> Result<()> {
        debug!("Sending direct int value for '{}': {:?}", var_name, value);

        // For direct values, we can build the protocol message with the value directly
        // This is a simplified implementation - in a real scenario you'd want to
        // build the actual protocol message structure

        // For now, just log the value - this should be replaced with actual protocol message sending
        warn!(
            "Direct value sending not fully implemented yet: {} = {:?}",
            var_name, value
        );
        Ok(())
    }

    /// Send float variable data directly (for direct values)
    fn send_float_variable(
        &mut self,
        var_name: &str,
        value: inkwell::values::FloatValue<'ctx>,
        _pc_address: u64,
    ) -> Result<()> {
        debug!("Sending direct float value for '{}': {:?}", var_name, value);

        // For direct values, we can build the protocol message with the value directly
        // This is a simplified implementation - in a real scenario you'd want to
        // build the actual protocol message structure

        // For now, just log the value - this should be replaced with actual protocol message sending
        warn!(
            "Direct float value sending not fully implemented yet: {} = {:?}",
            var_name, value
        );
        Ok(())
    }

    fn get_variable_type_from_dwarf(&self, var_name: &str, pc_address: u64) -> Option<VarType> {
        if let Some(analyzer_ptr) = self.binary_analyzer {
            unsafe {
                let analyzer = &mut *analyzer_ptr;
                if let Some(dwarf_context) = analyzer.dwarf_context_mut() {
                    let enhanced_vars = dwarf_context.get_enhanced_variable_locations(pc_address);

                    for var_info in enhanced_vars {
                        if var_info.variable.name == var_name {
                            // Use the structured DWARF type information instead of string matching
                            return Some(
                                self.determine_var_type_from_dwarf(&var_info.variable.dwarf_type),
                            );
                        }
                    }
                }
            }
        }
        None
    }

    /// Create register value access (register contains the value directly)
    /// This is a simplified wrapper around create_register_variable_access
    fn create_register_value_access(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        register: u16,
        var_name: &str,
    ) -> Result<PointerValue<'ctx>> {
        debug!(
            "Creating register value access for variable '{}' in register {}",
            var_name, register
        );

        // Create a simplified RegisterAccess for direct register value access
        let reg_access = ghostscope_binary::expression::RegisterAccess {
            register,
            offset: None,       // No offset for direct register value
            dereference: false, // Don't dereference, we want the register value itself
            size: Some(8),      // Default to 8 bytes
        };

        // Reuse the existing implementation
        self.create_register_variable_access(&reg_access, var_name, ctx_param)
    }

    /// Create register address access (register + offset = address to dereference)
    fn create_register_address_access(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        register: u16,
        offset: Option<i64>,
        var_name: &str,
    ) -> Result<PointerValue<'ctx>> {
        debug!(
            "Creating register address access for variable '{}': reg{} + {:?}",
            var_name, register, offset
        );

        // Use existing register offset access which handles address calculation
        let reg_access = ghostscope_binary::expression::RegisterAccess {
            register,
            offset,
            dereference: true, // We need to dereference the computed address
            size: Some(8),     // Default to 8 bytes
        };

        // Reuse existing implementation
        self.create_register_variable_access(&reg_access, var_name, ctx_param)
    }

    /// Create computed value access (expression computes value directly)
    fn create_computed_value_access(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        steps: &[ghostscope_binary::expression::AccessStep],
        _requires_registers: &[u16],
        _requires_frame_base: &bool,
        _requires_cfa: &bool,
        var_name: &str,
    ) -> Result<PointerValue<'ctx>> {
        debug!(
            "Creating computed value access for variable '{}' with {} steps",
            var_name,
            steps.len()
        );

        // For computed values, we execute the steps to get the final value
        // Use existing computed expression infrastructure but treat result as value
        self.create_computed_variable_access(steps, var_name, ctx_param)
    }
}

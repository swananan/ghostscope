use aya_ebpf_bindings::bindings::bpf_func_id::BPF_FUNC_ringbuf_output;
use inkwell::basic_block::BasicBlock;
use inkwell::builder::Builder;
use inkwell::context::Context;
use inkwell::debug_info::{DebugInfoBuilder, AsDIScope};
use inkwell::module::Module;
use inkwell::types::BasicTypeEnum;
use inkwell::values::{
    BasicMetadataValueEnum, BasicValueEnum, FunctionValue, IntValue, PointerValue,
};
use inkwell::AddressSpace;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};
use inkwell::targets::{Target, TargetMachine, TargetTriple};
use inkwell::module::Linkage;
use inkwell::OptimizationLevel;

use crate::ast::{BinaryOp, Expr, Program, Statement};
use crate::map::{MapError, MapManager};

#[derive(Debug, Clone, Copy)]
enum VarType {
    Int,
    Float,
    String,
}

pub struct CodeGen<'ctx> {
    context: &'ctx Context,
    module: Module<'ctx>,
    builder: Builder<'ctx>,
    di_builder: DebugInfoBuilder<'ctx>,
    compile_unit: inkwell::debug_info::DICompileUnit<'ctx>,
    variables: HashMap<String, PointerValue<'ctx>>,
    var_types: HashMap<String, VarType>, // Track variable types
    map_manager: MapManager<'ctx>,
}

#[derive(Debug, thiserror::Error)]
pub enum CodeGenError {
    #[error("Variable not found: {0}")]
    VariableNotFound(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Builder error: {0}")]
    Builder(String),

    #[error("Type error: {0}")]
    TypeError(String),

    #[error("Map error: {0}")]
    Map(#[from] MapError),

    #[error("Debug info error: {0}")]
    DebugInfo(String),
}

pub type Result<T> = std::result::Result<T, CodeGenError>;

impl<'ctx> CodeGen<'ctx> {
    pub fn new(context: &'ctx Context, module_name: &str) -> Self {
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
        module.add_metadata_flag("Debug Info Version", inkwell::module::FlagBehavior::Warning, debug_version_md);

        // Create debug info builder for BTF/DWARF generation
        let (di_builder, compile_unit) = module.create_debug_info_builder(
            true, // allow_unresolved
            inkwell::debug_info::DWARFSourceLanguage::C, // Use C language for BPF compatibility
            "ghostscope_generated", // filename
            "/", // directory  
            "GhostScope Compiler v0.1.0", // producer
            false, // is_optimized
            "-g", // flags - enable debug info generation
            5, // runtime_version - use DWARF version 5 for BTF compatibility
            "", // split_name
            inkwell::debug_info::DWARFEmissionKind::Full, // kind
            0, // dwo_id
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
            variables: HashMap::new(),
            var_types: HashMap::new(),
            map_manager,
        }
    }

    pub fn compile_with_function_name(&mut self, program: &Program, function_name: &str, trace_statements: &[Statement]) -> Result<&Module<'ctx>> {
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
        let i32_di_type = self.di_builder.create_basic_type("int", 32, 0x05, 0)
            .map_err(|e| CodeGenError::DebugInfo(e.to_string()))?;
        
        // Create void pointer type for ctx parameter
        let void_di_type = self.di_builder.create_basic_type("void", 0, 0, 0)
            .map_err(|e| CodeGenError::DebugInfo(e.to_string()))?;
        let void_ptr_di_type = self.di_builder.create_pointer_type("", void_di_type.as_type(), 64, 64, AddressSpace::default());
        
        let di_function_type = self.di_builder.create_subroutine_type(
            self.compile_unit.get_file(),
            Some(i32_di_type.as_type()), // return type - i32 instead of None
            &[void_ptr_di_type.as_type()],  // parameter types - void *ctx
            0,    // flags
        );

        let di_function = self.di_builder.create_function(
            self.compile_unit.as_debug_info_scope(), // scope
            function_name,         // name
            Some(function_name),   // linkage_name 
            self.compile_unit.get_file(), // file
            1,              // line_no
            di_function_type, // ty
            false,          // is_local_to_unit - set to false for global linkage
            true,           // is_definition
            1,              // scope_line
            0,              // flags
            false,          // is_optimized
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

        // Create required maps
        // Use 8 pages (32KB) for ringbuf map
        self.map_manager
            .create_ringbuf_map(&self.module, &self.di_builder, &self.compile_unit, "ringbuf", 8)?;
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

        // Ensure module verification passes
        if let Err(e) = self.module.verify() {
            return Err(CodeGenError::Builder(format!("Module verification failed: {}", e)));
        }

        Ok(&self.module)
    }

    // Keep original compile method for backward compatibility
    pub fn compile(&mut self, program: &Program) -> Result<&Module<'ctx>> {
        // For backward compatibility, use "main" as function name and compile all statements
        self.compile_with_function_name(program, "main", &program.statements)
    }

    fn declare_external_functions(&mut self) {
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
        let ringbuf_output_fn = self.module.add_function("ringbuf_output", fn_type, None);
        ringbuf_output_fn.set_linkage(inkwell::module::Linkage::External);

        // Declare llvm.bpf.pseudo function - used for handling BPF maps
        let pseudo_fn_type = i64_type.fn_type(&[i64_type.into(), i64_type.into()], false);
        let pseudo_fn = self.module.add_function("llvm.bpf.pseudo", pseudo_fn_type, None);
        pseudo_fn.set_linkage(inkwell::module::Linkage::External);
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

                // Create variable
                let alloca = self.create_entry_block_alloca(name, value_expr.get_type())?;
                self.builder
                    .build_store(alloca, value_expr)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                self.variables.insert(name.clone(), alloca);

                // Store variable type
                self.var_types.insert(name.clone(), var_type);

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
            Expr::String(value) => {
                // Handle string printing with known length
                let str_ptr = self.compile_expr(expr)?;
                if let BasicValueEnum::PointerValue(ptr) = str_ptr {
                    // Use actual string length + 1 for null terminator
                    self.compile_print_string_with_length(ptr, (value.len() + 1) as u64)
                } else {
                    Err(CodeGenError::TypeError("Expected string pointer".to_string()))
                }
            }
            _ => {
                let value = self.compile_expr(expr)?;
                match value {
                    BasicValueEnum::PointerValue(str_ptr) => {
                        // Handle string printing (fallback with fixed length)
                        self.compile_print_string(str_ptr)
                    }
                    BasicValueEnum::IntValue(int_val) => {
                        // Handle integer printing
                        self.compile_print_integer(int_val)
                    }
                    BasicValueEnum::FloatValue(float_val) => {
                        // Handle float printing (convert to string representation)
                        self.compile_print_float(float_val)
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

    fn create_entry_block_alloca(
        &self,
        name: &str,
        ty: BasicTypeEnum<'ctx>,
    ) -> Result<PointerValue<'ctx>> {
        let builder = self.context.create_builder();
        let entry = self
            .builder
            .get_insert_block()
            .unwrap()
            .get_parent()
            .unwrap()
            .get_first_basic_block()
            .unwrap();

        match entry.get_first_instruction() {
            Some(first_instr) => builder.position_before(&first_instr),
            None => builder.position_at_end(entry),
        }

        builder
            .build_alloca(ty, name)
            .map_err(|e| CodeGenError::Builder(e.to_string()))
    }

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

    fn compile_print_string_with_length(&mut self, str_ptr: PointerValue<'ctx>, length: u64) -> Result<()> {
        // Send string data to ringbuf with the specified length
        self.create_ringbuf_output(str_ptr, length)?;
        Ok(())
    }

    fn compile_print_integer(&mut self, int_val: IntValue<'ctx>) -> Result<()> {
        // Convert integer to bytes and send to ringbuf
        // Create storage for the integer
        let int_ptr = self.builder
            .build_alloca(self.context.i64_type(), "int_storage")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        
        // Store the integer value
        self.builder
            .build_store(int_ptr, int_val)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Cast to byte pointer for ringbuf output
        let byte_ptr = self.builder
            .build_pointer_cast(
                int_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "int_as_bytes",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Send 8 bytes (i64) to ringbuf
        self.create_ringbuf_output(byte_ptr, 8)?;
        
        Ok(())
    }

    fn compile_print_float(&mut self, float_val: inkwell::values::FloatValue<'ctx>) -> Result<()> {
        // Similar to integer, convert float to bytes
        let float_ptr = self.builder
            .build_alloca(self.context.f64_type(), "float_storage")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        
        self.builder
            .build_store(float_ptr, float_val)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let byte_ptr = self.builder
            .build_pointer_cast(
                float_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "float_as_bytes",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Send 8 bytes (f64) to ringbuf  
        self.create_ringbuf_output(byte_ptr, 8)?;
        
        Ok(())
    }

    fn create_ringbuf_output(&mut self, data: PointerValue<'ctx>, size: u64) -> Result<()> {
        // Get ringbuf map
        let map_ptr = self.map_manager.get_map(&self.module, "ringbuf")?;
        
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
                i64_type.into()
            ], 
            false
        );
        
        // Create function pointer type
        let fn_ptr_type = fn_type.ptr_type(AddressSpace::default());
        
        // Convert function ID to function pointer
        let func_id_val = self.context.i64_type().const_int(BPF_FUNC_ringbuf_output as u64, false);
        let func_ptr = self.builder.build_int_to_ptr(
            func_id_val, 
            fn_ptr_type, 
            "ringbuf_output_fn_ptr"
        ).map_err(|e| CodeGenError::Builder(e.to_string()))?;
        
        // Build parameter array
        let args: &[BasicMetadataValueEnum] = &[
            map_ptr.into(),
            data.into(),
            size_val.into(),
            flags_val.into()
        ];
        
        // Use build_indirect_call to create call from function pointer
        let _ = self.builder.build_indirect_call(
            fn_type,
            func_ptr,
            args,
            "ringbuf_output"
        ).map_err(|e| CodeGenError::Builder(e.to_string()))?;
        
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
        let license_values: Vec<_> = license_bytes.iter()
            .map(|&b| i8_type.const_int(b as u64, false))
            .collect();
        let license_initializer = i8_type.const_array(&license_values);
        
        // Create global variable for license
        let license_global = self.module.add_global(license_array_type, None, "_license");
        license_global.set_initializer(&license_initializer);
        license_global.set_section(Some("license"));
        license_global.set_linkage(inkwell::module::Linkage::External);
        
        // Create BTF debug info for license
        let char_di_type = self.di_builder.create_basic_type("char", 8, 0x06, 0) // DW_ATE_signed_char
            .map_err(|e| CodeGenError::DebugInfo(e.to_string()))?;
            
        let license_array_di_type = self.di_builder.create_array_type(
            char_di_type.as_type(),
            (license_bytes.len() * 8) as u64, // size in bits
            8, // align in bits
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
            false, // is_local_to_unit
            None,  // expr
            None,  // decl
            license_global.get_alignment(), // align_in_bits
        );
        
        // Attach debug info to global
        license_global.set_metadata(license_di_global.as_metadata_value(self.context), 0);
        
        info!("Created GPL license section");
        Ok(())
    }
}

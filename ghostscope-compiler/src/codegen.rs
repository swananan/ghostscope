use aya_ebpf_bindings::bindings::bpf_func_id::{
    BPF_FUNC_get_current_pid_tgid, BPF_FUNC_ktime_get_ns, BPF_FUNC_probe_read_user,
    BPF_FUNC_ringbuf_output, BPF_FUNC_trace_printk,
};
use inkwell::basic_block::BasicBlock;
use inkwell::builder::Builder;
use inkwell::context::Context;
use inkwell::debug_info::{AsDIScope, DebugInfoBuilder};
use inkwell::module::Linkage;
use inkwell::module::Module;
use inkwell::targets::{Target, TargetMachine, TargetTriple};
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
use crate::map::{MapError, MapManager};
use ghostscope_binary::dwarf::{
    DwarfEncoding, DwarfType, EnhancedVariableLocation, LocationExpression,
};
use ghostscope_protocol::{consts, MessageType, TypeEncoding};

/// Register indices for pt_regs array access in eBPF
/// Dynamically calculated from aya's pt_regs structure layout using offset_of! macro
///
/// Note: In eBPF, pt_regs is typically accessed as an array of u64 values,
/// where each register is at a specific index. This is the standard approach
/// used in eBPF programs for accessing register values.
///
/// The indices are calculated by dividing the field offset by the size of u64,
/// which gives us the array index for accessing pt_regs as a u64 array.
mod pt_regs_indices {
    use aya_ebpf_bindings::bindings::pt_regs;

    // Size of u64 in bytes for array index calculation
    const U64_SIZE: usize = core::mem::size_of::<u64>();

    // Core registers - calculated from pt_regs structure layout
    pub const R15: usize = core::mem::offset_of!(pt_regs, r15) / U64_SIZE;
    pub const R14: usize = core::mem::offset_of!(pt_regs, r14) / U64_SIZE;
    pub const R13: usize = core::mem::offset_of!(pt_regs, r13) / U64_SIZE;
    pub const R12: usize = core::mem::offset_of!(pt_regs, r12) / U64_SIZE;
    pub const RBP: usize = core::mem::offset_of!(pt_regs, rbp) / U64_SIZE; // Frame pointer
    pub const RBX: usize = core::mem::offset_of!(pt_regs, rbx) / U64_SIZE;
    pub const R11: usize = core::mem::offset_of!(pt_regs, r11) / U64_SIZE;
    pub const R10: usize = core::mem::offset_of!(pt_regs, r10) / U64_SIZE;
    pub const R9: usize = core::mem::offset_of!(pt_regs, r9) / U64_SIZE;
    pub const R8: usize = core::mem::offset_of!(pt_regs, r8) / U64_SIZE;
    pub const RAX: usize = core::mem::offset_of!(pt_regs, rax) / U64_SIZE; // Return value
    pub const RCX: usize = core::mem::offset_of!(pt_regs, rcx) / U64_SIZE; // 4th argument
    pub const RDX: usize = core::mem::offset_of!(pt_regs, rdx) / U64_SIZE; // 3rd argument
    pub const RSI: usize = core::mem::offset_of!(pt_regs, rsi) / U64_SIZE; // 2nd argument
    pub const RDI: usize = core::mem::offset_of!(pt_regs, rdi) / U64_SIZE; // 1st argument

    // Special registers
    pub const ORIG_RAX: usize = core::mem::offset_of!(pt_regs, orig_rax) / U64_SIZE; // Original syscall number
    pub const RIP: usize = core::mem::offset_of!(pt_regs, rip) / U64_SIZE; // Instruction pointer
    pub const CS: usize = core::mem::offset_of!(pt_regs, cs) / U64_SIZE; // Code segment
    pub const EFLAGS: usize = core::mem::offset_of!(pt_regs, eflags) / U64_SIZE; // Flags register
    pub const RSP: usize = core::mem::offset_of!(pt_regs, rsp) / U64_SIZE; // Stack pointer
    pub const SS: usize = core::mem::offset_of!(pt_regs, ss) / U64_SIZE; // Stack segment
}

pub struct CodeGen<'ctx> {
    context: &'ctx Context,
    module: Module<'ctx>,
    builder: Builder<'ctx>,
    di_builder: DebugInfoBuilder<'ctx>,
    compile_unit: inkwell::debug_info::DICompileUnit<'ctx>,
    variables: HashMap<String, PointerValue<'ctx>>,
    var_types: HashMap<String, VarType>, // Track variable types
    optimized_out_vars: HashMap<String, bool>, // Track which variables are optimized out
    var_pc_addresses: HashMap<String, u64>, // Track PC addresses for variables (for size calculation)
    map_manager: MapManager<'ctx>,
    variable_context: Option<VariableContext>, // Variable scope context for validation
    pending_dwarf_variables: Option<Vec<ghostscope_binary::EnhancedVariableLocation>>, // DWARF variables awaiting population
    debug_logger: DebugLogger<'ctx>,
    binary_analyzer: Option<*const ghostscope_binary::BinaryAnalyzer>, // CFI and DWARF information access
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

    #[error("Debug info error: {0}")]
    DebugInfo(String),
}

pub type Result<T> = std::result::Result<T, CodeGenError>;

impl<'ctx> CodeGen<'ctx> {
    pub fn new(context: &'ctx Context, module_name: &str) -> Self {
        Self::new_with_binary_analyzer(context, module_name, None)
    }

    pub fn new_with_binary_analyzer(
        context: &'ctx Context,
        module_name: &str,
        binary_analyzer: Option<&ghostscope_binary::BinaryAnalyzer>,
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
            variables: HashMap::new(),
            var_types: HashMap::new(),
            optimized_out_vars: HashMap::new(),
            var_pc_addresses: HashMap::new(),
            map_manager,
            variable_context: None, // Will be set later when trace point context is available
            pending_dwarf_variables: None, // Will be set when DWARF variables are prepared
            debug_logger: DebugLogger::new(context),
            binary_analyzer: binary_analyzer.map(|ba| ba as *const _),
        }
    }

    /// Set the variable context for scope validation
    pub fn set_variable_context(&mut self, context: VariableContext) {
        self.variable_context = Some(context);
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

    /// Populate only the variables that are actually used in the script from DWARF location information
    pub fn populate_variables_from_dwarf(
        &mut self,
        enhanced_variables: &[ghostscope_binary::EnhancedVariableLocation],
        ctx_param: PointerValue<'ctx>,
        used_variables: &std::collections::HashSet<String>, // Only variables used in the script
    ) -> Result<()> {
        info!(
            "Analyzing {} DWARF variables, will generate code for {} used variables",
            enhanced_variables.len(),
            used_variables.len()
        );

        // Group variables by name for scope-based resolution
        let mut variables_by_name: std::collections::HashMap<
            String,
            Vec<&ghostscope_binary::EnhancedVariableLocation>,
        > = std::collections::HashMap::new();

        // Group all variables by name
        for enhanced_var in enhanced_variables {
            let var = &enhanced_var.variable;

            // Skip variables not used in the script
            if !used_variables.contains(&var.name) {
                debug!(
                    "Skipping unused variable '{}' - not referenced in script",
                    var.name
                );
                continue;
            }

            variables_by_name
                .entry(var.name.clone())
                .or_insert_with(Vec::new)
                .push(enhanced_var);
        }

        // For each used variable name, select the best candidate based on scope hierarchy
        // First collect all the selected variables to avoid borrowing conflicts
        let mut selected_variables = Vec::new();

        for (var_name, candidates) in variables_by_name {
            let best_candidate =
                self.select_best_variable_by_scope(&candidates, var_name.clone())?;

            if let Some(enhanced_var) = best_candidate {
                // Clone the data to avoid borrowing conflicts
                selected_variables.push((var_name, enhanced_var.clone()));
            } else {
                warn!(
                    "No suitable variable found for '{}' in current scope",
                    var_name
                );
            }
        }

        // Now process the selected variables without borrowing conflicts
        for (var_name, enhanced_var) in selected_variables {
            let var = &enhanced_var.variable;

            info!(
                "Processing used DWARF variable: '{}' of type '{}' (scope-resolved)",
                var.name, var.type_name
            );

            // Convert DWARF location expression to LLVM pointer
            let variable_ptr = match &enhanced_var.location_at_address {
                LocationExpression::Register { reg } => {
                    debug!("Variable '{}' is in register {}", var.name, reg);
                    // For eBPF, we need to extract register values from the context
                    self.create_register_access(ctx_param, *reg, &var.name)?
                }
                LocationExpression::StackOffset { offset } => {
                    debug!("Variable '{}' is at stack offset {}", var.name, offset);
                    self.create_stack_offset_access(
                        ctx_param,
                        *offset,
                        &var.name,
                        enhanced_var.address,
                    )?
                }
                LocationExpression::FrameBaseOffset { offset } => {
                    debug!(
                        "Variable '{}' is at frame base + offset {} at PC 0x{:x}",
                        var.name, offset, enhanced_var.address
                    );
                    self.create_frame_base_offset_access(
                        ctx_param,
                        *offset,
                        &var.name,
                        enhanced_var.address,
                    )?
                }
                LocationExpression::Address { addr } => {
                    debug!(
                        "Variable '{}' is at absolute address 0x{:x}",
                        var.name, addr
                    );
                    self.create_absolute_address_access(*addr, &var.name, enhanced_var.address)?
                }
                LocationExpression::OptimizedOut => {
                    warn!(
                        "Variable '{}' was optimized out, creating placeholder",
                        var.name
                    );
                    // Mark this variable as optimized out
                    self.optimized_out_vars.insert(var.name.clone(), true);
                    self.create_optimized_out_placeholder(&var.name)?
                }
                LocationExpression::RegisterOffset { reg, offset } => {
                    debug!(
                        "Variable '{}' is at register {} + offset {}",
                        var.name, reg, offset
                    );
                    self.create_register_offset_access(ctx_param, *reg, *offset, &var.name)?
                }
                LocationExpression::ComputedExpression {
                    operations,
                    requires_frame_base,
                    requires_registers,
                } => {
                    debug!(
                        "Variable '{}' has computed expression with {} operations (frame_base: {}, registers: {:?})",
                        var.name, operations.len(), requires_frame_base, requires_registers
                    );
                    self.create_computed_expression_access(
                        ctx_param,
                        operations,
                        *requires_frame_base,
                        requires_registers,
                        &var.name,
                    )?
                }
                LocationExpression::DwarfExpression { bytecode: _ } => {
                    warn!(
                        "Variable '{}' has complex DWARF expression, using fallback",
                        var.name
                    );
                    self.create_complex_expression_fallback(&var.name)?
                }
            };

            // Determine variable type from DWARF information
            let var_type = self.determine_var_type_from_dwarf(&var.dwarf_type);

            // Add to code generation HashMaps
            self.variables.insert(var.name.clone(), variable_ptr);
            self.var_types.insert(var.name.clone(), var_type);
            self.var_pc_addresses
                .insert(var.name.clone(), enhanced_var.address);

            info!(
                "Successfully added used DWARF variable '{}' to code generation context",
                var.name
            );
        }

        info!(
            "Generated LLVM IR code for {} used variables",
            self.variables.len()
        );
        Ok(())
    }

    /// Select the best variable from multiple candidates based on scope hierarchy
    /// Prefers variables in the most specific (innermost) scope first
    fn select_best_variable_by_scope<'a>(
        &self,
        candidates: &[&'a ghostscope_binary::EnhancedVariableLocation],
        var_name: String,
    ) -> Result<Option<&'a ghostscope_binary::EnhancedVariableLocation>> {
        if candidates.is_empty() {
            return Ok(None);
        }

        if candidates.len() == 1 {
            info!(
                "Single candidate found for variable '{}', using it directly",
                var_name
            );
            return Ok(Some(candidates[0]));
        }

        info!(
            "Multiple candidates ({}) found for variable '{}', selecting best scope",
            candidates.len(),
            var_name
        );

        // Score each candidate based on scope specificity
        let mut scored_candidates: Vec<(usize, &ghostscope_binary::EnhancedVariableLocation)> =
            Vec::new();

        for candidate in candidates {
            // Get target address from first candidate
            let target_address = candidates[0].address;
            let score = self.calculate_scope_score_with_address(candidate, target_address);
            scored_candidates.push((score, candidate));

            // Check if variable scope contains target address
            let in_scope = candidate.variable.scope_ranges.is_empty()
                || candidate
                    .variable
                    .scope_ranges
                    .iter()
                    .any(|range| target_address >= range.start && target_address < range.end);

            info!(
                "Variable '{}' candidate - type={}, scope_ranges={:?}, in_scope_at_target=0x{:x}:{}, location_expr={:?}, score={}",
                var_name, candidate.variable.type_name, candidate.variable.scope_ranges,
                target_address, in_scope, candidate.location_at_address, score
            );
        }

        // Sort by score (higher score = better match, more specific scope)
        scored_candidates.sort_by(|a, b| b.0.cmp(&a.0));

        let best_candidate = scored_candidates[0].1;

        // Log detailed information about the selected variable
        let target_address = candidates[0].address;
        let in_scope = best_candidate.variable.scope_ranges.is_empty()
            || best_candidate
                .variable
                .scope_ranges
                .iter()
                .any(|range| target_address >= range.start && target_address < range.end);

        info!(
            "SELECTED: Variable '{}' with score {} - type: {}, scope_ranges: {:?}, in_scope_at_0x{:x}: {}, location: {:?}",
            var_name, scored_candidates[0].0, best_candidate.variable.type_name,
            best_candidate.variable.scope_ranges, target_address, in_scope, best_candidate.location_at_address
        );

        Ok(Some(best_candidate))
    }

    /// Calculate scope specificity score for a variable candidate
    /// Higher score means more specific (better) scope
    fn calculate_scope_score(
        &self,
        candidate: &ghostscope_binary::EnhancedVariableLocation,
    ) -> usize {
        let var = &candidate.variable;

        // Base score starts at 0
        let mut score = 0;

        // If variable has scope ranges, prefer those with smaller ranges (more specific)
        if !var.scope_ranges.is_empty() {
            // Calculate total range size - smaller ranges get higher scores
            let total_range_size: u64 = var
                .scope_ranges
                .iter()
                .map(|range| range.end.saturating_sub(range.start))
                .sum();

            // Use the inverse of range size as the primary score component
            // This heavily favors smaller scopes
            score += if total_range_size > 0 {
                // Scale down to prevent overflow: (100000 / size)
                let inverted_score = 100000_u64.saturating_div(total_range_size.max(1));
                inverted_score as usize
            } else {
                50000 // High score for zero-size ranges (very specific)
            };

            // Additional bonus for having scope information
            score += 10000;
        } else {
            // Variables without explicit scope get a much lower base score
            // But still allow them to compete based on other factors
            score += 5000;
        }

        // Prefer local variables over parameters (parameters are usually in outer scope)
        if !var.is_parameter {
            score += 1000;
        }

        // Avoid artificial/compiler-generated variables if possible
        if !var.is_artificial {
            score += 500;
        }

        debug!("Variable '{}' scope score calculation: range_size={}, has_scope={}, is_param={}, is_artificial={}, final_score={}", 
               var.name,
               var.scope_ranges.iter().map(|r| r.end.saturating_sub(r.start)).sum::<u64>(),
               !var.scope_ranges.is_empty(),
               var.is_parameter,
               var.is_artificial,
               score);

        score
    }

    /// Calculate scope specificity score considering target address containment
    /// Higher score means better match - prioritizes variables whose scope contains target address
    fn calculate_scope_score_with_address(
        &self,
        candidate: &ghostscope_binary::EnhancedVariableLocation,
        target_address: u64,
    ) -> usize {
        let var = &candidate.variable;
        let mut score = 0;

        // Check if target address is within any of the variable's scope ranges
        let in_target_scope = var.scope_ranges.is_empty()
            || var
                .scope_ranges
                .iter()
                .any(|range| target_address >= range.start && target_address < range.end);

        // HEAVILY prioritize variables whose scope contains the target address
        if in_target_scope {
            score += 1000000; // Massive bonus for being in correct scope
        }

        // If variable has scope ranges, prefer those with smaller ranges (more specific)
        if !var.scope_ranges.is_empty() {
            let total_range_size: u64 = var
                .scope_ranges
                .iter()
                .map(|range| range.end.saturating_sub(range.start))
                .sum();

            // Use the inverse of range size as the score component
            score += if total_range_size > 0 {
                let inverted_score = 100000_u64.saturating_div(total_range_size.max(1));
                inverted_score as usize
            } else {
                50000 // High score for zero-size ranges
            };

            // Additional bonus for having scope information
            score += 10000;
        } else {
            // Variables without explicit scope get a lower base score
            score += 5000;
        }

        // Prefer local variables over parameters
        if !var.is_parameter {
            score += 1000;
        }

        // Avoid artificial/compiler-generated variables if possible
        if !var.is_artificial {
            score += 500;
        }

        debug!("Variable '{}' enhanced scope score: target_addr=0x{:x}, in_target_scope={}, range_size={}, has_scope={}, is_param={}, is_artificial={}, final_score={}", 
               var.name, target_address, in_target_scope,
               var.scope_ranges.iter().map(|r| r.end.saturating_sub(r.start)).sum::<u64>(),
               !var.scope_ranges.is_empty(),
               var.is_parameter,
               var.is_artificial,
               score);

        score
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
        // pt_regs structure: [r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs, eflags, rsp, ss]
        // Convert DWARF register number to pt_regs array index
        let pt_regs_index = self.convert_dwarf_reg_to_pt_regs_index(register);

        let i64_type = self.context.i64_type();
        let _ptr_type = self.context.ptr_type(AddressSpace::default());

        // For eBPF, access register values from pt_regs safely
        let reg_index = self
            .context
            .i64_type()
            .const_int(pt_regs_index as u64, false);

        // Get pointer to the register in pt_regs
        let reg_ptr = unsafe {
            self.builder
                .build_gep(
                    i64_type,
                    ctx_param,
                    &[reg_index],
                    &format!("{}_reg_ptr", var_name),
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        // Register values can be read directly from pt_regs (kernel memory)
        Ok(reg_ptr)
    }

    /// Create stack offset access for DWARF variables on the stack
    /// Returns a global storage pointer containing the read data
    fn create_stack_offset_access(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        offset: i64,
        var_name: &str,
        pc_address: u64,
    ) -> Result<PointerValue<'ctx>> {
        debug!(
            "Creating stack access for variable '{}' at stack offset {}",
            var_name, offset
        );

        let i64_type = self.context.i64_type();
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        // Get the stack pointer from pt_regs using aya's pt_regs structure
        let rsp_index = self
            .context
            .i64_type()
            .const_int(pt_regs_indices::RSP as u64, false);
        let rsp_ptr = unsafe {
            self.builder
                .build_gep(i64_type, ctx_param, &[rsp_index], "rsp_ptr")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        let rsp_value = self
            .builder
            .build_load(i64_type, rsp_ptr, "rsp_value")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();

        // Calculate the variable address (RSP + offset)
        let var_offset_const = self.context.i64_type().const_int(offset as u64, offset < 0);
        let user_var_addr = if offset >= 0 {
            self.builder
                .build_int_add(rsp_value, var_offset_const, &format!("{}_addr", var_name))
        } else {
            self.builder.build_int_sub(
                rsp_value,
                var_offset_const.const_neg(),
                &format!("{}_addr", var_name),
            )
        }
        .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Convert to pointer for user memory address
        let user_ptr = self
            .builder
            .build_int_to_ptr(user_var_addr, ptr_type, &format!("{}_user_ptr", var_name))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Create global storage for the variable data (eBPF kernel memory)
        // Use unique name based on variable name and address to avoid duplicates
        let unique_name = format!(
            "_stack_var_{}_{:x}",
            var_name,
            user_var_addr.get_name().to_string_lossy().len()
        );
        // Get variable size and create appropriate type
        let var_size = self.get_variable_size(pc_address, var_name);
        let storage_type = self.get_llvm_type_for_size(var_size);
        let storage_global =
            self.module
                .add_global(storage_type, Some(AddressSpace::default()), &unique_name);

        // Initialize with zero value of correct type
        let zero_value: inkwell::values::BasicValueEnum = match storage_type {
            inkwell::types::BasicTypeEnum::IntType(int_type) => int_type.const_zero().into(),
            _ => self.context.i64_type().const_zero().into(), // Fallback
        };
        storage_global.set_initializer(&zero_value);

        // Use bpf_probe_read_user() to safely copy data from user memory to eBPF storage
        let helper_id = self
            .context
            .i64_type()
            .const_int(BPF_FUNC_probe_read_user as u64, false);
        let helper_fn_type = i64_type.fn_type(
            &[
                ptr_type.into(), // dst
                i32_type.into(), // size
                ptr_type.into(), // unsafe_ptr
            ],
            false,
        );
        let helper_fn_ptr = self
            .builder
            .build_int_to_ptr(
                helper_id,
                helper_fn_type.ptr_type(AddressSpace::default()),
                "probe_read_user_fn",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let size = i32_type.const_int(var_size, false);
        let probe_read_result = self
            .builder
            .build_indirect_call(
                helper_fn_type,
                helper_fn_ptr,
                &[
                    storage_global.as_pointer_value().into(),
                    size.into(),
                    user_ptr.into(),
                ],
                "probe_read_result",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Check bpf_probe_read_user return value and handle errors
        if let Either::Left(BasicValueEnum::IntValue(result_int)) =
            probe_read_result.try_as_basic_value()
        {
            // Check if bpf_probe_read_user failed (non-zero return value)
            let zero_value = i64_type.const_int(0, false);
            let is_error = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::NE,
                    result_int,
                    zero_value,
                    "probe_read_failed",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Create conditional branch for error handling
            let current_fn = self
                .builder
                .get_insert_block()
                .unwrap()
                .get_parent()
                .unwrap();
            let error_block = self
                .context
                .append_basic_block(current_fn, "probe_read_error");
            let success_block = self
                .context
                .append_basic_block(current_fn, "probe_read_success");
            let continue_block = self
                .context
                .append_basic_block(current_fn, "probe_read_continue");

            self.builder
                .build_conditional_branch(is_error, error_block, success_block)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Error block - send execution failure message
            self.builder.position_at_end(error_block);
            // Use the full i64 return value directly, no truncation needed
            if let BasicValueEnum::IntValue(error_code_int) = result_int.as_basic_value_enum() {
                let error_msg = format!("bpf_probe_read_user failed for variable '{}'", var_name);
                // Pass the runtime LLVM value instead of constant
                self.send_execution_failure(1, error_code_int, &error_msg)?;
            }

            // Return error - set storage to zero and jump to continue block
            let zero_storage = storage_global.as_pointer_value();
            self.builder
                .build_store(zero_storage, i64_type.const_int(0, false))
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Success block - no special processing needed, just continue
            self.builder.position_at_end(success_block);
            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Continue block - continue with normal execution
            self.builder.position_at_end(continue_block);
        }

        debug!(
            "Stack variable '{}' data safely read into global storage",
            var_name
        );
        Ok(storage_global.as_pointer_value())
    }

    /// Create frame base offset access for DWARF variables relative to frame base
    /// Returns a global storage pointer containing the read data
    fn create_frame_base_offset_access(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        offset: i64,
        var_name: &str,
        pc_address: u64,
    ) -> Result<PointerValue<'ctx>> {
        debug!(
            "Creating frame base access for variable '{}' at offset {}",
            var_name, offset
        );

        // Frame base calculation for DW_OP_fbreg using CFI information
        // We now use CFI to determine the precise frame base location
        let i64_type = self.context.i64_type();
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        // Get RBP from pt_regs using aya's pt_regs structure
        let rbp_index = self
            .context
            .i64_type()
            .const_int(pt_regs_indices::RBP as u64, false);
        let rbp_ptr = unsafe {
            self.builder
                .build_gep(i64_type, ctx_param, &[rbp_index], "rbp_ptr")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        let rbp_value = self
            .builder
            .build_load(i64_type, rbp_ptr, "rbp_value")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();

        // Debug: Generate eBPF bpf_trace_printk for RBP value
        self.generate_rbp_trace_printk(var_name, rbp_value)?;

        // CFI-based frame base calculation using PC-specific rules
        // Query CFI information based on the actual PC address
        let cfi_offset_value = self.get_cfi_offset_for_pc(pc_address);

        debug!(
            "Using CFI-enhanced frame base calculation for PC 0x{:x}: frame_base = RBP + {}, variable_addr = (RBP + {}) + {}",
            pc_address, cfi_offset_value, cfi_offset_value, offset
        );

        // Calculate: frame_base = RBP + cfi_offset
        let cfi_offset = self
            .context
            .i64_type()
            .const_int(cfi_offset_value as u64, false);
        let frame_base = self
            .builder
            .build_int_add(rbp_value, cfi_offset, "frame_base_cfi")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Calculate: variable_addr = frame_base + variable_offset
        let var_offset_const = self
            .context
            .i64_type()
            .const_int(offset.unsigned_abs(), offset < 0);
        let user_var_addr = if offset >= 0 {
            self.builder.build_int_add(
                frame_base,
                var_offset_const,
                &format!("{}_addr_cfi", var_name),
            )
        } else {
            self.builder.build_int_sub(
                frame_base,
                var_offset_const,
                &format!("{}_addr_cfi", var_name),
            )
        }
        .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        debug!(
            "CFI calculation for '{}': RBP + {} + ({}) = final_addr (should be RBP + {})",
            var_name,
            cfi_offset_value,
            offset,
            cfi_offset_value + offset
        );

        // Convert to pointer for user memory address
        let user_ptr = self
            .builder
            .build_int_to_ptr(user_var_addr, ptr_type, &format!("{}_user_ptr", var_name))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Create global storage for the variable data (eBPF kernel memory)
        // Use unique name based on variable name and address to avoid duplicates
        let unique_name = format!(
            "_frame_var_{}_{:x}",
            var_name,
            user_var_addr.get_name().to_string_lossy().len()
        );
        // Get variable size and create appropriate type
        let var_size = self.get_variable_size(pc_address, var_name);
        let storage_type = self.get_llvm_type_for_size(var_size);
        let storage_global =
            self.module
                .add_global(storage_type, Some(AddressSpace::default()), &unique_name);

        // Initialize with zero value of correct type
        let zero_value: inkwell::values::BasicValueEnum = match storage_type {
            inkwell::types::BasicTypeEnum::IntType(int_type) => int_type.const_zero().into(),
            _ => self.context.i64_type().const_zero().into(), // Fallback
        };
        storage_global.set_initializer(&zero_value);

        // Use bpf_probe_read_user() to safely copy data from user memory to eBPF storage
        let helper_id = self
            .context
            .i64_type()
            .const_int(BPF_FUNC_probe_read_user as u64, false);
        let helper_fn_type = i64_type.fn_type(
            &[
                ptr_type.into(), // dst
                i32_type.into(), // size
                ptr_type.into(), // unsafe_ptr
            ],
            false,
        );
        let helper_fn_ptr = self
            .builder
            .build_int_to_ptr(
                helper_id,
                helper_fn_type.ptr_type(AddressSpace::default()),
                "probe_read_user_fn",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let size = i32_type.const_int(var_size, false);
        let probe_read_result = self
            .builder
            .build_indirect_call(
                helper_fn_type,
                helper_fn_ptr,
                &[
                    storage_global.as_pointer_value().into(),
                    size.into(),
                    user_ptr.into(),
                ],
                "probe_read_result",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Check bpf_probe_read_user return value and handle errors
        if let Either::Left(BasicValueEnum::IntValue(result_int)) =
            probe_read_result.try_as_basic_value()
        {
            // Check if bpf_probe_read_user failed (non-zero return value)
            let zero_value = i64_type.const_int(0, false);
            let is_error = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::NE,
                    result_int,
                    zero_value,
                    "probe_read_failed",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Create conditional branch for error handling
            let current_fn = self
                .builder
                .get_insert_block()
                .unwrap()
                .get_parent()
                .unwrap();
            let error_block = self
                .context
                .append_basic_block(current_fn, "probe_read_error_frame");
            let success_block = self
                .context
                .append_basic_block(current_fn, "probe_read_success_frame");
            let continue_block = self
                .context
                .append_basic_block(current_fn, "probe_read_continue_frame");

            self.builder
                .build_conditional_branch(is_error, error_block, success_block)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Error block - send execution failure message
            self.builder.position_at_end(error_block);
            // Use the full i64 return value directly, no truncation needed
            if let BasicValueEnum::IntValue(error_code_int) = result_int.as_basic_value_enum() {
                let error_msg = format!(
                    "bpf_probe_read_user failed for frame variable '{}'",
                    var_name
                );
                // Pass the runtime LLVM value instead of constant
                self.send_execution_failure(2, error_code_int, &error_msg)?;
            }

            // Return error - set storage to zero and jump to continue block
            let zero_storage = storage_global.as_pointer_value();
            self.builder
                .build_store(zero_storage, i64_type.const_int(0, false))
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Success block - no special processing needed, just continue
            self.builder.position_at_end(success_block);
            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Continue block - continue with normal execution
            self.builder.position_at_end(continue_block);
        }

        debug!(
            "Frame base variable '{}' data safely read into global storage",
            var_name
        );
        Ok(storage_global.as_pointer_value())
    }

    /// Create absolute address access for DWARF variables at fixed memory locations
    /// Returns a global storage pointer containing the read data
    fn create_absolute_address_access(
        &mut self,
        address: u64,
        var_name: &str,
        pc_address: u64,
    ) -> Result<PointerValue<'ctx>> {
        debug!(
            "Creating absolute address access for variable '{}' at 0x{:x}",
            var_name, address
        );

        let i64_type = self.context.i64_type();
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        // Convert address to pointer for user memory
        let addr_const = self.context.i64_type().const_int(address, false);

        let user_ptr = self
            .builder
            .build_int_to_ptr(addr_const, ptr_type, &format!("{}_user_ptr", var_name))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Create global storage for the variable data (eBPF kernel memory)
        // Use unique name based on variable name and address to avoid duplicates
        let unique_name = format!("_abs_var_{}_{:x}", var_name, address);
        // Get variable size and create appropriate type
        let var_size = self.get_variable_size(pc_address, var_name);
        let storage_type = self.get_llvm_type_for_size(var_size);
        let storage_global =
            self.module
                .add_global(storage_type, Some(AddressSpace::default()), &unique_name);

        // Initialize with zero value of correct type
        let zero_value: inkwell::values::BasicValueEnum = match storage_type {
            inkwell::types::BasicTypeEnum::IntType(int_type) => int_type.const_zero().into(),
            _ => self.context.i64_type().const_zero().into(), // Fallback
        };
        storage_global.set_initializer(&zero_value);

        // Use bpf_probe_read_user() to safely copy data from user memory to eBPF storage
        let helper_id = self
            .context
            .i64_type()
            .const_int(BPF_FUNC_probe_read_user as u64, false);
        let helper_fn_type = i64_type.fn_type(
            &[
                ptr_type.into(), // dst
                i32_type.into(), // size
                ptr_type.into(), // unsafe_ptr
            ],
            false,
        );
        let helper_fn_ptr = self
            .builder
            .build_int_to_ptr(
                helper_id,
                helper_fn_type.ptr_type(AddressSpace::default()),
                "probe_read_user_fn",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let size = i32_type.const_int(var_size, false);
        let probe_read_result = self
            .builder
            .build_indirect_call(
                helper_fn_type,
                helper_fn_ptr,
                &[
                    storage_global.as_pointer_value().into(),
                    size.into(),
                    user_ptr.into(),
                ],
                "probe_read_result",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Check bpf_probe_read_user return value and handle errors
        if let Either::Left(BasicValueEnum::IntValue(result_int)) =
            probe_read_result.try_as_basic_value()
        {
            // Check if bpf_probe_read_user failed (non-zero return value)
            let zero_value = i64_type.const_int(0, false);
            let is_error = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::NE,
                    result_int,
                    zero_value,
                    "probe_read_failed",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Create conditional branch for error handling
            let current_fn = self
                .builder
                .get_insert_block()
                .unwrap()
                .get_parent()
                .unwrap();
            let error_block = self
                .context
                .append_basic_block(current_fn, "probe_read_error_abs");
            let success_block = self
                .context
                .append_basic_block(current_fn, "probe_read_success_abs");
            let continue_block = self
                .context
                .append_basic_block(current_fn, "probe_read_continue_abs");

            self.builder
                .build_conditional_branch(is_error, error_block, success_block)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Error block - send execution failure message
            self.builder.position_at_end(error_block);
            // Use the full i64 return value directly, no truncation needed
            if let BasicValueEnum::IntValue(error_code_int) = result_int.as_basic_value_enum() {
                let error_msg = format!(
                    "bpf_probe_read_user failed for absolute address variable '{}'",
                    var_name
                );
                self.send_execution_failure(3, error_code_int, &error_msg)?;
            }

            // Return error - set storage to zero and jump to continue block
            let zero_storage = storage_global.as_pointer_value();
            self.builder
                .build_store(zero_storage, i64_type.const_int(0, false))
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Success block - no special processing needed, just continue
            self.builder.position_at_end(success_block);
            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Continue block - continue with normal execution
            self.builder.position_at_end(continue_block);
        }

        debug!(
            "Absolute address variable '{}' data safely read into global storage",
            var_name
        );
        Ok(storage_global.as_pointer_value())
    }

    /// Create placeholder for optimized out variables
    fn create_optimized_out_placeholder(&mut self, var_name: &str) -> Result<PointerValue<'ctx>> {
        debug!(
            "Creating optimized out placeholder for variable '{}'",
            var_name
        );

        let i64_type = self.context.i64_type();
        // For eBPF compatibility, create a constant pointer to zero
        let zero_value = self.context.i64_type().const_zero();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        // Create a global constant for optimized out variables
        let global_zero = self.module.add_global(
            i64_type,
            Some(AddressSpace::default()),
            &format!("_optimized_out_{}", var_name),
        );
        global_zero.set_initializer(&zero_value);

        Ok(global_zero.as_pointer_value())
    }

    /// Create fallback for complex DWARF expressions
    fn create_complex_expression_fallback(&mut self, var_name: &str) -> Result<PointerValue<'ctx>> {
        debug!(
            "Creating complex expression fallback for variable '{}'",
            var_name
        );

        // For now, treat complex expressions like optimized out variables
        // TODO: Implement full DWARF expression evaluation
        self.create_optimized_out_placeholder(var_name)
    }

    /// Create LLVM pointer for variable at register + offset location
    fn create_register_offset_access(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        register: u16,
        offset: i64,
        var_name: &str,
    ) -> Result<PointerValue<'ctx>> {
        debug!(
            "Creating register offset access for variable '{}': reg {} + offset {}",
            var_name, register, offset
        );

        // Get register value first
        let reg_value = self.get_register_value(ctx_param, register)?;

        // Add offset to register value
        let offset_value = self.context.i64_type().const_int(offset as u64, true);
        let address = self
            .builder
            .build_int_add(reg_value, offset_value, &format!("{}_addr", var_name))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Convert to pointer
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let address_ptr = self
            .builder
            .build_int_to_ptr(address, ptr_type, &format!("{}_ptr", var_name))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        Ok(address_ptr)
    }

    /// Create LLVM pointer for variable with computed DWARF expression
    fn create_computed_expression_access(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        operations: &[ghostscope_binary::dwarf::DwarfOp],
        requires_frame_base: bool,
        requires_registers: &[u16],
        var_name: &str,
    ) -> Result<PointerValue<'ctx>> {
        use ghostscope_binary::dwarf::DwarfOp;

        debug!(
            "Creating computed expression access for variable '{}' with {} operations",
            var_name,
            operations.len()
        );

        // Initialize a simple stack for expression evaluation
        let mut stack: Vec<IntValue<'ctx>> = Vec::new();
        let i64_type = self.context.i64_type();

        // Process each operation
        for (i, op) in operations.iter().enumerate() {
            debug!("  Operation {}: {:?}", i, op);

            match op {
                DwarfOp::Const(value) => {
                    let const_val = i64_type.const_int(*value as u64, true);
                    stack.push(const_val);
                }
                DwarfOp::Reg(reg) => {
                    let reg_value = self.get_register_value(ctx_param, *reg)?;
                    stack.push(reg_value);
                }
                DwarfOp::Breg(reg, offset) => {
                    let reg_value = self.get_register_value(ctx_param, *reg)?;
                    let offset_value = i64_type.const_int(*offset as u64, true);
                    let result = self
                        .builder
                        .build_int_add(
                            reg_value,
                            offset_value,
                            &format!("{}_breg_result", var_name),
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    stack.push(result);
                }
                DwarfOp::Fbreg(offset) => {
                    if !requires_frame_base {
                        warn!("Fbreg operation without frame base requirement");
                    }
                    // For now, treat frame base as RBP (DWARF register 5 on x86_64)
                    let rbp_value = self.get_register_value(ctx_param, 5)?;
                    let offset_value = i64_type.const_int(*offset as u64, true);
                    let result = self
                        .builder
                        .build_int_add(
                            rbp_value,
                            offset_value,
                            &format!("{}_fbreg_result", var_name),
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    stack.push(result);
                }
                DwarfOp::Plus => {
                    if stack.len() < 2 {
                        return Err(CodeGenError::DwarfError(
                            "Stack underflow in DWARF Plus operation".to_string(),
                        ));
                    }
                    let b = stack.pop().unwrap();
                    let a = stack.pop().unwrap();
                    let result = self
                        .builder
                        .build_int_add(a, b, &format!("{}_plus_result", var_name))
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    stack.push(result);
                }
                DwarfOp::PlusUconst(value) => {
                    if stack.is_empty() {
                        return Err(CodeGenError::DwarfError(
                            "Stack underflow in DWARF PlusUconst operation".to_string(),
                        ));
                    }
                    let a = stack.pop().unwrap();
                    let const_val = i64_type.const_int(*value, false);
                    let result = self
                        .builder
                        .build_int_add(a, const_val, &format!("{}_plus_const_result", var_name))
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    stack.push(result);
                }
                DwarfOp::Deref => {
                    if stack.is_empty() {
                        return Err(CodeGenError::DwarfError(
                            "Stack underflow in DWARF Deref operation".to_string(),
                        ));
                    }
                    let address = stack.pop().unwrap();

                    // Convert to pointer and dereference
                    let ptr_type = self.context.ptr_type(AddressSpace::default());
                    let address_ptr = self
                        .builder
                        .build_int_to_ptr(address, ptr_type, &format!("{}_deref_ptr", var_name))
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                    // For now, just return the pointer - actual dereferencing happens later
                    // when the variable is accessed
                    return Ok(address_ptr);
                }
                DwarfOp::StackValue => {
                    // The value is already on the stack, convert to address
                    if stack.is_empty() {
                        return Err(CodeGenError::DwarfError(
                            "Stack underflow in DWARF StackValue operation".to_string(),
                        ));
                    }
                    let value = stack.pop().unwrap();
                    let ptr_type = self.context.ptr_type(AddressSpace::default());
                    let result_ptr = self
                        .builder
                        .build_int_to_ptr(value, ptr_type, &format!("{}_stack_value_ptr", var_name))
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    return Ok(result_ptr);
                }
                _ => {
                    warn!(
                        "Unsupported DWARF operation in computed expression: {:?}",
                        op
                    );
                    return self.create_optimized_out_placeholder(var_name);
                }
            }
        }

        // After processing all operations, the final result should be on the stack
        if stack.is_empty() {
            return Err(CodeGenError::DwarfError(
                "Empty stack after DWARF expression evaluation".to_string(),
            ));
        }

        let final_address = stack.pop().unwrap();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let result_ptr = self
            .builder
            .build_int_to_ptr(
                final_address,
                ptr_type,
                &format!("{}_computed_ptr", var_name),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        Ok(result_ptr)
    }

    /// Get register value from eBPF context
    fn get_register_value(
        &mut self,
        ctx_param: PointerValue<'ctx>,
        register: u16,
    ) -> Result<IntValue<'ctx>> {
        debug!("Getting value for register {}", register);

        // For x86_64 register mapping in eBPF context
        // This is a simplified mapping - real implementation would need complete register context
        let reg_offset = match register {
            0 => 0,                           // RAX
            1 => 8,                           // RDX
            2 => 16,                          // RCX
            3 => 24,                          // RBX
            4 => 32,                          // RSI
            5 => 40,                          // RDI
            6 => 48,                          // RBP
            7 => 56,                          // RSP
            8..=15 => (register - 8 + 8) * 8, // R8-R15
            _ => {
                warn!("Unknown register {}, using offset 0", register);
                0
            }
        };

        let i64_type = self.context.i64_type();
        let offset_value = i64_type.const_int(reg_offset.into(), false);

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

    /// Convert DWARF register number to pt_regs array index
    /// Using aya's pt_regs structure indices
    fn convert_dwarf_reg_to_pt_regs_index(&self, dwarf_reg: u16) -> usize {
        match dwarf_reg {
            // x86_64 DWARF register mappings to pt_regs indices
            0 => pt_regs_indices::RAX,  // RAX -> pt_regs[RAX]
            1 => pt_regs_indices::RCX,  // RCX -> pt_regs[RCX]
            2 => pt_regs_indices::RDX,  // RDX -> pt_regs[RDX]
            3 => pt_regs_indices::RBX,  // RBX -> pt_regs[RBX]
            4 => pt_regs_indices::RSP,  // RSP -> pt_regs[RSP]
            5 => pt_regs_indices::RBP,  // RBP -> pt_regs[RBP]
            6 => pt_regs_indices::RSI,  // RSI -> pt_regs[RSI]
            7 => pt_regs_indices::RDI,  // RDI -> pt_regs[RDI]
            8 => pt_regs_indices::R8,   // R8 -> pt_regs[R8]
            9 => pt_regs_indices::R9,   // R9 -> pt_regs[R9]
            10 => pt_regs_indices::R10, // R10 -> pt_regs[R10]
            11 => pt_regs_indices::R11, // R11 -> pt_regs[R11]
            12 => pt_regs_indices::R12, // R12 -> pt_regs[R12]
            13 => pt_regs_indices::R13, // R13 -> pt_regs[R13]
            14 => pt_regs_indices::R14, // R14 -> pt_regs[R14]
            15 => pt_regs_indices::R15, // R15 -> pt_regs[R15]
            16 => pt_regs_indices::RIP, // RIP -> pt_regs[RIP]
            _ => {
                warn!("Unknown DWARF register {}, defaulting to RAX", dwarf_reg);
                pt_regs_indices::RAX // Default to RAX
            }
        }
    }

    /// Determine VarType from DWARF type information
    fn determine_var_type_from_dwarf(&self, dwarf_type: &Option<DwarfType>) -> VarType {
        match dwarf_type {
            Some(DwarfType::BaseType { encoding, .. }) => {
                match encoding {
                    DwarfEncoding::Signed | DwarfEncoding::Unsigned => VarType::Int,
                    DwarfEncoding::Float => VarType::Int, // Treat as int for now
                    _ => VarType::Int,
                }
            }
            Some(DwarfType::PointerType { .. }) => VarType::Int, // Pointers as int
            _ => VarType::Int,                                   // Default to int for unknown types
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
        save_ir_path: Option<&str>,
    ) -> Result<&Module<'ctx>> {
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

            self.populate_variables_from_dwarf(&dwarf_variables, ctx_param, &used_variables)?;
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
        self.compile_with_function_name(program, "main", &program.statements, None, None)
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

    /// Send variable data using protocol format
    fn send_variable_data(&mut self, var_name: &str) -> Result<()> {
        // Validate variable exists
        self.validate_variable_access(var_name)?;

        let var_ptr = *self
            .variables
            .get(var_name)
            .ok_or_else(|| CodeGenError::VariableNotFound(var_name.to_string()))?;
        let var_type = self
            .var_types
            .get(var_name)
            .ok_or_else(|| CodeGenError::VariableNotFound(var_name.to_string()))?
            .clone();

        info!("Sending variable data: {} (type: {:?})", var_name, var_type);

        // Check if variable is optimized out and handle separately
        if *self.optimized_out_vars.get(var_name).unwrap_or(&false) {
            info!(
                "Variable '{}' is optimized out, sending OptimizedOut protocol message",
                var_name
            );
            // Get PC address for the variable (needed for size calculation)
            let pc_address = self.var_pc_addresses.get(var_name).copied().unwrap_or(0);
            self.build_and_send_optimized_out_message(var_name, &var_type, pc_address)
        } else {
            // Build protocol message for normal variables
            // Get PC address for the variable to calculate correct size
            let pc_address = self.var_pc_addresses.get(var_name).copied().unwrap_or(0);
            self.build_and_send_protocol_message(var_name, &var_type, var_ptr, pc_address)
        }
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
        let trace_id = i64_type.const_int(1, false); // Simple trace_id
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

        // trace_id (8 bytes) - simple sequential ID
        let trace_id = i64_type.const_int(consts::DEFAULT_TRACE_ID, false);
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

        // trace_id (8 bytes) - simple sequential ID
        let trace_id = i64_type.const_int(consts::DEFAULT_TRACE_ID, false);
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
                let analyzer = &*analyzer_ptr;
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
                let analyzer = &*analyzer_ptr;
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
}

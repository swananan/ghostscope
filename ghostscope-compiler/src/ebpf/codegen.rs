//! Code generation for instructions
//!
//! This module handles the conversion from statements to compiled instructions
//! and generates LLVM IR for individual instructions.

use super::context::{CodeGenError, EbpfContext, Result};
use crate::script::{Expr, PrintStatement, Program, Statement};
use aya_ebpf_bindings::bindings::bpf_func_id::BPF_FUNC_probe_read_user;
use ghostscope_protocol::trace_event::{
    BacktraceData, InstructionHeader, PrintComplexVariableData, PrintFormatData,
    PrintStringIndexData, PrintVariableIndexData, VariableStatus,
};
use ghostscope_protocol::{InstructionType, TraceContext, TypeKind};
use inkwell::values::{BasicValueEnum, IntValue, PointerValue};
use inkwell::AddressSpace;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Information about a variable in formatted print
#[derive(Debug, Clone)]
struct FormatVariableInfo {
    var_name: String,
    var_name_index: u16,
    type_encoding: TypeKind,
    data_size: usize,
    value_source: FormatValueSource,
}

/// Source of the value for a format variable
#[derive(Debug, Clone)]
enum FormatValueSource {
    Variable,       // Read from DWARF/register
    StringLiteral,  // String literal value handled via string table
    IntegerLiteral, // Integer literal value serialized directly
}

/// Source for complex formatted argument data
#[derive(Debug, Clone)]
enum ComplexArgSource {
    RuntimeRead {
        eval_result: ghostscope_dwarf::EvaluationResult,
        dwarf_type: ghostscope_dwarf::TypeInfo,
    },
    ImmediateBytes {
        bytes: Vec<u8>,
    },
    AddressValue {
        eval_result: ghostscope_dwarf::EvaluationResult,
    },
}

/// Argument descriptor for PrintComplexFormat
#[derive(Debug, Clone)]
struct ComplexArg {
    var_name_index: u16,
    type_index: u16,
    access_path: Vec<u8>,
    data_len: usize,
    source: ComplexArgSource,
}

impl<'ctx> EbpfContext<'ctx> {
    /// Determine if a TypeInfo qualifies as a "simple variable" for PrintVariableIndex
    /// Simple: base types (bool/int/float/char), enums (with base type 1/2/4/8), pointers;
    /// Complex: arrays, structs, unions, functions
    #[allow(clippy::only_used_in_recursion)]
    fn is_simple_typeinfo(&self, t: &ghostscope_dwarf::TypeInfo) -> bool {
        use ghostscope_dwarf::TypeInfo as TI;
        match t {
            TI::BaseType { size, .. } => matches!(*size, 1 | 2 | 4 | 8),
            TI::EnumType { base_type, .. } => {
                let sz = base_type.size();
                matches!(sz, 1 | 2 | 4 | 8)
            }
            TI::PointerType { .. } => true,
            TI::TypedefType {
                underlying_type, ..
            }
            | TI::QualifiedType {
                underlying_type, ..
            } => self.is_simple_typeinfo(underlying_type),
            _ => false,
        }
    }

    /// Compute read size for a given DWARF type.
    /// No fallback: if DWARF doesn't provide size for arrays, return 0 and let caller error out.
    #[allow(clippy::only_used_in_recursion)]
    fn compute_read_size_for_type(&self, t: &ghostscope_dwarf::TypeInfo) -> usize {
        use ghostscope_dwarf::TypeInfo as TI;
        match t {
            TI::ArrayType {
                element_type,
                element_count,
                total_size,
            } => {
                if let Some(ts) = total_size {
                    return *ts as usize;
                }
                let elem_size = element_type.size() as usize;
                if elem_size == 0 {
                    return 0;
                }
                if let Some(cnt) = element_count {
                    return elem_size * (*cnt as usize);
                }
                0
            }
            TI::TypedefType {
                underlying_type, ..
            }
            | TI::QualifiedType {
                underlying_type, ..
            } => self.compute_read_size_for_type(underlying_type),
            _ => t.size() as usize,
        }
    }

    /// Main entry point: compile program with staged transmission system
    pub fn compile_program_with_staged_transmission(
        &mut self,
        program: &Program,
        _variable_types: HashMap<String, TypeKind>,
    ) -> Result<TraceContext> {
        info!("Compiling program with staged transmission system");

        // Step 1: Send TraceEventHeader
        self.send_trace_event_header()?;
        info!("Sent TraceEventHeader");

        // Step 2: Send TraceEventMessage with dynamic trace_id
        let trace_id = self.current_trace_id.map(|id| id as u64).unwrap_or(0);
        self.send_trace_event_message(trace_id)?;
        info!("Sent TraceEventMessage");

        // Reset per-event execution status flags
        self.store_flag_value("_gs_any_fail", 0)?;
        self.store_flag_value("_gs_any_success", 0)?;

        // Step 3: Process each statement and generate LLVM IR on-demand
        let mut instruction_count = 0u16;
        for statement in &program.statements {
            instruction_count += self.compile_statement(statement)?;
        }

        // Step 4: Send EndInstruction to mark completion
        self.send_end_instruction(instruction_count)?;
        info!(
            "Sent EndInstruction with {} total instructions",
            instruction_count
        );

        // Step 5: Return the trace context for user-space parsing
        Ok(self.trace_context.clone())
    }

    /// Compile a statement and return the number of instructions generated
    pub fn compile_statement(&mut self, statement: &Statement) -> Result<u16> {
        debug!("Compiling statement: {:?}", statement);

        match statement {
            Statement::VarDeclaration { name, value } => {
                info!("Processing variable declaration: {} = {:?}", name, value);
                // Compile the value expression and store in variable
                let compiled_value = self.compile_expr(value)?;
                self.store_variable(name, compiled_value)?;
                Ok(0) // VarDeclaration doesn't generate instructions
            }
            Statement::Print(print_stmt) => self.compile_print_statement(print_stmt),
            Statement::If {
                condition,
                then_body,
                else_body,
            } => {
                // Compile condition expression
                let cond_value = self.compile_expr(condition)?;

                // Convert condition to i1 (boolean) for branching
                let cond_bool = match cond_value {
                    BasicValueEnum::IntValue(int_val) => {
                        // Convert integer to boolean (non-zero = true)
                        self.builder
                            .build_int_compare(
                                inkwell::IntPredicate::NE,
                                int_val,
                                int_val.get_type().const_zero(),
                                "cond_bool",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!(
                                    "Failed to create condition: {}",
                                    e
                                ))
                            })?
                    }
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Condition must evaluate to integer".to_string(),
                        ));
                    }
                };

                // Get current function from builder
                let current_function = self
                    .builder
                    .get_insert_block()
                    .ok_or_else(|| CodeGenError::LLVMError("No current basic block".to_string()))?
                    .get_parent()
                    .ok_or_else(|| CodeGenError::LLVMError("No parent function".to_string()))?;

                // Create basic blocks for then and else paths
                let then_block = self
                    .context
                    .append_basic_block(current_function, "then_block");
                let else_block = self
                    .context
                    .append_basic_block(current_function, "else_block");
                let merge_block = self
                    .context
                    .append_basic_block(current_function, "merge_block");

                // Branch based on condition
                self.builder
                    .build_conditional_branch(cond_bool, then_block, else_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to create branch: {}", e))
                    })?;

                // Build then block
                self.builder.position_at_end(then_block);
                let mut then_instructions = 0u16;
                for stmt in then_body {
                    then_instructions += self.compile_statement(stmt)?;
                }
                self.builder
                    .build_unconditional_branch(merge_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to branch to merge: {}", e))
                    })?;

                // Build else block
                self.builder.position_at_end(else_block);
                let mut else_instructions = 0u16;
                if let Some(else_stmt) = else_body {
                    else_instructions += self.compile_statement(else_stmt)?;
                }
                self.builder
                    .build_unconditional_branch(merge_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to branch to merge: {}", e))
                    })?;

                // Continue with merge block
                self.builder.position_at_end(merge_block);

                // Return the maximum instructions from either branch
                Ok(std::cmp::max(then_instructions, else_instructions))
            }
            Statement::Block(nested_statements) => {
                let mut total_instructions = 0u16;
                for stmt in nested_statements {
                    total_instructions += self.compile_statement(stmt)?;
                }
                Ok(total_instructions)
            }
            Statement::TracePoint { pattern: _, body } => {
                let mut total_instructions = 0u16;
                for stmt in body {
                    total_instructions += self.compile_statement(stmt)?;
                }
                Ok(total_instructions)
            }
            _ => {
                warn!("Unsupported statement type: {:?}", statement);
                Ok(0)
            }
        }
    }

    /// Compile print statement and generate LLVM IR on-demand
    pub fn compile_print_statement(&mut self, print_stmt: &PrintStatement) -> Result<u16> {
        info!("Compiling print statement: {:?}", print_stmt);

        match print_stmt {
            PrintStatement::String(s) => {
                info!("Processing string literal: {}", s);
                // 1. Add string to TraceContext
                let string_index = self.trace_context.add_string(s.to_string());
                // 2. Generate eBPF code for PrintStringIndex
                self.generate_print_string_index(string_index)?;
                Ok(1) // Generated 1 instruction
            }
            PrintStatement::Variable(var_name) => {
                info!("Processing variable: {}", var_name);
                // Resolve display name index and type encoding first
                let (var_name_index, type_encoding) =
                    self.resolve_variable_with_priority(var_name)?;

                // If DWARF type exists and is complex, route to complex path
                let is_complex = match self.query_dwarf_for_variable(var_name)? {
                    Some(v) => match v.dwarf_type {
                        Some(ref t) => !self.is_simple_typeinfo(t),
                        None => false,
                    },
                    None => false,
                };
                tracing::trace!(
                    var_name = %var_name,
                    var_name_index = var_name_index,
                    ?type_encoding,
                    is_complex,
                    "compile_print_statement: routing decision"
                );
                if is_complex {
                    // Use complex var pipeline for better formatting and correct sizing
                    let expr = crate::script::Expr::Variable(var_name.clone());
                    let n = self.process_complex_variable_print(&expr)?;
                    tracing::trace!(
                        var_name = %var_name,
                        instructions = n,
                        "compile_print_statement: complex variable emitted"
                    );
                    Ok(n)
                } else {
                    // Simple variable - use PrintVariableIndex with type_index
                    self.generate_print_variable_index(var_name_index, type_encoding, var_name)?;
                    tracing::trace!(
                        var_name = %var_name,
                        var_name_index = var_name_index,
                        ?type_encoding,
                        "compile_print_statement: simple variable emitted (PrintVariableIndex)"
                    );
                    Ok(1)
                }
            }
            PrintStatement::ComplexVariable(expr) => {
                info!("Processing complex variable: {:?}", expr);
                // Special-case address-of: print pointer value with type info
                if let crate::script::Expr::AddressOf(inner) = expr {
                    let var = self
                        .query_dwarf_for_complex_expr(inner)?
                        .ok_or_else(|| CodeGenError::VariableNotFound(format!("{:?}", inner)))?;
                    let inner_ty = var.dwarf_type.as_ref().ok_or_else(|| {
                        CodeGenError::DwarfError(
                            "Expression has no DWARF type information".to_string(),
                        )
                    })?;
                    let ptr_ty = ghostscope_dwarf::TypeInfo::PointerType {
                        target_type: Box::new(inner_ty.clone()),
                        size: 8,
                    };
                    let type_index = self.trace_context.add_type(ptr_ty);
                    let var_name_index = self.trace_context.add_variable_name("&expr".to_string());

                    let one_arg = vec![ComplexArg {
                        var_name_index,
                        type_index,
                        access_path: Vec::new(),
                        data_len: 8,
                        source: ComplexArgSource::AddressValue {
                            eval_result: var.evaluation_result.clone(),
                        },
                    }];
                    let fmt_idx = self.trace_context.add_string("{}".to_string());
                    self.generate_print_complex_format_instruction(fmt_idx, &one_arg)?;
                    tracing::trace!(
                        "compile_print_statement: address-of emitted via ComplexFormat"
                    );
                    return Ok(1);
                }
                let n = self.process_complex_variable_print(expr)?;
                tracing::trace!(
                    instructions = n,
                    "compile_print_statement: complex expr emitted"
                );
                Ok(n)
            }
            PrintStatement::Formatted { format, args } => {
                info!(
                    "Processing formatted print: '{}' with {} args",
                    format,
                    args.len()
                );
                self.compile_formatted_print(format, args)
            }
        }
    }

    /// Compile formatted print statement: collect all variable data and send as PrintFormat/PrintComplexFormat instruction
    fn compile_formatted_print(
        &mut self,
        format: &str,
        args: &[crate::script::ast::Expr],
    ) -> Result<u16> {
        info!(
            "Compiling formatted print: '{}' with {} arguments",
            format,
            args.len()
        );

        // 1. Add format string to TraceContext
        let format_string_index = self.trace_context.add_string(format.to_string());
        info!(
            "Added format string to TraceContext at index {}",
            format_string_index
        );

        // 2. Decide path:
        //    - If any arg has a complex shape (MemberAccess/ArrayAccess/PointerDeref/ChainAccess/AddressOf),
        //      emit PrintComplexFormat.
        //    - Otherwise, only use complex path when a DWARF variable is not a simple base/pointer type.
        //      Simple DWARF variables (including register or computed values) can go through the fast path
        //      which evaluates values directly (no memory address needed).
        let has_complex_shape = args.iter().any(|arg| {
            matches!(
                arg,
                crate::script::ast::Expr::MemberAccess(_, _)
                    | crate::script::ast::Expr::ArrayAccess(_, _)
                    | crate::script::ast::Expr::PointerDeref(_)
                    | crate::script::ast::Expr::ChainAccess(_)
                    | crate::script::ast::Expr::AddressOf(_)
            )
        });
        // Refined check for DWARF-backed variables: only mark complex if the DWARF type
        // itself is complex (arrays/structs/unions/func). Base/enums/pointers are simple.
        let has_complex_dwarf_var = if !has_complex_shape {
            let mut complex = false;
            for arg in args.iter() {
                if let crate::script::ast::Expr::Variable(name) = arg {
                    if !self.variable_exists(name) {
                        if let Some(v) = self.query_dwarf_for_variable(name)? {
                            if let Some(ref t) = v.dwarf_type {
                                if !self.is_simple_typeinfo(t) {
                                    complex = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            complex
        } else {
            false
        };

        let use_complex = has_complex_shape || has_complex_dwarf_var;

        if !use_complex {
            // Simple fast path: variables + literals via PrintFormat
            let mut variable_infos = Vec::new();
            for (i, arg) in args.iter().enumerate() {
                match arg {
                    crate::script::ast::Expr::Variable(var_name) => {
                        info!("Processing argument {}: variable '{}'", i, var_name);
                        let (var_name_index, type_encoding) =
                            self.resolve_variable_with_priority(var_name)?;
                        let data_size = self.get_type_size(type_encoding);
                        variable_infos.push(FormatVariableInfo {
                            var_name: var_name.clone(),
                            var_name_index,
                            type_encoding,
                            data_size,
                            value_source: FormatValueSource::Variable,
                        });
                    }
                    crate::script::ast::Expr::String(s) => {
                        info!("Processing argument {}: string literal '{}'", i, s);
                        let var_name = format!("__str_literal_{}", i);
                        let var_name_index = self.trace_context.add_variable_name(var_name.clone());
                        variable_infos.push(FormatVariableInfo {
                            var_name,
                            var_name_index,
                            type_encoding: TypeKind::CString,
                            data_size: s.len() + 1,
                            value_source: FormatValueSource::StringLiteral,
                        });
                    }
                    crate::script::ast::Expr::Int(_) => {
                        info!("Processing argument {}: integer literal", i);
                        let var_name = format!("__int_literal_{}", i);
                        let var_name_index = self.trace_context.add_variable_name(var_name.clone());
                        variable_infos.push(FormatVariableInfo {
                            var_name,
                            var_name_index,
                            type_encoding: TypeKind::I64,
                            data_size: 8,
                            value_source: FormatValueSource::IntegerLiteral,
                        });
                    }
                    other => {
                        return Err(CodeGenError::NotImplemented(format!(
                            "Expression type {:?} not supported in formatted print",
                            other
                        )));
                    }
                }
            }
            self.generate_print_format_instruction(format_string_index, &variable_infos)?;
            return Ok(1);
        }

        // Complex path: build PrintComplexFormat with DWARF-resolved arguments (and embed literals)
        let mut complex_args: Vec<ComplexArg> = Vec::with_capacity(args.len());
        for (i, arg) in args.iter().enumerate() {
            match arg {
                crate::script::ast::Expr::String(s) => {
                    // Treat as char array type with immediate bytes
                    let var_name = format!("__str_literal_{}", i);
                    let var_name_index = self.trace_context.add_variable_name(var_name);
                    let mut bytes = s.as_bytes().to_vec();
                    bytes.push(0); // null-terminate like C string
                    let char_type = ghostscope_dwarf::TypeInfo::BaseType {
                        name: "char".to_string(),
                        size: 1,
                        encoding: ghostscope_dwarf::constants::DW_ATE_unsigned_char.0 as u16,
                    };
                    let array_type = ghostscope_dwarf::TypeInfo::ArrayType {
                        element_type: Box::new(char_type),
                        element_count: Some(bytes.len() as u64),
                        total_size: Some(bytes.len() as u64),
                    };
                    let type_index = self.trace_context.add_type(array_type.clone());
                    complex_args.push(ComplexArg {
                        var_name_index,
                        type_index,
                        access_path: Vec::new(),
                        data_len: bytes.len(),
                        source: ComplexArgSource::ImmediateBytes { bytes },
                    });
                }
                crate::script::ast::Expr::Int(v) => {
                    // Treat as i64 base type with immediate bytes
                    let var_name = format!("__int_literal_{}", i);
                    let var_name_index = self.trace_context.add_variable_name(var_name);
                    let mut bytes = Vec::with_capacity(8);
                    bytes.extend_from_slice(&(*v).to_le_bytes());
                    let int_type = ghostscope_dwarf::TypeInfo::BaseType {
                        name: "i64".to_string(),
                        size: 8,
                        encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
                    };
                    let type_index = self.trace_context.add_type(int_type.clone());
                    complex_args.push(ComplexArg {
                        var_name_index,
                        type_index,
                        access_path: Vec::new(),
                        data_len: 8,
                        source: ComplexArgSource::ImmediateBytes { bytes },
                    });
                }
                // Variables and complex expressions -> resolve via DWARF
                expr @ (crate::script::ast::Expr::Variable(_)
                | crate::script::ast::Expr::MemberAccess(_, _)
                | crate::script::ast::Expr::ArrayAccess(_, _)
                | crate::script::ast::Expr::PointerDeref(_)
                | crate::script::ast::Expr::ChainAccess(_)) => {
                    let var = self
                        .query_dwarf_for_complex_expr(expr)?
                        .ok_or_else(|| CodeGenError::VariableNotFound(format!("{:?}", expr)))?;
                    let dwarf_type = var.dwarf_type.as_ref().ok_or_else(|| {
                        CodeGenError::DwarfError(
                            "Expression has no DWARF type information".to_string(),
                        )
                    })?;
                    let var_name_index = self.trace_context.add_variable_name(var.name.clone());
                    let type_index = self.trace_context.add_type(dwarf_type.clone());
                    let mut data_len = self.compute_read_size_for_type(dwarf_type);
                    if data_len == 0 {
                        return Err(CodeGenError::TypeSizeNotAvailable(var.name));
                    }
                    // Avoid over-reading: cap upper bound only.
                    data_len = std::cmp::min(data_len, 1993);
                    complex_args.push(ComplexArg {
                        var_name_index,
                        type_index,
                        access_path: Vec::new(), // The raw data already points to the final member
                        data_len,
                        source: ComplexArgSource::RuntimeRead {
                            eval_result: var.evaluation_result.clone(),
                            dwarf_type: dwarf_type.clone(),
                        },
                    });
                }
                crate::script::ast::Expr::AddressOf(inner) => {
                    let var = self
                        .query_dwarf_for_complex_expr(inner)?
                        .ok_or_else(|| CodeGenError::VariableNotFound(format!("{:?}", inner)))?;
                    let inner_ty = var.dwarf_type.as_ref().ok_or_else(|| {
                        CodeGenError::DwarfError(
                            "Expression has no DWARF type information".to_string(),
                        )
                    })?;
                    let ptr_ty = ghostscope_dwarf::TypeInfo::PointerType {
                        target_type: Box::new(inner_ty.clone()),
                        size: 8,
                    };
                    let type_index = self.trace_context.add_type(ptr_ty);

                    complex_args.push(ComplexArg {
                        var_name_index: self.trace_context.add_variable_name("&expr".to_string()),
                        type_index,
                        access_path: Vec::new(),
                        data_len: 8,
                        source: ComplexArgSource::AddressValue {
                            eval_result: var.evaluation_result.clone(),
                        },
                    });
                }
                other => {
                    return Err(CodeGenError::NotImplemented(format!(
                        "Expression type {:?} not supported in formatted print",
                        other
                    )));
                }
            }
        }

        self.generate_print_complex_format_instruction(format_string_index, &complex_args)?;
        Ok(1)
    }

    /// Get the size in bytes for a given type encoding
    fn get_type_size(&self, type_encoding: TypeKind) -> usize {
        match type_encoding {
            TypeKind::U8 | TypeKind::I8 | TypeKind::Bool | TypeKind::Char => 1,
            TypeKind::U16 | TypeKind::I16 => 2,
            TypeKind::U32 | TypeKind::I32 | TypeKind::F32 => 4,
            TypeKind::U64 | TypeKind::I64 | TypeKind::F64 | TypeKind::Pointer => 8,
            TypeKind::CString | TypeKind::String => 256, // Default string buffer size
            _ => {
                warn!("Unknown type size for {:?}, using 8 bytes", type_encoding);
                8
            }
        }
    }

    /// Resolve variable with correct priority: script variables first, then DWARF variables
    /// This method is copied from protocol.rs to maintain functionality
    pub fn resolve_variable_with_priority(&mut self, var_name: &str) -> Result<(u16, TypeKind)> {
        info!("Resolving variable '{}' with correct priority", var_name);

        // Step 1: Check if it's a script-defined variable first
        if self.variable_exists(var_name) {
            info!("Found script variable: {}", var_name);

            // Get the variable's LLVM value to infer type
            let loaded_value = self.load_variable(var_name)?;
            let type_encoding = self.infer_type_from_llvm_value(&loaded_value);

            // Add to TraceContext
            let var_name_index = self.trace_context.add_variable_name(var_name.to_string());

            return Ok((var_name_index, type_encoding));
        }

        // Step 2: If not found in script variables, try DWARF variables
        info!(
            "Variable '{}' not found in script variables, checking DWARF",
            var_name
        );

        let compile_context = self.get_compile_time_context()?.clone();
        let variable_with_eval = match self.query_dwarf_for_variable(var_name)? {
            Some(var) => var,
            None => {
                return Err(CodeGenError::VariableNotFound(format!(
                    "Variable '{}' not found in script or DWARF at PC 0x{:x} in module '{}'",
                    var_name, compile_context.pc_address, compile_context.module_path
                )));
            }
        };

        // Convert DWARF type information to TypeKind using existing method
        let dwarf_type = variable_with_eval.dwarf_type.as_ref().ok_or_else(|| {
            CodeGenError::DwarfError("Variable has no DWARF type information".to_string())
        })?;
        let type_encoding = TypeKind::from(dwarf_type);

        // Add to StringTable
        let var_name_index = self.trace_context.add_variable_name(var_name.to_string());

        info!(
            "DWARF variable '{}' resolved successfully with type: {:?}",
            var_name, type_encoding
        );

        Ok((var_name_index, type_encoding))
    }

    /// Synthesize a DWARF-like TypeInfo for a basic TypeKind (for script variables)
    fn synthesize_typeinfo_for_typekind(&self, kind: TypeKind) -> ghostscope_dwarf::TypeInfo {
        use ghostscope_dwarf::constants::{
            DW_ATE_boolean, DW_ATE_float, DW_ATE_signed, DW_ATE_signed_char, DW_ATE_unsigned,
        };
        use ghostscope_dwarf::TypeInfo as TI;

        match kind {
            TypeKind::Bool => TI::BaseType {
                name: "bool".to_string(),
                size: 1,
                encoding: DW_ATE_boolean.0 as u16,
            },
            TypeKind::F32 => TI::BaseType {
                name: "f32".to_string(),
                size: 4,
                encoding: DW_ATE_float.0 as u16,
            },
            TypeKind::F64 => TI::BaseType {
                name: "f64".to_string(),
                size: 8,
                encoding: DW_ATE_float.0 as u16,
            },
            TypeKind::I8 => TI::BaseType {
                name: "i8".to_string(),
                size: 1,
                encoding: DW_ATE_signed_char.0 as u16,
            },
            TypeKind::I16 => TI::BaseType {
                name: "i16".to_string(),
                size: 2,
                encoding: DW_ATE_signed.0 as u16,
            },
            TypeKind::I32 => TI::BaseType {
                name: "i32".to_string(),
                size: 4,
                encoding: DW_ATE_signed.0 as u16,
            },
            TypeKind::I64 => TI::BaseType {
                name: "i64".to_string(),
                size: 8,
                encoding: DW_ATE_signed.0 as u16,
            },
            TypeKind::U8 | TypeKind::Char => TI::BaseType {
                name: "u8".to_string(),
                size: 1,
                encoding: DW_ATE_unsigned.0 as u16,
            },
            TypeKind::U16 => TI::BaseType {
                name: "u16".to_string(),
                size: 2,
                encoding: DW_ATE_unsigned.0 as u16,
            },
            TypeKind::U32 => TI::BaseType {
                name: "u32".to_string(),
                size: 4,
                encoding: DW_ATE_unsigned.0 as u16,
            },
            TypeKind::U64 => TI::BaseType {
                name: "u64".to_string(),
                size: 8,
                encoding: DW_ATE_unsigned.0 as u16,
            },
            TypeKind::Pointer | TypeKind::CString | TypeKind::String | TypeKind::Unknown => {
                // Use void* as a reasonable default for pointers/strings in script land
                TI::PointerType {
                    target_type: Box::new(TI::UnknownType {
                        name: "void".to_string(),
                    }),
                    size: 8,
                }
            }
            TypeKind::NullPointer => TI::PointerType {
                target_type: Box::new(TI::UnknownType {
                    name: "void".to_string(),
                }),
                size: 8,
            },
            _ => TI::BaseType {
                name: "i64".to_string(),
                size: 8,
                encoding: DW_ATE_signed.0 as u16,
            },
        }
    }

    fn add_synthesized_type_index_for_kind(&mut self, kind: TypeKind) -> u16 {
        let ti = self.synthesize_typeinfo_for_typekind(kind);
        self.trace_context.add_type(ti)
    }

    /// Infer TypeKind from LLVM value type
    /// Copied from protocol.rs
    fn infer_type_from_llvm_value(&self, value: &BasicValueEnum<'_>) -> TypeKind {
        match value {
            BasicValueEnum::IntValue(int_val) => {
                match int_val.get_type().get_bit_width() {
                    1 => TypeKind::Bool,
                    8 => TypeKind::I8, // Default to signed for script variables
                    16 => TypeKind::I16,
                    32 => TypeKind::I32,
                    64 => TypeKind::I64,
                    _ => TypeKind::I64, // Default fallback
                }
            }
            BasicValueEnum::FloatValue(float_val) => {
                match float_val.get_type() {
                    t if t == self.context.f32_type() => TypeKind::F32,
                    t if t == self.context.f64_type() => TypeKind::F64,
                    _ => TypeKind::F64, // Default fallback
                }
            }
            BasicValueEnum::PointerValue(_) => TypeKind::Pointer,
            _ => TypeKind::I64, // Conservative default
        }
    }

    /// Generate eBPF code for PrintFormat instruction (true single instruction implementation)
    fn generate_print_format_instruction(
        &mut self,
        format_string_index: u16,
        variable_infos: &[FormatVariableInfo],
    ) -> Result<()> {
        info!(
            "Generating true single PrintFormat instruction: format_index={}, {} variables",
            format_string_index,
            variable_infos.len()
        );

        // Calculate total instruction size:
        // InstructionHeader + PrintFormatData + variable data
        let mut total_variable_data_size = 0;
        for var_info in variable_infos {
            if let FormatValueSource::Variable = &var_info.value_source {
                // Each variable header is 8 bytes:
                //   var_name_index(2) + type_encoding(1) + type_index(2) + status(1) + data_len(2)
                // Then followed by `data_len` bytes of data
                total_variable_data_size += 8 + var_info.data_size;
            }
        }

        let instruction_data_size =
            std::mem::size_of::<PrintFormatData>() + total_variable_data_size;
        let total_instruction_size =
            std::mem::size_of::<InstructionHeader>() + instruction_data_size;

        info!(
            "PrintFormat instruction size: {} bytes (header: {}, data: {}, variables: {})",
            total_instruction_size,
            std::mem::size_of::<InstructionHeader>(),
            std::mem::size_of::<PrintFormatData>(),
            total_variable_data_size
        );

        // Allocate buffer using existing method
        let buffer = self.create_instruction_buffer();

        // Clear the buffer
        let buffer_size = self
            .context
            .i64_type()
            .const_int(total_instruction_size as u64, false);
        self.builder
            .build_memset(
                buffer,
                std::mem::align_of::<InstructionHeader>() as u32,
                self.context.i8_type().const_zero(),
                buffer_size,
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to clear buffer: {}", e)))?;

        // Write InstructionHeader
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintFormat as u64, false);
        self.builder
            .build_store(buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {}", e)))?;

        // data_length at offset 1
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(1, false)],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {}", e))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(inkwell::AddressSpace::default()),
                "data_length_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast data_length pointer: {}", e))
            })?;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(instruction_data_size as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {}", e)))?;

        // Write PrintFormatData at offset 4 (after InstructionHeader)
        let format_data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(4, false)],
                    "format_data_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get format_data GEP: {}", e))
                })?
        };

        // format_string_index at offset 0 within PrintFormatData
        let format_string_index_ptr = self
            .builder
            .build_pointer_cast(
                format_data_ptr,
                self.context.ptr_type(inkwell::AddressSpace::default()),
                "format_string_index_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!(
                    "Failed to cast format_string_index pointer: {}",
                    e
                ))
            })?;
        let format_index_val = self
            .context
            .i16_type()
            .const_int(format_string_index as u64, false);
        self.builder
            .build_store(format_string_index_ptr, format_index_val)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store format_string_index: {}", e))
            })?;

        // arg_count at offset 2 within PrintFormatData
        let arg_count_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    format_data_ptr,
                    &[self.context.i32_type().const_int(2, false)],
                    "arg_count_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get arg_count GEP: {}", e))
                })?
        };

        // Only count actual variables, not string/integer literals
        let actual_var_count = variable_infos
            .iter()
            .filter(|vi| matches!(vi.value_source, FormatValueSource::Variable))
            .count();
        let arg_count_val = self
            .context
            .i8_type()
            .const_int(actual_var_count as u64, false);
        self.builder
            .build_store(arg_count_ptr, arg_count_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store arg_count: {}", e)))?;

        // reserved field at offset 3 (set to 0)
        let reserved_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    format_data_ptr,
                    &[self.context.i32_type().const_int(3, false)],
                    "reserved_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get reserved GEP: {}", e))
                })?
        };
        let reserved_val = self.context.i8_type().const_int(0, false);
        self.builder
            .build_store(reserved_ptr, reserved_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store reserved: {}", e)))?;

        // Write variable data starting after PrintFormatData
        let mut current_offset = 4 + std::mem::size_of::<PrintFormatData>();
        for var_info in variable_infos {
            if let FormatValueSource::Variable = &var_info.value_source {
                info!(
                    "Writing variable '{}' at offset {}",
                    var_info.var_name, current_offset
                );

                // Resolve type index: prefer DWARF when available, else synthesize for script vars
                let type_index = match self.query_dwarf_for_variable(&var_info.var_name)? {
                    Some(v) => match v.dwarf_type {
                        Some(ref t) => self.trace_context.add_type(t.clone()),
                        None => {
                            return Err(CodeGenError::DwarfError(format!(
                                "Variable '{}' missing DWARF type for formatted print",
                                var_info.var_name
                            )));
                        }
                    },
                    None => {
                        if self.variable_exists(&var_info.var_name) {
                            self.add_synthesized_type_index_for_kind(var_info.type_encoding)
                        } else {
                            return Err(CodeGenError::VariableNotFound(format!(
                                "Variable '{}' not found for formatted print",
                                var_info.var_name
                            )));
                        }
                    }
                };

                // Write variable header: [var_name_index:u16, type_encoding:u8, type_index:u16, data_len:u16]
                let var_header_ptr = unsafe {
                    self.builder
                        .build_gep(
                            self.context.i8_type(),
                            buffer,
                            &[self
                                .context
                                .i32_type()
                                .const_int(current_offset as u64, false)],
                            "var_header_ptr",
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to get var_header GEP: {}", e))
                        })?
                };

                // var_name_index at offset 0
                let var_name_index_ptr = self
                    .builder
                    .build_pointer_cast(
                        var_header_ptr,
                        self.context.ptr_type(inkwell::AddressSpace::default()),
                        "var_name_index_ptr",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!(
                            "Failed to cast var_name_index pointer: {}",
                            e
                        ))
                    })?;
                let var_name_index_val = self
                    .context
                    .i16_type()
                    .const_int(var_info.var_name_index as u64, false);
                self.builder
                    .build_store(var_name_index_ptr, var_name_index_val)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store var_name_index: {}", e))
                    })?;

                // type_encoding at offset 2
                let type_encoding_ptr = unsafe {
                    self.builder
                        .build_gep(
                            self.context.i8_type(),
                            var_header_ptr,
                            &[self.context.i32_type().const_int(2, false)],
                            "type_encoding_ptr",
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!(
                                "Failed to get type_encoding GEP: {}",
                                e
                            ))
                        })?
                };
                let type_encoding_val = self
                    .context
                    .i8_type()
                    .const_int(var_info.type_encoding as u8 as u64, false);
                self.builder
                    .build_store(type_encoding_ptr, type_encoding_val)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store type_encoding: {}", e))
                    })?;

                // data_len at offset 3..4
                let data_len_ptr = unsafe {
                    self.builder
                        .build_gep(
                            self.context.i8_type(),
                            var_header_ptr,
                            &[self.context.i32_type().const_int(3, false)],
                            "data_len_ptr",
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to get data_len GEP: {}", e))
                        })?
                };
                let data_len_i16_ptr = self
                    .builder
                    .build_pointer_cast(
                        data_len_ptr,
                        self.context.ptr_type(AddressSpace::default()),
                        "data_len_i16_ptr",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to cast data_len ptr: {}", e))
                    })?;
                let data_len_val = self
                    .context
                    .i16_type()
                    .const_int(var_info.data_size as u64, false);
                self.builder
                    .build_store(data_len_i16_ptr, data_len_val)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store data_len: {}", e))
                    })?;

                // type_index at offset 5..6
                let type_index_ptr = unsafe {
                    self.builder
                        .build_gep(
                            self.context.i8_type(),
                            var_header_ptr,
                            &[self.context.i32_type().const_int(5, false)],
                            "type_index_ptr",
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to get type_index GEP: {}", e))
                        })?
                };
                let type_index_i16_ptr = self
                    .builder
                    .build_pointer_cast(
                        type_index_ptr,
                        self.context.ptr_type(AddressSpace::default()),
                        "type_index_i16_ptr",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to cast type_index ptr: {}", e))
                    })?;
                let type_index_val = self.context.i16_type().const_int(type_index as u64, false);
                self.builder
                    .build_store(type_index_i16_ptr, type_index_val)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store type_index: {}", e))
                    })?;

                // status at offset 7
                let status_ptr = unsafe {
                    self.builder
                        .build_gep(
                            self.context.i8_type(),
                            var_header_ptr,
                            &[self.context.i32_type().const_int(7, false)],
                            "status_ptr",
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to get status GEP: {}", e))
                        })?
                };
                self.builder
                    .build_store(status_ptr, self.context.i8_type().const_int(0, false))
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store status: {}", e))
                    })?;

                // Generate variable data reading at offset 8
                let var_data_ptr = unsafe {
                    self.builder
                        .build_gep(
                            self.context.i8_type(),
                            var_header_ptr,
                            &[self.context.i32_type().const_int(8, false)],
                            "var_data_ptr",
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to get var_data GEP: {}", e))
                        })?
                };

                // Read variable data using existing DWARF resolution logic
                match self.resolve_variable_value(&var_info.var_name, var_info.type_encoding) {
                    Ok(var_data) => {
                        // Store the resolved variable data
                        self.store_variable_data(
                            var_data_ptr,
                            var_data,
                            var_info.type_encoding,
                            var_info.data_size,
                        )?;
                    }
                    Err(e) => {
                        info!(
                            "Variable '{}' read failed: {}, skipping data",
                            var_info.var_name, e
                        );
                        // For failed reads, we could either skip or fill with error marker
                        // For now, we'll fill with zeros
                        let zero_size = self
                            .context
                            .i64_type()
                            .const_int(var_info.data_size as u64, false);
                        self.builder
                            .build_memset(
                                var_data_ptr,
                                1,
                                self.context.i8_type().const_zero(),
                                zero_size,
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!(
                                    "Failed to zero variable data: {}",
                                    e
                                ))
                            })?;
                    }
                }

                current_offset += 8 + var_info.data_size;
            }
        }

        // Send the complete instruction via ringbuf using existing method
        self.create_ringbuf_output(buffer, total_instruction_size as u64)?;

        info!(
            "Successfully generated true single PrintFormat instruction with {} variables",
            actual_var_count
        );
        Ok(())
    }

    /// Generate eBPF code for PrintComplexFormat instruction with runtime reads for variables
    fn generate_print_complex_format_instruction(
        &mut self,
        format_string_index: u16,
        complex_args: &[ComplexArg],
    ) -> Result<()> {
        use ghostscope_protocol::trace_event::PrintComplexFormatData;
        use InstructionType::PrintComplexFormat as IT;

        // Calculate total size (reserve worst-case payload per-arg to avoid overflow)
        let mut total_args_payload = 0usize;
        let mut arg_count = 0u8;
        for a in complex_args.iter() {
            // Header bytes per-arg: var_name_index(2) + type_index(2) + status(1) + access_path_len(1) + access_path + data_len(2)
            let header_len = 2 + 2 + 1 + 1 + a.access_path.len() + 2;
            // Reserve payload bytes: for runtime reads, failures may carry errno(4)+addr(8) = 12 bytes
            let reserved_payload = match &a.source {
                ComplexArgSource::ImmediateBytes { bytes } => bytes.len(),
                ComplexArgSource::AddressValue { .. } => 8,
                ComplexArgSource::RuntimeRead { .. } => std::cmp::max(a.data_len, 12),
            };
            total_args_payload += header_len + reserved_payload;
            arg_count = arg_count.saturating_add(1);
        }
        let inst_data_size = std::mem::size_of::<PrintComplexFormatData>() + total_args_payload;
        let total_size = std::mem::size_of::<InstructionHeader>() + inst_data_size;

        // Allocate buffer
        let buffer = self.create_instruction_buffer();

        // Clear buffer
        let total_size_val = self.context.i64_type().const_int(total_size as u64, false);
        self.builder
            .build_memset(
                buffer,
                std::mem::align_of::<InstructionHeader>() as u32,
                self.context.i8_type().const_zero(),
                total_size_val,
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to clear buffer: {}", e)))?;

        // Write InstructionHeader
        let inst_type_val = self.context.i8_type().const_int(IT as u8 as u64, false);
        self.builder
            .build_store(buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {}", e)))?;
        // data_length at +1
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(1, false)],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {}", e))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {}", e))
            })?;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(inst_data_size as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {}", e)))?;

        // Write PrintComplexFormatData at offset 4
        let data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(4, false)],
                    "pcf_data_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get pcf_data_ptr GEP: {}", e))
                })?
        };

        // format_string_index (u16) at +0
        let fsi_ptr = self
            .builder
            .build_pointer_cast(
                data_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "fsi_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast fsi_ptr: {}", e)))?;
        let fsi_val = self
            .context
            .i16_type()
            .const_int(format_string_index as u64, false);
        self.builder
            .build_store(fsi_ptr, fsi_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store fsi: {}", e)))?;
        // arg_count (u8) at +2
        let arg_cnt_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(2, false)],
                    "arg_count_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get arg_count GEP: {}", e))
                })?
        };
        self.builder
            .build_store(
                arg_cnt_ptr,
                self.context.i8_type().const_int(arg_count as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store arg_count: {}", e)))?;

        // Start of variable payload after PrintComplexFormatData — use compile-time offsets with reserved payload
        let mut offset = std::mem::size_of::<PrintComplexFormatData>();
        for a in complex_args.iter() {
            // Per-arg reserved payload length
            let reserved_len = match &a.source {
                ComplexArgSource::ImmediateBytes { bytes } => bytes.len(),
                ComplexArgSource::AddressValue { .. } => 8,
                ComplexArgSource::RuntimeRead { .. } => std::cmp::max(a.data_len, 12),
            };

            // Base pointer = data_ptr + offset
            let arg_base = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        data_ptr,
                        &[self.context.i32_type().const_int(offset as u64, false)],
                        "arg_base",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get arg_base GEP: {}", e))
                    })?
            };

            // var_name_index(u16) at +0
            let vni_cast = self
                .builder
                .build_pointer_cast(
                    arg_base,
                    self.context.ptr_type(AddressSpace::default()),
                    "vni_cast",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast vni ptr: {}", e)))?;
            self.builder
                .build_store(
                    vni_cast,
                    self.context
                        .i16_type()
                        .const_int(a.var_name_index as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store vni: {}", e)))?;

            // type_index(u16) at +2
            let ti_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self.context.i32_type().const_int(2, false)],
                        "ti_ptr",
                    )
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to get ti GEP: {}", e)))?
            };
            let ti_cast = self
                .builder
                .build_pointer_cast(
                    ti_ptr,
                    self.context.ptr_type(AddressSpace::default()),
                    "ti_cast",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast ti ptr: {}", e)))?;
            self.builder
                .build_store(
                    ti_cast,
                    self.context
                        .i16_type()
                        .const_int(a.type_index as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store ti: {}", e)))?;

            // status(u8) at +4
            let apl_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self.context.i32_type().const_int(4, false)],
                        "status_ptr",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get status GEP: {}", e))
                    })?
            };
            self.builder
                .build_store(apl_ptr, self.context.i8_type().const_int(0, false))
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {}", e)))?;

            // access_path_len(u8) at +5
            let apl_ptr2 = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self.context.i32_type().const_int(5, false)],
                        "apl_ptr",
                    )
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to get apl GEP: {}", e)))?
            };
            self.builder
                .build_store(
                    apl_ptr2,
                    self.context
                        .i8_type()
                        .const_int(a.access_path.len() as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store apl: {}", e)))?;

            // access_path bytes at +6..+6+len
            for (i, b) in a.access_path.iter().enumerate() {
                let byte_ptr = unsafe {
                    self.builder
                        .build_gep(
                            self.context.i8_type(),
                            arg_base,
                            &[self.context.i32_type().const_int((6 + i) as u64, false)],
                            &format!("ap_byte_{}", i),
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to get ap byte GEP: {}", e))
                        })?
                };
                self.builder
                    .build_store(byte_ptr, self.context.i8_type().const_int(*b as u64, false))
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store ap byte: {}", e))
                    })?;
            }

            // data_len(u16) at +6+path_len (store reserved_len to keep layout consistent)
            let dl_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self
                            .context
                            .i32_type()
                            .const_int((6 + a.access_path.len()) as u64, false)],
                        "dl_ptr",
                    )
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to get dl GEP: {}", e)))?
            };
            let dl_cast = self
                .builder
                .build_pointer_cast(
                    dl_ptr,
                    self.context.ptr_type(AddressSpace::default()),
                    "dl_cast",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast dl ptr: {}", e)))?;
            self.builder
                .build_store(
                    dl_cast,
                    self.context
                        .i16_type()
                        .const_int(reserved_len as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {}", e)))?;

            // variable data starts at +8+path_len
            let var_data_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        arg_base,
                        &[self
                            .context
                            .i32_type()
                            .const_int((8 + a.access_path.len()) as u64, false)],
                        "var_data_ptr",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get var_data GEP: {}", e))
                    })?
            };

            // No dynamic cursor; we keep a compile-time offset and use reserved_len for layout

            match &a.source {
                ComplexArgSource::ImmediateBytes { bytes, .. } => {
                    for (i, b) in bytes.iter().enumerate() {
                        let byte_ptr = unsafe {
                            self.builder
                                .build_gep(
                                    self.context.i8_type(),
                                    var_data_ptr,
                                    &[self.context.i32_type().const_int(i as u64, false)],
                                    &format!("var_byte_{}", i),
                                )
                                .map_err(|e| {
                                    CodeGenError::LLVMError(format!(
                                        "Failed to get var byte GEP: {}",
                                        e
                                    ))
                                })?
                        };
                        self.builder
                            .build_store(
                                byte_ptr,
                                self.context.i8_type().const_int(*b as u64, false),
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to store var byte: {}", e))
                            })?;
                    }
                    // data_len already set to reserved_len
                }
                ComplexArgSource::RuntimeRead {
                    eval_result,
                    dwarf_type,
                } => {
                    // Read from user memory at runtime via BPF helper
                    let ptr_type = self.context.ptr_type(AddressSpace::default());
                    let i32_type = self.context.i32_type();
                    let i64_type = self.context.i64_type();
                    let dst_ptr = self
                        .builder
                        .build_bit_cast(var_data_ptr, ptr_type, "dst_ptr")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let size_val = i32_type.const_int(a.data_len as u64, false);
                    let src_addr = self.evaluation_result_to_address(eval_result)?;
                    let src_ptr = self
                        .builder
                        .build_int_to_ptr(src_addr, ptr_type, "src_ptr")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // status_ptr was stored in apl_ptr earlier (we named it status_ptr)
                    // Build NULL check
                    let zero64 = i64_type.const_zero();
                    let is_null = self
                        .builder
                        .build_int_compare(inkwell::IntPredicate::EQ, src_addr, zero64, "is_null")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let current_fn = self
                        .builder
                        .get_insert_block()
                        .unwrap()
                        .get_parent()
                        .unwrap();
                    let null_block = self.context.append_basic_block(current_fn, "null_deref");
                    let read_block = self.context.append_basic_block(current_fn, "read_user");
                    let cont2_block = self.context.append_basic_block(current_fn, "after_read");
                    self.builder
                        .build_conditional_branch(is_null, null_block, read_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // NULL path: status=1, keep reserved_len in header, no data write (buffer pre-zeroed)
                    self.builder.position_at_end(null_block);
                    self.builder
                        .build_store(
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::NullDeref as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.mark_any_fail()?;
                    self.builder
                        .build_unconditional_branch(cont2_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Read path
                    self.builder.position_at_end(read_block);
                    let ret = self
                        .create_bpf_helper_call(
                            BPF_FUNC_probe_read_user as u64,
                            &[dst_ptr, size_val.into(), src_ptr.into()],
                            i32_type.into(),
                            "probe_read_user",
                        )?
                        .into_int_value();
                    let is_err = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::SLT,
                            ret,
                            i32_type.const_zero(),
                            "ret_lt_zero",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let err_block = self.context.append_basic_block(current_fn, "read_err");
                    let ok_block = self.context.append_basic_block(current_fn, "read_ok");
                    self.builder
                        .build_conditional_branch(is_err, err_block, ok_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Error branch: status=2 (read_user failed); write errno+addr payload at start; header keeps reserved_len
                    self.builder.position_at_end(err_block);
                    self.builder
                        .build_store(
                            apl_ptr,
                            self.context
                                .i8_type()
                                .const_int(VariableStatus::ReadError as u64, false),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // write errno at [0..4]
                    let i32_ptr = self
                        .builder
                        .build_pointer_cast(
                            var_data_ptr,
                            self.context.ptr_type(AddressSpace::default()),
                            "errno_ptr",
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to cast errno ptr: {}", e))
                        })?;
                    self.builder.build_store(i32_ptr, ret).map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store errno: {}", e))
                    })?;
                    // write addr at [4..12]
                    let addr_ptr_i8 = unsafe {
                        self.builder
                            .build_gep(
                                self.context.i8_type(),
                                var_data_ptr,
                                &[i32_type.const_int(4, false)],
                                "addr_ptr_i8",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to get addr gep: {}", e))
                            })?
                    };
                    let addr_ptr = self
                        .builder
                        .build_pointer_cast(
                            addr_ptr_i8,
                            self.context.ptr_type(AddressSpace::default()),
                            "addr_ptr",
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to cast addr ptr: {}", e))
                        })?;
                    let src_as_i64 = src_addr;
                    self.builder
                        .build_store(addr_ptr, src_as_i64)
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store addr: {}", e))
                        })?;
                    self.mark_any_fail()?;
                    self.builder
                        .build_unconditional_branch(cont2_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // OK branch: success or truncated (header keeps reserved_len)
                    self.builder.position_at_end(ok_block);
                    if a.data_len < dwarf_type.size() as usize {
                        self.builder
                            .build_store(
                                apl_ptr,
                                self.context
                                    .i8_type()
                                    .const_int(VariableStatus::Truncated as u64, false),
                            )
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        self.mark_any_success()?;
                        self.mark_any_fail()?;
                    } else {
                        self.mark_any_success()?;
                    }
                    self.builder
                        .build_unconditional_branch(cont2_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    self.builder.position_at_end(cont2_block);
                }
                ComplexArgSource::AddressValue { eval_result } => {
                    // Compute address and store as 8 bytes
                    let addr = self.evaluation_result_to_address(eval_result)?;
                    let cast_ptr = self
                        .builder
                        .build_pointer_cast(
                            var_data_ptr,
                            self.context.ptr_type(AddressSpace::default()),
                            "addr_store_ptr",
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    self.builder
                        .build_store(cast_ptr, addr)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // header already set to reserved_len (8)
                }
            }
            // Advance compile-time offset by header_len + reserved_len
            offset += 2 + 2 + 1 + 1 + a.access_path.len() + 2 + reserved_len;
        }

        // Send via ringbuf (reserved size is sufficient for worst-case payload)
        self.create_ringbuf_output(buffer, total_size as u64)
            .map_err(|e| CodeGenError::LLVMError(format!("Ringbuf output failed: {}", e)))?;
        Ok(())
    }

    /// Store variable data at the specified pointer location
    fn store_variable_data(
        &mut self,
        var_data_ptr: PointerValue<'ctx>,
        var_data: BasicValueEnum<'ctx>,
        type_encoding: TypeKind,
        data_size: usize,
    ) -> Result<()> {
        match data_size {
            1 => {
                // Store as i8
                let truncated = match var_data {
                    BasicValueEnum::IntValue(int_val) => self
                        .builder
                        .build_int_truncate(int_val, self.context.i8_type(), "truncated_i8")
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to truncate to i8: {}", e))
                        })?,
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Expected integer value for integer type".to_string(),
                        ));
                    }
                };
                self.builder
                    .build_store(var_data_ptr, truncated)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store i8 data: {}", e))
                    })?;
            }
            2 => {
                // Store as i16
                let truncated = match var_data {
                    BasicValueEnum::IntValue(int_val) => self
                        .builder
                        .build_int_truncate(int_val, self.context.i16_type(), "truncated_i16")
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to truncate to i16: {}", e))
                        })?,
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Expected integer value for integer type".to_string(),
                        ));
                    }
                };
                let i16_ptr = self
                    .builder
                    .build_pointer_cast(
                        var_data_ptr,
                        self.context.ptr_type(AddressSpace::default()),
                        "i16_ptr",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to cast to i16 ptr: {}", e))
                    })?;
                self.builder.build_store(i16_ptr, truncated).map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to store i16 data: {}", e))
                })?;
            }
            4 => {
                // Store as i32 or f32
                match var_data {
                    BasicValueEnum::IntValue(int_val) => {
                        let truncated = self
                            .builder
                            .build_int_truncate(int_val, self.context.i32_type(), "truncated_i32")
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to truncate to i32: {}", e))
                            })?;
                        let i32_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "i32_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to i32 ptr: {}", e))
                            })?;
                        self.builder.build_store(i32_ptr, truncated).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store i32 data: {}", e))
                        })?;
                    }
                    BasicValueEnum::FloatValue(float_val) => {
                        let f32_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "f32_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to f32 ptr: {}", e))
                            })?;
                        self.builder.build_store(f32_ptr, float_val).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store f32 data: {}", e))
                        })?;
                    }
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Expected integer or float value for 4-byte type".to_string(),
                        ));
                    }
                }
            }
            8 => {
                // Store as i64, f64, or pointer
                match var_data {
                    BasicValueEnum::IntValue(int_val) => {
                        let i64_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "i64_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to i64 ptr: {}", e))
                            })?;
                        self.builder.build_store(i64_ptr, int_val).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store i64 data: {}", e))
                        })?;
                    }
                    BasicValueEnum::FloatValue(float_val) => {
                        let f64_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "f64_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to f64 ptr: {}", e))
                            })?;
                        self.builder.build_store(f64_ptr, float_val).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store f64 data: {}", e))
                        })?;
                    }
                    BasicValueEnum::PointerValue(ptr_val) => {
                        // Store pointer as u64
                        let ptr_int = self
                            .builder
                            .build_ptr_to_int(ptr_val, self.context.i64_type(), "ptr_as_int")
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!(
                                    "Failed to convert ptr to int: {}",
                                    e
                                ))
                            })?;
                        let i64_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "i64_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to i64 ptr: {}", e))
                            })?;
                        self.builder.build_store(i64_ptr, ptr_int).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store pointer data: {}", e))
                        })?;
                    }
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Expected integer, float, or pointer value for 8-byte type".to_string(),
                        ));
                    }
                }
            }
            _ => {
                // Handle string or other variable-length data
                match var_data {
                    BasicValueEnum::PointerValue(str_ptr) => {
                        // Copy string data byte by byte without using alloca (verifier-friendly)
                        let i8_type = self.context.i8_type();
                        let i32_type = self.context.i32_type();

                        // Get current function and create blocks
                        let current_function = self
                            .builder
                            .get_insert_block()
                            .ok_or_else(|| {
                                CodeGenError::LLVMError("No current basic block".to_string())
                            })?
                            .get_parent()
                            .ok_or_else(|| {
                                CodeGenError::LLVMError("No parent function".to_string())
                            })?;

                        let pre_block = self.builder.get_insert_block().ok_or_else(|| {
                            CodeGenError::LLVMError("No current basic block".to_string())
                        })?;
                        let check_block = self
                            .context
                            .append_basic_block(current_function, "copy_check");
                        let loop_block = self
                            .context
                            .append_basic_block(current_function, "copy_loop");
                        let end_block = self
                            .context
                            .append_basic_block(current_function, "copy_end");

                        self.builder
                            .build_unconditional_branch(check_block)
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to branch to check: {}", e))
                            })?;

                        // check: i < data_size ? loop : end
                        self.builder.position_at_end(check_block);
                        let i_phi = self.builder.build_phi(i32_type, "i").map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to build phi: {}", e))
                        })?;
                        let zero = i32_type.const_zero();
                        i_phi.add_incoming(&[(&zero, pre_block)]);
                        let i_val = i_phi.as_basic_value().into_int_value();
                        let size_limit = i32_type.const_int(data_size as u64, false);
                        let cond = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::ULT,
                                i_val,
                                size_limit,
                                "cond",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to build condition: {}", e))
                            })?;
                        self.builder
                            .build_conditional_branch(cond, loop_block, end_block)
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to build br: {}", e))
                            })?;

                        // loop: copy one byte and increment
                        self.builder.position_at_end(loop_block);
                        let src_byte_ptr = unsafe {
                            self.builder
                                .build_gep(i8_type, str_ptr, &[i_val], "src_byte_ptr")
                                .map_err(|e| {
                                    CodeGenError::LLVMError(format!("Failed to get src GEP: {}", e))
                                })?
                        };
                        let dst_byte_ptr = unsafe {
                            self.builder
                                .build_gep(i8_type, var_data_ptr, &[i_val], "dst_byte_ptr")
                                .map_err(|e| {
                                    CodeGenError::LLVMError(format!("Failed to get dst GEP: {}", e))
                                })?
                        };
                        let byte_val = self
                            .builder
                            .build_load(i8_type, src_byte_ptr, "byte_val")
                            .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to load byte: {}", e))
                        })?;
                        self.builder
                            .build_store(dst_byte_ptr, byte_val)
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to store byte: {}", e))
                            })?;
                        let next_i = self
                            .builder
                            .build_int_add(i_val, i32_type.const_int(1, false), "next_i")
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to add: {}", e))
                            })?;
                        // back to check, add backedge to phi
                        self.builder
                            .build_unconditional_branch(check_block)
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to back br: {}", e))
                            })?;
                        let loop_block_ended = self
                            .builder
                            .get_insert_block()
                            .ok_or_else(|| CodeGenError::LLVMError("No loop block".to_string()))?;
                        i_phi.add_incoming(&[(&next_i, loop_block_ended)]);

                        // end
                        self.builder.position_at_end(end_block);
                    }
                    _ => {
                        return Err(CodeGenError::LLVMError(format!(
                            "Unsupported variable data type for size {}: {:?}",
                            data_size, type_encoding
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Generate eBPF code for PrintStringIndex instruction
    pub fn generate_print_string_index(&mut self, string_index: u16) -> Result<()> {
        info!(
            "Generating PrintStringIndex instruction: index={}",
            string_index
        );

        // Allocate instruction structure on eBPF stack
        let inst_buffer = self.create_instruction_buffer();

        // Clear memory with static size
        let inst_size = self.context.i64_type().const_int(
            (std::mem::size_of::<PrintStringIndexData>()
                + std::mem::size_of::<ghostscope_protocol::trace_event::InstructionHeader>())
                as u64,
            false,
        );
        self.builder
            .build_memset(
                inst_buffer,
                std::mem::align_of::<InstructionHeader>() as u32, // proper alignment
                self.context.i8_type().const_zero(),
                inst_size,
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to memset: {}", e)))?;

        // Fill instruction header using byte offsets
        // inst_type at offset 0 (first field of InstructionHeader)
        let inst_type_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(InstructionHeader, inst_type) as u64,
                        false,
                    )],
                    "inst_type_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get inst_type GEP: {}", e))
                })?
        };
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintStringIndex as u64, false);
        self.builder
            .build_store(inst_type_ptr, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {}", e)))?;

        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(InstructionHeader, data_length) as u64,
                        false,
                    )],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {}", e))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {}", e))
            })?;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(std::mem::size_of::<PrintStringIndexData>() as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {}", e)))?;

        // Fill string index data (after InstructionHeader)
        let string_index_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(std::mem::size_of::<InstructionHeader>() as u64, false)],
                    "string_index_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get string_index GEP: {}", e))
                })?
        };
        let string_index_i16_ptr = self
            .builder
            .build_pointer_cast(
                string_index_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "string_index_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast string_index ptr: {}", e))
            })?;
        let string_index_val = self
            .context
            .i16_type()
            .const_int(string_index as u64, false);
        self.builder
            .build_store(string_index_i16_ptr, string_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store string_index: {}", e)))?;

        // Send via ringbuf
        self.send_instruction_via_ringbuf(inst_buffer, inst_size)
    }

    /// Generate eBPF code for PrintVariableIndex instruction
    pub fn generate_print_variable_index(
        &mut self,
        var_name_index: u16,
        type_encoding: TypeKind,
        var_name: &str,
    ) -> Result<()> {
        info!(
            "Generating PrintVariableIndex instruction: var_name_index={}, type={:?}, var_name={}",
            var_name_index, type_encoding, var_name
        );

        // Resolve type_index from DWARF if available; otherwise synthesize for script variables
        let type_index = match self.query_dwarf_for_variable(var_name)? {
            Some(var) => match var.dwarf_type {
                Some(ref t) => self.trace_context.add_type(t.clone()),
                None => {
                    return Err(CodeGenError::DwarfError(
                        "Variable has no DWARF type information".to_string(),
                    ));
                }
            },
            None => {
                // If it's a script variable, synthesize a compatible TypeInfo
                if self.variable_exists(var_name) {
                    self.add_synthesized_type_index_for_kind(type_encoding)
                } else {
                    return Err(CodeGenError::VariableNotFound(var_name.to_string()));
                }
            }
        };

        match self.resolve_variable_value(var_name, type_encoding) {
            Ok(var_data) => self.generate_successful_variable_instruction(
                var_name_index,
                type_encoding,
                type_index,
                var_data,
            ),
            Err(e) => Err(e),
        }
    }

    /// Generate successful variable instruction with data
    fn generate_successful_variable_instruction(
        &mut self,
        var_name_index: u16,
        type_encoding: TypeKind,
        type_index: u16,
        var_data: BasicValueEnum<'ctx>,
    ) -> Result<()> {
        // Determine data size based on type
        let data_size = match type_encoding {
            TypeKind::U8 | TypeKind::I8 | TypeKind::Bool | TypeKind::Char => 1,
            TypeKind::U16 | TypeKind::I16 => 2,
            TypeKind::U32 | TypeKind::I32 | TypeKind::F32 => 4,
            TypeKind::U64 | TypeKind::I64 | TypeKind::F64 | TypeKind::Pointer => 8,
            _ => 8, // Default to 8 bytes for complex types
        };

        let inst_buffer = self.create_instruction_buffer();

        // Clear memory with static size for PrintVariableIndexData
        let inst_size = self.context.i64_type().const_int(
            (std::mem::size_of::<PrintVariableIndexData>()
                + std::mem::size_of::<ghostscope_protocol::trace_event::InstructionHeader>()
                + data_size as usize) as u64,
            false,
        );
        self.builder
            .build_memset(
                inst_buffer,
                std::mem::align_of::<InstructionHeader>() as u32, // proper alignment
                self.context.i8_type().const_zero(),
                inst_size,
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to memset: {}", e)))?;

        // Store instruction type at offset 0
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintVariableIndex as u64, false);
        self.builder
            .build_store(inst_buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {}", e)))?;

        // Store data_length field of InstructionHeader
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(InstructionHeader, data_length) as u64,
                        false,
                    )],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {}", e))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {}", e))
            })?;
        let total_data_length = std::mem::size_of::<PrintVariableIndexData>() + data_size as usize;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(total_data_length as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {}", e)))?;

        // Write PrintVariableIndexData after InstructionHeader
        let variable_data_start = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(std::mem::size_of::<InstructionHeader>() as u64, false)],
                    "variable_data_start",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get variable_data_start GEP: {}", e))
                })?
        };

        // Store var_name_index using correct offset
        let var_name_index_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_start,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(PrintVariableIndexData, var_name_index) as u64,
                        false,
                    )],
                    "var_name_index_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get var_name_index GEP: {}", e))
                })?
        };
        let var_name_index_i16_ptr = self
            .builder
            .build_pointer_cast(
                var_name_index_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "var_name_index_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast var_name_index ptr: {}", e))
            })?;
        let var_name_index_val = self
            .context
            .i16_type()
            .const_int(var_name_index as u64, false);
        self.builder
            .build_store(var_name_index_i16_ptr, var_name_index_val)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store var_name_index: {}", e))
            })?;

        // Store type_encoding using correct offset
        let type_encoding_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_start,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(PrintVariableIndexData, type_encoding) as u64,
                        false,
                    )],
                    "type_encoding_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get type_encoding GEP: {}", e))
                })?
        };
        let type_encoding_val = self
            .context
            .i8_type()
            .const_int(type_encoding as u8 as u64, false);
        self.builder
            .build_store(type_encoding_ptr, type_encoding_val)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store type_encoding: {}", e))
            })?;

        // Store data_len using correct offset
        let data_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_start,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(PrintVariableIndexData, data_len) as u64,
                        false,
                    )],
                    "data_len_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_len GEP: {}", e))
                })?
        };
        let data_len_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_i16_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_len ptr: {}", e)))?;
        let data_len_val = self.context.i16_type().const_int(data_size as u64, false); // Store as u16
        self.builder
            .build_store(data_len_i16_ptr, data_len_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {}", e)))?;

        // Store type_index using correct offset
        let type_index_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_start,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(PrintVariableIndexData, type_index) as u64,
                        false,
                    )],
                    "type_index_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get type_index GEP: {}", e))
                })?
        };
        let type_index_i16_ptr = self
            .builder
            .build_pointer_cast(
                type_index_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "type_index_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast type_index ptr: {}", e))
            })?;
        let type_index_val = self.context.i16_type().const_int(type_index as u64, false);
        self.builder
            .build_store(type_index_i16_ptr, type_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store type_index: {}", e)))?;

        // Store status (set to 0)
        let reserved_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_start,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(PrintVariableIndexData, status) as u64,
                        false,
                    )],
                    "status_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get status GEP: {}", e)))?
        };
        let reserved_val = self
            .context
            .i8_type()
            .const_int(VariableStatus::Ok as u64, false);
        self.builder
            .build_store(reserved_ptr, reserved_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {}", e)))?;

        // Store actual variable data after PrintVariableIndexData structure
        let var_data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_start,
                    &[self
                        .context
                        .i32_type()
                        .const_int(std::mem::size_of::<PrintVariableIndexData>() as u64, false)],
                    "var_data_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get var_data GEP: {}", e))
                })?
        };

        // Store the runtime variable value based on data size
        // The var_data contains the LLVM IR value (from register/memory access)
        match data_size {
            1 => {
                // Store as i8
                let truncated = match var_data {
                    BasicValueEnum::IntValue(int_val) => self
                        .builder
                        .build_int_truncate(int_val, self.context.i8_type(), "truncated_i8")
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to truncate to i8: {}", e))
                        })?,
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Expected integer value for integer type".to_string(),
                        ));
                    }
                };
                self.builder
                    .build_store(var_data_ptr, truncated)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to store i8 data: {}", e))
                    })?;
            }
            2 => {
                // Store as i16
                let truncated = match var_data {
                    BasicValueEnum::IntValue(int_val) => self
                        .builder
                        .build_int_truncate(int_val, self.context.i16_type(), "truncated_i16")
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to truncate to i16: {}", e))
                        })?,
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Expected integer value for integer type".to_string(),
                        ));
                    }
                };
                let i16_ptr = self
                    .builder
                    .build_pointer_cast(
                        var_data_ptr,
                        self.context.ptr_type(AddressSpace::default()),
                        "i16_ptr",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to cast to i16 ptr: {}", e))
                    })?;
                self.builder.build_store(i16_ptr, truncated).map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to store i16 data: {}", e))
                })?;
            }
            4 => {
                // Store as i32 or f32
                match var_data {
                    BasicValueEnum::IntValue(int_val) => {
                        let truncated = self
                            .builder
                            .build_int_truncate(int_val, self.context.i32_type(), "truncated_i32")
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to truncate to i32: {}", e))
                            })?;
                        let i32_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "i32_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to i32 ptr: {}", e))
                            })?;
                        self.builder.build_store(i32_ptr, truncated).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store i32 data: {}", e))
                        })?;
                    }
                    BasicValueEnum::FloatValue(float_val) => {
                        let f32_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "f32_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to f32 ptr: {}", e))
                            })?;
                        self.builder.build_store(f32_ptr, float_val).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store f32 data: {}", e))
                        })?;
                    }
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Expected integer or float value for 4-byte type".to_string(),
                        ));
                    }
                }
            }
            8 => {
                // Store as i64, f64, or pointer
                match var_data {
                    BasicValueEnum::IntValue(int_val) => {
                        let i64_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "i64_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to i64 ptr: {}", e))
                            })?;
                        self.builder.build_store(i64_ptr, int_val).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store i64 data: {}", e))
                        })?;
                    }
                    BasicValueEnum::FloatValue(float_val) => {
                        let f64_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "f64_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to f64 ptr: {}", e))
                            })?;
                        self.builder.build_store(f64_ptr, float_val).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store f64 data: {}", e))
                        })?;
                    }
                    BasicValueEnum::PointerValue(ptr_val) => {
                        // Store pointer as u64
                        let ptr_int = self
                            .builder
                            .build_ptr_to_int(ptr_val, self.context.i64_type(), "ptr_as_int")
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!(
                                    "Failed to convert ptr to int: {}",
                                    e
                                ))
                            })?;
                        let i64_ptr = self
                            .builder
                            .build_pointer_cast(
                                var_data_ptr,
                                self.context.ptr_type(AddressSpace::default()),
                                "i64_ptr",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to cast to i64 ptr: {}", e))
                            })?;
                        self.builder.build_store(i64_ptr, ptr_int).map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to store pointer data: {}", e))
                        })?;
                    }
                    _ => {
                        return Err(CodeGenError::LLVMError(
                            "Expected integer, float, or pointer value for 8-byte type".to_string(),
                        ));
                    }
                }
            }
            _ => {
                return Err(CodeGenError::LLVMError(format!(
                    "Unsupported data size: {}",
                    data_size
                )));
            }
        }

        // Send via ringbuf
        self.send_instruction_via_ringbuf(inst_buffer, inst_size)
    }

    // PrintVariableError instruction has been removed; compile-time errors are returned as Err,
    // runtime errors are carried via per-variable status in Print* instructions.

    /// Generate Backtrace instruction
    pub fn generate_backtrace_instruction(&mut self, depth: u8) -> Result<()> {
        info!("Generating Backtrace instruction: depth={}", depth);

        let inst_buffer = self.create_instruction_buffer();

        // Clear memory with static size for BacktraceData
        let inst_size = self.context.i64_type().const_int(
            (std::mem::size_of::<BacktraceData>()
                + std::mem::size_of::<ghostscope_protocol::trace_event::InstructionHeader>())
                as u64,
            false,
        );
        self.builder
            .build_memset(
                inst_buffer,
                std::mem::align_of::<InstructionHeader>() as u32, // proper alignment
                self.context.i8_type().const_zero(),
                inst_size,
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to memset: {}", e)))?;

        // Send via ringbuf
        self.send_instruction_via_ringbuf(inst_buffer, inst_size)
    }

    /// Send instruction via ringbuf using bpf_ringbuf_output
    fn send_instruction_via_ringbuf(
        &mut self,
        inst_ptr: PointerValue<'ctx>,
        inst_size: IntValue<'ctx>,
    ) -> Result<()> {
        info!("Sending instruction via ringbuf (size: {:?})", inst_size);

        // Convert IntValue to u64 for the ringbuf output call
        let size_value = inst_size.get_zero_extended_constant().ok_or_else(|| {
            CodeGenError::LLVMError("Failed to get instruction size as constant".to_string())
        })?;

        // Call the actual bpf_ringbuf_output helper function
        self.create_ringbuf_output(inst_ptr, size_value)
            .map_err(|e| CodeGenError::LLVMError(format!("Ringbuf output failed: {}", e)))?;

        debug!("Successfully queued instruction for ringbuf output");
        Ok(())
    }

    /// Resolve variable value from script variables first, then DWARF
    fn resolve_variable_value(
        &mut self,
        var_name: &str,
        type_encoding: TypeKind,
    ) -> Result<BasicValueEnum<'ctx>> {
        info!(
            "Resolving variable value: {} ({:?})",
            var_name, type_encoding
        );

        // 1) Script variable first
        if self.variable_exists(var_name) {
            info!("Found script variable for '{}', loading value", var_name);
            return self.load_variable(var_name);
        }

        // 2) DWARF variable as fallback
        match self.query_dwarf_for_variable(var_name)? {
            Some(var_info) => {
                info!(
                    "Found DWARF variable: {} = {:?}",
                    var_name, var_info.evaluation_result
                );

                // Require DWARF type information
                let dwarf_type = var_info.dwarf_type.as_ref().ok_or_else(|| {
                    CodeGenError::DwarfError(format!(
                        "Variable '{}' has no type information in DWARF",
                        var_name
                    ))
                })?;

                let compile_context = self.get_compile_time_context()?;
                self.evaluate_result_to_llvm_value(
                    &var_info.evaluation_result,
                    dwarf_type,
                    var_name,
                    compile_context.pc_address,
                )
            }
            None => {
                let compile_context = self.get_compile_time_context()?;
                warn!(
                    "Variable '{}' not found in DWARF at address 0x{:x}",
                    var_name, compile_context.pc_address
                );
                Err(CodeGenError::VariableNotFound(var_name.to_string()))
            }
        }
    }

    /// Process complex variable for print statement with full DWARF support
    fn process_complex_variable_print(&mut self, expr: &Expr) -> Result<u16> {
        info!(
            "Processing complex variable with full DWARF support: {:?}",
            expr
        );
        tracing::trace!(?expr, "process_complex_variable_print: start");
        // Query DWARF for the complex expression
        let variable_with_eval = match self.query_dwarf_for_complex_expr(expr)? {
            Some(var) => var,
            None => {
                let expr_str = format!("{:?}", expr);
                warn!("Complex expression '{}' not found in DWARF", expr_str);
                return Err(CodeGenError::VariableNotFound(expr_str));
            }
        };
        tracing::trace!(
            var_name = %variable_with_eval.name,
            type_name = %variable_with_eval.type_name,
            scope_depth = variable_with_eval.scope_depth,
            is_parameter = variable_with_eval.is_parameter,
            is_artificial = variable_with_eval.is_artificial,
            eval = ?variable_with_eval.evaluation_result,
            "process_complex_variable_print: resolved DWARF variable"
        );
        let dwarf_type = variable_with_eval.dwarf_type.as_ref().ok_or_else(|| {
            CodeGenError::DwarfError("Complex expression has no DWARF type information".to_string())
        })?;

        // Add variable name to TraceContext
        let var_name_index = self
            .trace_context
            .add_variable_name(variable_with_eval.name.clone());

        // Add type information to TraceContext
        let type_index = self.trace_context.add_type(dwarf_type.clone());

        // Compute data size with truncation cap
        let mut data_size = self.compute_read_size_for_type(dwarf_type);
        tracing::trace!(
            var_name_index,
            type_index,
            data_size,
            type_size = dwarf_type.size(),
            "process_complex_variable_print: sizing"
        );
        if data_size == 0 {
            return Err(CodeGenError::TypeSizeNotAvailable(
                variable_with_eval.name.clone(),
            ));
        }
        // Avoid over-reading: cap upper bound only.
        data_size = std::cmp::min(data_size, 1993);

        // Build and emit PrintComplexVariable with runtime memory copy
        tracing::trace!(
            var_name_index,
            type_index,
            data_size,
            "process_complex_variable_print: emitting PrintComplexVariable(runtime)"
        );
        self.generate_print_complex_variable_runtime(
            var_name_index,
            type_index,
            "",
            &variable_with_eval.evaluation_result,
            dwarf_type,
            data_size,
        )?;
        tracing::trace!("process_complex_variable_print: emitted successfully");

        Ok(1)
    }

    /// Generate print instruction with both legacy type encoding and new type info
    #[allow(dead_code)]
    fn generate_print_variable_with_type_info(
        &mut self,
        var_name_index: u16,
        type_index: u16,
        type_encoding: TypeKind,
        var_name: &str,
        _variable_with_eval: Option<&ghostscope_dwarf::VariableWithEvaluation>,
    ) -> Result<()> {
        info!(
            "Generating enhanced print variable instruction: {} (var_idx={}, type_idx={}, encoding={:?})",
            var_name, var_name_index, type_index, type_encoding
        );

        // Prefer complex variable runtime path even for top-level if requested
        let _dummy_eval = ghostscope_dwarf::EvaluationResult::Optimized;
        let _size = 0usize;
        let _ = (type_index, type_encoding, var_name);
        // No-op as this path is now superseded by process_complex_variable_print
        Ok(())
    }

    /// Generate PrintComplexVariable instruction and copy data at runtime using probe_read_user
    fn generate_print_complex_variable_runtime(
        &mut self,
        var_name_index: u16,
        type_index: u16,
        access_path: &str,
        eval_result: &ghostscope_dwarf::EvaluationResult,
        dwarf_type: &ghostscope_dwarf::TypeInfo,
        data_len_limit: usize,
    ) -> Result<()> {
        tracing::trace!(
            var_name_index,
            type_index,
            access_path = %access_path,
            type_size = dwarf_type.size(),
            data_len_limit,
            eval = ?eval_result,
            "generate_print_complex_variable_runtime: begin"
        );
        // Create instruction buffer
        let inst_buffer = self.create_instruction_buffer();

        // Compute sizes
        let access_path_bytes = access_path.as_bytes();
        let access_path_len = std::cmp::min(access_path_bytes.len(), 255); // u8 max
        let type_size = dwarf_type.size() as usize;
        let mut data_len = std::cmp::min(type_size, data_len_limit);
        if data_len > u16::MAX as usize {
            data_len = u16::MAX as usize;
        }

        let header_size = std::mem::size_of::<InstructionHeader>();
        let data_struct_size = std::mem::size_of::<PrintComplexVariableData>();
        // Reserve enough space to hold either the value (read_len) or an error payload (12 bytes)
        let reserved_payload = std::cmp::max(data_len, 12);
        let total_data_length = data_struct_size + access_path_len + reserved_payload;
        let total_size = header_size + total_data_length;
        tracing::trace!(
            header_size,
            data_struct_size,
            access_path_len,
            data_len,
            total_data_length,
            total_size,
            "generate_print_complex_variable_runtime: sizes computed"
        );

        // Clear memory buffer
        self.builder
            .build_memset(
                inst_buffer,
                std::mem::align_of::<InstructionHeader>() as u32,
                self.context.i8_type().const_zero(),
                self.context.i64_type().const_int(total_size as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to memset: {}", e)))?;

        // Write InstructionHeader.inst_type at offset 0
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintComplexVariable as u64, false);
        self.builder
            .build_store(inst_buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {}", e)))?;
        tracing::trace!(
            "generate_print_complex_variable_runtime: wrote inst_type=PrintComplexVariable"
        );

        // Write InstructionHeader
        // data_length field (u16) at offset 1
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(1, false)],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {}", e))
                })?
        };
        let data_length_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_ptr_cast",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {}", e))
            })?;
        self.builder
            .build_store(
                data_length_ptr_cast,
                self.context
                    .i16_type()
                    .const_int(total_data_length as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {}", e)))?;
        tracing::trace!(
            data_length = total_data_length,
            "generate_print_complex_variable_runtime: wrote data_length"
        );

        // Data pointer (after header)
        let data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(header_size as u64, false)],
                    "data_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get data GEP: {}", e)))?
        };

        // var_name_index (u16)
        let var_name_index_val = self
            .context
            .i16_type()
            .const_int(var_name_index as u64, false);
        // Store var_name_index at offset offsetof(PrintComplexVariableData, var_name_index)
        let var_name_index_off =
            std::mem::offset_of!(PrintComplexVariableData, var_name_index) as u64;
        let var_name_index_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(var_name_index_off, false)],
                    "var_name_index_ptr_i8",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get var_name_index GEP: {}", e))
                })?
        };
        let var_name_index_ptr_i16 = self
            .builder
            .build_pointer_cast(
                var_name_index_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "var_name_index_ptr_i16",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast var_name_index ptr: {}", e))
            })?;
        self.builder
            .build_store(var_name_index_ptr_i16, var_name_index_val)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store var_name_index: {}", e))
            })?;
        tracing::trace!(
            var_name_index,
            "generate_print_complex_variable_runtime: wrote var_name_index"
        );

        // type_index (u16) right after var_name_index
        // type_index at offset offsetof(PrintComplexVariableData, type_index) = 2
        let type_index_offset = std::mem::offset_of!(PrintComplexVariableData, type_index) as u64;
        let type_index_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(type_index_offset, false)],
                    "type_index_ptr_i8",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get type_index GEP: {}", e))
                })?
        };
        let type_index_ptr = self
            .builder
            .build_pointer_cast(
                type_index_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "type_index_ptr_i16",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast type_index ptr: {}", e))
            })?;
        let type_index_val = self.context.i16_type().const_int(type_index as u64, false);
        self.builder
            .build_store(type_index_ptr, type_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store type_index: {}", e)))?;
        tracing::trace!(
            type_index,
            "generate_print_complex_variable_runtime: wrote type_index"
        );

        // access_path_len (u8)
        // access_path_len at offset offsetof(..., access_path_len)
        let access_path_len_off =
            std::mem::offset_of!(PrintComplexVariableData, access_path_len) as u64;
        let access_path_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(access_path_len_off, false)],
                    "access_path_len_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get access_path_len GEP: {}", e))
                })?
        };
        self.builder
            .build_store(
                access_path_len_ptr,
                self.context
                    .i8_type()
                    .const_int(access_path_len as u64, false),
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store access_path_len: {}", e))
            })?;
        tracing::trace!(
            access_path_len,
            "generate_print_complex_variable_runtime: wrote access_path_len"
        );

        // status (u8) at offset offsetof(..., status)
        let status_off = std::mem::offset_of!(PrintComplexVariableData, status) as u64;
        let status_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(status_off, false)],
                    "status_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get status GEP: {}", e)))?
        };
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::Ok as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {}", e)))?;

        // data_len (u16)
        let data_len_off = std::mem::offset_of!(PrintComplexVariableData, data_len) as u64;
        let data_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(data_len_off, false)],
                    "data_len_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_len GEP: {}", e))
                })?
        };
        let data_len_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_ptr_i16",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_len ptr: {}", e)))?;
        self.builder
            .build_store(
                data_len_ptr_cast,
                self.context.i16_type().const_int(data_len as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {}", e)))?;
        tracing::trace!(
            data_len,
            "generate_print_complex_variable_runtime: wrote data_len"
        );

        // access_path bytes start after PrintComplexVariableData
        let access_path_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(
                        std::mem::size_of::<PrintComplexVariableData>() as u64,
                        false,
                    )],
                    "access_path_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get access_path GEP: {}", e))
                })?
        };

        // Copy access path bytes
        for (i, &byte) in access_path_bytes.iter().enumerate().take(access_path_len) {
            let byte_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        access_path_ptr,
                        &[self.context.i32_type().const_int(i as u64, false)],
                        &format!("access_path_byte_{}", i),
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!(
                            "Failed to get access_path byte GEP: {}",
                            e
                        ))
                    })?
            };
            let byte_val = self.context.i8_type().const_int(byte as u64, false);
            self.builder.build_store(byte_ptr, byte_val).map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store access_path byte: {}", e))
            })?;
        }
        if access_path_len > 0 {
            tracing::trace!("generate_print_complex_variable_runtime: wrote access_path bytes");
        }

        // Variable data starts after access_path
        let variable_data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    access_path_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(access_path_len as u64, false)],
                    "variable_data_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get variable_data GEP: {}", e))
                })?
        };

        // Compute source address from evaluation result
        let src_addr = self.evaluation_result_to_address(eval_result)?;
        tracing::trace!(src_addr = %{src_addr}, "generate_print_complex_variable_runtime: computed src_addr");

        // Setup common types and casts
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let dst_ptr = self
            .builder
            .build_bit_cast(variable_data_ptr, ptr_type, "dst_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let size_val = i32_type.const_int(data_len as u64, false);
        let src_ptr = self
            .builder
            .build_int_to_ptr(src_addr, ptr_type, "src_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Branch: NULL deref if src_addr == 0
        let zero64 = i64_type.const_zero();
        let is_null = self
            .builder
            .build_int_compare(inkwell::IntPredicate::EQ, src_addr, zero64, "is_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let current_fn = self
            .builder
            .get_insert_block()
            .unwrap()
            .get_parent()
            .unwrap();
        let null_block = self.context.append_basic_block(current_fn, "null_deref");
        let read_block = self.context.append_basic_block(current_fn, "read_user");
        let cont_block = self.context.append_basic_block(current_fn, "after_read");
        self.builder
            .build_conditional_branch(is_null, null_block, read_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // NULL path
        self.builder.position_at_end(null_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::NullDeref as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // data_len = 0
        self.builder
            .build_store(data_len_ptr_cast, self.context.i16_type().const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // mark fail
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Read path
        self.builder.position_at_end(read_block);
        let ret = self
            .create_bpf_helper_call(
                BPF_FUNC_probe_read_user as u64,
                &[dst_ptr, size_val.into(), src_ptr.into()],
                i32_type.into(),
                "probe_read_user",
            )?
            .into_int_value();
        let is_err = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::SLT,
                ret,
                i32_type.const_zero(),
                "ret_lt_zero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let err_block = self.context.append_basic_block(current_fn, "read_err");
        let ok_block = self.context.append_basic_block(current_fn, "read_ok");
        self.builder
            .build_conditional_branch(is_err, err_block, ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Error: status=2 (read_user failed); attach errno+addr payload and set data_len=12
        self.builder.position_at_end(err_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::ReadError as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // data_len = 12 (errno:i32 + addr:u64)
        self.builder
            .build_store(
                data_len_ptr_cast,
                self.context.i16_type().const_int(12, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // write errno at [0..4]
        let errno_ptr = self
            .builder
            .build_pointer_cast(
                variable_data_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "errno_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast errno ptr: {}", e)))?;
        self.builder
            .build_store(errno_ptr, ret)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store errno: {}", e)))?;
        // write addr at [4..12]
        let addr_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_ptr,
                    &[self.context.i32_type().const_int(4, false)],
                    "addr_ptr_i8",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get addr GEP: {}", e)))?
        };
        let addr_ptr = self
            .builder
            .build_pointer_cast(
                addr_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "addr_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast addr ptr: {}", e)))?;
        self.builder
            .build_store(addr_ptr, src_addr)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store addr: {}", e)))?;
        // mark fail
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // OK path: status=0; optional truncated if data_len_limit < dwarf_type.size()
        self.builder.position_at_end(ok_block);
        if data_len < dwarf_type.size() as usize {
            // truncated
            self.builder
                .build_store(
                    status_ptr,
                    self.context
                        .i8_type()
                        .const_int(VariableStatus::Truncated as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            // mark both success and fail
            self.mark_any_success()?;
            self.mark_any_fail()?;
        } else {
            // success
            self.mark_any_success()?;
        }
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Continue
        self.builder.position_at_end(cont_block);

        // Send the instruction via ringbuf
        self.send_instruction_via_ringbuf(
            inst_buffer,
            self.context.i64_type().const_int(total_size as u64, false),
        )?;
        tracing::trace!(
            total_size,
            "generate_print_complex_variable_runtime: sent via ringbuf"
        );

        Ok(())
    }

    /// Generate eBPF code for PrintComplexVariable instruction with full type info
    #[allow(dead_code)]
    fn generate_print_complex_variable_instruction(
        &mut self,
        var_name_index: u16,
        type_index: u16,
        access_path: &str,
    ) -> Result<()> {
        info!(
            "Generating PrintComplexVariable instruction: access_path='{}', var_idx={}, type_idx={}",
            access_path, var_name_index, type_index
        );

        // For now, create a simple placeholder instruction similar to PrintVariableError
        // TODO: Implement full complex variable data generation when DWARF integration is complete

        let inst_buffer = self.create_instruction_buffer();

        // Use a static size for now - in real implementation this would be dynamic
        // based on actual variable data size
        let inst_size = self.context.i64_type().const_int(
            (std::mem::size_of::<PrintComplexVariableData>()
                + std::mem::size_of::<InstructionHeader>()
                + 64) // Extra space for access path and variable data
                as u64,
            false,
        );

        // Clear memory buffer
        self.builder
            .build_memset(
                inst_buffer,
                std::mem::align_of::<InstructionHeader>() as u32,
                self.context.i8_type().const_zero(),
                inst_size,
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to memset: {}", e)))?;

        // Send via ringbuf - the actual instruction data will be filled by higher-level code
        // that has access to the runtime variable values
        self.send_instruction_via_ringbuf(inst_buffer, inst_size)?;

        info!(
            "PrintComplexVariable instruction generated successfully (placeholder): var_idx={}, type_idx={}, access_path={}",
            var_name_index, type_index, access_path
        );
        Ok(())
    }

    /// Convert LLVM value to byte representation for embedding in trace events
    #[allow(dead_code)]
    fn llvm_value_to_bytes(
        &mut self,
        llvm_value: BasicValueEnum<'ctx>,
        dwarf_type: &ghostscope_dwarf::TypeInfo,
    ) -> Result<Vec<u8>> {
        info!(
            "Converting LLVM value to bytes: type_name={}, size={}",
            dwarf_type.type_name(),
            dwarf_type.size()
        );

        let mut bytes = Vec::new();
        let type_size = dwarf_type.size() as usize;

        match llvm_value {
            BasicValueEnum::IntValue(int_val) => {
                // Convert integer value to bytes in little endian format
                let bit_width = int_val.get_type().get_bit_width();
                match bit_width {
                    8 => {
                        let val = int_val.get_zero_extended_constant().unwrap_or(0) as u8;
                        bytes.push(val);
                    }
                    16 => {
                        let val = int_val.get_zero_extended_constant().unwrap_or(0) as u16;
                        bytes.extend_from_slice(&val.to_le_bytes());
                    }
                    32 => {
                        let val = int_val.get_zero_extended_constant().unwrap_or(0) as u32;
                        bytes.extend_from_slice(&val.to_le_bytes());
                    }
                    64 => {
                        let val = int_val.get_zero_extended_constant().unwrap_or(0);
                        bytes.extend_from_slice(&val.to_le_bytes());
                    }
                    _ => {
                        return Err(CodeGenError::LLVMError(format!(
                            "Unsupported integer bit width: {}",
                            bit_width
                        )));
                    }
                }
            }
            BasicValueEnum::FloatValue(float_val) => {
                // Convert float value to bytes
                if float_val.get_type().get_context().f32_type() == float_val.get_type() {
                    // f32
                    if let Some(const_val) = float_val.get_constant() {
                        let val_bits = const_val.0.to_bits();
                        bytes.extend_from_slice(&(val_bits as u32).to_le_bytes());
                    } else {
                        // For non-constant values, use placeholder
                        bytes.extend_from_slice(&0u32.to_le_bytes());
                    }
                } else if float_val.get_type().get_context().f64_type() == float_val.get_type() {
                    // f64
                    if let Some(const_val) = float_val.get_constant() {
                        let val_bits = const_val.0.to_bits();
                        bytes.extend_from_slice(&val_bits.to_le_bytes());
                    } else {
                        // For non-constant values, use placeholder
                        bytes.extend_from_slice(&0u64.to_le_bytes());
                    }
                } else {
                    return Err(CodeGenError::LLVMError(
                        "Unsupported float type".to_string(),
                    ));
                }
            }
            BasicValueEnum::PointerValue(_ptr_val) => {
                // For pointer values, store as 64-bit address
                // Note: At compile time we can't get the actual runtime address,
                // so this is a placeholder that would be filled at runtime
                bytes.extend_from_slice(&0u64.to_le_bytes());
            }
            BasicValueEnum::StructValue(_struct_val) => {
                // For struct values, we'd need to iterate through fields
                // For now, pad with zeros to match the expected size
                bytes.resize(type_size, 0);
            }
            BasicValueEnum::ArrayValue(_array_val) => {
                // For array values, we'd need to iterate through elements
                // For now, pad with zeros to match the expected size
                bytes.resize(type_size, 0);
            }
            _ => {
                return Err(CodeGenError::LLVMError(format!(
                    "Unsupported LLVM value type: {:?}",
                    llvm_value
                )));
            }
        }

        // Ensure we have the correct size
        if bytes.len() < type_size {
            bytes.resize(type_size, 0);
        } else if bytes.len() > type_size {
            bytes.truncate(type_size);
        }

        info!(
            "Converted LLVM value to {} bytes: {:?}",
            bytes.len(),
            &bytes[..std::cmp::min(bytes.len(), 16)] // Log first 16 bytes
        );

        Ok(bytes)
    }

    /// Generate PrintComplexVariable instruction with actual data embedded
    #[allow(dead_code)]
    fn generate_print_complex_variable_instruction_with_data(
        &mut self,
        var_name_index: u16,
        type_index: u16,
        access_path: &str,
        variable_data: &[u8],
    ) -> Result<()> {
        info!(
            "Generating PrintComplexVariable instruction with data: access_path='{}', var_idx={}, type_idx={}, data_len={}",
            access_path, var_name_index, type_index, variable_data.len()
        );

        let inst_buffer = self.create_instruction_buffer();

        let access_path_bytes = access_path.as_bytes();
        let access_path_len = access_path_bytes.len();
        let data_len = variable_data.len();

        // Calculate total instruction size
        let total_size = std::mem::size_of::<InstructionHeader>()
            + std::mem::size_of::<PrintComplexVariableData>()
            + access_path_len
            + data_len;

        let inst_size = self.context.i64_type().const_int(total_size as u64, false);

        // Clear memory buffer
        self.builder
            .build_memset(
                inst_buffer,
                std::mem::align_of::<InstructionHeader>() as u32,
                self.context.i8_type().const_zero(),
                inst_size,
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to memset: {}", e)))?;

        // Write InstructionHeader
        let _header_ptr = self
            .builder
            .build_pointer_cast(
                inst_buffer,
                self.context.ptr_type(AddressSpace::default()),
                "header_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast header ptr: {}", e)))?;

        // Set instruction type
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintComplexVariable as u64, false);
        let inst_type_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(0, false)],
                    "inst_type_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get inst_type GEP: {}", e))
                })?
        };
        self.builder
            .build_store(inst_type_ptr, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {}", e)))?;

        // Set data length
        let data_length_val = self.context.i16_type().const_int(
            (std::mem::size_of::<PrintComplexVariableData>() + access_path_len + data_len) as u64,
            false,
        );
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(1, false)],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {}", e))
                })?
        };
        let data_length_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_ptr_cast",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {}", e))
            })?;
        self.builder
            .build_store(data_length_ptr_cast, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {}", e)))?;

        // Write PrintComplexVariableData
        let data_offset = std::mem::size_of::<InstructionHeader>();
        let data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(data_offset as u64, false)],
                    "data_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get data GEP: {}", e)))?
        };

        // Set var_name_index
        let var_name_index_val = self
            .context
            .i16_type()
            .const_int(var_name_index as u64, false);
        let var_name_index_ptr = self
            .builder
            .build_pointer_cast(
                data_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "var_name_index_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast var_name_index ptr: {}", e))
            })?;
        self.builder
            .build_store(var_name_index_ptr, var_name_index_val)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store var_name_index: {}", e))
            })?;

        // Set type_index
        let type_index_val = self.context.i16_type().const_int(type_index as u64, false);
        let type_index_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i16_type(),
                    var_name_index_ptr,
                    &[self.context.i32_type().const_int(1, false)],
                    "type_index_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get type_index GEP: {}", e))
                })?
        };
        self.builder
            .build_store(type_index_ptr, type_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store type_index: {}", e)))?;

        // Set access_path_len
        let access_path_len_val = self
            .context
            .i8_type()
            .const_int(access_path_len as u64, false);
        let access_path_len_offset = 4; // 2 * u16 = 4 bytes
        let access_path_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(access_path_len_offset, false)],
                    "access_path_len_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get access_path_len GEP: {}", e))
                })?
        };
        self.builder
            .build_store(access_path_len_ptr, access_path_len_val)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store access_path_len: {}", e))
            })?;

        // Set data_len
        let data_len_val = self.context.i16_type().const_int(data_len as u64, false);
        let data_len_offset = 6; // 2 * u16 + 1 * u8 + 1 * u8 (padding) = 6 bytes
        let data_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(data_len_offset, false)],
                    "data_len_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_len GEP: {}", e))
                })?
        };
        let data_len_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_ptr_cast",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_len ptr: {}", e)))?;
        self.builder
            .build_store(data_len_ptr_cast, data_len_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {}", e)))?;

        // Write access path
        let access_path_start_offset = std::mem::size_of::<PrintComplexVariableData>();
        let access_path_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(access_path_start_offset as u64, false)],
                    "access_path_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get access_path GEP: {}", e))
                })?
        };

        // Copy access path bytes
        for (i, &byte) in access_path_bytes.iter().enumerate() {
            let byte_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        access_path_ptr,
                        &[self.context.i32_type().const_int(i as u64, false)],
                        &format!("access_path_byte_{}", i),
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!(
                            "Failed to get access_path byte GEP: {}",
                            e
                        ))
                    })?
            };
            let byte_val = self.context.i8_type().const_int(byte as u64, false);
            self.builder.build_store(byte_ptr, byte_val).map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store access_path byte: {}", e))
            })?;
        }

        // Write variable data
        let variable_data_start_offset = access_path_start_offset + access_path_len;
        let variable_data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(variable_data_start_offset as u64, false)],
                    "variable_data_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get variable_data GEP: {}", e))
                })?
        };

        // Copy variable data bytes
        for (i, &byte) in variable_data.iter().enumerate() {
            let byte_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        variable_data_ptr,
                        &[self.context.i32_type().const_int(i as u64, false)],
                        &format!("var_data_byte_{}", i),
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get var_data byte GEP: {}", e))
                    })?
            };
            let byte_val = self.context.i8_type().const_int(byte as u64, false);
            self.builder.build_store(byte_ptr, byte_val).map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store var_data byte: {}", e))
            })?;
        }

        // Send via ringbuf
        self.send_instruction_via_ringbuf(inst_buffer, inst_size)?;

        info!(
            "PrintComplexVariable instruction with data generated successfully: var_idx={}, type_idx={}, access_path='{}', data_len={}",
            var_name_index, type_index, access_path, variable_data.len()
        );

        Ok(())
    }
}

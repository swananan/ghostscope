//! Code generation for instructions
//!
//! This module handles the conversion from statements to compiled instructions
//! and generates LLVM IR for individual instructions.

use super::context::{CodeGenError, EbpfContext, Result};
use crate::script::{Expr, PrintStatement, Program, Statement};
use ghostscope_protocol::trace_event::{
    BacktraceData, InstructionHeader, PrintComplexVariableData, PrintFormatData,
    PrintStringIndexData, PrintVariableErrorData, PrintVariableIndexData,
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

impl<'ctx> EbpfContext<'ctx> {
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

                // Follow the correct priority: script variables first, then DWARF variables
                let (var_name_index, type_encoding) =
                    self.resolve_variable_with_priority(var_name)?;

                // Generate eBPF code for PrintVariableIndex
                self.generate_print_variable_index(var_name_index, type_encoding, var_name)?;
                Ok(1) // Generated 1 instruction
            }
            PrintStatement::ComplexVariable(expr) => {
                info!("Processing complex variable: {:?}", expr);
                self.process_complex_variable_print(expr)
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

    /// Compile formatted print statement: collect all variable data and send as PrintFormat instruction
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

        // 2. Process each argument and collect variable data information
        let mut variable_infos = Vec::new();

        for (i, arg) in args.iter().enumerate() {
            match arg {
                crate::script::ast::Expr::Variable(var_name) => {
                    info!("Processing argument {}: variable '{}'", i, var_name);

                    // Resolve variable to get type and name index
                    let (var_name_index, type_encoding) =
                        self.resolve_variable_with_priority(var_name)?;

                    // Determine data size based on type
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

                    // Add string literal to variable names with a unique identifier
                    let var_name = format!("__str_literal_{}", i);
                    let var_name_index = self.trace_context.add_variable_name(var_name.clone());

                    variable_infos.push(FormatVariableInfo {
                        var_name,
                        var_name_index,
                        type_encoding: TypeKind::CString,
                        data_size: s.len() + 1, // +1 for null terminator
                        value_source: FormatValueSource::StringLiteral,
                    });
                }
                crate::script::ast::Expr::Int(value) => {
                    info!("Processing argument {}: integer literal {}", i, value);

                    // Add integer literal to variable names
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
                _ => {
                    return Err(CodeGenError::NotImplemented(format!(
                        "Expression type {:?} not supported in formatted print",
                        arg
                    )));
                }
            }
        }

        // 3. Generate PrintFormat instruction in LLVM IR
        self.generate_print_format_instruction(format_string_index, &variable_infos)?;

        Ok(1) // Generated 1 PrintFormat instruction
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
                // Each variable: var_name_index(2) + type_encoding(1) + data_len(2) + data
                total_variable_data_size += 5 + var_info.data_size;
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

                // Write variable header: [var_name_index:u16, type_encoding:u8, data_len:u16]
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

                // data_len at offset 3
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
                        self.context.ptr_type(inkwell::AddressSpace::default()),
                        "data_len_i16_ptr",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to cast data_len pointer: {}", e))
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

                // Generate variable data reading at offset 5
                let var_data_ptr = unsafe {
                    self.builder
                        .build_gep(
                            self.context.i8_type(),
                            var_header_ptr,
                            &[self.context.i32_type().const_int(5, false)],
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

                current_offset += 5 + var_info.data_size;
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
                        // Copy string data byte by byte (simple loop for eBPF compatibility)
                        let i8_type = self.context.i8_type();
                        let i32_type = self.context.i32_type();

                        let loop_counter = self
                            .builder
                            .build_alloca(i32_type, "loop_counter")
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!(
                                    "Failed to alloca loop counter: {}",
                                    e
                                ))
                            })?;
                        self.builder
                            .build_store(loop_counter, i32_type.const_zero())
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!(
                                    "Failed to init loop counter: {}",
                                    e
                                ))
                            })?;

                        // Get current function from builder
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

                        let loop_block = self
                            .context
                            .append_basic_block(current_function, "copy_loop");
                        let check_block = self
                            .context
                            .append_basic_block(current_function, "copy_check");
                        let end_block = self
                            .context
                            .append_basic_block(current_function, "copy_end");

                        self.builder
                            .build_unconditional_branch(check_block)
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to branch to check: {}", e))
                            })?;

                        // Check block: test if counter < data_size
                        self.builder.position_at_end(check_block);
                        let counter_val = self
                            .builder
                            .build_load(i32_type, loop_counter, "counter_val")
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to load counter: {}", e))
                            })?;
                        let counter_i32 = counter_val.into_int_value();
                        let size_limit = i32_type.const_int(data_size as u64, false);
                        let condition = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::ULT,
                                counter_i32,
                                size_limit,
                                "copy_condition",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to build condition: {}", e))
                            })?;

                        self.builder
                            .build_conditional_branch(condition, loop_block, end_block)
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!(
                                    "Failed to build conditional branch: {}",
                                    e
                                ))
                            })?;

                        // Loop block: copy one byte
                        self.builder.position_at_end(loop_block);
                        let counter_val = self
                            .builder
                            .build_load(i32_type, loop_counter, "counter_val2")
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to load counter: {}", e))
                            })?;
                        let counter_i32 = counter_val.into_int_value();

                        let src_byte_ptr = unsafe {
                            self.builder
                                .build_gep(i8_type, str_ptr, &[counter_i32], "src_byte_ptr")
                                .map_err(|e| {
                                    CodeGenError::LLVMError(format!("Failed to get src GEP: {}", e))
                                })?
                        };
                        let dst_byte_ptr = unsafe {
                            self.builder
                                .build_gep(i8_type, var_data_ptr, &[counter_i32], "dst_byte_ptr")
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

                        // Increment counter
                        let next_counter = self
                            .builder
                            .build_int_add(
                                counter_i32,
                                i32_type.const_int(1, false),
                                "next_counter",
                            )
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!(
                                    "Failed to increment counter: {}",
                                    e
                                ))
                            })?;
                        self.builder
                            .build_store(loop_counter, next_counter)
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to store counter: {}", e))
                            })?;

                        self.builder
                            .build_unconditional_branch(check_block)
                            .map_err(|e| {
                                CodeGenError::LLVMError(format!("Failed to branch back: {}", e))
                            })?;

                        // End block: continue after loop
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

        // First, try to read the variable value
        match self.resolve_variable_value(var_name, type_encoding) {
            Ok(var_data) => self.generate_successful_variable_instruction(
                var_name_index,
                type_encoding,
                var_data,
            ),
            Err(_) => {
                // Variable read failed, generate error instruction
                self.generate_print_variable_error(var_name_index, 1, var_name) // error_code=1 for read failure
            }
        }
    }

    /// Generate successful variable instruction with data
    fn generate_successful_variable_instruction(
        &mut self,
        var_name_index: u16,
        type_encoding: TypeKind,
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

    /// Generate PrintVariableError instruction
    pub fn generate_print_variable_error(
        &mut self,
        var_name_index: u16,
        error_code: u8,
        var_name: &str,
    ) -> Result<()> {
        warn!("Generating PrintVariableError instruction: var_name_index={}, error_code={}, var_name={}",
              var_name_index, error_code, var_name);

        let inst_buffer = self.create_instruction_buffer();

        // Clear memory with static size for PrintVariableErrorData
        let inst_size = self.context.i64_type().const_int(
            (std::mem::size_of::<PrintVariableErrorData>()
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

    /// Resolve variable value from DWARF information
    fn resolve_variable_value(
        &mut self,
        var_name: &str,
        type_encoding: TypeKind,
    ) -> Result<BasicValueEnum<'ctx>> {
        info!(
            "Resolving variable value: {} ({:?})",
            var_name, type_encoding
        );

        // Use the existing query_dwarf_for_variable function
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

        // Query DWARF for the complex expression
        let variable_with_eval = match self.query_dwarf_for_complex_expr(expr)? {
            Some(var) => var,
            None => {
                let expr_str = format!("{:?}", expr);
                warn!("Complex expression '{}' not found in DWARF", expr_str);
                return Err(CodeGenError::VariableNotFound(expr_str));
            }
        };

        let dwarf_type = variable_with_eval.dwarf_type.as_ref().ok_or_else(|| {
            CodeGenError::DwarfError("Complex expression has no DWARF type information".to_string())
        })?;

        // Add variable name to TraceContext
        let var_name_index = self
            .trace_context
            .add_variable_name(variable_with_eval.name.clone());

        // Add type information to TraceContext
        let type_index = self.trace_context.add_type(dwarf_type.clone());

        // Convert DWARF type to protocol encoding for backward compatibility
        let type_encoding = TypeKind::from(dwarf_type);

        info!(
            "Complex expression '{}' resolved successfully: var_index={}, type_index={}, type_encoding={:?}",
            variable_with_eval.name, var_name_index, type_index, type_encoding
        );

        // Generate print instruction with enhanced type information
        self.generate_print_variable_with_type_info(
            var_name_index,
            type_index,
            type_encoding,
            &variable_with_eval.name,
            Some(&variable_with_eval),
        )?;

        Ok(1) // Generated 1 instruction
    }

    /// Generate print instruction with both legacy type encoding and new type info
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

        // For now, fallback to the old PrintVariableIndex implementation
        // TODO: Complete the complex variable implementation later
        warn!("Complex variable printing not fully implemented yet, falling back to basic variable printing for: {}", var_name);

        // Use the existing PrintVariableIndex implementation
        self.generate_print_variable_index(var_name_index, type_encoding, var_name)?;

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

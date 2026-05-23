use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
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
            Statement::AliasDeclaration { name, target } => {
                info!("Registering alias variable: {} = {:?}", name, target);
                // Declare in current scope (no redeclaration or shadowing)
                self.declare_name_in_current_scope(name)?;
                self.set_alias_variable(name, target.clone());
                Ok(0)
            }
            Statement::VarDeclaration { name, value } => {
                info!("Processing variable declaration: {} = {:?}", name, value);
                // Declare in current scope (no redeclaration or shadowing)
                self.declare_name_in_current_scope(name)?;
                // Decide whether this is an alias binding (DWARF-backed address/reference)
                if self.is_alias_candidate_expr(value) {
                    self.set_alias_variable(name, value.clone());
                    tracing::debug!(var=%name, "Registered DWARF alias variable");
                    Ok(0)
                } else {
                    // Compile the value expression and store as concrete variable
                    // Special-case: string literal and string var copy — record bytes for content printing
                    match value {
                        crate::script::Expr::String(s) => {
                            let mut bytes = s.as_bytes().to_vec();
                            bytes.push(0); // NUL terminate for display convenience
                            self.set_string_variable_bytes(name, bytes);
                        }
                        crate::script::Expr::Variable(ref nm) => {
                            if self
                                .get_variable_type(nm)
                                .is_some_and(|t| matches!(t, crate::script::VarType::String))
                            {
                                if let Some(b) = self.get_string_variable_bytes(nm).cloned() {
                                    self.set_string_variable_bytes(name, b);
                                }
                            }
                        }
                        _ => {}
                    }
                    let compiled_value = self.compile_expr(value)?;
                    // Disallow storing pointer values in script variables, except for string literals
                    if let BasicValueEnum::PointerValue(_) = compiled_value {
                        // Allow if RHS is a string literal OR a string variable (VarType::String)
                        let allow_string_var_copy = match value {
                            crate::script::Expr::String(_) => true,
                            crate::script::Expr::Variable(ref nm) => self
                                .get_variable_type(nm)
                                .is_some_and(|t| matches!(t, crate::script::VarType::String)),
                            _ => false,
                        };
                        if !allow_string_var_copy {
                            return Err(CodeGenError::TypeError(
                                "script variables cannot store pointer values; use DWARF alias (let v = &expr) or keep it as a string".to_string(),
                            ));
                        }
                    }
                    self.store_variable(name, compiled_value)?;
                    Ok(0) // VarDeclaration doesn't generate instructions
                }
            }
            Statement::Print(print_stmt) => self.compile_print_statement(print_stmt),
            Statement::If {
                condition,
                then_body,
                else_body,
            } => {
                let entry_event_bytes = self.compile_time_event_bytes_upper_bound;
                // Prepare condition context (runtime error capture)
                // Pretty expression text for warning
                let expr_text = self.expr_to_name(condition);
                let expr_index = self.trace_context.add_string(expr_text);
                // Activate condition context (compile-time flag) and reset runtime error byte
                self.condition_context_active = true;
                self.reset_condition_error()?;

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
                                CodeGenError::LLVMError(format!("Failed to create condition: {e}"))
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

                // Create basic blocks for error/noerror and then/else paths
                let then_block = self
                    .context
                    .append_basic_block(current_function, "then_block");
                let else_block = self
                    .context
                    .append_basic_block(current_function, "else_block");
                let merge_block = self
                    .context
                    .append_basic_block(current_function, "merge_block");
                let err_block = self
                    .context
                    .append_basic_block(current_function, "cond_err_block");
                let ok_block = self
                    .context
                    .append_basic_block(current_function, "cond_ok_block");
                // After cond compiled, deactivate compile-time flag
                self.condition_context_active = false;

                // First branch: did runtime errors occur while evaluating the condition?
                let cond_err_pred = self.build_condition_error_predicate()?;
                self.builder
                    .build_conditional_branch(cond_err_pred, err_block, ok_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to branch on cond_err: {e}"))
                    })?;

                // Error path: emit ExprError and decide destination
                self.builder.position_at_end(err_block);
                self.compile_time_event_bytes_upper_bound = entry_event_bytes;
                self.emit_current_condition_exprerror(expr_index, "cond")?;
                // Decide where to go on error: if else_body is If (else-if), go to else_block to continue;
                // otherwise, skip else (suppress) and jump to merge.
                let goto_else = matches!(else_body.as_deref(), Some(Statement::If { .. }));
                let err_path_event_bytes = self.compile_time_event_bytes_upper_bound;
                if goto_else {
                    self.builder
                        .build_unconditional_branch(else_block)
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!(
                                "Failed to branch to else on error: {e}"
                            ))
                        })?;
                } else {
                    self.builder
                        .build_unconditional_branch(merge_block)
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!(
                                "Failed to branch to merge on error: {e}"
                            ))
                        })?;
                }

                // No-error path: branch on boolean condition
                self.builder.position_at_end(ok_block);
                self.compile_time_event_bytes_upper_bound = entry_event_bytes;
                self.builder
                    .build_conditional_branch(cond_bool, then_block, else_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to create branch: {e}"))
                    })?;

                // Build then block
                self.builder.position_at_end(then_block);
                self.compile_time_event_bytes_upper_bound = entry_event_bytes;
                let mut then_instructions = 0u16;
                self.enter_scope();
                for stmt in then_body {
                    then_instructions += self.compile_statement(stmt)?;
                }
                self.exit_scope();
                let then_event_bytes = self.compile_time_event_bytes_upper_bound;
                self.builder
                    .build_unconditional_branch(merge_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to branch to merge: {e}"))
                    })?;

                // Build else block
                self.builder.position_at_end(else_block);
                let else_entry_event_bytes = if goto_else {
                    entry_event_bytes.max(err_path_event_bytes)
                } else {
                    entry_event_bytes
                };
                self.compile_time_event_bytes_upper_bound = else_entry_event_bytes;
                let mut else_instructions = 0u16;
                if let Some(else_stmt) = else_body {
                    self.enter_scope();
                    else_instructions += self.compile_statement(else_stmt)?;
                    self.exit_scope();
                }
                self.builder
                    .build_unconditional_branch(merge_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to branch to merge: {e}"))
                    })?;
                let else_event_bytes = self.compile_time_event_bytes_upper_bound;

                // Continue with merge block
                self.builder.position_at_end(merge_block);
                self.compile_time_event_bytes_upper_bound = if goto_else {
                    then_event_bytes.max(else_event_bytes)
                } else {
                    then_event_bytes
                        .max(else_event_bytes)
                        .max(err_path_event_bytes)
                };

                // Return the maximum instructions from either branch
                Ok(std::cmp::max(then_instructions, else_instructions))
            }
            Statement::Block(nested_statements) => {
                let mut total_instructions = 0u16;
                self.enter_scope();
                for stmt in nested_statements {
                    total_instructions += self.compile_statement(stmt)?;
                }
                self.exit_scope();
                Ok(total_instructions)
            }
            Statement::TracePoint { pattern: _, body } => {
                let mut total_instructions = 0u16;
                // Start a new scope for the trace body
                self.enter_scope();
                for stmt in body {
                    total_instructions += self.compile_statement(stmt)?;
                }
                self.exit_scope();
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
                let expr = crate::script::Expr::Variable(var_name.clone());
                let arg = self.resolve_expr_to_arg(&expr)?;
                let n = self.emit_print_from_arg(arg)?;
                tracing::trace!(
                    var_name = %var_name,
                    instructions = n,
                    "compile_print_statement: emitted via unified resolver"
                );
                Ok(n)
            }
            PrintStatement::ComplexVariable(expr) => {
                info!("Processing complex variable: {:?}", expr);
                let arg = self.compile_print_expr_with_builtin_exprerror(expr, |ctx| {
                    ctx.resolve_expr_to_arg(expr)
                })?;
                let n = self.emit_print_from_arg(arg)?;
                tracing::trace!(
                    instructions = n,
                    "compile_print_statement: emitted via unified resolver"
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
}

// DWARF Expression Evaluator
// Provides comprehensive DWARF expression evaluation with structured results for LLVM codegen

use crate::dwarf::{DwarfContext, DwarfOp, LocationExpression};
use crate::scoped_variables::AddressRange;
use std::collections::HashMap;
use tracing::{debug, error, warn};

/// DWARF expression evaluation errors
#[derive(Debug, thiserror::Error)]
pub enum ExpressionError {
    #[error("Stack underflow during operation")]
    StackUnderflow,

    #[error("Stack overflow - expression too complex")]
    StackOverflow,

    #[error("Division by zero in expression")]
    DivisionByZero,

    #[error("Invalid register number: {0}")]
    InvalidRegister(u16),

    #[error("Frame base not available")]
    FrameBaseUnavailable,

    #[error("Unsupported DWARF operation: {0:?}")]
    UnsupportedOperation(String),

    #[error("Expression evaluation failed: {0}")]
    EvaluationFailed(String),

    #[error("Empty stack when result expected")]
    EmptyStack,

    #[error("Invalid bytecode: {0}")]
    InvalidBytecode(String),
}

/// Complete DWARF operations enum - supports the full DWARF specification
#[derive(Debug, Clone, PartialEq)]
pub enum DwarfOperation {
    // Literal operations (DW_OP_lit*, DW_OP_const*)
    Literal(i64),

    // Register operations (DW_OP_reg*, DW_OP_breg*, DW_OP_regval_type)
    Register(u16),
    RegisterOffset(u16, i64),
    RegisterValue(u16), // DW_OP_regval_type

    // Stack operations (DW_OP_dup, DW_OP_drop, DW_OP_swap, DW_OP_rot)
    Dup,
    Drop,
    Swap,
    Rotate,
    Pick(u8), // DW_OP_pick
    Over,     // DW_OP_over

    // Arithmetic operations (DW_OP_plus, DW_OP_minus, DW_OP_mul, DW_OP_div, etc.)
    Add, // DW_OP_plus
    Sub, // DW_OP_minus
    Mul, // DW_OP_mul
    Div, // DW_OP_div
    Mod, // DW_OP_mod
    Neg, // DW_OP_neg
    Abs, // DW_OP_abs

    // Bitwise operations
    And,  // DW_OP_and
    Or,   // DW_OP_or
    Xor,  // DW_OP_xor
    Not,  // DW_OP_not
    Shl,  // DW_OP_shl
    Shr,  // DW_OP_shr
    Shra, // DW_OP_shra (arithmetic right shift)

    // Memory access (DW_OP_deref*, DW_OP_xderef*)
    Deref(usize),       // DW_OP_deref with size
    DerefSize(u8),      // DW_OP_deref_size
    XDeref(usize),      // DW_OP_xderef with address space
    XDerefSize(u8, u8), // DW_OP_xderef_size with size and address space

    // Comparison operations
    Eq, // DW_OP_eq
    Ne, // DW_OP_ne
    Lt, // DW_OP_lt
    Gt, // DW_OP_gt
    Le, // DW_OP_le
    Ge, // DW_OP_ge

    // Control flow (DW_OP_skip, DW_OP_bra)
    Skip(i16),   // DW_OP_skip
    Branch(i16), // DW_OP_bra (conditional branch)

    // Special operations
    FrameBase(i64),            // DW_OP_fbreg
    CallFrameCFA,              // DW_OP_call_frame_cfa
    StackValue,                // DW_OP_stack_value
    ImplicitValue(Vec<u8>),    // DW_OP_implicit_value
    ImplicitPointer(u64, i64), // DW_OP_implicit_pointer

    // Address operations
    Address(u64), // DW_OP_addr
    Const1u(u8),  // DW_OP_const1u
    Const1s(i8),  // DW_OP_const1s
    Const2u(u16), // DW_OP_const2u
    Const2s(i16), // DW_OP_const2s
    Const4u(u32), // DW_OP_const4u
    Const4s(i32), // DW_OP_const4s
    Const8u(u64), // DW_OP_const8u
    Const8s(i64), // DW_OP_const8s
    Constu(u64),  // DW_OP_constu
    Consts(i64),  // DW_OP_consts

    // Piece operations for composite locations
    Piece(u64),         // DW_OP_piece
    BitPiece(u64, u64), // DW_OP_bit_piece

    // DWARF 5 operations
    Convert(u64),            // DW_OP_convert
    Reinterpret(u64),        // DW_OP_reinterpret
    Entry(u64),              // DW_OP_entry_value
    ConstType(u64, Vec<u8>), // DW_OP_const_type
    RegvalType(u16, u64),    // DW_OP_regval_type
    DerefType(u8, u64),      // DW_OP_deref_type
    XDerefType(u8, u64, u8), // DW_OP_xderef_type

    // GNU extensions
    GnuEntryValue(Vec<DwarfOperation>), // DW_OP_GNU_entry_value
    GnuConstType(u64, Vec<u8>),         // DW_OP_GNU_const_type
}

/// Arithmetic operations for expression steps
#[derive(Debug, Clone, PartialEq)]
pub enum ArithOp {
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    And,
    Or,
    Xor,
    Not,
    Shl,
    Shr,
    Shra,
    Neg,
    Abs,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

/// Access step for complex expression decomposition
#[derive(Debug, Clone, PartialEq)]
pub enum AccessStep {
    LoadRegister(u16),
    AddConstant(i64),
    LoadFrameBase,
    LoadCallFrameCFA,
    Dereference {
        size: usize,
    },
    ArithmeticOp(ArithOp),
    Conditional {
        condition: ArithOp,
        then_steps: Vec<AccessStep>,
        else_steps: Vec<AccessStep>,
    },
    Piece {
        size: u64,
        offset: u64,
    }, // For composite locations
}

/// Register access information for LLVM codegen
#[derive(Debug, Clone, PartialEq)]
pub struct RegisterAccess {
    pub register: u16,
    pub offset: Option<i64>,
    pub dereference: bool,   // Whether to dereference register content
    pub size: Option<usize>, // Size of dereference if applicable
}

/// Expression evaluation result - structured information for LLVM code generation
#[derive(Clone, PartialEq)]
pub enum EvaluationResult {
    /// Simple memory address
    Address(u64),

    /// Register content access
    Register(RegisterAccess),

    /// Stack relative position
    StackOffset(i64),

    /// Frame base relative position
    FrameOffset(i64),

    /// Call frame CFA relative position
    CFAOffset(i64),

    /// Composite location (multiple pieces)
    Composite(Vec<EvaluationResult>),

    /// Implicit value (constant embedded in DWARF)
    ImplicitValue(Vec<u8>),

    /// Complex computed access path (multi-step memory dereference)
    ComputedAccess {
        steps: Vec<AccessStep>,
        requires_registers: Vec<u16>,
        requires_frame_base: bool,
        requires_cfa: bool,
    },

    /// Cannot evaluate/optimized out
    Optimized,

    /// Direct value (result of stack value operation)
    Value(i64),
}

impl std::fmt::Debug for EvaluationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvaluationResult::Address(addr) => {
                write!(f, "Address(0x{:x})", addr)
            }
            EvaluationResult::Register(reg_access) => {
                let mut result = format!("Register(%{}", reg_access.register);
                if let Some(offset) = reg_access.offset {
                    if offset >= 0 {
                        result.push_str(&format!("+{}", offset));
                    } else {
                        result.push_str(&format!("{}", offset));
                    }
                }
                if reg_access.dereference {
                    result.push_str(" -> deref");
                    if let Some(size) = reg_access.size {
                        result.push_str(&format!("({})", size));
                    }
                }
                result.push(')');
                write!(f, "{}", result)
            }
            EvaluationResult::StackOffset(offset) => {
                write!(f, "Stack({:+})", offset)
            }
            EvaluationResult::FrameOffset(offset) => {
                write!(f, "Frame({:+})", offset)
            }
            EvaluationResult::CFAOffset(offset) => {
                write!(f, "CFA({:+})", offset)
            }
            EvaluationResult::Composite(results) => {
                write!(f, "Composite[")?;
                for (i, result) in results.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{:?}", result)?;
                }
                write!(f, "]")
            }
            EvaluationResult::ImplicitValue(bytes) => {
                write!(f, "ImplicitValue({} bytes: 0x", bytes.len())?;
                for byte in bytes.iter().take(8) {
                    // Show first 8 bytes
                    write!(f, "{:02x}", byte)?;
                }
                if bytes.len() > 8 {
                    write!(f, "...")?;
                }
                write!(f, ")")
            }
            EvaluationResult::ComputedAccess {
                steps,
                requires_registers,
                requires_frame_base,
                requires_cfa,
            } => {
                write!(f, "Computed({} steps", steps.len())?;
                if *requires_frame_base {
                    write!(f, ", +Frame")?;
                }
                if *requires_cfa {
                    write!(f, ", +CFA")?;
                }
                if !requires_registers.is_empty() {
                    write!(f, ", +Regs[")?;
                    for (i, reg) in requires_registers.iter().enumerate() {
                        if i > 0 {
                            write!(f, ",")?;
                        }
                        write!(f, "%{}", reg)?;
                    }
                    write!(f, "]")?;
                }
                write!(f, ")")
            }
            EvaluationResult::Optimized => {
                write!(f, "OptimizedOut")
            }
            EvaluationResult::Value(value) => {
                write!(f, "Value({})", value)
            }
        }
    }
}

/// Optimized expression patterns for fast evaluation
#[derive(Debug, Clone, PartialEq)]
pub enum OptimizedPattern {
    RegisterDirect(u16),              // Direct register access
    RegisterOffset(u16, i64),         // Register + offset
    FrameBaseOffset(i64),             // Frame base + offset
    CFAOffset(i64),                   // CFA + offset
    TwoStepDereference(u16, i64),     // *(register + offset)
    ConstantValue(i64),               // Simple constant
    ComplexComputed(Vec<AccessStep>), // Multi-step computation required
}

/// Evaluation context - provides runtime environment information
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    pub pc_address: u64,
    pub address_size: u8, // Target architecture address size (4 or 8 bytes)
}

impl Default for EvaluationContext {
    fn default() -> Self {
        Self {
            pc_address: 0,
            address_size: 8, // Default to 64-bit
        }
    }
}

/// CFI-specific evaluation context for stack unwinding
#[derive(Debug, Clone)]
pub struct CFIContext {
    pub pc_address: u64,
    pub available_registers: HashMap<u16, u64>,
    pub address_size: u8,
}

/// DWARF expression evaluator - main entry point
#[derive(Debug)]
pub struct DwarfExpressionEvaluator {
    /// Maximum stack depth to prevent infinite recursion
    max_stack_depth: usize,
    /// Enable pattern optimization
    optimize_patterns: bool,
}

impl Default for DwarfExpressionEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl DwarfExpressionEvaluator {
    /// Create a new DWARF expression evaluator
    pub fn new() -> Self {
        Self {
            max_stack_depth: 1000,
            optimize_patterns: true,
        }
    }

    /// Create evaluator with custom configuration
    pub fn with_config(max_stack_depth: usize, optimize_patterns: bool) -> Self {
        Self {
            max_stack_depth,
            optimize_patterns,
        }
    }

    /// Universal DWARF expression evaluator for LLVM codegen
    ///
    /// This is the core interface that can evaluate any DWARF expression operations.
    /// It handles CFI queries internally when encountering FrameBase or CallFrameCFA operations.
    pub fn evaluate_dwarf_expression_for_codegen(
        &self,
        operations: &[DwarfOperation],
        pc_address: u64,
        context: &EvaluationContext,
        dwarf_context: Option<&DwarfContext>,
    ) -> Result<EvaluationResult, ExpressionError> {
        debug!(
            "Evaluating {} DWARF operations for codegen at PC 0x{:x}",
            operations.len(),
            pc_address
        );

        // Handle single operation patterns for optimization
        if operations.len() == 1 {
            return self.evaluate_single_operation_for_codegen(
                &operations[0],
                pc_address,
                context,
                dwarf_context,
            );
        }

        // Handle common patterns
        if let Some(result) = self.analyze_operation_patterns_for_codegen(
            operations,
            pc_address,
            context,
            dwarf_context,
        )? {
            return Ok(result);
        }

        // Fall back to step-by-step evaluation with CFI-aware operations
        self.evaluate_operations_with_cfi(operations, pc_address, context, dwarf_context)
    }

    /// Enhanced entry: evaluate LocationExpression for LLVM codegen with CFI support
    pub fn evaluate_location_for_codegen(
        &self,
        location_expr: &LocationExpression,
        pc_address: u64,
        context: &EvaluationContext,
        dwarf_context: Option<&DwarfContext>,
    ) -> Result<EvaluationResult, ExpressionError> {
        debug!(
            "Evaluating location expression for codegen with CFI at PC 0x{:x}",
            pc_address
        );

        match location_expr {
            LocationExpression::ComputedExpression {
                operations,
                requires_frame_base,
                requires_registers,
            } => {
                debug!(
                    "Evaluating computed expression with {} operations",
                    operations.len()
                );

                // Convert legacy DwarfOp to new DwarfOperation
                let new_operations: Result<Vec<DwarfOperation>, ExpressionError> = operations
                    .iter()
                    .map(|op| self.convert_legacy_dwarf_op(op))
                    .collect();

                match new_operations {
                    Ok(ops) => {
                        // Use the universal evaluator with CFI support
                        self.evaluate_dwarf_expression_for_codegen(
                            &ops,
                            pc_address,
                            context,
                            dwarf_context,
                        )
                    }
                    Err(e) => {
                        error!("Failed to convert legacy DWARF operations: {}", e);
                        Err(e)
                    }
                }
            }

            LocationExpression::LocationList { entries } => {
                debug!("Processing location list with {} entries", entries.len());

                // Find applicable entry for this PC
                for entry in entries {
                    if pc_address >= entry.start_pc && pc_address < entry.end_pc {
                        debug!(
                            "Found matching location list entry: PC 0x{:x} in range 0x{:x}-0x{:x}",
                            pc_address, entry.start_pc, entry.end_pc
                        );
                        // Recursively evaluate the location expression for this PC range
                        return self.evaluate_location_for_codegen(
                            &entry.location_expr,
                            pc_address,
                            context,
                            dwarf_context,
                        );
                    }
                }

                debug!(
                    "No matching location list entry found for PC 0x{:x}",
                    pc_address
                );
                Ok(EvaluationResult::Optimized)
            }

            // Handle simple expressions
            LocationExpression::Register { reg } => {
                Ok(EvaluationResult::Register(RegisterAccess {
                    register: *reg,
                    offset: None,
                    dereference: false,
                    size: None,
                }))
            }

            LocationExpression::RegisterOffset { reg, offset } => {
                Ok(EvaluationResult::Register(RegisterAccess {
                    register: *reg,
                    offset: Some(*offset),
                    dereference: false,
                    size: None,
                }))
            }

            LocationExpression::FrameBaseOffset { offset } => {
                // Use CFI-aware frame base evaluation
                if let Some(dwarf_ctx) = dwarf_context {
                    if let Some(cfi_rule) = dwarf_ctx.get_cfi_rule_for_pc(pc_address) {
                        debug!(
                            "Found CFI rule for frame base offset at PC 0x{:x}: {:?}",
                            pc_address, cfi_rule
                        );
                        return self.combine_cfi_with_offset(
                            &cfi_rule, *offset, dwarf_ctx, pc_address, context,
                        );
                    }
                }
                // Fallback
                warn!(
                    "No CFI context for frame base offset at PC 0x{:x}",
                    pc_address
                );
                Ok(EvaluationResult::FrameOffset(*offset))
            }

            LocationExpression::OptimizedOut => Ok(EvaluationResult::Optimized),

            LocationExpression::DwarfExpression { bytecode } => {
                warn!("Raw DWARF bytecode not yet supported for CFI-aware evaluation");
                Ok(EvaluationResult::Optimized)
            }

            _ => {
                warn!(
                    "Unsupported location expression for CFI-aware evaluation: {:?}",
                    location_expr
                );
                Ok(EvaluationResult::Optimized)
            }
        }
    }

    /// Main entry: evaluate LocationExpression for LLVM codegen (backward compatibility)
    pub fn evaluate_for_codegen(
        &self,
        location_expr: &LocationExpression,
        pc_address: u64,
        context: &EvaluationContext,
    ) -> Result<EvaluationResult, ExpressionError> {
        debug!(
            "Evaluating location expression for codegen at PC 0x{:x}",
            pc_address
        );

        match location_expr {
            LocationExpression::ComputedExpression {
                operations,
                requires_frame_base,
                requires_registers,
            } => {
                debug!(
                    "Evaluating computed expression with {} operations",
                    operations.len()
                );

                // Convert legacy DwarfOp to new DwarfOperation
                let new_operations: Result<Vec<DwarfOperation>, ExpressionError> = operations
                    .iter()
                    .map(|op| self.convert_legacy_dwarf_op(op))
                    .collect();

                match new_operations {
                    Ok(ops) => self.evaluate_operations(&ops, context),
                    Err(e) => {
                        warn!("Failed to convert legacy operations: {}", e);
                        Ok(EvaluationResult::Optimized)
                    }
                }
            }

            LocationExpression::DwarfExpression { bytecode } => {
                debug!(
                    "Evaluating DWARF expression from {} bytes of bytecode",
                    bytecode.len()
                );
                self.evaluate_bytecode(bytecode, context)
            }

            LocationExpression::LocationList { entries } => {
                debug!("Resolving location list with {} entries", entries.len());
                self.resolve_location_list(entries, pc_address, context)
            }

            // Simple cases - direct conversion
            _ => {
                debug!("Converting simple location expression");
                self.convert_simple_location(location_expr)
            }
        }
    }

    /// CFI-specific evaluation for stack unwinding
    pub fn evaluate_for_cfi(
        &self,
        operations: &[DwarfOp],
        context: &CFIContext,
    ) -> Result<u64, ExpressionError> {
        debug!(
            "Evaluating CFI expression with {} operations at PC 0x{:x}",
            operations.len(),
            context.pc_address
        );

        // Try to optimize common CFI patterns first
        if let Some(optimized_result) = self.try_cfi_pattern_optimization(operations, context)? {
            debug!("Used CFI pattern optimization");
            return Ok(optimized_result);
        }

        // Convert legacy operations and evaluate on stack machine
        let new_operations: Result<Vec<DwarfOperation>, ExpressionError> = operations
            .iter()
            .map(|op| self.convert_legacy_dwarf_op(op))
            .collect();

        match new_operations {
            Ok(ops) => {
                let mut stack = Vec::new();
                let eval_context = self.cfi_to_eval_context(context);

                for op in &ops {
                    self.execute_operation(op, &mut stack, &eval_context)?;
                }

                stack
                    .pop()
                    .map(|val| val as u64)
                    .ok_or(ExpressionError::EmptyStack)
            }
            Err(e) => {
                error!("Failed to convert CFI operations: {}", e);
                Err(e)
            }
        }
    }

    /// Try to optimize common CFI patterns without full evaluation
    fn try_cfi_pattern_optimization(
        &self,
        operations: &[DwarfOp],
        context: &CFIContext,
    ) -> Result<Option<u64>, ExpressionError> {
        match operations {
            // We don't need CFI optimization branches for this eBPF debugging tool
            // All patterns will generate symbolic expressions instead

            // Constant value: DW_OP_const
            [DwarfOp::Const(value)] => {
                debug!("CFI pattern: Constant value ({})", value);
                Ok(Some(*value as u64))
            }

            _ => {
                debug!(
                    "CFI pattern: No optimization available for {} operations",
                    operations.len()
                );
                Ok(None)
            }
        }
    }

    /// Enhanced pattern analysis for optimization opportunities (based on LLDB/GDB implementations)
    pub fn analyze_pattern(&self, ops: &[DwarfOp]) -> OptimizedPattern {
        debug!("Analyzing expression pattern with {} operations", ops.len());

        if !self.optimize_patterns {
            return OptimizedPattern::ComplexComputed(self.convert_to_steps(ops));
        }

        match ops {
            // === Single Operation Patterns ===

            // Direct register access: DW_OP_reg0, DW_OP_reg1, etc.
            [DwarfOp::Reg(reg)] => {
                debug!("Pattern: Direct register access (reg {})", reg);
                OptimizedPattern::RegisterDirect(*reg)
            }

            // Register + offset: DW_OP_breg0 <offset>
            [DwarfOp::Breg(reg, offset)] => {
                debug!("Pattern: Register + offset (reg {} + {})", reg, offset);
                OptimizedPattern::RegisterOffset(*reg, *offset)
            }

            // Frame base + offset: DW_OP_fbreg <offset>
            [DwarfOp::Fbreg(offset)] => {
                debug!("Pattern: Frame base + offset (fb + {})", offset);
                OptimizedPattern::FrameBaseOffset(*offset)
            }

            // Simple constant: DW_OP_const* <value>
            [DwarfOp::Const(value)] => {
                debug!("Pattern: Constant value ({})", value);
                OptimizedPattern::ConstantValue(*value)
            }

            // === Two Operation Patterns ===

            // Two-step dereference: DW_OP_breg0 <offset>, DW_OP_deref
            [DwarfOp::Breg(reg, offset), DwarfOp::Deref] => {
                debug!(
                    "Pattern: Two-step dereference (*(reg {} + {}))",
                    reg, offset
                );
                OptimizedPattern::TwoStepDereference(*reg, *offset)
            }

            // Frame base dereference: DW_OP_fbreg <offset>, DW_OP_deref
            [DwarfOp::Fbreg(offset), DwarfOp::Deref] => {
                debug!("Pattern: Frame base dereference (*(fb + {}))", offset);
                // This needs complex steps but is a common pattern
                OptimizedPattern::ComplexComputed(vec![
                    AccessStep::LoadFrameBase,
                    AccessStep::AddConstant(*offset),
                    AccessStep::Dereference { size: 8 },
                ])
            }

            // Register with constant addition: DW_OP_reg* DW_OP_const* DW_OP_plus
            [DwarfOp::Reg(reg), DwarfOp::Const(offset), DwarfOp::Plus] => {
                debug!("Pattern: Register + constant ({} + {})", reg, offset);
                OptimizedPattern::RegisterOffset(*reg, *offset)
            }

            // Register + constant via plus_uconst: DW_OP_reg* DW_OP_plus_uconst
            [DwarfOp::Reg(reg), DwarfOp::PlusUconst(offset)] => {
                debug!("Pattern: Register + uconst ({} + {})", reg, offset);
                OptimizedPattern::RegisterOffset(*reg, *offset as i64)
            }

            // === Three Operation Patterns ===

            // Complex dereference: DW_OP_reg* DW_OP_const* DW_OP_plus DW_OP_deref
            [DwarfOp::Reg(reg), DwarfOp::Const(offset), DwarfOp::Plus, DwarfOp::Deref] => {
                debug!(
                    "Pattern: Register + constant + deref (*(reg {} + {}))",
                    reg, offset
                );
                OptimizedPattern::TwoStepDereference(*reg, *offset)
            }

            // Stack value patterns: DW_OP_* ... DW_OP_stack_value
            ops if ops.len() >= 2 && matches!(ops[ops.len() - 1], DwarfOp::StackValue) => {
                debug!("Pattern: Stack value expression");
                // Analyze the operations before stack_value
                let value_ops = &ops[..ops.len() - 1];
                match self.analyze_value_expression(value_ops) {
                    Some(pattern) => pattern,
                    None => OptimizedPattern::ComplexComputed(self.convert_to_steps(ops)),
                }
            }

            // === Multi-operation arithmetic patterns ===

            // Frame base with multi-step offset calculation
            ops if ops.len() >= 3
                && matches!(ops[0], DwarfOp::Fbreg(_))
                && self.is_simple_arithmetic_sequence(&ops[1..]) =>
            {
                debug!("Pattern: Frame base with arithmetic sequence");
                // Calculate the effective offset if possible
                if let Some(total_offset) = self.calculate_constant_offset(&ops[1..]) {
                    let DwarfOp::Fbreg(base_offset) = ops[0] else {
                        unreachable!()
                    };
                    debug!(
                        "Optimized frame base offset: {} + {} = {}",
                        base_offset,
                        total_offset,
                        base_offset + total_offset
                    );
                    OptimizedPattern::FrameBaseOffset(base_offset + total_offset)
                } else {
                    OptimizedPattern::ComplexComputed(self.convert_to_steps(ops))
                }
            }

            // Register with multi-step offset calculation
            ops if ops.len() >= 3
                && matches!(ops[0], DwarfOp::Breg(_, _))
                && self.is_simple_arithmetic_sequence(&ops[1..]) =>
            {
                debug!("Pattern: Register with arithmetic sequence");
                if let Some(additional_offset) = self.calculate_constant_offset(&ops[1..]) {
                    let DwarfOp::Breg(reg, base_offset) = ops[0] else {
                        unreachable!()
                    };
                    debug!(
                        "Optimized register offset: {} + {} = {}",
                        base_offset,
                        additional_offset,
                        base_offset + additional_offset
                    );
                    OptimizedPattern::RegisterOffset(reg, base_offset + additional_offset)
                } else {
                    OptimizedPattern::ComplexComputed(self.convert_to_steps(ops))
                }
            }

            // === Default: Complex pattern ===
            _ => {
                debug!(
                    "Pattern: Complex expression with {} operations - converting to steps",
                    ops.len()
                );
                OptimizedPattern::ComplexComputed(self.convert_to_steps(ops))
            }
        }
    }

    /// Analyze expression patterns that end with DW_OP_stack_value
    fn analyze_value_expression(&self, ops: &[DwarfOp]) -> Option<OptimizedPattern> {
        match ops {
            [DwarfOp::Const(value)] => Some(OptimizedPattern::ConstantValue(*value)),
            [DwarfOp::Reg(reg)] => {
                // Register value (not address)
                Some(OptimizedPattern::RegisterDirect(*reg))
            }
            [DwarfOp::Breg(reg, offset)] => Some(OptimizedPattern::RegisterOffset(*reg, *offset)),
            [DwarfOp::Fbreg(offset)] => Some(OptimizedPattern::FrameBaseOffset(*offset)),
            _ => None, // Too complex for simple optimization
        }
    }

    /// Check if a sequence of operations is simple arithmetic (constants and basic ops)
    fn is_simple_arithmetic_sequence(&self, ops: &[DwarfOp]) -> bool {
        ops.iter().all(|op| match op {
            DwarfOp::Const(_) | DwarfOp::Plus | DwarfOp::PlusUconst(_) => true,
            _ => false,
        })
    }

    /// Calculate the constant offset from a sequence of arithmetic operations
    fn calculate_constant_offset(&self, ops: &[DwarfOp]) -> Option<i64> {
        let mut stack = Vec::new();

        for op in ops {
            match op {
                DwarfOp::Const(value) => {
                    stack.push(*value);
                }
                DwarfOp::PlusUconst(value) => {
                    if let Some(top) = stack.pop() {
                        stack.push(top + (*value as i64));
                    } else {
                        // This operation expects a value on stack, but we don't have one
                        return None;
                    }
                }
                DwarfOp::Plus => {
                    if stack.len() >= 2 {
                        let b = stack.pop().unwrap();
                        let a = stack.pop().unwrap();
                        stack.push(a + b);
                    } else {
                        return None;
                    }
                }
                _ => {
                    // Unsupported operation for constant calculation
                    return None;
                }
            }
        }

        // Should have exactly one value left
        if stack.len() == 1 {
            Some(stack[0])
        } else {
            None
        }
    }

    // Placeholder implementations for core methods - will be implemented in subsequent tasks

    fn convert_legacy_dwarf_op(&self, op: &DwarfOp) -> Result<DwarfOperation, ExpressionError> {
        match op {
            DwarfOp::Const(val) => Ok(DwarfOperation::Literal(*val)),
            DwarfOp::Reg(reg) => Ok(DwarfOperation::Register(*reg)),
            DwarfOp::Breg(reg, offset) => Ok(DwarfOperation::RegisterOffset(*reg, *offset)),
            DwarfOp::Fbreg(offset) => Ok(DwarfOperation::FrameBase(*offset)),
            DwarfOp::Deref => Ok(DwarfOperation::Deref(8)), // Default to 8-byte deref
            DwarfOp::Plus => Ok(DwarfOperation::Add),
            // PlusUconst is a combined operation: push constant and add
            // For CFI evaluation, we handle it as a single RegisterOffset operation
            DwarfOp::PlusUconst(val) => Ok(DwarfOperation::Literal(*val as i64)),
            DwarfOp::Dup => Ok(DwarfOperation::Dup),
            DwarfOp::Drop => Ok(DwarfOperation::Drop),
            DwarfOp::Swap => Ok(DwarfOperation::Swap),
            DwarfOp::StackValue => Ok(DwarfOperation::StackValue),
        }
    }

    /// Evaluate a sequence of DWARF operations using the mixed strategy
    fn evaluate_operations(
        &self,
        operations: &[DwarfOperation],
        context: &EvaluationContext,
    ) -> Result<EvaluationResult, ExpressionError> {
        debug!("Evaluating {} DWARF operations", operations.len());

        // === Mixed Strategy Implementation ===
        // 1. First, try pattern optimization for simple cases
        if self.optimize_patterns && operations.len() <= 3 {
            if let Some(optimized) = self.try_pattern_optimization(operations, context)? {
                debug!("Used pattern optimization for simple expression");
                return Ok(optimized);
            }
        }

        // 2. Full stack machine evaluation for complex expressions
        let mut stack = Vec::with_capacity(16);
        let mut requires_memory_access = false;
        let mut requires_registers = Vec::new();
        let mut requires_frame_base = false;
        let mut requires_cfa = false;

        for (i, operation) in operations.iter().enumerate() {
            debug!(
                "Executing operation {}/{}: {:?}",
                i + 1,
                operations.len(),
                operation
            );

            // Track what resources this expression needs
            match operation {
                DwarfOperation::Register(reg) | DwarfOperation::RegisterOffset(reg, _) => {
                    if !requires_registers.contains(reg) {
                        requires_registers.push(*reg);
                    }
                }
                DwarfOperation::FrameBase(_) => requires_frame_base = true,
                DwarfOperation::CallFrameCFA => requires_cfa = true,
                DwarfOperation::Deref(_) | DwarfOperation::DerefSize(_) => {
                    requires_memory_access = true;
                }
                _ => {}
            }

            match self.execute_operation(operation, &mut stack, context) {
                Ok(()) => continue,
                Err(ExpressionError::EvaluationFailed(msg))
                    if msg.contains("requires codegen handling") =>
                {
                    // This operation needs to be handled at codegen time
                    debug!("Operation requires codegen handling: {}", msg);
                    requires_memory_access = true;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }

        // 3. Analyze the final result and return appropriate EvaluationResult
        let final_result = stack.last().copied().unwrap_or(0);

        if requires_memory_access {
            // Expression involves memory dereference - needs complex codegen
            let steps = self.operations_to_access_steps(operations);
            return Ok(EvaluationResult::ComputedAccess {
                steps,
                requires_registers,
                requires_frame_base,
                requires_cfa,
            });
        }

        // Simple cases that can be resolved to concrete values or patterns
        match operations.len() {
            0 => Ok(EvaluationResult::Optimized),
            1 => {
                // Single operation - try to optimize to specific result types
                match &operations[0] {
                    DwarfOperation::Register(reg) => {
                        Ok(EvaluationResult::Register(RegisterAccess {
                            register: *reg,
                            offset: None,
                            dereference: false,
                            size: None,
                        }))
                    }

                    DwarfOperation::RegisterOffset(reg, offset) => {
                        Ok(EvaluationResult::Register(RegisterAccess {
                            register: *reg,
                            offset: Some(*offset),
                            dereference: false,
                            size: None,
                        }))
                    }

                    DwarfOperation::FrameBase(offset) => Ok(EvaluationResult::FrameOffset(*offset)),

                    DwarfOperation::CallFrameCFA => Ok(EvaluationResult::CFAOffset(0)),

                    DwarfOperation::Address(addr) => Ok(EvaluationResult::Address(*addr)),

                    DwarfOperation::Literal(value) | DwarfOperation::Consts(value) => {
                        Ok(EvaluationResult::Value(*value))
                    }

                    _ => Ok(EvaluationResult::Value(final_result)),
                }
            }
            _ => {
                // Multi-operation expression
                if requires_frame_base || requires_cfa || !requires_registers.is_empty() {
                    // Complex expression that needs runtime evaluation
                    let steps = self.operations_to_access_steps(operations);
                    Ok(EvaluationResult::ComputedAccess {
                        steps,
                        requires_registers,
                        requires_frame_base,
                        requires_cfa,
                    })
                } else {
                    // Pure computational result
                    Ok(EvaluationResult::Value(final_result))
                }
            }
        }
    }

    /// Try to optimize simple expression patterns without full stack evaluation
    fn try_pattern_optimization(
        &self,
        operations: &[DwarfOperation],
        _context: &EvaluationContext,
    ) -> Result<Option<EvaluationResult>, ExpressionError> {
        match operations {
            // Direct register access: DW_OP_reg0, DW_OP_reg1, etc.
            [DwarfOperation::Register(reg)] => {
                Ok(Some(EvaluationResult::Register(RegisterAccess {
                    register: *reg,
                    offset: None,
                    dereference: false,
                    size: None,
                })))
            }

            // Register with offset: DW_OP_breg0 <offset>
            [DwarfOperation::RegisterOffset(reg, offset)] => {
                Ok(Some(EvaluationResult::Register(RegisterAccess {
                    register: *reg,
                    offset: Some(*offset),
                    dereference: false,
                    size: None,
                })))
            }

            // Frame base with offset: DW_OP_fbreg <offset>
            [DwarfOperation::FrameBase(offset)] => Ok(Some(EvaluationResult::FrameOffset(*offset))),

            // Simple dereference: DW_OP_breg0 <offset>, DW_OP_deref
            [DwarfOperation::RegisterOffset(reg, offset), DwarfOperation::Deref(size)] => {
                Ok(Some(EvaluationResult::ComputedAccess {
                    steps: vec![
                        AccessStep::LoadRegister(*reg),
                        AccessStep::AddConstant(*offset),
                        AccessStep::Dereference { size: *size },
                    ],
                    requires_registers: vec![*reg],
                    requires_frame_base: false,
                    requires_cfa: false,
                }))
            }

            // Frame base dereference: DW_OP_fbreg <offset>, DW_OP_deref
            [DwarfOperation::FrameBase(offset), DwarfOperation::Deref(_size)] => {
                // This will need complex handling in codegen
                Ok(Some(EvaluationResult::ComputedAccess {
                    steps: vec![
                        AccessStep::LoadFrameBase,
                        AccessStep::AddConstant(*offset),
                        AccessStep::Dereference { size: *_size },
                    ],
                    requires_registers: vec![],
                    requires_frame_base: true,
                    requires_cfa: false,
                }))
            }

            // Constant values
            [DwarfOperation::Literal(value)] | [DwarfOperation::Consts(value)] => {
                Ok(Some(EvaluationResult::Value(*value)))
            }

            [DwarfOperation::Address(addr)] => Ok(Some(EvaluationResult::Address(*addr))),

            // No optimization available for this pattern
            _ => Ok(None),
        }
    }

    /// Convert operations to access steps for complex expressions
    fn operations_to_access_steps(&self, operations: &[DwarfOperation]) -> Vec<AccessStep> {
        let mut steps = Vec::new();

        for op in operations {
            match op {
                DwarfOperation::Register(reg) => {
                    steps.push(AccessStep::LoadRegister(*reg));
                }

                DwarfOperation::RegisterOffset(reg, offset) => {
                    steps.push(AccessStep::LoadRegister(*reg));
                    steps.push(AccessStep::AddConstant(*offset));
                }

                DwarfOperation::FrameBase(offset) => {
                    steps.push(AccessStep::LoadFrameBase);
                    steps.push(AccessStep::AddConstant(*offset));
                }

                DwarfOperation::CallFrameCFA => {
                    steps.push(AccessStep::LoadCallFrameCFA);
                }

                DwarfOperation::Deref(size) => {
                    steps.push(AccessStep::Dereference { size: *size });
                }

                DwarfOperation::DerefSize(size) => {
                    steps.push(AccessStep::Dereference {
                        size: *size as usize,
                    });
                }

                DwarfOperation::Add => {
                    steps.push(AccessStep::ArithmeticOp(ArithOp::Add));
                }

                DwarfOperation::Sub => {
                    steps.push(AccessStep::ArithmeticOp(ArithOp::Sub));
                }

                DwarfOperation::Mul => {
                    steps.push(AccessStep::ArithmeticOp(ArithOp::Mul));
                }

                DwarfOperation::Literal(value) | DwarfOperation::Consts(value) => {
                    steps.push(AccessStep::AddConstant(*value));
                }

                // For other operations, we'll need to extend this
                _ => {
                    debug!("Unsupported operation in access steps conversion: {:?}", op);
                }
            }
        }

        steps
    }

    fn evaluate_bytecode(
        &self,
        _bytecode: &[u8],
        _context: &EvaluationContext,
    ) -> Result<EvaluationResult, ExpressionError> {
        // TODO: Implement bytecode evaluation - will be implemented in task 4
        debug!("evaluate_bytecode - placeholder implementation");
        Ok(EvaluationResult::Optimized)
    }

    fn resolve_location_list(
        &self,
        entries: &[crate::dwarf::LocationListEntry],
        pc_address: u64,
        context: &EvaluationContext,
    ) -> Result<EvaluationResult, ExpressionError> {
        // Find the appropriate location list entry for the given PC
        for entry in entries {
            if pc_address >= entry.start_pc && pc_address < entry.end_pc {
                debug!(
                    "Found location list entry for PC 0x{:x}: 0x{:x}-0x{:x}",
                    pc_address, entry.start_pc, entry.end_pc
                );
                // Recursively evaluate the location expression for this PC range
                return self.evaluate_for_codegen(&entry.location_expr, pc_address, context);
            }
        }

        debug!("No location list entry found for PC 0x{:x}", pc_address);
        Ok(EvaluationResult::Optimized)
    }

    fn convert_simple_location(
        &self,
        location_expr: &LocationExpression,
    ) -> Result<EvaluationResult, ExpressionError> {
        match location_expr {
            LocationExpression::Register { reg } => {
                Ok(EvaluationResult::Register(RegisterAccess {
                    register: *reg,
                    offset: None,
                    dereference: false,
                    size: None,
                }))
            }

            LocationExpression::FrameBaseOffset { offset } => {
                Ok(EvaluationResult::FrameOffset(*offset))
            }

            LocationExpression::Address { addr } => Ok(EvaluationResult::Address(*addr)),

            LocationExpression::StackOffset { offset } => {
                Ok(EvaluationResult::StackOffset(*offset))
            }

            LocationExpression::RegisterOffset { reg, offset } => {
                Ok(EvaluationResult::Register(RegisterAccess {
                    register: *reg,
                    offset: Some(*offset),
                    dereference: false,
                    size: None,
                }))
            }

            LocationExpression::OptimizedOut => Ok(EvaluationResult::Optimized),

            _ => {
                warn!(
                    "Unsupported simple location expression: {:?}",
                    location_expr
                );
                Ok(EvaluationResult::Optimized)
            }
        }
    }

    /// Evaluate single operation with CFI awareness for codegen
    fn evaluate_single_operation_for_codegen(
        &self,
        operation: &DwarfOperation,
        pc_address: u64,
        context: &EvaluationContext,
        dwarf_context: Option<&DwarfContext>,
    ) -> Result<EvaluationResult, ExpressionError> {
        debug!("Evaluating single operation with CFI: {:?}", operation);

        match operation {
            DwarfOperation::Register(reg) => Ok(EvaluationResult::Register(RegisterAccess {
                register: *reg,
                offset: None,
                dereference: false,
                size: None,
            })),

            DwarfOperation::RegisterOffset(reg, offset) => {
                Ok(EvaluationResult::Register(RegisterAccess {
                    register: *reg,
                    offset: Some(*offset),
                    dereference: false,
                    size: None,
                }))
            }

            DwarfOperation::FrameBase(offset) => {
                // Query CFI for frame base calculation
                if let Some(dwarf_ctx) = dwarf_context {
                    if let Some(cfi_rule) = dwarf_ctx.get_cfi_rule_for_pc(pc_address) {
                        debug!(
                            "Found CFI rule for frame base at PC 0x{:x}: {:?}",
                            pc_address, cfi_rule
                        );
                        return self.combine_cfi_with_offset(
                            &cfi_rule, *offset, dwarf_ctx, pc_address, context,
                        );
                    }
                }
                // Fallback to simple frame offset
                warn!(
                    "No CFI context available for frame base at PC 0x{:x}, using simple offset",
                    pc_address
                );
                Ok(EvaluationResult::FrameOffset(*offset))
            }

            DwarfOperation::CallFrameCFA => {
                // Query CFI for CFA calculation
                if let Some(dwarf_ctx) = dwarf_context {
                    if let Some(cfi_rule) = dwarf_ctx.get_cfi_rule_for_pc(pc_address) {
                        debug!(
                            "Found CFI rule for CFA at PC 0x{:x}: {:?}",
                            pc_address, cfi_rule
                        );
                        return self
                            .combine_cfi_with_offset(&cfi_rule, 0, dwarf_ctx, pc_address, context);
                    }
                }
                // Fallback to simple CFA offset
                warn!("No CFI context available for CFA at PC 0x{:x}", pc_address);
                Ok(EvaluationResult::CFAOffset(0))
            }

            DwarfOperation::Address(addr) => Ok(EvaluationResult::Address(*addr)),

            DwarfOperation::Literal(value) | DwarfOperation::Consts(value) => {
                Ok(EvaluationResult::Value(*value))
            }

            _ => {
                // For other operations, evaluate normally and convert result
                let mut stack = Vec::new();
                self.execute_operation(operation, &mut stack, context)?;
                let value = stack.last().copied().unwrap_or(0);
                Ok(EvaluationResult::Value(value))
            }
        }
    }

    /// Pattern analysis with CFI awareness
    fn analyze_operation_patterns_for_codegen(
        &self,
        operations: &[DwarfOperation],
        pc_address: u64,
        context: &EvaluationContext,
        dwarf_context: Option<&DwarfContext>,
    ) -> Result<Option<EvaluationResult>, ExpressionError> {
        // Handle common patterns with CFI awareness
        match operations {
            // Frame base + offset: DW_OP_fbreg <offset>
            [DwarfOperation::FrameBase(offset)] => {
                Ok(Some(self.evaluate_single_operation_for_codegen(
                    &DwarfOperation::FrameBase(*offset),
                    pc_address,
                    context,
                    dwarf_context,
                )?))
            }

            // Frame base dereference: DW_OP_fbreg <offset>, DW_OP_deref
            [DwarfOperation::FrameBase(offset), DwarfOperation::Deref(size)] => {
                if let Some(dwarf_ctx) = dwarf_context {
                    if let Some(cfi_rule) = dwarf_ctx.get_cfi_rule_for_pc(pc_address) {
                        // Convert CFI rule to register access with dereference
                        let base_result = self.combine_cfi_with_offset(
                            &cfi_rule, *offset, dwarf_ctx, pc_address, context,
                        )?;
                        if let EvaluationResult::Register(mut reg_access) = base_result {
                            reg_access.dereference = true;
                            reg_access.size = Some(*size);
                            return Ok(Some(EvaluationResult::Register(reg_access)));
                        }
                    }
                }
                // Fallback to computed access
                Ok(Some(EvaluationResult::ComputedAccess {
                    steps: vec![
                        AccessStep::LoadFrameBase,
                        AccessStep::AddConstant(*offset),
                        AccessStep::Dereference { size: *size },
                    ],
                    requires_frame_base: true,
                    requires_registers: vec![],
                    requires_cfa: false,
                }))
            }

            // Other patterns can be added here
            _ => Ok(None),
        }
    }

    /// Combine CFI rule with offset for final calculation
    fn combine_cfi_with_offset(
        &self,
        cfi_rule: &crate::dwarf::CFARule,
        offset: i64,
        dwarf_context: &DwarfContext,
        pc_address: u64,
        context: &EvaluationContext,
    ) -> Result<EvaluationResult, ExpressionError> {
        use crate::dwarf::CFARule;

        match cfi_rule {
            CFARule::RegisterOffset {
                register,
                offset: cfi_offset,
            } => {
                // Combine CFI offset with variable offset
                let final_offset = cfi_offset + offset;
                Ok(EvaluationResult::Register(RegisterAccess {
                    register: *register,
                    offset: Some(final_offset),
                    dereference: false,
                    size: None,
                }))
            }

            CFARule::Expression(dwarf_ops) => {
                // Convert legacy DwarfOp to DwarfOperation and evaluate recursively
                debug!(
                    "Evaluating CFI expression with {} operations",
                    dwarf_ops.len()
                );
                let converted_ops: Result<Vec<DwarfOperation>, ExpressionError> = dwarf_ops
                    .iter()
                    .map(|op| self.convert_legacy_dwarf_op(op))
                    .collect();

                match converted_ops {
                    Ok(operations) => {
                        // Recursively evaluate CFI expression
                        let cfi_result = self.evaluate_dwarf_expression_for_codegen(
                            &operations,
                            pc_address,
                            context,
                            Some(dwarf_context),
                        )?;

                        // Apply offset to the CFI result
                        self.apply_offset_to_result(cfi_result, offset)
                    }
                    Err(e) => {
                        error!("Failed to convert CFI expression: {}", e);
                        Err(e)
                    }
                }
            }

            CFARule::Undefined => Err(ExpressionError::EvaluationFailed(format!(
                "CFI rule undefined at PC 0x{:x}",
                pc_address
            ))),
        }
    }

    /// Apply offset to evaluation result
    fn apply_offset_to_result(
        &self,
        mut result: EvaluationResult,
        offset: i64,
    ) -> Result<EvaluationResult, ExpressionError> {
        if offset == 0 {
            return Ok(result);
        }

        match &mut result {
            EvaluationResult::Register(reg_access) => {
                let current_offset = reg_access.offset.unwrap_or(0);
                reg_access.offset = Some(current_offset + offset);
                Ok(result)
            }
            EvaluationResult::Address(addr) => {
                *addr = ((*addr as i64) + offset) as u64;
                Ok(result)
            }
            EvaluationResult::Value(value) => {
                *value += offset;
                Ok(result)
            }
            _ => {
                debug!(
                    "Cannot apply offset {} to result type: {:?}",
                    offset, result
                );
                Ok(result)
            }
        }
    }

    /// Full evaluation with CFI awareness (fallback method)
    fn evaluate_operations_with_cfi(
        &self,
        operations: &[DwarfOperation],
        pc_address: u64,
        context: &EvaluationContext,
        dwarf_context: Option<&DwarfContext>,
    ) -> Result<EvaluationResult, ExpressionError> {
        debug!(
            "Performing full CFI-aware evaluation of {} operations",
            operations.len()
        );

        // For now, fall back to existing evaluation and enhance step by step
        // TODO: Implement full CFI-aware stack evaluation
        let steps = self.operations_to_access_steps(operations);
        Ok(EvaluationResult::ComputedAccess {
            steps,
            requires_frame_base: operations
                .iter()
                .any(|op| matches!(op, DwarfOperation::FrameBase(_))),
            requires_registers: self.extract_required_registers(operations),
            requires_cfa: operations
                .iter()
                .any(|op| matches!(op, DwarfOperation::CallFrameCFA)),
        })
    }

    /// Extract required registers from operations
    fn extract_required_registers(&self, operations: &[DwarfOperation]) -> Vec<u16> {
        let mut registers = Vec::new();
        for op in operations {
            match op {
                DwarfOperation::Register(reg) | DwarfOperation::RegisterOffset(reg, _) => {
                    if !registers.contains(reg) {
                        registers.push(*reg);
                    }
                }
                _ => {}
            }
        }
        registers
    }

    /// Execute a single DWARF operation on the expression stack
    fn execute_operation(
        &self,
        op: &DwarfOperation,
        stack: &mut Vec<i64>,
        context: &EvaluationContext,
    ) -> Result<(), ExpressionError> {
        // Check stack depth limit
        if stack.len() > self.max_stack_depth {
            return Err(ExpressionError::StackOverflow);
        }

        debug!("Executing DWARF operation: {:?}", op);

        match op {
            // === Literal Operations ===
            DwarfOperation::Literal(value) => {
                stack.push(*value);
                debug!("Pushed literal: {}", value);
            }

            DwarfOperation::Const1u(value) => stack.push(*value as i64),
            DwarfOperation::Const1s(value) => stack.push(*value as i64),
            DwarfOperation::Const2u(value) => stack.push(*value as i64),
            DwarfOperation::Const2s(value) => stack.push(*value as i64),
            DwarfOperation::Const4u(value) => stack.push(*value as i64),
            DwarfOperation::Const4s(value) => stack.push(*value as i64),
            DwarfOperation::Const8u(value) => stack.push(*value as i64),
            DwarfOperation::Const8s(value) => stack.push(*value),
            DwarfOperation::Constu(value) => stack.push(*value as i64),
            DwarfOperation::Consts(value) => stack.push(*value),

            // === Register Operations ===
            // These operations should not be used in symbolic expression generation
            // All register accesses should go through symbolic paths instead
            DwarfOperation::Register(reg) => {
                debug!("Register operation: reg {} (should use symbolic path)", reg);
                return Err(ExpressionError::EvaluationFailed(format!(
                    "Register {} access requires codegen handling",
                    reg
                )));
            }

            DwarfOperation::RegisterOffset(reg, offset) => {
                debug!(
                    "Register offset operation: reg {} + {} (should use symbolic path)",
                    reg, offset
                );
                return Err(ExpressionError::EvaluationFailed(format!(
                    "Register {} offset {} requires codegen handling",
                    reg, offset
                )));
            }

            // === Stack Manipulation ===
            DwarfOperation::Dup => {
                let top = stack
                    .last()
                    .copied()
                    .ok_or(ExpressionError::StackUnderflow)?;
                stack.push(top);
                debug!("Duplicated top stack value: {}", top);
            }

            DwarfOperation::Drop => {
                stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                debug!("Dropped top stack value");
            }

            DwarfOperation::Swap => {
                if stack.len() < 2 {
                    return Err(ExpressionError::StackUnderflow);
                }
                let len = stack.len();
                stack.swap(len - 1, len - 2);
                debug!("Swapped top two stack values");
            }

            DwarfOperation::Rotate => {
                if stack.len() < 3 {
                    return Err(ExpressionError::StackUnderflow);
                }
                let len = stack.len();
                // DWARF rotation: [c, b, a] -> [a, c, b]
                // Top (a) becomes third, Second (b) becomes top, Third (c) becomes second
                let a = stack[len - 1]; // top element
                let b = stack[len - 2]; // second element
                let c = stack[len - 3]; // third element
                stack[len - 1] = b; // second becomes new top
                stack[len - 2] = c; // third becomes second
                stack[len - 3] = a; // top becomes third
                debug!(
                    "Rotated top three stack values: [c={}, b={}, a={}] -> [a={}, c={}, b={}]",
                    c, b, a, a, c, b
                );
            }

            DwarfOperation::Pick(index) => {
                let stack_index = stack
                    .len()
                    .checked_sub((*index as usize) + 1)
                    .ok_or(ExpressionError::StackUnderflow)?;
                let value = stack[stack_index];
                stack.push(value);
                debug!("Picked value from stack index {}: {}", index, value);
            }

            DwarfOperation::Over => {
                if stack.len() < 2 {
                    return Err(ExpressionError::StackUnderflow);
                }
                let len = stack.len();
                let value = stack[len - 2];
                stack.push(value);
                debug!("Copied second stack value to top: {}", value);
            }

            // === Arithmetic Operations ===
            DwarfOperation::Add => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = a.wrapping_add(b);
                stack.push(result);
                debug!("Addition: {} + {} = {}", a, b, result);
            }

            DwarfOperation::Sub => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = a.wrapping_sub(b);
                stack.push(result);
                debug!("Subtraction: {} - {} = {}", a, b, result);
            }

            DwarfOperation::Mul => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = a.wrapping_mul(b);
                stack.push(result);
                debug!("Multiplication: {} * {} = {}", a, b, result);
            }

            DwarfOperation::Div => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                if b == 0 {
                    return Err(ExpressionError::DivisionByZero);
                }
                let result = a / b;
                stack.push(result);
                debug!("Division: {} / {} = {}", a, b, result);
            }

            DwarfOperation::Mod => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                if b == 0 {
                    return Err(ExpressionError::DivisionByZero);
                }
                let result = a % b;
                stack.push(result);
                debug!("Modulo: {} % {} = {}", a, b, result);
            }

            DwarfOperation::Neg => {
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = a.wrapping_neg();
                stack.push(result);
                debug!("Negation: -{} = {}", a, result);
            }

            DwarfOperation::Abs => {
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = a.abs();
                stack.push(result);
                debug!("Absolute: abs({}) = {}", a, result);
            }

            // === Bitwise Operations ===
            DwarfOperation::And => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = a & b;
                stack.push(result);
                debug!("Bitwise AND: {} & {} = {}", a, b, result);
            }

            DwarfOperation::Or => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = a | b;
                stack.push(result);
                debug!("Bitwise OR: {} | {} = {}", a, b, result);
            }

            DwarfOperation::Xor => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = a ^ b;
                stack.push(result);
                debug!("Bitwise XOR: {} ^ {} = {}", a, b, result);
            }

            DwarfOperation::Not => {
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = !a;
                stack.push(result);
                debug!("Bitwise NOT: ~{} = {}", a, result);
            }

            DwarfOperation::Shl => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                if b < 0 || b >= 64 {
                    return Err(ExpressionError::EvaluationFailed(format!(
                        "Invalid shift amount: {}",
                        b
                    )));
                }
                let result = a << (b as u32);
                stack.push(result);
                debug!("Left shift: {} << {} = {}", a, b, result);
            }

            DwarfOperation::Shr => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                if b < 0 || b >= 64 {
                    return Err(ExpressionError::EvaluationFailed(format!(
                        "Invalid shift amount: {}",
                        b
                    )));
                }
                let result = ((a as u64) >> (b as u32)) as i64;
                stack.push(result);
                debug!("Right shift (logical): {} >> {} = {}", a, b, result);
            }

            DwarfOperation::Shra => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                if b < 0 || b >= 64 {
                    return Err(ExpressionError::EvaluationFailed(format!(
                        "Invalid shift amount: {}",
                        b
                    )));
                }
                let result = a >> (b as u32);
                stack.push(result);
                debug!("Right shift (arithmetic): {} >> {} = {}", a, b, result);
            }

            // === Comparison Operations ===
            DwarfOperation::Eq => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = if a == b { 1 } else { 0 };
                stack.push(result);
                debug!("Equality: {} == {} = {}", a, b, result);
            }

            DwarfOperation::Ne => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = if a != b { 1 } else { 0 };
                stack.push(result);
                debug!("Not equal: {} != {} = {}", a, b, result);
            }

            DwarfOperation::Lt => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = if a < b { 1 } else { 0 };
                stack.push(result);
                debug!("Less than: {} < {} = {}", a, b, result);
            }

            DwarfOperation::Gt => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = if a > b { 1 } else { 0 };
                stack.push(result);
                debug!("Greater than: {} > {} = {}", a, b, result);
            }

            DwarfOperation::Le => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = if a <= b { 1 } else { 0 };
                stack.push(result);
                debug!("Less or equal: {} <= {} = {}", a, b, result);
            }

            DwarfOperation::Ge => {
                let b = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let a = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                let result = if a >= b { 1 } else { 0 };
                stack.push(result);
                debug!("Greater or equal: {} >= {} = {}", a, b, result);
            }

            // === Frame Base and CFA Operations ===
            // These operations should generate symbolic expressions instead of actual calculations
            DwarfOperation::FrameBase(offset) => {
                debug!(
                    "Frame base operation with offset: {} (should use symbolic path)",
                    offset
                );
                return Err(ExpressionError::EvaluationFailed(format!(
                    "Frame base {} requires codegen handling",
                    offset
                )));
            }

            DwarfOperation::CallFrameCFA => {
                debug!("Call frame CFA operation (should use symbolic path)");
                return Err(ExpressionError::EvaluationFailed(
                    "CFA requires codegen handling".into(),
                ));
            }

            // === Memory Operations ===
            DwarfOperation::Deref(size) => {
                let addr = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                debug!("Memory dereference: addr=0x{:x}, size={}", addr, size);

                // In our eBPF context, we cannot actually dereference memory here
                // This will be handled by LLVM codegen to generate bpf_probe_read_user calls
                // For now, we keep the address on stack and mark it for deref in codegen
                stack.push(addr);

                // Return a special marker indicating this needs memory access in codegen
                return Err(ExpressionError::EvaluationFailed(format!(
                    "Memory dereference at 0x{:x} requires codegen handling",
                    addr
                )));
            }

            DwarfOperation::DerefSize(size) => {
                let addr = stack.pop().ok_or(ExpressionError::StackUnderflow)?;
                debug!(
                    "Memory dereference with size: addr=0x{:x}, size={}",
                    addr, size
                );

                stack.push(addr);
                return Err(ExpressionError::EvaluationFailed(format!(
                    "Memory dereference at 0x{:x} (size {}) requires codegen handling",
                    addr, size
                )));
            }

            // === Special Operations ===
            DwarfOperation::Address(addr) => {
                stack.push(*addr as i64);
                debug!("Pushed address: 0x{:x}", addr);
            }

            DwarfOperation::StackValue => {
                debug!("Stack value operation - value remains on stack");
                // The top of stack is the result value, not an address
                // This is a marker for the expression evaluator
            }

            DwarfOperation::ImplicitValue(data) => {
                debug!("Implicit value operation with {} bytes", data.len());
                // For implicit values, we need to interpret the data based on context
                // For now, just push 0 as a placeholder
                stack.push(0);
            }

            // === Control Flow Operations (Simplified) ===
            DwarfOperation::Skip(offset) => {
                debug!("Skip operation with offset: {}", offset);
                // In our simplified implementation, we don't support jumps
                return Err(ExpressionError::UnsupportedOperation(
                    "Skip operations not supported in this context".into(),
                ));
            }

            DwarfOperation::Branch(_offset) => {
                debug!("Branch operation");
                // Conditional branch - not supported in our simplified implementation
                return Err(ExpressionError::UnsupportedOperation(
                    "Branch operations not supported in this context".into(),
                ));
            }

            // === TODO: Advanced Operations ===
            DwarfOperation::Convert(_) => {
                return Err(ExpressionError::UnsupportedOperation(
                    "TODO: DW_OP_convert not yet implemented".into(),
                ));
            }

            DwarfOperation::Reinterpret(_) => {
                return Err(ExpressionError::UnsupportedOperation(
                    "TODO: DW_OP_reinterpret not yet implemented".into(),
                ));
            }

            DwarfOperation::Entry(_) => {
                return Err(ExpressionError::UnsupportedOperation(
                    "TODO: DW_OP_entry_value not yet implemented".into(),
                ));
            }

            DwarfOperation::ConstType(_, _) => {
                return Err(ExpressionError::UnsupportedOperation(
                    "TODO: DW_OP_const_type not yet implemented".into(),
                ));
            }

            DwarfOperation::RegvalType(_, _) => {
                return Err(ExpressionError::UnsupportedOperation(
                    "TODO: DW_OP_regval_type not yet implemented".into(),
                ));
            }

            DwarfOperation::DerefType(_, _) => {
                return Err(ExpressionError::UnsupportedOperation(
                    "TODO: DW_OP_deref_type not yet implemented".into(),
                ));
            }

            DwarfOperation::XDeref(_)
            | DwarfOperation::XDerefSize(_, _)
            | DwarfOperation::XDerefType(_, _, _) => {
                return Err(ExpressionError::UnsupportedOperation(
                    "TODO: Extended dereference operations not yet implemented".into(),
                ));
            }

            DwarfOperation::Piece(_) | DwarfOperation::BitPiece(_, _) => {
                return Err(ExpressionError::UnsupportedOperation(
                    "TODO: Piece operations not yet implemented".into(),
                ));
            }

            DwarfOperation::ImplicitPointer(_, _) => {
                return Err(ExpressionError::UnsupportedOperation(
                    "TODO: DW_OP_implicit_pointer not yet implemented".into(),
                ));
            }

            DwarfOperation::GnuEntryValue(_) => {
                return Err(ExpressionError::UnsupportedOperation(
                    "TODO: GNU entry value extension not yet implemented".into(),
                ));
            }

            DwarfOperation::GnuConstType(_, _) => {
                return Err(ExpressionError::UnsupportedOperation(
                    "TODO: GNU const type extension not yet implemented".into(),
                ));
            }

            DwarfOperation::RegisterValue(_) => {
                return Err(ExpressionError::UnsupportedOperation(
                    "TODO: DW_OP_regval_type not yet implemented".into(),
                ));
            }
        }

        Ok(())
    }

    /// Enhanced pattern analysis and optimization (implements task 6)
    fn convert_to_steps(&self, ops: &[DwarfOp]) -> Vec<AccessStep> {
        debug!("Converting {} legacy operations to access steps", ops.len());

        let mut steps = Vec::new();

        for op in ops {
            match op {
                DwarfOp::Reg(reg) => {
                    steps.push(AccessStep::LoadRegister(*reg));
                }

                DwarfOp::Breg(reg, offset) => {
                    steps.push(AccessStep::LoadRegister(*reg));
                    if *offset != 0 {
                        steps.push(AccessStep::AddConstant(*offset));
                    }
                }

                DwarfOp::Fbreg(offset) => {
                    steps.push(AccessStep::LoadFrameBase);
                    if *offset != 0 {
                        steps.push(AccessStep::AddConstant(*offset));
                    }
                }

                DwarfOp::Deref => {
                    steps.push(AccessStep::Dereference { size: 8 }); // Default to 8 bytes
                }

                DwarfOp::Plus => {
                    steps.push(AccessStep::ArithmeticOp(ArithOp::Add));
                }

                DwarfOp::PlusUconst(value) => {
                    steps.push(AccessStep::AddConstant(*value as i64));
                }

                DwarfOp::Const(value) => {
                    steps.push(AccessStep::AddConstant(*value));
                }

                DwarfOp::Dup => {
                    // Dup doesn't translate directly to access steps
                    // This would need special handling in complex expressions
                    debug!("Stack operation DW_OP_dup in access steps - may need special handling");
                }

                DwarfOp::Drop => {
                    debug!(
                        "Stack operation DW_OP_drop in access steps - may need special handling"
                    );
                }

                DwarfOp::Swap => {
                    debug!(
                        "Stack operation DW_OP_swap in access steps - may need special handling"
                    );
                }

                DwarfOp::StackValue => {
                    // StackValue is a marker that the result is a value, not an address
                    debug!("DW_OP_stack_value encountered - result is a value");
                }
            }
        }

        steps
    }

    fn cfi_to_eval_context(&self, cfi_context: &CFIContext) -> EvaluationContext {
        EvaluationContext {
            pc_address: cfi_context.pc_address,
            address_size: cfi_context.address_size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Helper function to create a basic evaluation context for testing
    fn create_test_context() -> EvaluationContext {
        let mut registers = HashMap::new();
        // Setup some test register values (using x86-64 register numbers)
        registers.insert(0, 0x1000); // RAX
        registers.insert(1, 0x2000); // RDX
        registers.insert(4, 0x3000); // RSI
        registers.insert(5, 0x4000); // RDI
        registers.insert(6, 0x7fff_ffff_f000); // RBP (frame pointer)
        registers.insert(7, 0x7fff_ffff_e000); // RSP (stack pointer)

        EvaluationContext {
            pc_address: 0x400000,
            frame_base: Some(0x7fff_ffff_f000),
            call_frame_cfa: Some(0x7fff_ffff_e008),
            available_registers: registers,
            address_size: 8,
        }
    }

    /// Helper function to create evaluator for testing
    fn create_evaluator() -> DwarfExpressionEvaluator {
        DwarfExpressionEvaluator::new()
    }

    #[test]
    fn test_basic_operation_execution() {
        let evaluator = create_evaluator();
        let context = create_test_context();
        let mut stack = Vec::new();

        // Test literal operation
        let result =
            evaluator.execute_operation(&DwarfOperation::Literal(42), &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![42]);

        // Test register operation
        stack.clear();
        let result = evaluator.execute_operation(
            &DwarfOperation::Register(0), // RAX
            &mut stack,
            &context,
        );
        assert!(result.is_ok());
        assert_eq!(stack, vec![0x1000]);

        // Test register + offset
        stack.clear();
        let result = evaluator.execute_operation(
            &DwarfOperation::RegisterOffset(0, 8), // RAX + 8
            &mut stack,
            &context,
        );
        assert!(result.is_ok());
        assert_eq!(stack, vec![0x1008]);
    }

    #[test]
    fn test_arithmetic_operations() {
        let evaluator = create_evaluator();
        let context = create_test_context();
        let mut stack = Vec::new();

        // Test addition: 10 + 20 = 30
        stack.push(10);
        stack.push(20);
        let result = evaluator.execute_operation(&DwarfOperation::Add, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![30]);

        // Test subtraction: 50 - 20 = 30
        stack.clear();
        stack.push(50);
        stack.push(20);
        let result = evaluator.execute_operation(&DwarfOperation::Sub, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![30]);

        // Test multiplication: 6 * 7 = 42
        stack.clear();
        stack.push(6);
        stack.push(7);
        let result = evaluator.execute_operation(&DwarfOperation::Mul, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![42]);

        // Test division: 84 / 2 = 42
        stack.clear();
        stack.push(84);
        stack.push(2);
        let result = evaluator.execute_operation(&DwarfOperation::Div, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![42]);

        // Test division by zero
        stack.clear();
        stack.push(42);
        stack.push(0);
        let result = evaluator.execute_operation(&DwarfOperation::Div, &mut stack, &context);
        assert!(matches!(result, Err(ExpressionError::DivisionByZero)));
    }

    #[test]
    fn test_bitwise_operations() {
        let evaluator = create_evaluator();
        let context = create_test_context();
        let mut stack = Vec::new();

        // Test bitwise AND: 0xFF & 0x0F = 0x0F
        stack.push(0xFF);
        stack.push(0x0F);
        let result = evaluator.execute_operation(&DwarfOperation::And, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![0x0F]);

        // Test bitwise OR: 0xF0 | 0x0F = 0xFF
        stack.clear();
        stack.push(0xF0);
        stack.push(0x0F);
        let result = evaluator.execute_operation(&DwarfOperation::Or, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![0xFF]);

        // Test bitwise XOR: 0xFF ^ 0xF0 = 0x0F
        stack.clear();
        stack.push(0xFF);
        stack.push(0xF0);
        let result = evaluator.execute_operation(&DwarfOperation::Xor, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![0x0F]);

        // Test bitwise NOT: ~0x00 = -1 (two's complement)
        stack.clear();
        stack.push(0x00);
        let result = evaluator.execute_operation(&DwarfOperation::Not, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![-1]);

        // Test left shift: 1 << 3 = 8
        stack.clear();
        stack.push(1);
        stack.push(3);
        let result = evaluator.execute_operation(&DwarfOperation::Shl, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![8]);

        // Test right shift: 16 >> 2 = 4
        stack.clear();
        stack.push(16);
        stack.push(2);
        let result = evaluator.execute_operation(&DwarfOperation::Shr, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![4]);
    }

    #[test]
    fn test_comparison_operations() {
        let evaluator = create_evaluator();
        let context = create_test_context();
        let mut stack = Vec::new();

        // Test equality: 42 == 42 = 1 (true)
        stack.push(42);
        stack.push(42);
        let result = evaluator.execute_operation(&DwarfOperation::Eq, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![1]);

        // Test inequality: 42 != 24 = 1 (true)
        stack.clear();
        stack.push(42);
        stack.push(24);
        let result = evaluator.execute_operation(&DwarfOperation::Ne, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![1]);

        // Test less than: 10 < 20 = 1 (true)
        stack.clear();
        stack.push(10);
        stack.push(20);
        let result = evaluator.execute_operation(&DwarfOperation::Lt, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![1]);

        // Test greater than: 30 > 20 = 1 (true)
        stack.clear();
        stack.push(30);
        stack.push(20);
        let result = evaluator.execute_operation(&DwarfOperation::Gt, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![1]);

        // Test less or equal: 20 <= 20 = 1 (true)
        stack.clear();
        stack.push(20);
        stack.push(20);
        let result = evaluator.execute_operation(&DwarfOperation::Le, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![1]);

        // Test greater or equal: 25 >= 20 = 1 (true)
        stack.clear();
        stack.push(25);
        stack.push(20);
        let result = evaluator.execute_operation(&DwarfOperation::Ge, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![1]);
    }

    #[test]
    fn test_stack_operations() {
        let evaluator = create_evaluator();
        let context = create_test_context();
        let mut stack = Vec::new();

        // Test DUP operation
        stack.push(42);
        let result = evaluator.execute_operation(&DwarfOperation::Dup, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![42, 42]);

        // Test DROP operation
        let result = evaluator.execute_operation(&DwarfOperation::Drop, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![42]);

        // Test SWAP operation
        stack.push(24);
        let result = evaluator.execute_operation(&DwarfOperation::Swap, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![24, 42]);

        // Test ROTATE operation
        stack.push(13);
        let result = evaluator.execute_operation(&DwarfOperation::Rotate, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![13, 24, 42]);

        // Test PICK operation
        let result = evaluator.execute_operation(&DwarfOperation::Pick(1), &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![13, 24, 42, 24]);

        // Test OVER operation
        stack.clear();
        stack.push(10);
        stack.push(20);
        let result = evaluator.execute_operation(&DwarfOperation::Over, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![10, 20, 10]);
    }

    #[test]
    fn test_frame_and_cfa_operations() {
        let evaluator = create_evaluator();
        let context = create_test_context();
        let mut stack = Vec::new();

        // Test frame base + offset
        let result =
            evaluator.execute_operation(&DwarfOperation::FrameBase(-8), &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![0x7fff_ffff_f000i64 - 8]);

        // Test call frame CFA
        stack.clear();
        let result =
            evaluator.execute_operation(&DwarfOperation::CallFrameCFA, &mut stack, &context);
        assert!(result.is_ok());
        assert_eq!(stack, vec![0x7fff_ffff_e008i64]);
    }

    #[test]
    fn test_error_conditions() {
        let evaluator = create_evaluator();
        let context = create_test_context();
        let mut stack = Vec::new();

        // Test stack underflow on ADD
        let result = evaluator.execute_operation(&DwarfOperation::Add, &mut stack, &context);
        assert!(matches!(result, Err(ExpressionError::StackUnderflow)));

        // Test stack underflow on DUP
        let result = evaluator.execute_operation(&DwarfOperation::Dup, &mut stack, &context);
        assert!(matches!(result, Err(ExpressionError::StackUnderflow)));

        // Test invalid register
        let result =
            evaluator.execute_operation(&DwarfOperation::Register(999), &mut stack, &context);
        assert!(matches!(result, Err(ExpressionError::InvalidRegister(999))));

        // Test frame base unavailable
        let mut context_no_fb = context.clone();
        context_no_fb.frame_base = None;
        let result =
            evaluator.execute_operation(&DwarfOperation::FrameBase(8), &mut stack, &context_no_fb);
        assert!(matches!(result, Err(ExpressionError::FrameBaseUnavailable)));
    }

    #[test]
    fn test_pattern_analysis() {
        let evaluator = create_evaluator();

        // Test direct register pattern
        let pattern = evaluator.analyze_pattern(&[DwarfOp::Reg(0)]);
        assert!(matches!(pattern, OptimizedPattern::RegisterDirect(0)));

        // Test register + offset pattern
        let pattern = evaluator.analyze_pattern(&[DwarfOp::Breg(1, 8)]);
        assert!(matches!(pattern, OptimizedPattern::RegisterOffset(1, 8)));

        // Test frame base + offset pattern
        let pattern = evaluator.analyze_pattern(&[DwarfOp::Fbreg(-16)]);
        assert!(matches!(pattern, OptimizedPattern::FrameBaseOffset(-16)));

        // Test constant pattern
        let pattern = evaluator.analyze_pattern(&[DwarfOp::Const(42)]);
        assert!(matches!(pattern, OptimizedPattern::ConstantValue(42)));

        // Test two-step dereference pattern
        let pattern = evaluator.analyze_pattern(&[DwarfOp::Breg(6, -8), DwarfOp::Deref]);
        assert!(matches!(
            pattern,
            OptimizedPattern::TwoStepDereference(6, -8)
        ));

        // Test register + constant pattern
        let pattern =
            evaluator.analyze_pattern(&[DwarfOp::Reg(0), DwarfOp::Const(16), DwarfOp::Plus]);
        assert!(matches!(pattern, OptimizedPattern::RegisterOffset(0, 16)));

        // Test register + plus_uconst pattern
        let pattern = evaluator.analyze_pattern(&[DwarfOp::Reg(1), DwarfOp::PlusUconst(24)]);
        assert!(matches!(pattern, OptimizedPattern::RegisterOffset(1, 24)));
    }

    #[test]
    fn test_constant_offset_calculation() {
        let evaluator = create_evaluator();

        // Test simple constant
        let offset = evaluator.calculate_constant_offset(&[DwarfOp::Const(42)]);
        assert_eq!(offset, Some(42));

        // Test plus_uconst on empty stack (should fail)
        let offset = evaluator.calculate_constant_offset(&[DwarfOp::PlusUconst(10)]);
        assert_eq!(offset, None);

        // Test addition: const 10, const 20, plus = 30
        let offset = evaluator.calculate_constant_offset(&[
            DwarfOp::Const(10),
            DwarfOp::Const(20),
            DwarfOp::Plus,
        ]);
        assert_eq!(offset, Some(30));

        // Test complex arithmetic: should result in single value
        let offset = evaluator.calculate_constant_offset(&[
            DwarfOp::Const(5),
            DwarfOp::Const(3),
            DwarfOp::Plus, // 5 + 3 = 8
            DwarfOp::Const(2),
            DwarfOp::Plus, // 8 + 2 = 10
        ]);
        assert_eq!(offset, Some(10));
    }

    #[test]
    fn test_legacy_dwarf_op_conversion() {
        let evaluator = create_evaluator();

        // Test various legacy operations
        assert!(matches!(
            evaluator.convert_legacy_dwarf_op(&DwarfOp::Const(42)),
            Ok(DwarfOperation::Literal(42))
        ));

        assert!(matches!(
            evaluator.convert_legacy_dwarf_op(&DwarfOp::Reg(0)),
            Ok(DwarfOperation::Register(0))
        ));

        assert!(matches!(
            evaluator.convert_legacy_dwarf_op(&DwarfOp::Breg(1, 8)),
            Ok(DwarfOperation::RegisterOffset(1, 8))
        ));

        assert!(matches!(
            evaluator.convert_legacy_dwarf_op(&DwarfOp::Fbreg(-16)),
            Ok(DwarfOperation::FrameBase(-16))
        ));

        assert!(matches!(
            evaluator.convert_legacy_dwarf_op(&DwarfOp::Deref),
            Ok(DwarfOperation::Deref(8))
        ));

        assert!(matches!(
            evaluator.convert_legacy_dwarf_op(&DwarfOp::Plus),
            Ok(DwarfOperation::Add)
        ));

        assert!(matches!(
            evaluator.convert_legacy_dwarf_op(&DwarfOp::PlusUconst(16)),
            Ok(DwarfOperation::Constu(16))
        ));
    }

    #[test]
    fn test_evaluate_operations_simple_cases() {
        let evaluator = create_evaluator();
        let context = create_test_context();

        // Test single register operation
        let ops = vec![DwarfOperation::Register(0)];
        let result = evaluator.evaluate_operations(&ops, &context);
        assert!(result.is_ok());
        if let Ok(EvaluationResult::Register(reg_access)) = result {
            assert_eq!(reg_access.register, 0);
            assert_eq!(reg_access.offset, None);
            assert_eq!(reg_access.dereference, false);
        } else {
            panic!("Expected Register result");
        }

        // Test constant operation
        let ops = vec![DwarfOperation::Literal(42)];
        let result = evaluator.evaluate_operations(&ops, &context);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), EvaluationResult::Value(42)));

        // Test frame base operation
        let ops = vec![DwarfOperation::FrameBase(-8)];
        let result = evaluator.evaluate_operations(&ops, &context);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), EvaluationResult::FrameOffset(-8)));
    }

    #[test]
    fn test_complex_expression_evaluation() {
        let evaluator = create_evaluator();
        let context = create_test_context();

        // Test complex arithmetic expression: reg0 + 8 + 4 = 0x1000 + 12 = 0x100C
        let ops = vec![
            DwarfOperation::Register(0), // Push 0x1000
            DwarfOperation::Literal(8),  // Push 8
            DwarfOperation::Add,         // 0x1000 + 8 = 0x1008
            DwarfOperation::Literal(4),  // Push 4
            DwarfOperation::Add,         // 0x1008 + 4 = 0x100C
        ];
        let result = evaluator.evaluate_operations(&ops, &context);
        assert!(result.is_ok());
        // This should be classified as a complex computed access since it involves a register
        if let Ok(EvaluationResult::ComputedAccess {
            requires_registers, ..
        }) = result
        {
            assert!(requires_registers.contains(&0));
        } else if let Ok(EvaluationResult::Value(_)) = result {
            // Could also be optimized to a pure value in some cases
        } else {
            panic!("Unexpected evaluation result: {:?}", result);
        }
    }

    #[test]
    fn test_memory_dereference_handling() {
        let evaluator = create_evaluator();
        let context = create_test_context();

        // Test that memory dereference is properly detected and marked
        let ops = vec![
            DwarfOperation::RegisterOffset(6, -8), // RBP - 8
            DwarfOperation::Deref(8),              // Dereference 8 bytes
        ];
        let result = evaluator.evaluate_operations(&ops, &context);
        assert!(result.is_ok());
        // Should be classified as computed access requiring memory dereference
        if let Ok(EvaluationResult::ComputedAccess {
            steps,
            requires_registers,
            ..
        }) = result
        {
            assert!(requires_registers.contains(&6));
            assert!(steps
                .iter()
                .any(|step| matches!(step, AccessStep::Dereference { .. })));
        } else {
            panic!("Expected ComputedAccess result for memory dereference");
        }
    }

    #[test]
    fn test_operations_to_access_steps() {
        let evaluator = create_evaluator();

        let ops = vec![
            DwarfOperation::RegisterOffset(6, -16),
            DwarfOperation::Deref(4),
            DwarfOperation::Literal(8),
            DwarfOperation::Add,
        ];

        let steps = evaluator.operations_to_access_steps(&ops);
        assert_eq!(steps.len(), 5);

        assert!(matches!(steps[0], AccessStep::LoadRegister(6)));
        assert!(matches!(steps[1], AccessStep::AddConstant(-16)));
        assert!(matches!(steps[2], AccessStep::Dereference { size: 4 }));
        assert!(matches!(steps[3], AccessStep::AddConstant(8)));
        assert!(matches!(steps[4], AccessStep::ArithmeticOp(ArithOp::Add)));
    }

    #[test]
    fn test_evaluator_configuration() {
        // Test with optimization disabled
        let evaluator = DwarfExpressionEvaluator::with_config(500, false);
        let pattern = evaluator.analyze_pattern(&[DwarfOp::Reg(0)]);
        // Should fall back to complex computed since optimization is disabled
        assert!(matches!(pattern, OptimizedPattern::ComplexComputed(_)));

        // Test with optimization enabled
        let evaluator = DwarfExpressionEvaluator::with_config(1000, true);
        let pattern = evaluator.analyze_pattern(&[DwarfOp::Reg(0)]);
        // Should recognize the pattern
        assert!(matches!(pattern, OptimizedPattern::RegisterDirect(0)));
    }

    #[test]
    fn test_edge_cases() {
        let evaluator = create_evaluator();
        let context = create_test_context();

        // Test empty operations
        let result = evaluator.evaluate_operations(&[], &context);
        assert!(result.is_ok());
        assert!(matches!(result.unwrap(), EvaluationResult::Optimized));

        // Test shift with invalid amount
        let mut stack = vec![10, 65]; // Shift by 65 bits (invalid for 64-bit)
        let result = evaluator.execute_operation(&DwarfOperation::Shl, &mut stack, &context);
        assert!(result.is_err());

        // Test negative shift
        let mut stack = vec![10, -1];
        let result = evaluator.execute_operation(&DwarfOperation::Shl, &mut stack, &context);
        assert!(result.is_err());

        // Test arithmetic with extreme values
        let mut stack = vec![i64::MAX, 1];
        let result = evaluator.execute_operation(&DwarfOperation::Add, &mut stack, &context);
        assert!(result.is_ok()); // Should use wrapping arithmetic
        assert_eq!(stack[0], i64::MIN); // Wrapped around
    }
}

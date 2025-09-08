// DWARF Expression Evaluator
// Provides comprehensive DWARF expression evaluation with structured results for LLVM codegen

use crate::dwarf::{DwarfContext, DwarfOp, LocationExpression};
use crate::scoped_variables::AddressRange;
use ghostscope_protocol::platform;
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

/// DWARF expression evaluation result with clear value vs location semantics
#[derive(Clone, PartialEq)]
pub enum EvaluationResult {
    /// Direct value - expression result is the variable value (no memory read needed)
    DirectValue(DirectValueResult),

    /// Memory location - expression result is an address that needs to be dereferenced
    MemoryLocation(LocationResult),

    /// Variable is optimized out (no location/value available)
    Optimized,

    /// Composite location (multiple pieces) - complex DWARF composite types
    Composite(Vec<EvaluationResult>),
}

/// Direct value results - expression produces the variable value directly
#[derive(Clone, PartialEq)]
pub enum DirectValueResult {
    /// Literal constant from DWARF expression (DW_OP_lit*, DW_OP_const*)
    Constant(i64),

    /// Implicit value embedded in DWARF (DW_OP_implicit_value)
    ImplicitValue(Vec<u8>),

    /// Register contains the variable value directly (DW_OP_reg*)
    RegisterValue(u16),

    /// Computed value from complex expression with stack value semantics
    /// (expressions ending with DW_OP_stack_value)
    ComputedValue {
        steps: Vec<AccessStep>,
        requires_registers: Vec<u16>,
        requires_frame_base: bool,
        requires_cfa: bool,
    },
}

/// Memory location results - expression produces an address to dereference
#[derive(Clone, PartialEq)]
pub enum LocationResult {
    /// Absolute memory address (DW_OP_addr)
    Address(u64),

    /// Register-based address with optional offset (DW_OP_breg*)
    RegisterAddress {
        register: u16,
        offset: Option<i64>,
        size: Option<u64>, // Size for partial reads
    },

    /// Frame base relative address (DW_OP_fbreg)
    FrameOffset(i64),

    /// Stack pointer relative address
    StackOffset(i64),

    /// Call Frame Address relative position (DW_OP_call_frame_cfa + offset)
    CFAOffset(i64),

    /// Complex computed address from multi-step expression
    ComputedLocation {
        steps: Vec<AccessStep>,
        requires_registers: Vec<u16>,
        requires_frame_base: bool,
        requires_cfa: bool,
    },
}

/// Helper function to get register name for debugging display
fn get_register_name(reg: u16) -> String {
    platform::dwarf_reg_to_name(reg)
        .map(|name| format!("%{}", name))
        .unwrap_or_else(|| format!("%{}", reg))
}

impl std::fmt::Debug for EvaluationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvaluationResult::DirectValue(direct) => {
                write!(f, "DirectValue({})", format!("{:?}", direct))
            }
            EvaluationResult::MemoryLocation(location) => {
                write!(f, "MemoryLocation({})", format!("{:?}", location))
            }
            EvaluationResult::Optimized => {
                write!(f, "OptimizedOut")
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
        }
    }
}

impl std::fmt::Debug for DirectValueResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DirectValueResult::Constant(value) => {
                if *value >= 0 && *value <= 100 {
                    write!(f, "{}", value)
                } else {
                    write!(f, "0x{:x}", value)
                }
            }
            DirectValueResult::ImplicitValue(bytes) => {
                if bytes.len() <= 8 {
                    // Convert to integer for compact display
                    let mut value = 0u64;
                    for (i, &byte) in bytes.iter().take(8).enumerate() {
                        value |= (byte as u64) << (i * 8);
                    }
                    write!(f, "Implicit(0x{:x})", value)
                } else {
                    write!(f, "Implicit({} bytes)", bytes.len())
                }
            }
            DirectValueResult::RegisterValue(reg) => {
                let reg_name = get_register_name(*reg);
                write!(f, "RegVal({})", reg_name)
            }
            DirectValueResult::ComputedValue {
                steps,
                requires_registers,
                requires_frame_base,
                requires_cfa,
            } => {
                write!(f, "Compute[")?;

                // Format computation steps
                for (i, step) in steps.iter().enumerate() {
                    if i > 0 {
                        write!(f, " → ")?;
                    }
                    match step {
                        AccessStep::LoadRegister(reg) => {
                            if let Some(reg_name) =
                                ghostscope_protocol::platform::dwarf_reg_to_name(*reg)
                            {
                                write!(f, "Load({})", reg_name)?;
                            } else {
                                write!(f, "Load(R{})", reg)?;
                            }
                        }
                        AccessStep::AddConstant(val) => {
                            if *val >= 0 {
                                write!(f, "+{}", val)?;
                            } else {
                                write!(f, "{}", val)?;
                            }
                        }
                        AccessStep::LoadFrameBase => write!(f, "FrameBase")?,
                        AccessStep::LoadCallFrameCFA => write!(f, "CFA")?,
                        AccessStep::Dereference { size } => {
                            write!(f, "Deref({})", size)?;
                        }
                        AccessStep::ArithmeticOp(op) => {
                            let op_str = match op {
                                ArithOp::Add => "+",
                                ArithOp::Sub => "-",
                                ArithOp::Mul => "*",
                                ArithOp::Div => "/",
                                ArithOp::Mod => "%",
                                ArithOp::And => "&",
                                ArithOp::Or => "|",
                                ArithOp::Xor => "^",
                                ArithOp::Not => "!",
                                ArithOp::Shl => "<<",
                                ArithOp::Shr => ">>",
                                ArithOp::Shra => ">>a",
                                ArithOp::Neg => "neg",
                                ArithOp::Abs => "abs",
                                ArithOp::Eq => "==",
                                ArithOp::Ne => "!=",
                                ArithOp::Lt => "<",
                                ArithOp::Gt => ">",
                                ArithOp::Le => "<=",
                                ArithOp::Ge => ">=",
                            };
                            write!(f, "{}", op_str)?;
                        }
                        AccessStep::Conditional { condition, .. } => {
                            write!(f, "If({:?})", condition)?;
                        }
                        AccessStep::Piece { size, offset } => {
                            write!(f, "Piece({}, {})", size, offset)?;
                        }
                    }
                }

                // Add requirements compactly
                let mut reqs = Vec::new();
                if *requires_frame_base {
                    reqs.push("Frame".to_string());
                }
                if *requires_cfa {
                    reqs.push("CFA".to_string());
                }
                if !requires_registers.is_empty() {
                    let reg_names: Vec<String> = requires_registers
                        .iter()
                        .map(|reg| {
                            ghostscope_protocol::platform::dwarf_reg_to_name(*reg)
                                .unwrap_or("?")
                                .to_string()
                        })
                        .collect();
                    reqs.push(format!("Regs[{}]", reg_names.join(",")));
                }

                if !reqs.is_empty() {
                    write!(f, " | {}", reqs.join(","))?;
                }

                write!(f, "]")
            }
        }
    }
}

impl std::fmt::Debug for LocationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocationResult::Address(addr) => {
                write!(f, "Addr(0x{:x})", addr)
            }
            LocationResult::RegisterAddress {
                register,
                offset,
                size,
            } => {
                let reg_name = get_register_name(*register);
                let mut result = reg_name;
                if let Some(off) = offset {
                    if *off >= 0 {
                        result.push_str(&format!("+{}", off));
                    } else {
                        result.push_str(&format!("{}", off));
                    }
                }
                if let Some(sz) = size {
                    result.push_str(&format!("@{}", sz));
                }
                write!(f, "RegAddr({})", result)
            }
            LocationResult::FrameOffset(offset) => {
                write!(f, "Frame({:+})", offset)
            }
            LocationResult::StackOffset(offset) => {
                write!(f, "Stack({:+})", offset)
            }
            LocationResult::CFAOffset(offset) => {
                write!(f, "CFA({:+})", offset)
            }
            LocationResult::ComputedLocation {
                steps,
                requires_registers,
                requires_frame_base,
                requires_cfa,
            } => {
                write!(f, "ComputeLoc[")?;

                // Same step formatting as ComputedValue
                for (i, step) in steps.iter().enumerate() {
                    if i > 0 {
                        write!(f, " → ")?;
                    }
                    match step {
                        AccessStep::LoadRegister(reg) => {
                            if let Some(reg_name) =
                                ghostscope_protocol::platform::dwarf_reg_to_name(*reg)
                            {
                                write!(f, "{}", reg_name)?;
                            } else {
                                write!(f, "R{}", reg)?;
                            }
                        }
                        AccessStep::AddConstant(val) => {
                            if *val >= 0 {
                                write!(f, "+{}", val)?;
                            } else {
                                write!(f, "{}", val)?;
                            }
                        }
                        AccessStep::ArithmeticOp(ArithOp::Add) => write!(f, "+")?,
                        AccessStep::ArithmeticOp(ArithOp::Sub) => write!(f, "-")?,
                        AccessStep::ArithmeticOp(ArithOp::Mul) => write!(f, "*")?,
                        AccessStep::ArithmeticOp(op) => write!(f, "{:?}", op)?,
                        _ => write!(f, "{:?}", step)?,
                    }
                }

                // Requirements summary
                if *requires_frame_base || *requires_cfa || !requires_registers.is_empty() {
                    write!(f, " | ")?;
                    let mut first = true;
                    if *requires_frame_base {
                        write!(f, "Frame")?;
                        first = false;
                    }
                    if *requires_cfa {
                        if !first {
                            write!(f, ",")?;
                        }
                        write!(f, "CFA")?;
                        first = false;
                    }
                    if !requires_registers.is_empty() {
                        if !first {
                            write!(f, ",")?;
                        }
                        let reg_names: Vec<&str> = requires_registers
                            .iter()
                            .map(|reg| {
                                ghostscope_protocol::platform::dwarf_reg_to_name(*reg)
                                    .unwrap_or("?")
                            })
                            .collect();
                        write!(f, "Regs[{}]", reg_names.join(","))?;
                    }
                }

                write!(f, "]")
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

    /// NEW: evaluate LocationExpression with enhanced type system
    pub fn evaluate_location_with_enhanced_types(
        &self,
        location_expr: &LocationExpression,
        pc_address: u64,
        context: &EvaluationContext,
        dwarf_context: Option<&DwarfContext>,
    ) -> Result<EvaluationResult, ExpressionError> {
        debug!(
            "Evaluating location expression with enhanced types at PC 0x{:x}",
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
                    Ok(ops) => self.evaluate_dwarf_operations_with_enhanced_types(
                        &ops,
                        pc_address,
                        context,
                        dwarf_context,
                    ),
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
                            "Found applicable location list entry for PC 0x{:x}: range 0x{:x}-0x{:x}",
                            pc_address, entry.start_pc, entry.end_pc
                        );
                        return self.evaluate_location_with_enhanced_types(
                            &entry.location_expr,
                            pc_address,
                            context,
                            dwarf_context,
                        );
                    }
                }
                warn!(
                    "No applicable location list entry found for PC 0x{:x}",
                    pc_address
                );
                Ok(EvaluationResult::Optimized)
            }

            // Simple register access: DW_OP_reg*
            LocationExpression::Register { reg } => {
                debug!("Direct register access: reg{}", reg);
                Ok(EvaluationResult::DirectValue(
                    DirectValueResult::RegisterValue(*reg),
                ))
            }

            // Register-based address: DW_OP_breg*
            LocationExpression::RegisterOffset { reg, offset } => {
                debug!("Register-based address: reg{} + {}", reg, offset);
                Ok(EvaluationResult::MemoryLocation(
                    LocationResult::RegisterAddress {
                        register: *reg,
                        offset: Some(*offset),
                        size: None,
                    },
                ))
            }

            // Frame base offset: DW_OP_fbreg
            LocationExpression::FrameBaseOffset { offset } => {
                debug!("Frame base offset: fbreg + {}", offset);
                // Use CFI-aware frame base evaluation when possible
                if let Some(dwarf_ctx) = dwarf_context {
                    if let Some(cfi_rule) = dwarf_ctx.get_cfi_rule_for_pc(pc_address) {
                        debug!(
                            "Found CFI rule for frame base offset at PC 0x{:x}: {:?}",
                            pc_address, cfi_rule
                        );
                        return self.combine_cfi_with_offset_enhanced(
                            "cfi_rule", *offset, dwarf_ctx, pc_address, context,
                        );
                    }
                }
                // Fallback to frame offset
                warn!(
                    "No CFI context for frame base offset at PC 0x{:x}, using fallback",
                    pc_address
                );
                Ok(EvaluationResult::MemoryLocation(
                    LocationResult::FrameOffset(*offset),
                ))
            }

            LocationExpression::OptimizedOut => {
                debug!("Variable optimized out");
                Ok(EvaluationResult::Optimized)
            }

            LocationExpression::DwarfExpression { bytecode } => {
                warn!("Raw DWARF bytecode not yet supported for enhanced type evaluation");
                Ok(EvaluationResult::Optimized)
            }

            _ => {
                warn!(
                    "Unsupported location expression for enhanced type evaluation: {:?}",
                    location_expr
                );
                Ok(EvaluationResult::Optimized)
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
            DwarfOp::Sub => Ok(DwarfOperation::Sub),
            DwarfOp::Mul => Ok(DwarfOperation::Mul),
            DwarfOp::Div => Ok(DwarfOperation::Div),
            DwarfOp::Mod => Ok(DwarfOperation::Mod),
            DwarfOp::Neg => Ok(DwarfOperation::Neg),
            // PlusUconst is a combined operation: push constant and add
            // For CFI evaluation, we handle it as a single RegisterOffset operation
            DwarfOp::PlusUconst(val) => Ok(DwarfOperation::Literal(*val as i64)),
            DwarfOp::Dup => Ok(DwarfOperation::Dup),
            DwarfOp::Drop => Ok(DwarfOperation::Drop),
            DwarfOp::Swap => Ok(DwarfOperation::Swap),
            DwarfOp::StackValue => Ok(DwarfOperation::StackValue),
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

                DwarfOp::Sub => {
                    steps.push(AccessStep::ArithmeticOp(ArithOp::Sub));
                }

                DwarfOp::Mul => {
                    steps.push(AccessStep::ArithmeticOp(ArithOp::Mul));
                }

                DwarfOp::Div => {
                    steps.push(AccessStep::ArithmeticOp(ArithOp::Div));
                }

                DwarfOp::Mod => {
                    steps.push(AccessStep::ArithmeticOp(ArithOp::Mod));
                }

                DwarfOp::Neg => {
                    steps.push(AccessStep::ArithmeticOp(ArithOp::Neg));
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

    /// Evaluate DWARF operations using enhanced type system with clear value vs location semantics
    fn evaluate_dwarf_operations_with_enhanced_types(
        &self,
        operations: &[DwarfOperation],
        pc_address: u64,
        context: &EvaluationContext,
        _dwarf_context: Option<&DwarfContext>,
    ) -> Result<EvaluationResult, ExpressionError> {
        debug!(
            "Evaluating {} DWARF operations with enhanced types",
            operations.len()
        );

        // Try pattern optimization first
        if let Some(optimized) = self.try_pattern_optimization_enhanced(operations, context)? {
            debug!("Used pattern optimization for enhanced types");
            return Ok(optimized);
        }

        // Collect metadata about the expression
        let requires_registers = self.collect_required_registers_for_ops(operations);
        let requires_frame_base = operations
            .iter()
            .any(|op| matches!(op, DwarfOperation::FrameBase(_)));
        let requires_cfa = operations
            .iter()
            .any(|op| matches!(op, DwarfOperation::CallFrameCFA));

        // Check for location vs value semantics
        let is_location_expression = self.is_location_expression(operations);

        // Convert operations to access steps
        let steps = self.operations_to_access_steps(operations);

        if is_location_expression {
            // Expression produces a memory address that needs dereferencing
            debug!("Detected location expression - result is a memory address");
            Ok(EvaluationResult::MemoryLocation(
                LocationResult::ComputedLocation {
                    steps,
                    requires_registers,
                    requires_frame_base,
                    requires_cfa,
                },
            ))
        } else {
            // Expression produces a direct value
            debug!("Detected value expression - result is the variable value");
            Ok(EvaluationResult::DirectValue(
                DirectValueResult::ComputedValue {
                    steps,
                    requires_registers,
                    requires_frame_base,
                    requires_cfa,
                },
            ))
        }
    }

    /// Enhanced pattern optimization for new type system
    fn try_pattern_optimization_enhanced(
        &self,
        operations: &[DwarfOperation],
        _context: &EvaluationContext,
    ) -> Result<Option<EvaluationResult>, ExpressionError> {
        match operations {
            // Direct register value: DW_OP_reg0, DW_OP_reg1, etc.
            [DwarfOperation::Register(reg)] => {
                debug!("Pattern: Direct register value reg{}", reg);
                Ok(Some(EvaluationResult::DirectValue(
                    DirectValueResult::RegisterValue(*reg),
                )))
            }

            // Register-based address: DW_OP_breg0 <offset>
            [DwarfOperation::RegisterOffset(reg, offset)] => {
                debug!("Pattern: Register-based address reg{} + {}", reg, offset);
                Ok(Some(EvaluationResult::MemoryLocation(
                    LocationResult::RegisterAddress {
                        register: *reg,
                        offset: Some(*offset),
                        size: None,
                    },
                )))
            }

            // Literal constant: DW_OP_lit*, DW_OP_const*
            [DwarfOperation::Literal(value)] => {
                debug!("Pattern: Literal constant {}", value);
                Ok(Some(EvaluationResult::DirectValue(
                    DirectValueResult::Constant(*value),
                )))
            }

            // Frame base offset: DW_OP_fbreg <offset>
            [DwarfOperation::FrameBase(offset)] => {
                debug!("Pattern: Frame base offset {}", offset);
                Ok(Some(EvaluationResult::MemoryLocation(
                    LocationResult::FrameOffset(*offset),
                )))
            }

            // Absolute address: DW_OP_addr
            [DwarfOperation::Address(addr)] => {
                debug!("Pattern: Absolute address 0x{:x}", addr);
                Ok(Some(EvaluationResult::MemoryLocation(
                    LocationResult::Address(*addr),
                )))
            }

            // Complex patterns can be added here as needed
            _ => {
                // No simple pattern matched
                Ok(None)
            }
        }
    }

    /// Determine if a DWARF expression produces a location (address) or value
    fn is_location_expression(&self, operations: &[DwarfOperation]) -> bool {
        // Most DWARF expressions produce locations unless they end with DW_OP_stack_value
        // or are register value operations (DW_OP_reg*)

        // Check for explicit value markers
        if operations
            .iter()
            .any(|op| matches!(op, DwarfOperation::StackValue))
        {
            return false; // Explicitly marked as value expression
        }

        // Check for register value operations (DW_OP_reg*)
        if let [DwarfOperation::Register(_)] = operations {
            return false; // Direct register value, not address
        }

        // Check for implicit value operations
        if operations
            .iter()
            .any(|op| matches!(op, DwarfOperation::ImplicitValue(_)))
        {
            return false; // Implicit value embedded in DWARF
        }

        // Most other cases produce locations that need dereferencing
        true
    }

    /// Enhanced CFI combination for new type system
    fn combine_cfi_with_offset_enhanced(
        &self,
        _cfi_rule: &str, // TODO: Replace with actual CFI rule type when available
        offset: i64,
        _dwarf_ctx: &DwarfContext,
        _pc_address: u64,
        _context: &EvaluationContext,
    ) -> Result<EvaluationResult, ExpressionError> {
        // For now, fallback to frame offset
        // TODO: Implement full CFI integration with enhanced types
        warn!("CFI integration with enhanced types not fully implemented yet");
        Ok(EvaluationResult::MemoryLocation(
            LocationResult::FrameOffset(offset),
        ))
    }

    /// Collect registers required by a list of DWARF operations
    fn collect_required_registers_for_ops(&self, operations: &[DwarfOperation]) -> Vec<u16> {
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
}

// DWARF Expression Evaluator
// Provides comprehensive DWARF expression evaluation with structured results for LLVM codegen

use crate::dwarf::DwarfContext;
use ghostscope_platform;
use std::collections::HashMap;
use tracing::{debug, error, warn};

/// DWARF location expression
#[derive(Debug, Clone)]
pub enum LocationExpression {
    /// Variable is stored in a register
    Register { reg: u16 },
    /// Variable is at frame base + offset
    FrameBaseOffset { offset: i64 },
    /// Variable is at an absolute address
    Address { addr: u64 },
    /// Variable is at stack pointer + offset
    StackOffset { offset: i64 },
    /// Variable is at register + offset (more precise than StackOffset)
    RegisterOffset { reg: u16, offset: i64 },
    /// Complex DWARF expression that requires evaluation
    ComputedExpression {
        operations: Vec<DwarfOp>,
        requires_frame_base: bool,
        requires_registers: Vec<u16>,
    },
    /// Legacy: Complex DWARF expression (to be implemented)
    DwarfExpression { bytecode: Vec<u8> },
    /// Variable has different locations at different PC ranges (location lists)
    LocationList { entries: Vec<LocationListEntry> },
    /// Variable was optimized away
    OptimizedOut,
}

/// Location list entry representing a variable location at a specific PC range
#[derive(Debug, Clone)]
pub(crate) struct LocationListEntry {
    /// Start PC address (inclusive)
    pub start_pc: u64,
    /// End PC address (exclusive)
    pub end_pc: u64,
    /// Location expression for this PC range
    pub location_expr: LocationExpression,
}

impl LocationExpression {
    /// Get the location expression for a specific PC address
    /// For location lists, this finds the correct entry for the given PC
    pub fn resolve_at_pc(&self, pc: u64) -> &LocationExpression {
        match self {
            LocationExpression::LocationList { entries } => {
                for entry in entries {
                    if pc >= entry.start_pc && pc < entry.end_pc {
                        debug!(
                            "Found location at PC 0x{:x} in range 0x{:x}-0x{:x}",
                            pc, entry.start_pc, entry.end_pc
                        );
                        return entry.location_expr.resolve_at_pc(pc);
                    }
                }
                debug!("No location found for PC 0x{:x} in location list", pc);
                &LocationExpression::OptimizedOut
            }
            // For non-location-list expressions, return self
            _ => self,
        }
    }

    /// Check if this location expression represents a function parameter
    /// Parameters are typically stored in registers or frame-based offsets with specific patterns
    pub fn is_parameter_location(&self) -> bool {
        match self {
            // Simple register locations often indicate parameters
            LocationExpression::Register { reg: _ } => true,
            // Frame base offsets with positive values are often parameters (passed arguments)
            LocationExpression::FrameBaseOffset { offset } => *offset >= 0,
            // Register + offset patterns for parameter passing
            LocationExpression::RegisterOffset { reg: _, offset: _ } => true,
            // For location lists, check the most common entry
            LocationExpression::LocationList { entries } => {
                if let Some(first_entry) = entries.first() {
                    first_entry.location_expr.is_parameter_location()
                } else {
                    false
                }
            }
            // Stack offsets and complex expressions are typically local variables
            LocationExpression::StackOffset { offset: _ } => false,
            LocationExpression::ComputedExpression { .. } => false,
            LocationExpression::DwarfExpression { .. } => false,
            // Address and optimized out locations are neither parameters nor locals
            LocationExpression::Address { addr: _ } => false,
            LocationExpression::OptimizedOut => false,
        }
    }
}

/// Simplified DWARF operations for common expression evaluation
#[derive(Debug, Clone)]
pub enum DwarfOp {
    /// Push a constant value onto the stack
    Const(i64),
    /// Push register value onto the stack
    Reg(u16),
    /// Push frame base + offset onto the stack
    Fbreg(i64),
    /// Push register + offset onto the stack
    Breg(u16, i64),
    /// Dereference the top stack value
    Deref,
    /// Add two values on stack
    Plus,
    /// Subtract two values on stack
    Sub,
    /// Multiply two values on stack
    Mul,
    /// Divide two values on stack
    Div,
    /// Modulo operation on two values on stack
    Mod,
    /// Negate the top stack value
    Neg,
    /// Add constant to top of stack
    PlusUconst(u64),
    /// Duplicate top stack value
    Dup,
    /// Pop top stack value
    Drop,
    /// Swap top two stack values
    Swap,
    /// Stack has the address, not the value (DW_OP_stack_value)
    StackValue,
}

/// Convert platform-specific error to expression error

/// DWARF expression evaluation errors
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExpressionError {
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

    #[error("Parameter optimized: {0}")]
    ParameterOptimized(String),
}

/// Complete DWARF operations enum - supports the full DWARF specification
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DwarfOperation {
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
    Const(u64),   // Generic constant value
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

    /// Complex computed address from multi-step expression
    ComputedLocation {
        steps: Vec<AccessStep>,
        requires_registers: Vec<u16>,
    },
}

/// Helper function to get register name for debugging display
fn get_register_name(reg: u16) -> String {
    ghostscope_protocol::platform::dwarf_reg_to_name(reg)
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
            LocationResult::ComputedLocation {
                steps,
                requires_registers,
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
                if !requires_registers.is_empty() {
                    write!(f, " | ")?;
                    let reg_names: Vec<&str> = requires_registers
                        .iter()
                        .map(|reg| {
                            ghostscope_protocol::platform::dwarf_reg_to_name(*reg).unwrap_or("?")
                        })
                        .collect();
                    write!(f, "Regs[{}]", reg_names.join(","))?;
                }

                write!(f, "]")
            }
        }
    }
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
                    if dwarf_ctx.has_cfi_context() {
                        debug!(
                            "Found CFI context for frame base offset at PC 0x{:x}",
                            pc_address
                        );

                        // Get CFA evaluation result directly
                        if let Some(cfa_result) = dwarf_ctx.get_cfa_evaluation_result(pc_address) {
                            debug!(
                                "Found CFA evaluation result, combining with offset {}",
                                offset
                            );

                            // Combine CFA result with offset
                            return self.combine_cfa_with_offset(cfa_result, *offset);
                        } else {
                            debug!("No CFA expression found for PC 0x{:x}", pc_address);
                        }
                    } else {
                        debug!("No CFI context available");
                    }
                } else {
                    debug!("No DWARF context provided");
                }

                // Return error instead of fake fallback
                debug!(
                    "No CFI-based frame base available for PC 0x{:x}, returning error",
                    pc_address
                );

                Err(ExpressionError::EvaluationFailed(format!(
                    "No CFI data available for frame base calculation at PC 0x{:x}",
                    pc_address
                )))
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

                DwarfOperation::FrameBase(_offset) => {
                    // Frame base operations need CFA resolution at evaluation time
                    // This should not happen in step conversion - the higher level should handle frame base
                    tracing::error!("FrameBase operation reached step conversion - this should be handled at evaluation level");
                    // Return error or placeholder - the evaluation should handle this case
                    return vec![];
                }

                DwarfOperation::CallFrameCFA => {
                    // CFA operations need CFI context resolution at evaluation time
                    // This should not happen in step conversion - the higher level should handle CFA
                    tracing::error!("CallFrameCFA operation reached step conversion - this should be handled at evaluation level");
                    // Return error or placeholder - the evaluation should handle this case
                    return vec![];
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
                debug!(
                    "Pattern: Frame base offset {} - cannot optimize, fallback to full evaluation",
                    offset
                );
                // Frame base operations should be resolved at higher evaluation level using CFI context
                // Don't generate LoadFrameBase steps - return None to trigger full evaluation path
                Ok(None)
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

    /// Combine CFA evaluation result with frame base offset
    fn combine_cfa_with_offset(
        &self,
        cfa_result: EvaluationResult,
        offset: i64,
    ) -> Result<EvaluationResult, ExpressionError> {
        debug!("Combining CFA result with offset {}", offset);

        match cfa_result {
            EvaluationResult::MemoryLocation(location_result) => {
                match location_result {
                    LocationResult::ComputedLocation {
                        mut steps,
                        requires_registers,
                    } => {
                        // Add offset to the CFA-based computation
                        if offset != 0 {
                            steps.push(AccessStep::AddConstant(offset));
                        }

                        Ok(EvaluationResult::MemoryLocation(
                            LocationResult::ComputedLocation {
                                steps,
                                requires_registers,
                            },
                        ))
                    }
                    LocationResult::RegisterAddress {
                        register,
                        offset: reg_offset,
                        size,
                    } => {
                        // CFA returned register + offset, combine with frame base offset
                        let combined_offset = reg_offset.unwrap_or(0) + offset;
                        debug!("Combining CFA register {} offset {} with frame base offset {} = total offset {}", 
                               register, reg_offset.unwrap_or(0), offset, combined_offset);

                        Ok(EvaluationResult::MemoryLocation(
                            LocationResult::RegisterAddress {
                                register,
                                offset: Some(combined_offset),
                                size,
                            },
                        ))
                    }
                    LocationResult::Address(cfa_address) => {
                        // CFA returned absolute address, add frame base offset
                        let final_address = if offset >= 0 {
                            cfa_address + offset as u64
                        } else {
                            cfa_address - (-offset) as u64
                        };

                        debug!(
                            "Combining CFA address 0x{:x} with frame base offset {} = 0x{:x}",
                            cfa_address, offset, final_address
                        );

                        Ok(EvaluationResult::MemoryLocation(LocationResult::Address(
                            final_address,
                        )))
                    } // All LocationResult variants should be handled above
                }
            }
            EvaluationResult::DirectValue(_value_result) => {
                // CFA gave us a direct value, but we can't easily use it for offset calculation
                // This should not happen with proper CFA evaluation
                debug!("CFA result is DirectValue, this indicates improper CFA evaluation");
                Err(ExpressionError::EvaluationFailed(
                    "CFA evaluation returned DirectValue instead of location - this indicates a CFA implementation error".into()
                ))
            }
            other => {
                debug!("Unexpected CFA result type: {:?}", other);
                Err(ExpressionError::EvaluationFailed(format!(
                    "Cannot combine CFA result with offset: unexpected result type"
                )))
            }
        }
    }
}

// Error conversions for gimli types
impl From<gimli::Error> for ExpressionError {
    fn from(err: gimli::Error) -> Self {
        ExpressionError::InvalidBytecode(format!("Gimli error: {}", err))
    }
}

//! DWARF expression evaluation results for LLVM/eBPF code generation
//!
//! This module defines the simplified representation of DWARF expressions
//! that can be directly converted to LLVM IR for eBPF code generation.
//!
//! Design principles:
//! 1. Optimize for eBPF constraints (read registers from pt_regs, read memory via bpf_probe_read_user)
//! 2. Pre-compute as much as possible at compile time
//! 3. Clearly separate value semantics from location semantics
//! 4. Make register dependencies explicit for eBPF verification

use std::fmt;

/// Result of evaluating a DWARF expression for eBPF code generation
#[derive(Debug, Clone, PartialEq)]
pub enum EvaluationResult {
    /// Direct value - expression result is the variable value (no memory read needed)
    DirectValue(DirectValueResult),

    /// Memory location - expression result is an address that needs to be dereferenced
    MemoryLocation(LocationResult),

    /// Variable is optimized out (no location/value available)
    Optimized,

    /// Composite location (multiple pieces) - for split variables
    Composite(Vec<PieceResult>),
}

/// Direct value results - expression produces the variable value directly
#[derive(Debug, Clone, PartialEq)]
pub enum DirectValueResult {
    /// Literal constant from DWARF expression (DW_OP_lit*, DW_OP_const*)
    Constant(i64),

    /// Implicit value embedded in DWARF (DW_OP_implicit_value)
    ImplicitValue(Vec<u8>),

    /// Register contains the variable value directly (DW_OP_reg*)
    RegisterValue(u16),

    /// Computed value from expression (DW_OP_stack_value)
    /// This is a full expression that computes the value
    ComputedValue {
        /// Expression steps (stack-based computation)
        steps: Vec<ComputeStep>,
        /// Expected result type size
        result_size: MemoryAccessSize,
    },
}

/// Memory location results - expression produces an address to be read via bpf_probe_read_user
#[derive(Debug, Clone, PartialEq)]
pub enum LocationResult {
    /// Absolute memory address (DW_OP_addr)
    Address(u64),

    /// Register-based address with optional offset (DW_OP_breg*)
    /// The register value will be read from pt_regs in eBPF
    RegisterAddress {
        register: u16, // DWARF register number
        offset: Option<i64>,
        size: Option<u64>, // Size hint for memory read
    },

    /// Complex computed address from multi-step expression
    /// Will be evaluated step by step in eBPF
    ComputedLocation {
        /// Expression that computes the final address
        steps: Vec<ComputeStep>,
    },
}

/// CFA (Canonical Frame Address) computation for stack variables
#[derive(Debug, Clone, PartialEq)]
pub enum CfaResult {
    /// CFA = register + offset (most common case)
    RegisterPlusOffset {
        register: u16, // Typically RSP or RBP
        offset: i64,
    },
    /// CFA computed by DWARF expression
    Expression { steps: Vec<ComputeStep> },
}

/// Piece of a composite location
#[derive(Debug, Clone, PartialEq)]
pub struct PieceResult {
    /// Location of this piece
    pub location: EvaluationResult,
    /// Size in bytes
    pub size: u64,
    /// Bit offset within the piece (for bit fields)
    pub bit_offset: Option<u64>,
}

/// Computation step for LLVM IR generation
/// These map directly to LLVM IR operations that can be generated in eBPF
#[derive(Debug, Clone, PartialEq)]
pub enum ComputeStep {
    /// Load register value from pt_regs
    LoadRegister(u16), // DWARF register number

    /// Push constant
    PushConstant(i64),

    /// Memory dereference via bpf_probe_read_user
    Dereference {
        size: MemoryAccessSize,
    },

    /// Binary arithmetic operations (pop 2, push 1)
    Add,
    Sub,
    Mul,
    Div,
    Mod,

    /// Binary bitwise operations
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Shra, // Arithmetic shift right

    /// Unary operations
    Not,
    Neg,
    Abs,

    /// Stack manipulation
    Dup,
    Drop,
    Swap,
    Rot,
    Pick(u8), // Pick nth item from stack

    /// Comparison operations (pop 2, push bool)
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,

    /// Control flow (simplified for eBPF)
    If {
        then_branch: Vec<ComputeStep>,
        else_branch: Vec<ComputeStep>,
    },
}

/// Memory access size for bpf_probe_read_user
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MemoryAccessSize {
    U8,  // 1 byte
    U16, // 2 bytes
    U32, // 4 bytes
    U64, // 8 bytes
}

impl MemoryAccessSize {
    /// Get size in bytes
    pub fn bytes(&self) -> usize {
        match self {
            MemoryAccessSize::U8 => 1,
            MemoryAccessSize::U16 => 2,
            MemoryAccessSize::U32 => 4,
            MemoryAccessSize::U64 => 8,
        }
    }
}

impl EvaluationResult {
    /// Check if this is a simple constant
    pub fn as_constant(&self) -> Option<i64> {
        match self {
            EvaluationResult::DirectValue(DirectValueResult::Constant(c)) => Some(*c),
            _ => None,
        }
    }

    /// Merge with CFA result for frame-relative addresses (DW_OP_fbreg)
    /// This is used when a variable location is relative to the frame base
    pub fn merge_with_cfa(self, cfa: CfaResult, frame_offset: i64) -> Self {
        match cfa {
            CfaResult::RegisterPlusOffset { register, offset } => {
                // CFA gives us the frame base, add the frame_offset to get final location
                EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                    register,
                    offset: Some(offset + frame_offset),
                    size: None,
                })
            }
            CfaResult::Expression { mut steps } => {
                // Add frame offset to the CFA computation
                steps.push(ComputeStep::PushConstant(frame_offset));
                steps.push(ComputeStep::Add);
                EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { steps })
            }
        }
    }
}

impl DirectValueResult {
    /// Check if this is a simple value that can be computed at compile time
    pub fn is_compile_time_constant(&self) -> bool {
        matches!(
            self,
            DirectValueResult::Constant(_) | DirectValueResult::ImplicitValue(_)
        )
    }

    /// Convert compute steps to a human-readable expression
    fn steps_to_expression(steps: &[ComputeStep]) -> String {
        use ghostscope_platform::register_mapping::dwarf_reg_to_name;

        // Stack for expression building
        let mut stack: Vec<String> = Vec::new();

        for step in steps {
            match step {
                ComputeStep::LoadRegister(r) => {
                    let reg_name = dwarf_reg_to_name(*r).unwrap_or("r?").to_string();
                    stack.push(reg_name);
                }
                ComputeStep::PushConstant(v) => {
                    if *v >= 0 && *v <= 0xFF {
                        stack.push(format!("{v}"));
                    } else {
                        stack.push(format!("0x{v:x}"));
                    }
                }
                ComputeStep::Add => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        // Special case: register + small offset
                        if a.chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
                            && b.parse::<i64>().is_ok()
                            && b.parse::<i64>().unwrap().abs() < 1000
                        {
                            stack.push(format!("{a}+{b}"));
                        } else {
                            stack.push(format!("({a}+{b})"));
                        }
                    } else {
                        stack.push("?+?".to_string());
                    }
                }
                ComputeStep::Sub => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}-{b})"));
                    } else {
                        stack.push("?-?".to_string());
                    }
                }
                ComputeStep::Mul => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("{a}*{b}"));
                    } else {
                        stack.push("?*?".to_string());
                    }
                }
                ComputeStep::Div => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}/{b})"));
                    } else {
                        stack.push("?/?".to_string());
                    }
                }
                ComputeStep::Mod => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}%{b})"));
                    } else {
                        stack.push("?%?".to_string());
                    }
                }
                ComputeStep::And => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}&{b})"));
                    } else {
                        stack.push("?&?".to_string());
                    }
                }
                ComputeStep::Or => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}|{b})"));
                    } else {
                        stack.push("?|?".to_string());
                    }
                }
                ComputeStep::Xor => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}^{b})"));
                    } else {
                        stack.push("?^?".to_string());
                    }
                }
                ComputeStep::Shl => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}<<{b})"));
                    } else {
                        stack.push("?<<?".to_string());
                    }
                }
                ComputeStep::Shr => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}>>{b})"));
                    } else {
                        stack.push("?>>?".to_string());
                    }
                }
                ComputeStep::Shra => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}>>>{b})"));
                    } else {
                        stack.push("?>>>?".to_string());
                    }
                }
                ComputeStep::Not => {
                    if let Some(a) = stack.pop() {
                        stack.push(format!("~{a}"));
                    } else {
                        stack.push("~?".to_string());
                    }
                }
                ComputeStep::Neg => {
                    if let Some(a) = stack.pop() {
                        stack.push(format!("-{a}"));
                    } else {
                        stack.push("-?".to_string());
                    }
                }
                ComputeStep::Abs => {
                    if let Some(a) = stack.pop() {
                        stack.push(format!("|{a}|"));
                    } else {
                        stack.push("|?|".to_string());
                    }
                }
                ComputeStep::Dereference { size } => {
                    if let Some(a) = stack.pop() {
                        stack.push(format!("*({a} as {size})"));
                    } else {
                        stack.push(format!("*(? as {size})"));
                    }
                }
                ComputeStep::Dup => {
                    if let Some(top) = stack.last() {
                        stack.push(top.clone());
                    }
                }
                ComputeStep::Drop => {
                    stack.pop();
                }
                ComputeStep::Swap => {
                    if stack.len() >= 2 {
                        let len = stack.len();
                        stack.swap(len - 1, len - 2);
                    }
                }
                ComputeStep::Rot => {
                    if stack.len() >= 3 {
                        let len = stack.len();
                        let third = stack.remove(len - 3);
                        stack.push(third);
                    }
                }
                ComputeStep::Pick(n) => {
                    if stack.len() > *n as usize {
                        let idx = stack.len() - 1 - (*n as usize);
                        let val = stack[idx].clone();
                        stack.push(val);
                    } else {
                        stack.push("?".to_string());
                    }
                }
                ComputeStep::Eq => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}=={b})"));
                    } else {
                        stack.push("?==?".to_string());
                    }
                }
                ComputeStep::Ne => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}!={b})"));
                    } else {
                        stack.push("?!=?".to_string());
                    }
                }
                ComputeStep::Lt => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}<{b})"));
                    } else {
                        stack.push("?<?".to_string());
                    }
                }
                ComputeStep::Le => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}<={b})"));
                    } else {
                        stack.push("?<=?".to_string());
                    }
                }
                ComputeStep::Gt => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}>{b})"));
                    } else {
                        stack.push("?>?".to_string());
                    }
                }
                ComputeStep::Ge => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}>={b})"));
                    } else {
                        stack.push("?>=?".to_string());
                    }
                }
                ComputeStep::If {
                    then_branch,
                    else_branch,
                } => {
                    if let Some(cond) = stack.pop() {
                        stack.push(format!("if {cond} then ... else ..."));
                    } else {
                        stack.push("if ? then ... else ...".to_string());
                    }
                    // Note: Full if-then-else evaluation would require recursive expression building
                    _ = then_branch;
                    _ = else_branch;
                }
            }
        }

        // Return the top of stack or a placeholder
        stack.pop().unwrap_or_else(|| "?".to_string())
    }
}

impl LocationResult {
    /// Check if this is a simple location (no computation needed)
    pub fn is_simple(&self) -> bool {
        matches!(
            self,
            LocationResult::Address(_) | LocationResult::RegisterAddress { .. }
        )
    }

    /// Convert compute steps to a human-readable expression (reuse from DirectValueResult)
    fn steps_to_expression(steps: &[ComputeStep]) -> String {
        DirectValueResult::steps_to_expression(steps)
    }
}

impl fmt::Display for EvaluationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvaluationResult::DirectValue(dv) => write!(f, "[DirectValue] {dv}"),
            EvaluationResult::MemoryLocation(loc) => write!(f, "[Memory] {loc}"),
            EvaluationResult::Optimized => write!(f, "<optimized out>"),
            EvaluationResult::Composite(pieces) => {
                write!(f, "Composite[{} pieces]", pieces.len())
            }
        }
    }
}

impl fmt::Display for DirectValueResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ghostscope_platform::register_mapping::dwarf_reg_to_name;

        match self {
            DirectValueResult::Constant(c) => {
                if *c >= 0 && *c <= 0xFF {
                    write!(f, "{c} (0x{c:x})")
                } else {
                    write!(f, "0x{c:x}")
                }
            }
            DirectValueResult::RegisterValue(r) => {
                if let Some(name) = dwarf_reg_to_name(*r) {
                    write!(f, "{name}")
                } else {
                    write!(f, "r{r}")
                }
            }
            DirectValueResult::ImplicitValue(bytes) => {
                if bytes.len() <= 8 {
                    write!(f, "implicit[")?;
                    for (i, b) in bytes.iter().enumerate() {
                        if i > 0 {
                            write!(f, " ")?;
                        }
                        write!(f, "{b:02x}")?;
                    }
                    write!(f, "]")
                } else {
                    write!(f, "implicit[{} bytes]", bytes.len())
                }
            }
            DirectValueResult::ComputedValue {
                steps,
                result_size: _,
            } => {
                // Convert compute steps to a readable expression
                write!(f, "=")?;

                // Simple expression builder for common patterns
                let expr = Self::steps_to_expression(steps);
                write!(f, "{expr}")
            }
        }
    }
}

impl fmt::Display for LocationResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ghostscope_platform::register_mapping::dwarf_reg_to_name;

        match self {
            LocationResult::Address(addr) => write!(f, "@0x{addr:x}"),
            LocationResult::RegisterAddress {
                register,
                offset,
                size,
            } => {
                let reg_name = dwarf_reg_to_name(*register).unwrap_or("r?");

                match (offset, size) {
                    (Some(o), Some(s)) => {
                        let offset = *o;
                        if offset >= 0 {
                            write!(f, "@[{reg_name}+{offset}]:{s}")
                        } else {
                            let neg = -offset;
                            write!(f, "@[{reg_name}-{neg}]:{s}")
                        }
                    }
                    (Some(o), None) => {
                        let offset = *o;
                        if offset >= 0 {
                            write!(f, "@[{reg_name}+{offset}]")
                        } else {
                            let neg = -offset;
                            write!(f, "@[{reg_name}-{neg}]")
                        }
                    }
                    (None, Some(s)) => write!(f, "@[{reg_name}]:{s}"),
                    (None, None) => write!(f, "@[{reg_name}]"),
                }
            }
            LocationResult::ComputedLocation { steps } => {
                // Convert compute steps to a readable expression for the address
                write!(f, "@[")?;
                let expr = Self::steps_to_expression(steps);
                write!(f, "{expr}]")
            }
        }
    }
}

impl fmt::Display for MemoryAccessSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemoryAccessSize::U8 => write!(f, "u8"),
            MemoryAccessSize::U16 => write!(f, "u16"),
            MemoryAccessSize::U32 => write!(f, "u32"),
            MemoryAccessSize::U64 => write!(f, "u64"),
        }
    }
}

impl fmt::Display for ComputeStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ghostscope_platform::register_mapping::dwarf_reg_to_name;

        match self {
            ComputeStep::LoadRegister(r) => {
                if let Some(name) = dwarf_reg_to_name(*r) {
                    write!(f, "load {name}")
                } else {
                    write!(f, "load r{r}")
                }
            }
            ComputeStep::PushConstant(v) => write!(f, "push {v}"),
            ComputeStep::Dereference { size } => write!(f, "deref {size}"),
            ComputeStep::Add => write!(f, "add"),
            ComputeStep::Sub => write!(f, "sub"),
            ComputeStep::Mul => write!(f, "mul"),
            ComputeStep::Div => write!(f, "div"),
            ComputeStep::Mod => write!(f, "mod"),
            ComputeStep::And => write!(f, "and"),
            ComputeStep::Or => write!(f, "or"),
            ComputeStep::Xor => write!(f, "xor"),
            ComputeStep::Shl => write!(f, "shl"),
            ComputeStep::Shr => write!(f, "shr"),
            ComputeStep::Shra => write!(f, "shra"),
            ComputeStep::Not => write!(f, "not"),
            ComputeStep::Neg => write!(f, "neg"),
            ComputeStep::Abs => write!(f, "abs"),
            ComputeStep::Dup => write!(f, "dup"),
            ComputeStep::Drop => write!(f, "drop"),
            ComputeStep::Swap => write!(f, "swap"),
            ComputeStep::Rot => write!(f, "rot"),
            ComputeStep::Pick(n) => write!(f, "pick {n}"),
            ComputeStep::Eq => write!(f, "eq"),
            ComputeStep::Ne => write!(f, "ne"),
            ComputeStep::Lt => write!(f, "lt"),
            ComputeStep::Le => write!(f, "le"),
            ComputeStep::Gt => write!(f, "gt"),
            ComputeStep::Ge => write!(f, "ge"),
            ComputeStep::If {
                then_branch,
                else_branch,
            } => {
                write!(
                    f,
                    "if[then:{} else:{}]",
                    then_branch.len(),
                    else_branch.len()
                )
            }
        }
    }
}

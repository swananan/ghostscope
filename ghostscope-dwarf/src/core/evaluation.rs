//! DWARF expression planning primitives
//!
//! This module keeps the expression op IR shared by DWARF lowering, semantic
//! plans, CFI recovery, and compiler lowering. `RawExpressionResult` is a
//! transient detail of DWARF expression lowering; semantic variable planning
//! should traffic in `ParsedLocation`/`VariableLocation` instead.
//!
//! Design principles:
//! 1. Preserve whether an expression describes a value or a location
//! 2. Pre-compute as much as possible at compile time
//! 3. Keep register and memory dependencies explicit for later lowering

use std::collections::BTreeMap;
use std::fmt;

/// Raw, short-lived result of evaluating a DWARF expression.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum RawExpressionResult {
    /// Direct value - expression result is the variable value (no memory read needed)
    DirectValue(DirectValueResult),

    /// Memory location - expression result is an address that needs to be dereferenced
    MemoryLocation(LocationResult),

    /// Variable is optimized out (no location/value available)
    Optimized,

    /// Composite location (multiple pieces) - for split variables
    #[allow(dead_code)]
    Composite(Vec<PieceResult>),
}

/// Direct value results - expression produces the variable value directly
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DirectValueResult {
    /// Literal constant from DWARF expression (DW_OP_lit*, DW_OP_const*)
    Constant(i64),

    /// Link-time absolute address that must be rebased to a runtime address
    /// before use (for example, DW_OP_implicit_pointer targeting static storage).
    AbsoluteAddress(u64),

    /// Implicit value embedded in DWARF (DW_OP_implicit_value)
    ImplicitValue(Vec<u8>),

    /// Register contains the variable value directly (DW_OP_reg*)
    RegisterValue(u16),

    /// Computed value from expression (DW_OP_stack_value)
    /// This is a full expression that computes the value
    ComputedValue {
        /// Expression steps (stack-based computation)
        steps: Vec<PlanExprOp>,
        /// Expected result type size
        result_size: MemoryAccessSize,
    },
}

/// Memory location results - expression produces an address to be read via bpf_probe_read_user
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum LocationResult {
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
        steps: Vec<PlanExprOp>,
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
    Expression { steps: Vec<PlanExprOp> },
}

/// Caller-frame recovery rules materialized as planned expression ops.
#[derive(Debug, Clone, PartialEq)]
pub struct CallerFrameRecovery {
    /// Steps that compute the current frame's CFA.
    pub cfa_steps: Vec<PlanExprOp>,
    /// DWARF register number that holds the caller's return address.
    pub return_address_register: u16,
    /// Steps that recover the caller PC from the current frame.
    pub caller_pc_steps: Vec<PlanExprOp>,
    /// Per-register recovery steps keyed by DWARF register number.
    pub register_recovery_steps: BTreeMap<u16, Vec<PlanExprOp>>,
}

/// Piece of a composite location
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PieceResult {
    /// Location of this piece
    pub(crate) location: RawExpressionResult,
    /// Size in bytes
    pub(crate) size: u64,
    /// Bit offset within the piece (for bit fields)
    pub(crate) bit_offset: Option<u64>,
}

/// One caller-side case for recovering a callee's DW_OP_entry_value.
#[derive(Debug, Clone, PartialEq)]
pub struct EntryValueCase {
    /// Link-time caller return PC from DW_AT_call_return_pc.
    pub caller_return_pc: u64,
    /// Materialized planned expression ops that recover the original caller value.
    pub value_steps: Vec<PlanExprOp>,
}

/// Stack-machine expression op selected by DWARF lowering.
///
/// This is the single planned expression IR shared by DWARF expression
/// lowering, read plans, CFI recovery, and compiler/eBPF lowering.
#[derive(Debug, Clone, PartialEq)]
pub enum PlanExprOp {
    /// Load register value from pt_regs
    LoadRegister(u16), // DWARF register number

    /// Push constant
    PushConstant(i64),

    /// Memory dereference via bpf_probe_read_user
    Dereference {
        size: MemoryAccessSize,
    },

    /// Convert a target-module TLS offset into the current thread's address.
    ///
    /// This models DW_OP_form_tls_address. Runtime lowering is responsible for
    /// combining the offset with the thread pointer for the traced thread.
    FormTlsAddress,

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
        then_branch: Vec<PlanExprOp>,
        else_branch: Vec<PlanExprOp>,
    },

    /// Recover a DW_OP_entry_value at runtime by matching the recovered caller
    /// return PC against caller-side DW_AT_call_return_pc cases.
    EntryValueLookup {
        caller_pc_steps: Vec<PlanExprOp>,
        cases: Vec<EntryValueCase>,
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

    /// Create MemoryAccessSize from byte size
    pub fn from_size(size: u64) -> Self {
        match size {
            1 => MemoryAccessSize::U8,
            2 => MemoryAccessSize::U16,
            4 => MemoryAccessSize::U32,
            8 => MemoryAccessSize::U64,
            _ if size <= 8 => MemoryAccessSize::U64, // Default to U64 for larger sizes
            _ => MemoryAccessSize::U64,              // Fallback
        }
    }
}

impl DirectValueResult {
    /// Convert compute steps to a human-readable expression
    fn steps_to_expression(steps: &[PlanExprOp]) -> String {
        use ghostscope_platform::register_mapping::dwarf_reg_to_name;

        // Stack for expression building
        let mut stack: Vec<String> = Vec::new();

        for step in steps {
            match step {
                PlanExprOp::LoadRegister(r) => {
                    let reg_name = dwarf_reg_to_name(*r).unwrap_or("r?").to_string();
                    stack.push(reg_name);
                }
                PlanExprOp::PushConstant(v) => {
                    if *v >= 0 && *v <= 0xFF {
                        stack.push(format!("{v}"));
                    } else {
                        stack.push(format!("0x{v:x}"));
                    }
                }
                PlanExprOp::Add => {
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
                PlanExprOp::Sub => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}-{b})"));
                    } else {
                        stack.push("?-?".to_string());
                    }
                }
                PlanExprOp::Mul => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("{a}*{b}"));
                    } else {
                        stack.push("?*?".to_string());
                    }
                }
                PlanExprOp::Div => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}/{b})"));
                    } else {
                        stack.push("?/?".to_string());
                    }
                }
                PlanExprOp::Mod => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}%{b})"));
                    } else {
                        stack.push("?%?".to_string());
                    }
                }
                PlanExprOp::And => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}&{b})"));
                    } else {
                        stack.push("?&?".to_string());
                    }
                }
                PlanExprOp::Or => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}|{b})"));
                    } else {
                        stack.push("?|?".to_string());
                    }
                }
                PlanExprOp::Xor => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}^{b})"));
                    } else {
                        stack.push("?^?".to_string());
                    }
                }
                PlanExprOp::Shl => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}<<{b})"));
                    } else {
                        stack.push("?<<?".to_string());
                    }
                }
                PlanExprOp::Shr => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}>>{b})"));
                    } else {
                        stack.push("?>>?".to_string());
                    }
                }
                PlanExprOp::Shra => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}>>>{b})"));
                    } else {
                        stack.push("?>>>?".to_string());
                    }
                }
                PlanExprOp::Not => {
                    if let Some(a) = stack.pop() {
                        stack.push(format!("~{a}"));
                    } else {
                        stack.push("~?".to_string());
                    }
                }
                PlanExprOp::Neg => {
                    if let Some(a) = stack.pop() {
                        stack.push(format!("-{a}"));
                    } else {
                        stack.push("-?".to_string());
                    }
                }
                PlanExprOp::Abs => {
                    if let Some(a) = stack.pop() {
                        stack.push(format!("|{a}|"));
                    } else {
                        stack.push("|?|".to_string());
                    }
                }
                PlanExprOp::Dereference { size } => {
                    if let Some(a) = stack.pop() {
                        stack.push(format!("*({a} as {size})"));
                    } else {
                        stack.push(format!("*(? as {size})"));
                    }
                }
                PlanExprOp::FormTlsAddress => {
                    if let Some(a) = stack.pop() {
                        stack.push(format!("tls({a})"));
                    } else {
                        stack.push("tls(?)".to_string());
                    }
                }
                PlanExprOp::Dup => {
                    if let Some(top) = stack.last() {
                        stack.push(top.clone());
                    }
                }
                PlanExprOp::Drop => {
                    stack.pop();
                }
                PlanExprOp::Swap => {
                    if stack.len() >= 2 {
                        let len = stack.len();
                        stack.swap(len - 1, len - 2);
                    }
                }
                PlanExprOp::Rot => {
                    if stack.len() >= 3 {
                        let len = stack.len();
                        let third = stack.remove(len - 3);
                        stack.push(third);
                    }
                }
                PlanExprOp::Pick(n) => {
                    if stack.len() > *n as usize {
                        let idx = stack.len() - 1 - (*n as usize);
                        let val = stack[idx].clone();
                        stack.push(val);
                    } else {
                        stack.push("?".to_string());
                    }
                }
                PlanExprOp::Eq => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}=={b})"));
                    } else {
                        stack.push("?==?".to_string());
                    }
                }
                PlanExprOp::Ne => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}!={b})"));
                    } else {
                        stack.push("?!=?".to_string());
                    }
                }
                PlanExprOp::Lt => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}<{b})"));
                    } else {
                        stack.push("?<?".to_string());
                    }
                }
                PlanExprOp::Le => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}<={b})"));
                    } else {
                        stack.push("?<=?".to_string());
                    }
                }
                PlanExprOp::Gt => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}>{b})"));
                    } else {
                        stack.push("?>?".to_string());
                    }
                }
                PlanExprOp::Ge => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(format!("({a}>={b})"));
                    } else {
                        stack.push("?>=?".to_string());
                    }
                }
                PlanExprOp::If {
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
                PlanExprOp::EntryValueLookup { cases, .. } => {
                    stack.push(format!("entry_value[{} cases]", cases.len()));
                }
            }
        }

        // Return the top of stack or a placeholder
        stack.pop().unwrap_or_else(|| "?".to_string())
    }
}

pub(crate) fn plan_expr_steps_to_expression(steps: &[PlanExprOp]) -> String {
    DirectValueResult::steps_to_expression(steps)
}

impl LocationResult {
    /// Convert compute steps to a human-readable expression (reuse from DirectValueResult)
    fn steps_to_expression(steps: &[PlanExprOp]) -> String {
        DirectValueResult::steps_to_expression(steps)
    }
}

impl fmt::Display for RawExpressionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RawExpressionResult::DirectValue(dv) => write!(f, "[DirectValue] {dv}"),
            RawExpressionResult::MemoryLocation(loc) => write!(f, "[Memory] {loc}"),
            RawExpressionResult::Optimized => write!(f, "<optimized out>"),
            RawExpressionResult::Composite(pieces) => {
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
            DirectValueResult::AbsoluteAddress(addr) => write!(f, "&@0x{addr:x}"),
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

impl fmt::Display for PlanExprOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ghostscope_platform::register_mapping::dwarf_reg_to_name;

        match self {
            PlanExprOp::LoadRegister(r) => {
                if let Some(name) = dwarf_reg_to_name(*r) {
                    write!(f, "load {name}")
                } else {
                    write!(f, "load r{r}")
                }
            }
            PlanExprOp::PushConstant(v) => write!(f, "push {v}"),
            PlanExprOp::Dereference { size } => write!(f, "deref {size}"),
            PlanExprOp::FormTlsAddress => write!(f, "form_tls_address"),
            PlanExprOp::Add => write!(f, "add"),
            PlanExprOp::Sub => write!(f, "sub"),
            PlanExprOp::Mul => write!(f, "mul"),
            PlanExprOp::Div => write!(f, "div"),
            PlanExprOp::Mod => write!(f, "mod"),
            PlanExprOp::And => write!(f, "and"),
            PlanExprOp::Or => write!(f, "or"),
            PlanExprOp::Xor => write!(f, "xor"),
            PlanExprOp::Shl => write!(f, "shl"),
            PlanExprOp::Shr => write!(f, "shr"),
            PlanExprOp::Shra => write!(f, "shra"),
            PlanExprOp::Not => write!(f, "not"),
            PlanExprOp::Neg => write!(f, "neg"),
            PlanExprOp::Abs => write!(f, "abs"),
            PlanExprOp::Dup => write!(f, "dup"),
            PlanExprOp::Drop => write!(f, "drop"),
            PlanExprOp::Swap => write!(f, "swap"),
            PlanExprOp::Rot => write!(f, "rot"),
            PlanExprOp::Pick(n) => write!(f, "pick {n}"),
            PlanExprOp::Eq => write!(f, "eq"),
            PlanExprOp::Ne => write!(f, "ne"),
            PlanExprOp::Lt => write!(f, "lt"),
            PlanExprOp::Le => write!(f, "le"),
            PlanExprOp::Gt => write!(f, "gt"),
            PlanExprOp::Ge => write!(f, "ge"),
            PlanExprOp::If {
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
            PlanExprOp::EntryValueLookup { cases, .. } => {
                write!(f, "entry_value_lookup[cases:{}]", cases.len())
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum Expr {
    Int(i64),
    Float(f64),
    String(String),
    Bool(bool),
    UnaryNot(Box<Expr>),
    Variable(String),
    MemberAccess(Box<Expr>, String),   // person.name
    PointerDeref(Box<Expr>),           // *ptr
    AddressOf(Box<Expr>),              // &expr
    ArrayAccess(Box<Expr>, Box<Expr>), // arr[0] (new)
    ChainAccess(Vec<String>),          // person.name.first (new)
    SpecialVar(String),                // For $arg0, $arg1, $retval, $pc, $sp etc.
    // Builtin function call, e.g., strncmp(expr, "lit", n), starts_with(expr, "lit")
    BuiltinCall {
        name: String,
        args: Vec<Expr>,
    },
    BinaryOp {
        left: Box<Expr>,
        op: BinaryOp,
        right: Box<Expr>,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum BinaryOp {
    Add,
    Subtract,
    Multiply,
    Divide,
    // Comparison operators
    Equal,
    NotEqual,
    LessThan,
    LessEqual,
    GreaterThan,
    GreaterEqual,
    // Logical operators
    LogicalAnd,
    LogicalOr,
}

#[derive(Debug, Clone, PartialEq)]
pub enum VarType {
    Int,
    Float,
    String,
    Bool,
}

#[derive(Debug, Clone)]
pub enum Statement {
    Print(PrintStatement), // Updated to use new PrintStatement
    Backtrace,
    Expr(Expr),
    VarDeclaration {
        name: String,
        value: Expr,
    },
    TracePoint {
        pattern: TracePattern,
        body: Vec<Statement>,
    },
    If {
        condition: Expr,
        then_body: Vec<Statement>,
        else_body: Option<Box<Statement>>,
    },
    Block(Vec<Statement>),
}

/// Print statement variants for new instruction system
#[derive(Debug, Clone)]
pub enum PrintStatement {
    /// print "hello world"
    String(String),
    /// print variable_name
    Variable(String),
    /// print person.name or arr[0] (new: support complex expressions)
    ComplexVariable(Expr),
    /// print "format {} {}" arg1, arg2
    Formatted { format: String, args: Vec<Expr> },
}

#[derive(Debug, Clone)]
pub enum TracePattern {
    FunctionName(String), // trace main { ... }
    Wildcard(String),     // trace printf* { ... }
    Address(u64),         // trace 0x400000 { ... }
    AddressInModule {
        // trace module_suffix:0xADDR { ... }
        module: String,
        address: u64,
    },
    SourceLine {
        // trace file.c:123 { ... }
        file_path: String,
        line_number: u32,
    },
}

/// Variable validation context
#[derive(Debug, Clone)]
pub struct VariableContext {
    pub current_address: Option<u64>,
    pub available_vars: Vec<String>, // Variables available at current context
}

impl VariableContext {
    pub fn new() -> Self {
        Self {
            current_address: None,
            available_vars: vec![
                // Always available special variables
                "$arg0".to_string(),
                "$arg1".to_string(),
                "$arg2".to_string(),
                "$arg3".to_string(),
                "$retval".to_string(),
                "$pc".to_string(),
                "$sp".to_string(),
            ],
        }
    }

    pub fn is_variable_available(&self, var_name: &str) -> bool {
        self.available_vars.contains(&var_name.to_string())
    }

    pub fn add_variable(&mut self, var_name: String) {
        if !self.available_vars.contains(&var_name) {
            self.available_vars.push(var_name);
        }
    }
}

impl Default for VariableContext {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct Program {
    pub statements: Vec<Statement>,
}

impl Program {
    pub fn new() -> Self {
        Program {
            statements: Vec::new(),
        }
    }

    pub fn add_statement(&mut self, statement: Statement) {
        self.statements.push(statement);
    }
}

impl Default for Program {
    fn default() -> Self {
        Self::new()
    }
}

// Add type inference function
pub fn infer_type(expr: &Expr) -> Result<VarType, String> {
    match expr {
        Expr::Int(_) => Ok(VarType::Int),
        Expr::Float(_) => Ok(VarType::Float),
        Expr::String(_) => Ok(VarType::String),
        Expr::Bool(_) => Ok(VarType::Bool),
        Expr::UnaryNot(_) => Ok(VarType::Bool),
        // During parsing phase, we cannot know variable types, only check literal expressions
        // For variable references, return a default type to allow compilation to continue, actual type checking will be done in code generation phase
        Expr::Variable(_) => Ok(VarType::Int), // Temporarily assume variables are integer type to let parsing pass
        Expr::MemberAccess(_, _) => Ok(VarType::Int), // Same as above
        Expr::PointerDeref(_) => Ok(VarType::Int), // Same as above
        Expr::AddressOf(_) => Ok(VarType::Int), // Address as integer/pointer value for now
        Expr::ArrayAccess(_, _) => Ok(VarType::Int), // New: array access returns element type (assume int for now)
        Expr::ChainAccess(_) => Ok(VarType::Int), // New: chain access returns final member type (assume int for now)
        Expr::SpecialVar(_) => Ok(VarType::Int),  // Special variables like $arg0, $retval etc.
        Expr::BuiltinCall { name, args: _ } => match name.as_str() {
            "strncmp" | "starts_with" | "memcmp" => Ok(VarType::Bool),
            _ => Err(format!("Unknown builtin function: {}", name)),
        },
        Expr::BinaryOp { left, op, right } => {
            // Only check types when both sides are literals
            let left_is_literal = matches!(
                left.as_ref(),
                Expr::Int(_) | Expr::Float(_) | Expr::String(_)
            );
            let right_is_literal = matches!(
                right.as_ref(),
                Expr::Int(_) | Expr::Float(_) | Expr::String(_)
            );

            if left_is_literal && right_is_literal {
                let left_type = infer_type(left)?;
                let right_type = infer_type(right)?;

                if left_type != right_type {
                    return Err(format!(
                        "Type mismatch: Cannot perform operation between {:?} and {:?}",
                        left_type, right_type
                    ));
                }

                // Strings only support addition operation and comparison operations
                if left_type == VarType::String
                    && !matches!(*op, BinaryOp::Add | BinaryOp::Equal | BinaryOp::NotEqual)
                {
                    return Err(
                        "String type only supports addition and comparison operations".to_string(),
                    );
                }

                // Comparison operations return boolean type
                if matches!(
                    *op,
                    BinaryOp::Equal
                        | BinaryOp::NotEqual
                        | BinaryOp::LessThan
                        | BinaryOp::LessEqual
                        | BinaryOp::GreaterThan
                        | BinaryOp::GreaterEqual
                ) {
                    return Ok(VarType::Bool);
                }

                // Logical operations return boolean; allow Int literals as truthy (non-zero)
                if matches!(*op, BinaryOp::LogicalAnd | BinaryOp::LogicalOr) {
                    match (left_type, right_type) {
                        (VarType::Bool, VarType::Bool)
                        | (VarType::Bool, VarType::Int)
                        | (VarType::Int, VarType::Bool)
                        | (VarType::Int, VarType::Int) => return Ok(VarType::Bool),
                        _ => {
                            return Err("Logical operations require boolean or integer operands"
                                .to_string())
                        }
                    }
                }

                Ok(left_type)
            } else {
                // If there are variable references, assume type compatibility to let parsing pass
                // Actual type checking will be done in code generation phase
                if matches!(*op, BinaryOp::LogicalAnd | BinaryOp::LogicalOr)
                    || matches!(
                        *op,
                        BinaryOp::Equal
                            | BinaryOp::NotEqual
                            | BinaryOp::LessThan
                            | BinaryOp::LessEqual
                            | BinaryOp::GreaterThan
                            | BinaryOp::GreaterEqual
                    )
                {
                    Ok(VarType::Bool)
                } else {
                    Ok(VarType::Int)
                }
            }
        }
    }
}

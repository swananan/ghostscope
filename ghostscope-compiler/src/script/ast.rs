#[derive(Debug, Clone)]
pub enum Expr {
    Int(i64),
    Float(f64),
    String(String),
    Variable(String),
    MemberAccess(Box<Expr>, String),
    PointerDeref(Box<Expr>),
    SpecialVar(String), // For $arg0, $arg1, $retval, $pc, $sp etc.
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
    /// print "format {} {}" arg1, arg2 (future)
    Formatted { format: String, args: Vec<Expr> },
}

#[derive(Debug, Clone)]
pub enum TracePattern {
    FunctionName(String), // trace main { ... }
    Wildcard(String),     // trace printf* { ... }
    Address(u64),         // trace 0x400000 { ... }
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

// Add type inference function
pub fn infer_type(expr: &Expr) -> Result<VarType, String> {
    match expr {
        Expr::Int(_) => Ok(VarType::Int),
        Expr::Float(_) => Ok(VarType::Float),
        Expr::String(_) => Ok(VarType::String),
        // During parsing phase, we cannot know variable types, only check literal expressions
        // For variable references, return a default type to allow compilation to continue, actual type checking will be done in code generation phase
        Expr::Variable(_) => Ok(VarType::Int), // Temporarily assume variables are integer type to let parsing pass
        Expr::MemberAccess(_, _) => Ok(VarType::Int), // Same as above
        Expr::PointerDeref(_) => Ok(VarType::Int), // Same as above
        Expr::SpecialVar(_) => Ok(VarType::Int), // Special variables like $arg0, $retval etc.
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

                // Logical operations expect boolean operands and return boolean
                if matches!(*op, BinaryOp::LogicalAnd | BinaryOp::LogicalOr) {
                    if left_type != VarType::Bool || right_type != VarType::Bool {
                        return Err("Logical operations require boolean operands".to_string());
                    }
                    return Ok(VarType::Bool);
                }

                Ok(left_type)
            } else {
                // If there are variable references, assume type compatibility to let parsing pass
                // Actual type checking will be done in code generation phase
                Ok(VarType::Int)
            }
        }
    }
}

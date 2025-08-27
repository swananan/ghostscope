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
}

#[derive(Debug, Clone, PartialEq)]
pub enum VarType {
    Int,
    Float,
    String,
}

#[derive(Debug, Clone)]
pub enum Statement {
    Print(Expr),
    Backtrace,
    Expr(Expr),
    VarDeclaration { name: String, value: Expr },
    TracePoint { pattern: TracePattern, body: Vec<Statement> },
}

#[derive(Debug, Clone)]
pub enum TracePattern {
    FunctionName(String),      // trace main { ... }
    Wildcard(String),         // trace printf* { ... }
    Address(u64),             // trace 0x400000 { ... }
}

#[derive(Debug)]
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

                // Strings only support addition operation
                if left_type == VarType::String && *op != BinaryOp::Add {
                    return Err("String type only supports addition operation".to_string());
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

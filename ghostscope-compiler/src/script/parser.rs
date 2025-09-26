use pest::iterators::{Pair, Pairs};
use pest::Parser;
use pest::RuleType;
use pest_derive::Parser;

use crate::script::ast::{
    infer_type, BinaryOp, Expr, PrintStatement, Program, Statement, TracePattern,
};
use crate::script::format_validator::FormatValidator;
use tracing::debug;

#[derive(Parser)]
#[grammar = "script/grammar.pest"]
pub struct GhostScopeParser;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("Pest parser error: {0}")]
    Pest(#[from] Box<pest::error::Error<Rule>>),

    #[error("Unexpected token: {0:?}")]
    UnexpectedToken(Rule),

    #[error("Invalid expression")]
    InvalidExpression,

    #[error("Type error: {0}")]
    TypeError(String),
}

impl From<pest::error::Error<Rule>> for ParseError {
    fn from(err: pest::error::Error<Rule>) -> Self {
        ParseError::Pest(Box::new(err))
    }
}

pub type Result<T> = std::result::Result<T, ParseError>;

// Custom chunks function with RuleType constraint
fn chunks_of_two<'a, T: RuleType>(pairs: Pairs<'a, T>) -> Vec<Vec<Pair<'a, T>>> {
    let pairs_vec: Vec<_> = pairs.collect();
    let mut result = Vec::new();

    let mut i = 0;
    while i + 1 < pairs_vec.len() {
        result.push(vec![pairs_vec[i].clone(), pairs_vec[i + 1].clone()]);
        i += 2;
    }

    // Handle remaining elements
    if i < pairs_vec.len() {
        result.push(vec![pairs_vec[i].clone()]);
    }

    result
}

pub fn parse(input: &str) -> Result<Program> {
    debug!("Starting to parse input: {}", input.trim());

    let pairs = GhostScopeParser::parse(Rule::program, input)?;
    let mut program = Program::new();

    for pair in pairs {
        debug!(
            "Parsing top-level rule: {:?} = '{}'",
            pair.as_rule(),
            pair.as_str().trim()
        );
        match pair.as_rule() {
            Rule::statement => {
                let statement = parse_statement(pair)?;
                program.add_statement(statement);
            }
            Rule::EOI => {}
            _ => return Err(ParseError::UnexpectedToken(pair.as_rule())),
        }
    }

    debug!("Parsing completed successfully");
    Ok(program)
}

fn parse_statement(pair: Pair<Rule>) -> Result<Statement> {
    debug!(
        "parse_statement: {:?} = '{}'",
        pair.as_rule(),
        pair.as_str().trim()
    );
    let inner = pair.into_inner().next().unwrap();
    debug!(
        "parse_statement inner: {:?} = '{}'",
        inner.as_rule(),
        inner.as_str().trim()
    );

    match inner.as_rule() {
        Rule::trace_stmt => {
            let mut inner_pairs = inner.into_inner();
            let pattern_pair = inner_pairs.next().unwrap();
            let pattern = parse_trace_pattern(pattern_pair)?;

            let mut body = Vec::new();
            for stmt_pair in inner_pairs {
                let stmt = parse_statement(stmt_pair)?;
                body.push(stmt);
            }

            Ok(Statement::TracePoint { pattern, body })
        }
        Rule::print_stmt => {
            let print_content = inner.into_inner().next().unwrap();
            let print_stmt = parse_print_content(print_content)?;
            Ok(Statement::Print(print_stmt))
        }
        Rule::backtrace_stmt => Ok(Statement::Backtrace),
        Rule::expr_stmt => {
            let expr = inner.into_inner().next().unwrap();
            let parsed_expr = parse_expr(expr)?;

            // Check expression type to ensure consistent operation types
            if let Err(err) = infer_type(&parsed_expr) {
                return Err(ParseError::TypeError(err));
            }

            Ok(Statement::Expr(parsed_expr))
        }
        Rule::var_decl_stmt => {
            let mut inner_pairs = inner.into_inner();
            let name = inner_pairs.next().unwrap().as_str().to_string();
            let expr = inner_pairs.next().unwrap();
            let parsed_expr = parse_expr(expr)?;

            // Check expression type to ensure consistent operation types
            if let Err(err) = infer_type(&parsed_expr) {
                return Err(ParseError::TypeError(err));
            }

            Ok(Statement::VarDeclaration {
                name,
                value: parsed_expr,
            })
        }
        Rule::if_stmt => {
            debug!("Parsing if_stmt");
            let mut inner_pairs = inner.into_inner();
            let condition_pair = inner_pairs.next().unwrap();
            debug!(
                "if_stmt condition_pair: {:?} = '{}'",
                condition_pair.as_rule(),
                condition_pair.as_str().trim()
            );
            let condition = parse_condition(condition_pair)?;

            // Parse then body statements
            let mut then_body = Vec::new();
            let mut else_body = None;

            for pair in inner_pairs {
                match pair.as_rule() {
                    Rule::statement => {
                        then_body.push(parse_statement(pair)?);
                    }
                    Rule::else_clause => {
                        else_body = Some(Box::new(parse_else_clause(pair)?));
                        break;
                    }
                    _ => return Err(ParseError::UnexpectedToken(pair.as_rule())),
                }
            }

            Ok(Statement::If {
                condition,
                then_body,
                else_body,
            })
        }
        _ => Err(ParseError::UnexpectedToken(inner.as_rule())),
    }
}

fn parse_expr(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::expr => {
            let mut pairs = pair.into_inner();
            let first = pairs.next().unwrap();
            let mut left = parse_term(first)?;

            for chunk in chunks_of_two(pairs) {
                if chunk.len() != 2 {
                    return Err(ParseError::InvalidExpression);
                }

                let op = match chunk[0].as_str() {
                    "+" => BinaryOp::Add,
                    "-" => BinaryOp::Subtract,
                    _ => return Err(ParseError::UnexpectedToken(chunk[0].as_rule())),
                };

                let right = parse_term(chunk[1].clone())?;

                // Check type consistency for binary operations
                let expr = Expr::BinaryOp {
                    left: Box::new(left),
                    op,
                    right: Box::new(right),
                };

                // Only check type consistency for literals here
                if let Err(err) = infer_type(&expr) {
                    return Err(ParseError::TypeError(err));
                }

                left = expr;
            }

            Ok(left)
        }
        _ => Err(ParseError::UnexpectedToken(pair.as_rule())),
    }
}

fn parse_condition(pair: Pair<Rule>) -> Result<Expr> {
    debug!(
        "parse_condition: {:?} = '{}'",
        pair.as_rule(),
        pair.as_str().trim()
    );
    match pair.as_rule() {
        Rule::condition => {
            let mut pairs = pair.into_inner();
            let left_expr = pairs.next().unwrap();
            debug!(
                "condition left_expr: {:?} = '{}'",
                left_expr.as_rule(),
                left_expr.as_str().trim()
            );
            let left = parse_expr(left_expr)?;

            let op_pair = pairs.next().unwrap();
            debug!(
                "condition op_pair: {:?} = '{}'",
                op_pair.as_rule(),
                op_pair.as_str().trim()
            );
            let op = match op_pair.as_str() {
                "==" => BinaryOp::Equal,
                "!=" => BinaryOp::NotEqual,
                "<" => BinaryOp::LessThan,
                "<=" => BinaryOp::LessEqual,
                ">" => BinaryOp::GreaterThan,
                ">=" => BinaryOp::GreaterEqual,
                _ => return Err(ParseError::UnexpectedToken(op_pair.as_rule())),
            };

            let right_expr = pairs.next().unwrap();
            let right = parse_expr(right_expr)?;

            let expr = Expr::BinaryOp {
                left: Box::new(left),
                op,
                right: Box::new(right),
            };

            // Check type consistency for comparison operations
            if let Err(err) = infer_type(&expr) {
                return Err(ParseError::TypeError(err));
            }

            Ok(expr)
        }
        _ => Err(ParseError::UnexpectedToken(pair.as_rule())),
    }
}

fn parse_else_clause(pair: Pair<Rule>) -> Result<Statement> {
    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::if_stmt => {
            // Directly parse if statement for else if
            debug!("Parsing else if statement");
            let mut inner_pairs = inner.into_inner();
            let condition_pair = inner_pairs.next().unwrap();
            debug!(
                "else if condition_pair: {:?} = '{}'",
                condition_pair.as_rule(),
                condition_pair.as_str().trim()
            );
            let condition = parse_condition(condition_pair)?;

            // Parse then body statements
            let mut then_body = Vec::new();
            let mut else_body = None;

            for pair in inner_pairs {
                match pair.as_rule() {
                    Rule::statement => {
                        then_body.push(parse_statement(pair)?);
                    }
                    Rule::else_clause => {
                        else_body = Some(Box::new(parse_else_clause(pair)?));
                        break;
                    }
                    _ => return Err(ParseError::UnexpectedToken(pair.as_rule())),
                }
            }

            Ok(Statement::If {
                condition,
                then_body,
                else_body,
            })
        }
        _ => {
            // Parse else block statements
            let mut else_body = Vec::new();
            for stmt_pair in inner.into_inner() {
                else_body.push(parse_statement(stmt_pair)?);
            }
            Ok(Statement::Block(else_body))
        }
    }
}

fn parse_term(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::term => {
            let mut pairs = pair.into_inner();
            let first = pairs.next().unwrap();
            let mut left = parse_factor(first)?;

            for chunk in chunks_of_two(pairs) {
                if chunk.len() != 2 {
                    return Err(ParseError::InvalidExpression);
                }

                let op = match chunk[0].as_str() {
                    "*" => BinaryOp::Multiply,
                    "/" => BinaryOp::Divide,
                    _ => return Err(ParseError::UnexpectedToken(chunk[0].as_rule())),
                };

                let right = parse_factor(chunk[1].clone())?;

                // Check type consistency for binary operations
                let expr = Expr::BinaryOp {
                    left: Box::new(left),
                    op,
                    right: Box::new(right),
                };

                // Only check type consistency for literals here
                if let Err(err) = infer_type(&expr) {
                    return Err(ParseError::TypeError(err));
                }

                left = expr;
            }

            Ok(left)
        }
        _ => Err(ParseError::UnexpectedToken(pair.as_rule())),
    }
}

fn parse_factor(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::factor => {
            let inner = pair.into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::int => {
                    let value = inner.as_str().parse::<i64>().unwrap();
                    Ok(Expr::Int(value))
                }
                Rule::float => {
                    let value = inner.as_str().parse::<f64>().unwrap();
                    Ok(Expr::Float(value))
                }
                Rule::string => {
                    // Remove quotes at the beginning and end
                    let raw_value = inner.as_str();
                    let value = &raw_value[1..raw_value.len() - 1];
                    Ok(Expr::String(value.to_string()))
                }
                Rule::identifier => {
                    let name = inner.as_str().to_string();
                    Ok(Expr::Variable(name))
                }
                Rule::array_access => parse_array_access(inner),
                Rule::member_access => {
                    let mut parts = inner.into_inner();
                    let base = parts.next().unwrap().as_str().to_string();
                    let member = parts.next().unwrap().as_str().to_string();

                    // Copy base to avoid move errors
                    let base_clone = base.clone();
                    let mut expr = Expr::Variable(base_clone);

                    for part in parts {
                        expr = Expr::MemberAccess(Box::new(expr), part.as_str().to_string());
                    }

                    Ok(Expr::MemberAccess(Box::new(Expr::Variable(base)), member))
                }
                Rule::pointer_deref => {
                    let var = inner.into_inner().next().unwrap().as_str().to_string();
                    Ok(Expr::PointerDeref(Box::new(Expr::Variable(var))))
                }
                Rule::special_var => {
                    let var_name = inner.as_str().to_string();
                    Ok(Expr::SpecialVar(var_name))
                }
                Rule::expr => parse_expr(inner),
                _ => Err(ParseError::UnexpectedToken(inner.as_rule())),
            }
        }
        _ => Err(ParseError::UnexpectedToken(pair.as_rule())),
    }
}

fn parse_trace_pattern(pair: Pair<Rule>) -> Result<TracePattern> {
    let inner = pair.into_inner().next().unwrap();

    match inner.as_rule() {
        Rule::hex_address => {
            let addr_str = inner.as_str();
            // Remove "0x" prefix and parse as hex
            let addr_hex = &addr_str[2..];
            let addr =
                u64::from_str_radix(addr_hex, 16).map_err(|_| ParseError::InvalidExpression)?;
            Ok(TracePattern::Address(addr))
        }
        Rule::wildcard_pattern => {
            let pattern = inner.as_str().to_string();
            Ok(TracePattern::Wildcard(pattern))
        }
        Rule::function_name => {
            let func_name = inner.into_inner().next().unwrap().as_str().to_string();
            Ok(TracePattern::FunctionName(func_name))
        }
        Rule::source_line => {
            let mut parts = inner.into_inner();
            let file_path = parts.next().unwrap().as_str().to_string();
            let line_number = parts
                .next()
                .unwrap()
                .as_str()
                .parse::<u32>()
                .map_err(|_| ParseError::InvalidExpression)?;
            Ok(TracePattern::SourceLine {
                file_path,
                line_number,
            })
        }
        _ => Err(ParseError::UnexpectedToken(inner.as_rule())),
    }
}

fn parse_print_content(pair: Pair<Rule>) -> Result<PrintStatement> {
    debug!(
        "parse_print_content: {:?} = \"{}\"",
        pair.as_rule(),
        pair.as_str().trim()
    );

    let inner = pair.into_inner().next().unwrap();
    debug!(
        "parse_print_content inner: {:?} = \"{}\"",
        inner.as_rule(),
        inner.as_str().trim()
    );

    match inner.as_rule() {
        Rule::string => {
            // Extract string content (remove quotes)
            let content = inner.as_str();
            let content = &content[1..content.len() - 1]; // Remove surrounding quotes
            Ok(PrintStatement::String(content.to_string()))
        }
        Rule::identifier => {
            // Variable name
            let var_name = inner.as_str().to_string();
            Ok(PrintStatement::Variable(var_name))
        }
        Rule::complex_variable => {
            // Parse complex variable expression (person.name, arr[0], etc.)
            let expr = parse_complex_variable(inner)?;
            Ok(PrintStatement::ComplexVariable(expr))
        }
        Rule::format_expr => {
            // Format string with arguments
            let mut inner_pairs = inner.into_inner();
            let format_string = inner_pairs.next().unwrap();

            // Extract format string content (remove quotes)
            let format_content = format_string.as_str();
            let format_content = &format_content[1..format_content.len() - 1];

            // Parse arguments
            let mut args = Vec::new();
            for arg_pair in inner_pairs {
                let arg_expr = parse_expr(arg_pair)?;
                args.push(arg_expr);
            }

            // Validate format string and arguments match
            FormatValidator::validate_format_arguments(format_content, &args)?;

            Ok(PrintStatement::Formatted {
                format: format_content.to_string(),
                args,
            })
        }
        _ => Err(ParseError::UnexpectedToken(inner.as_rule())),
    }
}

// Parse complex variable expressions (person.name, arr[0], etc.)
fn parse_complex_variable(pair: Pair<Rule>) -> Result<Expr> {
    debug!(
        "parse_complex_variable: {:?} = \"{}\"",
        pair.as_rule(),
        pair.as_str().trim()
    );

    let inner = pair.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::chain_access => parse_chain_access(inner),
        Rule::array_access => parse_array_access(inner),
        Rule::member_access => parse_member_access(inner),
        Rule::pointer_deref => parse_pointer_deref(inner),
        _ => Err(ParseError::UnexpectedToken(inner.as_rule())),
    }
}

// Parse chain access: person.name.first
fn parse_chain_access(pair: Pair<Rule>) -> Result<Expr> {
    let mut chain = Vec::new();
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::identifier => {
                chain.push(inner_pair.as_str().to_string());
            }
            Rule::expr => {
                // This would be for arr[index] part in chain_access
                // For now, we'll keep it simple and just handle the identifier chain
                // TODO: Handle array access within chain access
            }
            _ => {}
        }
    }

    if chain.is_empty() {
        return Err(ParseError::InvalidExpression);
    }

    Ok(Expr::ChainAccess(chain))
}

// Parse array access: arr[index]
fn parse_array_access(pair: Pair<Rule>) -> Result<Expr> {
    let mut inner_pairs = pair.into_inner();
    let array_name = inner_pairs.next().unwrap();
    let index_expr = inner_pairs.next().unwrap();

    let array_expr = Box::new(Expr::Variable(array_name.as_str().to_string()));
    let index_expr = Box::new(parse_expr(index_expr)?);

    Ok(Expr::ArrayAccess(array_expr, index_expr))
}

// Parse member access: person.name
fn parse_member_access(pair: Pair<Rule>) -> Result<Expr> {
    let mut parts = pair.into_inner();
    let base = parts.next().unwrap().as_str().to_string();
    let member = parts.next().unwrap().as_str().to_string();

    // Copy base to avoid move errors
    let base_clone = base.clone();
    let mut expr = Expr::Variable(base_clone);

    for part in parts {
        expr = Expr::MemberAccess(Box::new(expr), part.as_str().to_string());
    }

    Ok(Expr::MemberAccess(Box::new(Expr::Variable(base)), member))
}

// Parse pointer dereference: *ptr
fn parse_pointer_deref(pair: Pair<Rule>) -> Result<Expr> {
    let var = pair.into_inner().next().unwrap().as_str().to_string();
    Ok(Expr::PointerDeref(Box::new(Expr::Variable(var))))
}

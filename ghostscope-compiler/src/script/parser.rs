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

    #[error("Unsupported feature: {0}")]
    UnsupportedFeature(String),
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
    // Only produce full (op, rhs) pairs; ignore any trailing leftover defensively
    while i + 1 < pairs_vec.len() {
        result.push(vec![pairs_vec[i].clone(), pairs_vec[i + 1].clone()]);
        i += 2;
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
            let inner = pair
                .into_inner()
                .next()
                .ok_or(ParseError::InvalidExpression)?;
            parse_logical_or(inner)
        }
        _ => Err(ParseError::UnexpectedToken(pair.as_rule())),
    }
}

fn parse_logical_or(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::logical_or => {
            let mut pairs = pair.into_inner();
            let first = pairs.next().ok_or(ParseError::InvalidExpression)?;
            let mut left = parse_logical_and(first)?;

            for chunk in chunks_of_two(pairs) {
                if chunk.len() != 2 {
                    return Err(ParseError::InvalidExpression);
                }
                if chunk[0].as_rule() != Rule::or_op {
                    return Err(ParseError::UnexpectedToken(chunk[0].as_rule()));
                }
                let right = parse_logical_and(chunk[1].clone())?;
                let expr = Expr::BinaryOp {
                    left: Box::new(left),
                    op: BinaryOp::LogicalOr,
                    right: Box::new(right),
                };
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

fn parse_logical_and(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::logical_and => {
            let mut pairs = pair.into_inner();
            let first = pairs.next().ok_or(ParseError::InvalidExpression)?;
            let mut left = parse_equality(first)?;

            for chunk in chunks_of_two(pairs) {
                if chunk.len() != 2 {
                    return Err(ParseError::InvalidExpression);
                }
                if chunk[0].as_rule() != Rule::and_op {
                    return Err(ParseError::UnexpectedToken(chunk[0].as_rule()));
                }
                let right = parse_equality(chunk[1].clone())?;
                let expr = Expr::BinaryOp {
                    left: Box::new(left),
                    op: BinaryOp::LogicalAnd,
                    right: Box::new(right),
                };
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

fn parse_equality(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::equality => {
            let mut pairs = pair.into_inner();
            let first = pairs.next().ok_or(ParseError::InvalidExpression)?;
            let mut left = parse_relational(first)?;

            for chunk in chunks_of_two(pairs) {
                if chunk.len() != 2 {
                    return Err(ParseError::InvalidExpression);
                }
                if chunk[0].as_rule() != Rule::eq_op {
                    return Err(ParseError::UnexpectedToken(chunk[0].as_rule()));
                }
                let op = match chunk[0].as_str() {
                    "==" => BinaryOp::Equal,
                    "!=" => BinaryOp::NotEqual,
                    _ => return Err(ParseError::UnexpectedToken(chunk[0].as_rule())),
                };
                let right = parse_relational(chunk[1].clone())?;
                let expr = Expr::BinaryOp {
                    left: Box::new(left),
                    op,
                    right: Box::new(right),
                };
                // Type check literals only
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

fn parse_relational(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::relational => {
            let mut pairs = pair.into_inner();
            let first = pairs.next().ok_or(ParseError::InvalidExpression)?;
            let mut left = parse_additive(first)?;

            for chunk in chunks_of_two(pairs) {
                if chunk.len() != 2 {
                    return Err(ParseError::InvalidExpression);
                }
                if chunk[0].as_rule() != Rule::rel_op {
                    return Err(ParseError::UnexpectedToken(chunk[0].as_rule()));
                }
                let op = match chunk[0].as_str() {
                    "<" => BinaryOp::LessThan,
                    "<=" => BinaryOp::LessEqual,
                    ">" => BinaryOp::GreaterThan,
                    ">=" => BinaryOp::GreaterEqual,
                    _ => return Err(ParseError::UnexpectedToken(chunk[0].as_rule())),
                };
                let right = parse_additive(chunk[1].clone())?;
                let expr = Expr::BinaryOp {
                    left: Box::new(left),
                    op,
                    right: Box::new(right),
                };
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

fn parse_additive(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::additive => {
            let mut pairs = pair.into_inner();
            let first = pairs.next().ok_or(ParseError::InvalidExpression)?;
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
                let expr = Expr::BinaryOp {
                    left: Box::new(left),
                    op,
                    right: Box::new(right),
                };
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
            // Condition now accepts a full expression (equality/relational/additive/etc.)
            let inner_expr_pair = pair
                .into_inner()
                .next()
                .ok_or(ParseError::InvalidExpression)?;
            let expr = parse_expr(inner_expr_pair)?;
            // Basic type check of the resulting expression
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
            let mut left = parse_unary(first)?;

            for chunk in chunks_of_two(pairs) {
                if chunk.len() != 2 {
                    return Err(ParseError::InvalidExpression);
                }

                let op = match chunk[0].as_str() {
                    "*" => BinaryOp::Multiply,
                    "/" => BinaryOp::Divide,
                    _ => return Err(ParseError::UnexpectedToken(chunk[0].as_rule())),
                };

                let right = parse_unary(chunk[1].clone())?;

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

fn parse_unary(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::unary => {
            let mut inner = pair.into_inner();
            let first = inner.next().ok_or(ParseError::InvalidExpression)?;
            match first.as_rule() {
                Rule::factor => parse_factor(first),
                // Recursive unary: '-' ~ unary
                Rule::unary => {
                    let right = parse_unary(first)?;
                    let expr = Expr::BinaryOp {
                        left: Box::new(Expr::Int(0)),
                        op: BinaryOp::Subtract,
                        right: Box::new(right),
                    };
                    if let Err(err) = infer_type(&expr) {
                        return Err(ParseError::TypeError(err));
                    }
                    Ok(expr)
                }
                _ => Err(ParseError::UnexpectedToken(first.as_rule())),
            }
        }
        _ => Err(ParseError::UnexpectedToken(pair.as_rule())),
    }
}

fn parse_factor(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::factor => {
            let inner = pair.into_inner().next().unwrap();
            match inner.as_rule() {
                Rule::strncmp_call => parse_builtin_call(inner),
                Rule::starts_with_call => parse_builtin_call(inner),
                Rule::chain_access => parse_chain_access(inner),
                Rule::pointer_deref => parse_pointer_deref(inner),
                Rule::address_of => parse_address_of(inner),
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
                Rule::member_access => parse_member_access(inner),
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

fn parse_builtin_call(pair: Pair<Rule>) -> Result<Expr> {
    // pair is strncmp_call or starts_with_call
    let rule = pair.as_rule();
    let mut it = pair.into_inner();
    // First token inside is the function name as identifier within the rule text; easier approach: use rule to select
    match rule {
        Rule::strncmp_call => {
            // grammar: strncmp "(" expr "," string "," int ")"
            let expr_node = it.next().ok_or(ParseError::InvalidExpression)?; // expr
            let arg0 = parse_expr(expr_node)?;
            let lit_node = it.next().ok_or(ParseError::InvalidExpression)?; // string
            if lit_node.as_rule() != Rule::string {
                return Err(ParseError::TypeError(
                    "strncmp second argument must be a string literal".to_string(),
                ));
            }
            let raw = lit_node.as_str();
            let lit = raw[1..raw.len() - 1].to_string();
            let n_node = it.next().ok_or(ParseError::InvalidExpression)?; // int
            if n_node.as_rule() != Rule::int {
                return Err(ParseError::TypeError(
                    "strncmp third argument must be a non-negative integer literal".to_string(),
                ));
            }
            let n_val: i64 = n_node.as_str().parse().unwrap_or(0);
            if n_val < 0 {
                return Err(ParseError::TypeError(
                    "strncmp length must be non-negative".to_string(),
                ));
            }
            Ok(Expr::BuiltinCall {
                name: "strncmp".to_string(),
                args: vec![arg0, Expr::String(lit), Expr::Int(n_val)],
            })
        }
        Rule::starts_with_call => {
            // grammar: starts_with "(" expr "," string ")"
            let expr_node = it.next().ok_or(ParseError::InvalidExpression)?;
            let arg0 = parse_expr(expr_node)?;
            let lit_node = it.next().ok_or(ParseError::InvalidExpression)?;
            if lit_node.as_rule() != Rule::string {
                return Err(ParseError::TypeError(
                    "starts_with second argument must be a string literal".to_string(),
                ));
            }
            let raw = lit_node.as_str();
            let lit = raw[1..raw.len() - 1].to_string();
            Ok(Expr::BuiltinCall {
                name: "starts_with".to_string(),
                args: vec![arg0, Expr::String(lit)],
            })
        }
        _ => Err(ParseError::UnexpectedToken(rule)),
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
        Rule::expr => {
            // Generic expression printing
            let expr = parse_expr(inner)?;
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
        Rule::address_of => parse_address_of(inner),
        _ => Err(ParseError::UnexpectedToken(inner.as_rule())),
    }
}

// Parse chain access: person.name.first
fn parse_chain_access(pair: Pair<Rule>) -> Result<Expr> {
    let mut chain: Vec<String> = Vec::new();
    let mut opt_index: Option<Expr> = None;
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::identifier => {
                chain.push(inner_pair.as_str().to_string());
            }
            Rule::expr => {
                // Support array index only at the end of the chain (Phase 1: require literal int)
                let parsed = parse_expr(inner_pair)?;
                if !matches!(parsed, Expr::Int(_)) {
                    return Err(ParseError::UnsupportedFeature(
                        "array index must be a literal integer (TODO: dynamic index)".to_string(),
                    ));
                }
                opt_index = Some(parsed);
            }
            _ => {}
        }
    }

    if chain.is_empty() {
        return Err(ParseError::InvalidExpression);
    }

    // Build base expression from the chain identifiers
    let mut expr = Expr::Variable(chain[0].clone());
    for seg in &chain[1..] {
        expr = Expr::MemberAccess(Box::new(expr), seg.clone());
    }

    // If there's a trailing index, convert to ArrayAccess on the built base
    if let Some(idx) = opt_index {
        expr = Expr::ArrayAccess(Box::new(expr), Box::new(idx));
    }

    Ok(expr)
}

// Parse array access: arr[index]
fn parse_array_access(pair: Pair<Rule>) -> Result<Expr> {
    let mut inner_pairs = pair.into_inner();
    let array_name = inner_pairs.next().unwrap();
    let index_expr = inner_pairs.next().unwrap();

    let _array_expr = Box::new(Expr::Variable(array_name.as_str().to_string()));
    let parsed_index = parse_expr(index_expr)?;

    // Enforce: array index must be a literal integer at parse stage
    if !matches!(parsed_index, Expr::Int(_)) {
        return Err(ParseError::UnsupportedFeature(
            "array index must be a literal integer (TODO: support non-literal)".to_string(),
        ));
    }

    // Build base array access expression
    let mut expr = Expr::ArrayAccess(
        Box::new(Expr::Variable(array_name.as_str().to_string())),
        Box::new(parsed_index),
    );

    // Consume trailing .field segments if present
    for next in inner_pairs {
        // Any remaining tokens are member identifiers
        let m = next.as_str().to_string();
        expr = Expr::MemberAccess(Box::new(expr), m);
    }

    Ok(expr)
}

// Parse member access: person.name
fn parse_member_access(pair: Pair<Rule>) -> Result<Expr> {
    let mut parts = pair.into_inner();
    let base = parts.next().unwrap().as_str().to_string();

    // Collect all subsequent identifiers after the base
    let mut tail: Vec<String> = Vec::new();
    for p in parts {
        tail.push(p.as_str().to_string());
    }

    // If there is only one member, keep MemberAccess for simplicity.
    // For multi-level chains like a.b.c, normalize to ChainAccess([a, b, c])
    match tail.len() {
        0 => Err(ParseError::InvalidExpression),
        1 => Ok(Expr::MemberAccess(
            Box::new(Expr::Variable(base)),
            tail.remove(0),
        )),
        _ => {
            let mut chain = Vec::with_capacity(1 + tail.len());
            chain.push(base);
            chain.extend(tail);
            Ok(Expr::ChainAccess(chain))
        }
    }
}

// Parse pointer dereference: *ptr
fn parse_pointer_deref(pair: Pair<Rule>) -> Result<Expr> {
    let mut inner = pair.into_inner();
    let target = inner.next().ok_or(ParseError::InvalidExpression)?;
    let parsed = match target.as_rule() {
        Rule::expr => parse_expr(target)?,
        Rule::complex_variable => parse_complex_variable(target)?,
        Rule::identifier => Expr::Variable(target.as_str().to_string()),
        _ => return Err(ParseError::UnexpectedToken(target.as_rule())),
    };
    // Early normalization: *(&x) => x
    match parsed {
        Expr::AddressOf(inner_expr) => Ok(*inner_expr),
        other => Ok(Expr::PointerDeref(Box::new(other))),
    }
}

// Parse address-of: &expr
fn parse_address_of(pair: Pair<Rule>) -> Result<Expr> {
    let mut inner = pair.into_inner();
    let target = inner.next().ok_or(ParseError::InvalidExpression)?;
    let parsed = match target.as_rule() {
        Rule::expr => parse_expr(target)?,
        Rule::complex_variable => parse_complex_variable(target)?,
        Rule::identifier => Expr::Variable(target.as_str().to_string()),
        _ => return Err(ParseError::UnexpectedToken(target.as_rule())),
    };
    // Early normalization: &(*p) => p
    match parsed {
        Expr::PointerDeref(inner_expr) => Ok(*inner_expr),
        other => Ok(Expr::AddressOf(Box::new(other))),
    }
}

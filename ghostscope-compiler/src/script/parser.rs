use pest::iterators::{Pair, Pairs};
use pest::Parser;
use pest::RuleType;
use pest_derive::Parser;

use crate::script::ast::{
    infer_type, BinaryOp, Expr, PrintStatement, Program, Statement, TracePattern,
};
use crate::script::format_validator::FormatValidator;
use tracing::{debug, info};

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

    #[error("Syntax error: {0}")]
    SyntaxError(String),

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

    let pairs = match GhostScopeParser::parse(Rule::program, input) {
        Ok(p) => p,
        Err(e) => {
            // Heuristic: detect unclosed string in print lines to provide a clearer hint
            if let Some(msg) = detect_unclosed_print_string(input) {
                return Err(ParseError::SyntaxError(msg));
            }
            return Err(ParseError::Pest(Box::new(e)));
        }
    };
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

// Best-effort heuristic: if a line contains a print statement with an opening quote
// but no closing quote before arguments, give a clearer error.
fn detect_unclosed_print_string(input: &str) -> Option<String> {
    for (i, raw_line) in input.lines().enumerate() {
        let line = raw_line.trim_start();
        if !line.contains("print ") && !line.starts_with("print") {
            continue;
        }
        // Toggle on '"' to detect unclosed string; ignore escaped quotes for simplicity
        let mut open = false;
        for ch in line.chars() {
            if ch == '"' {
                open = !open;
            }
        }
        if open {
            // Common case: missing closing quote before comma and arguments
            if line.contains(',') {
                return Some(format!(
                    "Unclosed string literal in print at line {}. Did you forget a closing \"\" before ',' and arguments?",
                    i + 1
                ));
            } else {
                return Some(format!(
                    "Unclosed string literal in print at line {}.",
                    i + 1
                ));
            }
        }
    }
    None
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
            for node in inner.into_inner() {
                match node.as_rule() {
                    Rule::statement => {
                        else_body.push(parse_statement(node)?);
                    }
                    // Some grammars flatten block children to concrete statements (e.g., print_stmt)
                    Rule::print_stmt => {
                        let content = node
                            .into_inner()
                            .next()
                            .ok_or(ParseError::InvalidExpression)?;
                        let pr = parse_print_content(content)?;
                        else_body.push(Statement::Print(pr));
                    }
                    _ => return Err(ParseError::UnexpectedToken(node.as_rule())),
                }
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
                // '-' ~ unary
                Rule::neg_unary => {
                    let u = first
                        .into_inner()
                        .next()
                        .ok_or(ParseError::InvalidExpression)?;
                    let right = parse_unary(u)?;
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
                // '!' ~ unary
                Rule::not_unary => {
                    let u = first
                        .into_inner()
                        .next()
                        .ok_or(ParseError::InvalidExpression)?;
                    let right = parse_unary(u)?;
                    Ok(Expr::UnaryNot(Box::new(right)))
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
                Rule::memcmp_call => parse_builtin_call(inner),
                Rule::strncmp_call => parse_builtin_call(inner),
                Rule::starts_with_call => parse_builtin_call(inner),
                Rule::chain_access => parse_chain_access(inner),
                Rule::pointer_deref => parse_pointer_deref(inner),
                Rule::address_of => parse_address_of(inner),
                Rule::int => {
                    let value = inner.as_str().parse::<i64>().unwrap();
                    Ok(Expr::Int(value))
                }
                Rule::hex_int => {
                    // strip 0x and parse as hex
                    let s = inner.as_str();
                    let v = i64::from_str_radix(&s[2..], 16).unwrap_or(0);
                    Ok(Expr::Int(v))
                }
                Rule::oct_int => {
                    let s = inner.as_str();
                    let v = i64::from_str_radix(&s[2..], 8).unwrap_or(0);
                    Ok(Expr::Int(v))
                }
                Rule::bin_int => {
                    let s = inner.as_str();
                    let v = i64::from_str_radix(&s[2..], 2).unwrap_or(0);
                    Ok(Expr::Int(v))
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
                Rule::bool => {
                    let val = inner.as_str() == "true";
                    Ok(Expr::Bool(val))
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
    // pair is memcmp_call / strncmp_call / starts_with_call
    let rule = pair.as_rule();
    let mut it = pair.into_inner();
    // First token inside is the function name as identifier within the rule text; easier approach: use rule to select
    match rule {
        Rule::memcmp_call => {
            // grammar: memcmp "(" expr "," expr "," expr ")"
            let a_node = it.next().ok_or(ParseError::InvalidExpression)?; // expr
            let a_expr = parse_expr(a_node)?;
            let b_node = it.next().ok_or(ParseError::InvalidExpression)?; // expr
            let b_expr = parse_expr(b_node)?;
            let n_node = it.next().ok_or(ParseError::InvalidExpression)?; // expr (支持变量或常量)
            let n_expr = parse_expr(n_node)?;

            Ok(Expr::BuiltinCall {
                name: "memcmp".to_string(),
                args: vec![a_expr, b_expr, n_expr],
            })
        }
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
        Rule::module_hex_address => {
            let mut parts = inner.into_inner();
            let module = parts.next().unwrap().as_str().to_string();
            let hex = parts.next().unwrap().as_str();
            let addr =
                u64::from_str_radix(&hex[2..], 16).map_err(|_| ParseError::InvalidExpression)?;
            Ok(TracePattern::AddressInModule {
                module,
                address: addr,
            })
        }
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
    info!(
        "parse_print_content: rule={:?} text=\"{}\"",
        pair.as_rule(),
        pair.as_str().trim()
    );
    // Flatten any nested print_content nodes into a single list of children
    fn collect_flattened<'a>(p: Pair<'a, Rule>, out: &mut Vec<Pair<'a, Rule>>) {
        if p.as_rule() == Rule::print_content {
            for c in p.into_inner() {
                collect_flattened(c, out);
            }
        } else {
            out.push(p);
        }
    }

    let mut flat: Vec<Pair<Rule>> = Vec::new();
    collect_flattened(pair, &mut flat);
    info!(
        "parse_print_content: flat_rules=[{}]",
        flat.iter()
            .map(|p| format!("{:?}", p.as_rule()))
            .collect::<Vec<_>>()
            .join(", ")
    );
    if flat.is_empty() {
        return Err(ParseError::InvalidExpression);
    }

    // Prefer an explicit format_expr if present
    if let Some(fmt_idx) = flat.iter().position(|p| p.as_rule() == Rule::format_expr) {
        let fmt_pair = flat.remove(fmt_idx);
        info!("parse_print_content: branch=format_expr");
        let mut inner_pairs = fmt_pair.into_inner();
        let format_string = inner_pairs.next().unwrap();
        let format_content = &format_string.as_str()[1..format_string.as_str().len() - 1];
        let mut args = Vec::new();
        for arg_pair in inner_pairs {
            args.push(parse_expr(arg_pair)?);
        }
        info!(
            "parse_print_content: fmt='{}' argc={}",
            format_content,
            args.len()
        );
        FormatValidator::validate_format_arguments(format_content, &args)?;
        return Ok(PrintStatement::Formatted {
            format: format_content.to_string(),
            args,
        });
    }

    // Else, if first is a string and followed by one or more exprs, treat as flattened format
    if flat[0].as_rule() == Rule::string && flat.len() >= 2 {
        info!("parse_print_content: branch=flattened_string_with_args");
        let content_quoted = flat[0].as_str();
        let content = &content_quoted[1..content_quoted.len() - 1];
        let mut args = Vec::new();
        for p in flat.iter().skip(1) {
            if p.as_rule() != Rule::expr {
                return Err(ParseError::UnexpectedToken(p.as_rule()));
            }
            args.push(parse_expr(p.clone())?);
        }
        info!("parse_print_content: fmt='{}' argc={}", content, args.len());
        FormatValidator::validate_format_arguments(content, &args)?;
        return Ok(PrintStatement::Formatted {
            format: content.to_string(),
            args,
        });
    }

    // Single string or single expr
    match flat[0].as_rule() {
        Rule::string => {
            info!("parse_print_content: branch=plain_string");
            let content = flat[0].as_str();
            let content = &content[1..content.len() - 1];
            Ok(PrintStatement::String(content.to_string()))
        }
        Rule::expr => {
            info!("parse_print_content: branch=complex_variable");
            let expr = parse_expr(flat[0].clone())?;
            Ok(PrintStatement::ComplexVariable(expr))
        }
        other => {
            info!("parse_print_content: branch=unexpected rule={:?}", other);
            Err(ParseError::UnexpectedToken(other))
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_memcmp_builtin_in_if_should_succeed() {
        let script = r#"
trace foo {
    if memcmp(&buf[0], &buf[1], 16) { print "EQ"; }
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_memcmp_with_dynamic_len() {
        let script = r#"
trace foo {
    let n = 10;
    if memcmp(&buf[0], &buf[0], n) { print "OK"; }
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_if_else_with_flattened_format_and_star_len() {
        // else branch contains a flattened format print with {:s.*} and two args
        let script = r#"
trace src/http/ngx_http_request.c:1845 {
    if strncmp(host.data, "ghostscope", 10) {
        print "We got the request {}", *r;
    } else {
        print "The other hostname is {:s.*}", host.len, host.data;
    }
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_memcmp_len_zero_and_negative() {
        let script = r#"
trace foo {
    if memcmp(&p[0], &q[0], 0) { print "Z0"; }
    let k = -5;
    if memcmp(&p[0], &q[0], k) { print "NEG"; }
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_numeric_literals_hex_oct_bin_and_memcmp_usage() {
        let script = r#"
trace foo {
    let a = 0x10;   // 16
    let b = 0o755;  // 493
    let c = 0b1010; // 10
    // use in memcmp length
    if memcmp(&buf[0], &buf[0], 0x20) { print "H"; }
    if memcmp(&buf[0], &buf[0], 0o40) { print "O"; }
    if memcmp(&buf[0], &buf[0], 0b100000) { print "B"; }
    // use numeric literal as pointer address for second arg
    if memcmp(&buf[0], 0x7fff0000, 16) { print "P"; }
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_memcmp_with_numeric_pointers_and_len_bases() {
        let script = r#"
trace foo {
    let n = 0x10;
    if memcmp(0x1000, 0x2000, n) { print "NP"; }
    if memcmp(0o4000, 0b1000000000000, 0o20) { print "NP2"; }
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_format_static_len_bases_in_prints() {
        // Validate that static length .N supports 0x/0o/0b in formatted prints
        let script = r#"
trace foo {
    print "HX={:x.0x10}", buf;
    print "HS={:s.0o20}", buf;
    print "HB={:X.0b1000}", buf;
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_trace_patterns_function_line_address_wildcard() {
        // Function name
        let s1 = r#"trace main { print "OK"; }"#;
        assert!(parse(s1).is_ok());

        // Source line with path and hyphen
        let s2 = r#"trace /tmp/test-file.c:42 { print "L"; }"#;
        assert!(parse(s2).is_ok());

        // Hex address
        let s3 = r#"trace 0x401234 { print "A"; }"#;
        assert!(parse(s3).is_ok());

        // Wildcard
        let s4 = r#"trace printf* { print "W"; }"#;
        assert!(parse(s4).is_ok());

        // Module-qualified address
        let s5 = r#"trace /lib/x86_64-linux-gnu/libc.so.6:0x1234 { print "M"; }"#;
        assert!(parse(s5).is_ok());
    }

    #[test]
    fn parse_module_hex_address_overflow_should_error() {
        // Address exceeds u64 (17 hex digits) -> parse error, not 0 fallback
        let s = r#"trace libfoo.so:0x10000000000000000 { print "X"; }"#;
        let r = parse(s);
        assert!(r.is_err(), "expected parse error for overflow address");
    }

    #[test]
    fn parse_special_variables_basic() {
        // $pid/$tid/$timestamp in expressions and prints
        let script = r#"
trace foo {
    if $pid == 123 && $tid != 0 { print "PID_TID"; }
    print $timestamp;
    print "P:{} T:{} TS:{}", $pid, $tid, $timestamp;
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_chain_and_array_access() {
        // Member/chain and array tail index
        let script = r#"
trace foo {
    print person.name.first;
    print arr[0];
    // Supported: top-level array access with trailing member
    print ifaces[0].mtu;
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_pointer_and_address_of() {
        let script = r#"
trace foo {
    print *ptr;
    print &var;
    print *(arr_ptr);
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_unclosed_print_string_reports_friendly_error() {
        let bad = r#"
trace foo {
    print "Unclosed {}, value
}
"#;
        let r = parse(bad);
        match r {
            Err(ParseError::SyntaxError(msg)) => assert!(msg.contains("Unclosed string literal")),
            other => panic!("expected SyntaxError, got {other:?}"),
        }
    }
}

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
            // Heuristic: detect likely misspelled or unknown keywords and suggest fixes
            if let Some(msg) = detect_unknown_keyword(input) {
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

// Try to detect lines that start with an unknown/misspelled keyword and suggest known ones.
fn detect_unknown_keyword(input: &str) -> Option<String> {
    // Suggest only currently supported top-level keywords.
    const SUGGEST: &[&str] = &["trace", "print", "if", "else", "let"];
    // Valid statement starters that should not be flagged as unknown
    const SUPPORTED_HEADS: &[&str] = &["trace", "print", "if", "else", "let", "backtrace", "bt"];
    // Builtin call names allowed at expression head
    const BUILTIN_CALLS: &[&str] = &["memcmp", "strncmp", "starts_with", "hex"];

    // Helper: simple Levenshtein distance (small strings, few keywords)
    fn levenshtein(a: &str, b: &str) -> usize {
        let (n, m) = (a.len(), b.len());
        let mut dp = vec![0usize; (n + 1) * (m + 1)];
        let idx = |i: usize, j: usize| i * (m + 1) + j;
        for i in 0..=n {
            dp[idx(i, 0)] = i;
        }
        for j in 0..=m {
            dp[idx(0, j)] = j;
        }
        let ac: Vec<char> = a.chars().collect();
        let bc: Vec<char> = b.chars().collect();
        for i in 1..=n {
            for j in 1..=m {
                let cost = if ac[i - 1] == bc[j - 1] { 0 } else { 1 };
                let del = dp[idx(i - 1, j)] + 1;
                let ins = dp[idx(i, j - 1)] + 1;
                let sub = dp[idx(i - 1, j - 1)] + cost;
                dp[idx(i, j)] = del.min(ins).min(sub);
            }
        }
        dp[idx(n, m)]
    }

    // Helper: check a slice for a command-like unknown keyword
    fn check_slice(slice: &str, line_no_1based: usize) -> Option<String> {
        let s = slice.trim_start();
        if s.is_empty() || s.starts_with("//") {
            return None;
        }
        let mut token = String::new();
        for ch in s.chars() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                token.push(ch);
            } else {
                break;
            }
        }
        if token.is_empty() {
            return None;
        }
        if SUPPORTED_HEADS.iter().any(|k| *k == token) {
            return None;
        }
        let rest_untrimmed = &s[token.len()..];
        let rest = rest_untrimmed.trim_start();
        if rest.starts_with('=') || rest.starts_with('[') || rest.starts_with('.') {
            // likely an expression starting with identifier
            return None;
        }
        // Allow builtin calls as expression statements
        if BUILTIN_CALLS.iter().any(|k| *k == token) && rest.starts_with('(') {
            return None;
        }
        if rest.starts_with('(')
            || rest.starts_with('{')
            || rest.starts_with('"')
            || rest_untrimmed.starts_with(char::is_whitespace)
        {
            let mut suggestions: Vec<(&str, usize)> = SUGGEST
                .iter()
                .map(|&k| (k, levenshtein(&token, k)))
                .collect();
            suggestions.sort_by_key(|&(_, d)| d);
            if let Some((cand, dist)) = suggestions.first().copied() {
                if dist <= 2 {
                    return Some(format!(
                        "Unknown keyword '{token}' at line {line_no_1based}. Did you mean '{cand}'?"
                    ));
                }
            }
            return Some(format!(
                "Unknown keyword '{token}' at line {}. Expected one of: {}",
                line_no_1based,
                SUGGEST.join(", ")
            ));
        }
        None
    }

    for (i, raw_line) in input.lines().enumerate() {
        let line = raw_line;
        // Scan potential statement starts: at line start, and right after '{' ';' or '}' that are outside of strings
        let mut quote_open = false;
        let mut positions: Vec<usize> = vec![0]; // include start-of-line
        for (idx, ch) in line.char_indices() {
            if ch == '"' {
                quote_open = !quote_open;
            }
            if !quote_open && (ch == '{' || ch == ';' || ch == '}') {
                let next = idx + ch.len_utf8();
                if next < line.len() {
                    positions.push(next);
                }
            }
        }
        for &pos in &positions {
            if let Some(msg) = check_slice(&line[pos..], i + 1) {
                return Some(msg);
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
    let inner = pair
        .into_inner()
        .next()
        .ok_or(ParseError::InvalidExpression)?;
    debug!(
        "parse_statement inner: {:?} = '{}'",
        inner.as_rule(),
        inner.as_str().trim()
    );

    match inner.as_rule() {
        Rule::trace_stmt => {
            let mut inner_pairs = inner.into_inner();
            let pattern_pair = inner_pairs.next().ok_or(ParseError::InvalidExpression)?;
            let pattern = parse_trace_pattern(pattern_pair)?;

            let mut body = Vec::new();
            for stmt_pair in inner_pairs {
                // Disallow nested trace statements (trace is top-level only)
                if stmt_pair.as_rule() == Rule::statement {
                    let mut peek = stmt_pair.clone().into_inner();
                    if let Some(first) = peek.next() {
                        if first.as_rule() == Rule::trace_stmt {
                            return Err(ParseError::SyntaxError(
                                "'trace' cannot be nested; it is only allowed at the top level"
                                    .to_string(),
                            ));
                        }
                    }
                }
                let stmt = parse_statement(stmt_pair)?;
                body.push(stmt);
            }

            Ok(Statement::TracePoint { pattern, body })
        }
        Rule::print_stmt => {
            let print_content = inner
                .into_inner()
                .next()
                .ok_or(ParseError::InvalidExpression)?;
            let print_stmt = parse_print_content(print_content)?;
            Ok(Statement::Print(print_stmt))
        }
        Rule::backtrace_stmt => Ok(Statement::Backtrace),
        Rule::assign_stmt => {
            // Friendly error for immutable variables (no assignment supported)
            let mut it = inner.into_inner();
            let name = it
                .next()
                .ok_or(ParseError::InvalidExpression)?
                .as_str()
                .to_string();
            // consume rhs expr
            let _ = it.next();
            Err(ParseError::TypeError(format!(
                "Assignment is not supported: variables are immutable. Use 'let {name} = ...' to bind once."
            )))
        }
        Rule::expr_stmt => {
            let expr = inner
                .into_inner()
                .next()
                .ok_or(ParseError::InvalidExpression)?;
            let parsed_expr = parse_expr(expr)?;

            // Check expression type to ensure consistent operation types
            if let Err(err) = infer_type(&parsed_expr) {
                return Err(ParseError::TypeError(err));
            }

            Ok(Statement::Expr(parsed_expr))
        }
        Rule::var_decl_stmt => {
            let mut inner_pairs = inner.into_inner();
            let name = inner_pairs
                .next()
                .ok_or(ParseError::InvalidExpression)?
                .as_str()
                .to_string();
            let expr = inner_pairs.next().ok_or(ParseError::InvalidExpression)?;
            let parsed_expr = parse_expr(expr)?;

            // Check expression type to ensure consistent operation types
            if let Err(err) = infer_type(&parsed_expr) {
                return Err(ParseError::TypeError(err));
            }

            if is_alias_expr(&parsed_expr) {
                Ok(Statement::AliasDeclaration {
                    name,
                    target: parsed_expr,
                })
            } else {
                Ok(Statement::VarDeclaration {
                    name,
                    value: parsed_expr,
                })
            }
        }
        Rule::if_stmt => {
            debug!("Parsing if_stmt");
            let mut inner_pairs = inner.into_inner();
            let condition_pair = inner_pairs.next().ok_or(ParseError::InvalidExpression)?;
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

/// Determine if an expression should be treated as a DWARF alias binding.
/// This is a purely syntactic check (parser phase) and does not consult DWARF.
fn is_alias_expr(e: &Expr) -> bool {
    use crate::script::ast::BinaryOp as BO;
    use crate::script::ast::Expr as E;
    match e {
        E::AddressOf(_) => true,
        // Constant offset on top of an alias-eligible expression
        E::BinaryOp {
            left,
            op: BO::Add,
            right,
        } => {
            let is_nonneg_lit = |x: &E| matches!(x, E::Int(v) if *v >= 0);
            (is_alias_expr(left) && is_nonneg_lit(right))
                || (is_alias_expr(right) && is_nonneg_lit(left))
        }
        _ => false,
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
    let inner = pair
        .into_inner()
        .next()
        .ok_or(ParseError::InvalidExpression)?;
    match inner.as_rule() {
        Rule::if_stmt => {
            // Directly parse if statement for else if
            debug!("Parsing else if statement");
            let mut inner_pairs = inner.into_inner();
            let condition_pair = inner_pairs.next().ok_or(ParseError::InvalidExpression)?;
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
            let first = pairs.next().ok_or(ParseError::InvalidExpression)?;
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
            let inner = pair
                .into_inner()
                .next()
                .ok_or(ParseError::InvalidExpression)?;
            match inner.as_rule() {
                Rule::memcmp_call => parse_builtin_call(inner),
                Rule::strncmp_call => parse_builtin_call(inner),
                Rule::starts_with_call => parse_builtin_call(inner),
                Rule::hex_call => parse_builtin_call(inner),
                Rule::chain_access => parse_chain_access(inner),
                Rule::pointer_deref => parse_pointer_deref(inner),
                Rule::address_of => parse_address_of(inner),
                Rule::int => match inner.as_str().parse::<i64>() {
                    Ok(value) => Ok(Expr::Int(value)),
                    Err(_) => Err(ParseError::TypeError(
                        "invalid decimal integer literal".to_string(),
                    )),
                },
                Rule::hex_int => {
                    // strip 0x and parse as hex
                    let s = inner.as_str();
                    match i64::from_str_radix(&s[2..], 16) {
                        Ok(v) => Ok(Expr::Int(v)),
                        Err(_) => Err(ParseError::TypeError(
                            "invalid hex integer literal".to_string(),
                        )),
                    }
                }
                Rule::oct_int => {
                    let s = inner.as_str();
                    match i64::from_str_radix(&s[2..], 8) {
                        Ok(v) => Ok(Expr::Int(v)),
                        Err(_) => Err(ParseError::TypeError(
                            "invalid octal integer literal".to_string(),
                        )),
                    }
                }
                Rule::bin_int => {
                    let s = inner.as_str();
                    match i64::from_str_radix(&s[2..], 2) {
                        Ok(v) => Ok(Expr::Int(v)),
                        Err(_) => Err(ParseError::TypeError(
                            "invalid binary integer literal".to_string(),
                        )),
                    }
                }
                // Floats are not supported by scripts/runtime; reject early with friendly error
                Rule::float => Err(ParseError::TypeError(
                    "float literals are not supported".to_string(),
                )),
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
    // pair is memcmp_call / strncmp_call / starts_with_call / hex_call
    let rule = pair.as_rule();
    let mut it = pair.into_inner();
    // First token inside is the function name as identifier within the rule text; easier approach: use rule to select
    match rule {
        Rule::memcmp_call => {
            // grammar: memcmp("(" expr "," expr ["," expr] ")")
            let mut nodes: Vec<_> = it.collect();
            if nodes.len() < 2 || nodes.len() > 3 {
                return Err(ParseError::InvalidExpression);
            }
            let a_expr = parse_expr(nodes.remove(0))?;
            let b_expr = parse_expr(nodes.remove(0))?;

            // Disallow obviously invalid types early
            if matches!(a_expr, Expr::Bool(_)) || matches!(b_expr, Expr::Bool(_)) {
                return Err(ParseError::TypeError(
                    "memcmp pointer arguments cannot be boolean; use an address or hex(...)"
                        .to_string(),
                ));
            }
            if matches!(a_expr, Expr::String(_)) || matches!(b_expr, Expr::String(_)) {
                return Err(ParseError::TypeError(
                    "memcmp does not accept string literals; use strncmp for strings".to_string(),
                ));
            }

            // Helper to get hex length (bytes)
            let hex_len = |e: &Expr| -> Option<usize> {
                if let Expr::BuiltinCall { name, args } = e {
                    if name == "hex" {
                        if let Some(Expr::String(s)) = args.first() {
                            return Some(s.len() / 2);
                        }
                    }
                }
                None
            };

            let n_expr = if let Some(n_node) = nodes.first() {
                // With explicit len: reuse previous literal checks
                let n_expr = parse_expr(n_node.clone())?;
                if matches!(n_expr, Expr::Bool(_)) {
                    return Err(ParseError::TypeError(
                        "memcmp length must be an integer or expression, not boolean".to_string(),
                    ));
                }
                let literal_len_opt: Option<isize> = match &n_expr {
                    Expr::Int(n) => Some(*n as isize),
                    Expr::BinaryOp {
                        left,
                        op: BinaryOp::Subtract,
                        right,
                    } => {
                        if matches!(left.as_ref(), Expr::Int(0)) {
                            if let Expr::Int(k) = right.as_ref() {
                                Some(-(*k as isize))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                if let Some(n) = literal_len_opt {
                    if n < 0 {
                        return Err(ParseError::TypeError(
                            "memcmp length must be non-negative".to_string(),
                        ));
                    }
                    let l = n as usize;
                    if let Some(la) = hex_len(&a_expr) {
                        if l > la {
                            return Err(ParseError::TypeError(format!(
                                "memcmp length ({l}) exceeds hex pattern size on left side ({la} bytes)"
                            )));
                        }
                    }
                    if let Some(lb) = hex_len(&b_expr) {
                        if l > lb {
                            return Err(ParseError::TypeError(format!(
                                "memcmp length ({l}) exceeds hex pattern size on right side ({lb} bytes)"
                            )));
                        }
                    }
                }
                n_expr
            } else {
                // No len provided: allow only when at least one side is hex(...)
                let la = hex_len(&a_expr);
                let lb = hex_len(&b_expr);
                match (la, lb) {
                    (Some(l), None) | (None, Some(l)) => Expr::Int(l as i64),
                    (Some(la), Some(lb)) => {
                        if la != lb {
                            return Err(ParseError::TypeError(
                                "memcmp hex operands have different sizes; provide explicit len"
                                    .to_string(),
                            ));
                        }
                        Expr::Int(la as i64)
                    }
                    _ => {
                        return Err(ParseError::TypeError(
                            "memcmp without len requires at least one hex(...) operand".to_string(),
                        ))
                    }
                }
            };

            // Constant folding: memcmp(hex(...), hex(...), N)
            let as_hex = |e: &Expr| -> Option<String> {
                if let Expr::BuiltinCall { name, args } = e {
                    if name == "hex" {
                        if let Some(Expr::String(s)) = args.first() {
                            return Some(s.clone());
                        }
                    }
                }
                None
            };

            if let (Some(h1), Some(h2), Expr::Int(n)) = (as_hex(&a_expr), as_hex(&b_expr), &n_expr)
            {
                // Safe hex -> bytes (sanitized earlier to hex digits only)
                fn hex_to_bytes(s: &str) -> std::result::Result<Vec<u8>, ParseError> {
                    let mut out = Vec::with_capacity(s.len() / 2);
                    let bytes = s.as_bytes();
                    let mut i = 0;
                    while i + 1 < bytes.len() {
                        let h = bytes[i] as char;
                        let l = bytes[i + 1] as char;
                        let hv = h
                            .to_digit(16)
                            .ok_or_else(|| ParseError::TypeError("invalid hex digit".to_string()))?
                            as u8;
                        let lv = l
                            .to_digit(16)
                            .ok_or_else(|| ParseError::TypeError("invalid hex digit".to_string()))?
                            as u8;
                        out.push((hv << 4) | lv);
                        i += 2;
                    }
                    Ok(out)
                }

                let v1 = hex_to_bytes(&h1)?;
                let v2 = hex_to_bytes(&h2)?;
                let ln = (*n).max(0) as usize;
                let eq = v1.iter().take(ln).eq(v2.iter().take(ln));
                return Ok(Expr::Bool(eq));
            }

            Ok(Expr::BuiltinCall {
                name: "memcmp".to_string(),
                args: vec![a_expr, b_expr, n_expr],
            })
        }
        Rule::strncmp_call => {
            // grammar: strncmp("(" expr "," expr "," expr ")") [len must be non-negative integer literal]
            let arg0 = parse_expr(it.next().ok_or(ParseError::InvalidExpression)?)?;
            let arg1 = parse_expr(it.next().ok_or(ParseError::InvalidExpression)?)?;
            let n_expr_parsed = parse_expr(it.next().ok_or(ParseError::InvalidExpression)?)?;
            let n_val: i64 = match n_expr_parsed {
                Expr::Int(v) if v >= 0 => v,
                _ => {
                    return Err(ParseError::TypeError(
                        "strncmp third argument must be a non-negative integer literal".to_string(),
                    ))
                }
            };
            // Optional constant fold when both sides are string literals
            if let (Expr::String(a), Expr::String(b)) = (&arg0, &arg1) {
                let ln = n_val.max(0) as usize;
                let eq = a
                    .as_bytes()
                    .iter()
                    .take(ln)
                    .eq(b.as_bytes().iter().take(ln));
                return Ok(Expr::Bool(eq));
            }
            Ok(Expr::BuiltinCall {
                name: "strncmp".to_string(),
                args: vec![arg0, arg1, Expr::Int(n_val)],
            })
        }
        Rule::starts_with_call => {
            // grammar: starts_with("(" expr "," expr ")")
            let arg0 = parse_expr(it.next().ok_or(ParseError::InvalidExpression)?)?;
            let arg1 = parse_expr(it.next().ok_or(ParseError::InvalidExpression)?)?;
            // Constant fold when both are string literals
            if let (Expr::String(a), Expr::String(b)) = (&arg0, &arg1) {
                return Ok(Expr::Bool(a.as_bytes().starts_with(b.as_bytes())));
            }
            Ok(Expr::BuiltinCall {
                name: "starts_with".to_string(),
                args: vec![arg0, arg1],
            })
        }
        Rule::hex_call => {
            // grammar: hex("HEX...")
            // Validate at parse time: allow only hex digits with optional whitespace separators.
            let lit_node = it.next().ok_or(ParseError::InvalidExpression)?;
            if lit_node.as_rule() != Rule::string {
                return Err(ParseError::TypeError(
                    "hex expects a string literal".to_string(),
                ));
            }
            let raw = lit_node.as_str();
            let inner = &raw[1..raw.len() - 1];
            let mut sanitized = String::with_capacity(inner.len());
            for ch in inner.chars() {
                if ch.is_ascii_hexdigit() {
                    sanitized.push(ch);
                } else if ch == ' ' {
                    // allow spaces as separators (tabs not allowed)
                    continue;
                } else {
                    return Err(ParseError::TypeError(format!(
                        "hex literal contains non-hex character: '{ch}'"
                    )));
                }
            }
            if sanitized.len() % 2 == 1 {
                return Err(ParseError::TypeError(
                    "hex literal must contain an even number of hex digits".to_string(),
                ));
            }
            Ok(Expr::BuiltinCall {
                name: "hex".to_string(),
                // Store sanitized hex-only string; codegen will convert to bytes
                args: vec![Expr::String(sanitized)],
            })
        }
        _ => Err(ParseError::UnexpectedToken(rule)),
    }
}

fn parse_trace_pattern(pair: Pair<Rule>) -> Result<TracePattern> {
    let inner = pair
        .into_inner()
        .next()
        .ok_or(ParseError::InvalidExpression)?;

    match inner.as_rule() {
        Rule::module_hex_address => {
            let mut parts = inner.into_inner();
            let module = parts
                .next()
                .ok_or(ParseError::InvalidExpression)?
                .as_str()
                .to_string();
            let hex = parts.next().ok_or(ParseError::InvalidExpression)?.as_str();
            let addr = match u64::from_str_radix(&hex[2..], 16) {
                Ok(v) => v,
                Err(_) => {
                    return Err(ParseError::SyntaxError(format!(
                        "module-qualified address '{hex}' is invalid or too large for u64"
                    )))
                }
            };
            Ok(TracePattern::AddressInModule {
                module,
                address: addr,
            })
        }
        Rule::hex_address => {
            let addr_str = inner.as_str();
            // Remove "0x" prefix and parse as hex
            let addr_hex = &addr_str[2..];
            let addr = match u64::from_str_radix(addr_hex, 16) {
                Ok(v) => v,
                Err(_) => {
                    return Err(ParseError::SyntaxError(format!(
                        "address '{addr_str}' is invalid or too large for u64"
                    )))
                }
            };
            Ok(TracePattern::Address(addr))
        }
        Rule::wildcard_pattern => {
            let pattern = inner.as_str().to_string();
            Ok(TracePattern::Wildcard(pattern))
        }
        Rule::function_name => {
            let func_name = inner
                .into_inner()
                .next()
                .ok_or(ParseError::InvalidExpression)?
                .as_str()
                .to_string();
            Ok(TracePattern::FunctionName(func_name))
        }
        Rule::source_line => {
            let mut parts = inner.into_inner();
            let file_path = parts
                .next()
                .ok_or(ParseError::InvalidExpression)?
                .as_str()
                .to_string();
            let line_pair = parts.next().ok_or(ParseError::InvalidExpression)?;
            let line_number = line_pair
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
        let format_string = inner_pairs.next().ok_or(ParseError::InvalidExpression)?;
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

    let inner = pair
        .into_inner()
        .next()
        .ok_or(ParseError::InvalidExpression)?;
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
    let array_name = inner_pairs.next().ok_or(ParseError::InvalidExpression)?;
    let index_expr = inner_pairs.next().ok_or(ParseError::InvalidExpression)?;

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
    let base = parts
        .next()
        .ok_or(ParseError::InvalidExpression)?
        .as_str()
        .to_string();

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
    fn parse_memcmp_hex_builtin() {
        let script = r#"
trace foo {
    if memcmp(&buf[0], hex("504F"), 2) { print "OK"; }
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
    fn parse_hex_with_non_hex_char_should_fail() {
        let script = r#"
trace foo {
    if memcmp(&buf[0], hex("G0"), 1) { print "X"; }
}
"#;
        let r = parse(script);
        match r {
            Ok(_) => panic!("expected parse error for non-hex char"),
            Err(ParseError::TypeError(msg)) => {
                assert!(
                    msg.contains("hex literal contains non-hex character"),
                    "unexpected msg: {msg}"
                );
            }
            Err(e) => panic!("unexpected error variant: {e:?}"),
        }
    }

    #[test]
    fn parse_hex_with_odd_digits_should_fail() {
        let script = r#"
trace foo {
    if memcmp(&buf[0], hex("123"), 1) { print "X"; }
}
"#;
        let r = parse(script);
        match r {
            Ok(_) => panic!("expected parse error for odd-length hex"),
            Err(ParseError::TypeError(msg)) => {
                assert!(
                    msg.contains("even number of hex digits"),
                    "unexpected msg: {msg}"
                );
            }
            Err(e) => panic!("unexpected error variant: {e:?}"),
        }
    }

    #[test]
    fn parse_hex_with_spaces_should_succeed() {
        let script = r#"
trace foo {
    if memcmp(&buf[0], hex("4c 49 42 5f"), 4) { print "OK"; }
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_alias_declaration_address_of_and_member_access() {
        let script = r#"
trace foo {
    let p = &buf[0];
    let s = obj.field;
}
"#;
        let prog = parse(script).expect("parse ok");
        let stmt0 = prog.statements.first().expect("trace");
        match stmt0 {
            Statement::TracePoint { body, .. } => {
                // Only the address-of form should be alias; member access is a value binding
                assert!(matches!(body[0], Statement::AliasDeclaration { .. }));
                assert!(matches!(body[1], Statement::VarDeclaration { .. }));
            }
            other => panic!("expected TracePoint, got {other:?}"),
        }
    }

    #[test]
    fn parse_alias_declaration_with_constant_offset() {
        let script = r#"
trace foo {
    let p = &arr[0] + 16;
    let q = 32 + &arr[0];
}
"#;
        let prog = parse(script).expect("parse ok");
        let stmt0 = prog.statements.first().expect("trace");
        match stmt0 {
            Statement::TracePoint { body, .. } => {
                assert!(matches!(body[0], Statement::AliasDeclaration { .. }));
                assert!(matches!(body[1], Statement::AliasDeclaration { .. }));
            }
            other => panic!("expected TracePoint, got {other:?}"),
        }
    }

    #[test]
    fn parse_member_access_scalar_not_alias() {
        let script = r#"
trace foo {
    let level = record.level;
}
"#;
        let prog = parse(script).expect("parse ok");
        let stmt0 = prog.statements.first().expect("trace");
        match stmt0 {
            Statement::TracePoint { body, .. } => {
                assert!(matches!(body[0], Statement::VarDeclaration { .. }));
            }
            other => panic!("expected TracePoint, got {other:?}"),
        }
    }

    #[test]
    fn parse_memcmp_rejects_string_literal() {
        let script = r#"
trace foo {
    if memcmp(&buf[0], "PO", 2) { print "X"; }
}
"#;
        let r = parse(script);
        assert!(
            matches!(r, Err(ParseError::TypeError(ref msg)) if msg.contains("memcmp does not accept string literals")),
            "expected type error, got: {r:?}"
        );
    }

    #[test]
    fn parse_memcmp_rejects_bool_args_and_len() {
        // Bool as pointer argument
        let s1 = r#"
trace foo { if memcmp(true, hex("00"), 1) { print "X"; } }
"#;
        let r1 = parse(s1);
        assert!(r1.is_err());

        // Bool as length
        let s2 = r#"
trace foo { if memcmp(&p[0], hex("00"), false) { print "X"; } }
"#;
        let r2 = parse(s2);
        assert!(
            matches!(r2, Err(ParseError::TypeError(ref msg)) if msg.contains("length must be")),
            "unexpected: {r2:?}"
        );
    }

    #[test]
    fn parse_strncmp_constant_folds_on_two_literals() {
        // equal for first 2 bytes
        let s = r#"
trace foo {
    if strncmp("abc", "abd", 2) { print "T"; } else { print "F"; }
}
"#;
        let prog = parse(s).expect("parse ok");
        // Walk down to the If condition and ensure it became a Bool(true)
        let stmt0 = prog.statements.first().expect("one trace");
        match stmt0 {
            Statement::TracePoint { body, .. } => match &body[0] {
                Statement::If { condition, .. } => {
                    assert!(matches!(condition, Expr::Bool(true)));
                }
                other => panic!("expected If, got {other:?}"),
            },
            other => panic!("expected TracePoint, got {other:?}"),
        }
    }

    #[test]
    fn parse_strncmp_requires_one_string_side_error() {
        let s = r#"
trace foo {
    if strncmp(1, 2, 1) { print "X"; }
}
"#;
        let r = parse(s);
        // Parser now accepts generic expr, so error will occur in compiler stage; ensure parse ok here
        assert!(
            r.is_ok(),
            "parse should succeed; semantic error in compiler"
        );
    }

    #[test]
    fn parse_memcmp_constant_folds_on_two_hex() {
        let s = r#"
trace foo {
    if memcmp(hex("504f"), hex("504F"), 2) { print "EQ"; } else { print "NE"; }
}
"#;
        let prog = parse(s).expect("parse ok");
        let stmt0 = prog.statements.first().expect("one trace");
        match stmt0 {
            Statement::TracePoint { body, .. } => match &body[0] {
                Statement::If { condition, .. } => assert!(matches!(condition, Expr::Bool(true))),
                other => panic!("expected If, got {other:?}"),
            },
            other => panic!("expected TracePoint, got {other:?}"),
        }

        // Mismatch without explicit len but equal sizes
        let s2 = r#"
trace foo {
    if memcmp(hex("504f"), hex("514f")) { print "EQ"; } else { print "NE"; }
}
"#;
        let prog2 = parse(s2).expect("parse ok");
        let stmt02 = prog2.statements.first().expect("one trace");
        match stmt02 {
            Statement::TracePoint { body, .. } => match &body[0] {
                Statement::If { condition, .. } => assert!(matches!(condition, Expr::Bool(false))),
                other => panic!("expected If, got {other:?}"),
            },
            other => panic!("expected TracePoint, got {other:?}"),
        }
    }

    #[test]
    fn parse_starts_with_constant_folds_on_two_literals() {
        let s = r#"
trace foo {
    if starts_with("abcdef", "abc") { print "T"; } else { print "F"; }
}
"#;
        let prog = parse(s).expect("parse ok");
        let stmt0 = prog.statements.first().expect("one trace");
        match stmt0 {
            Statement::TracePoint { body, .. } => match &body[0] {
                Statement::If { condition, .. } => assert!(matches!(condition, Expr::Bool(true))),
                other => panic!("expected If, got {other:?}"),
            },
            other => panic!("expected TracePoint, got {other:?}"),
        }

        let s2 = r#"
trace foo {
    if starts_with("ab", "abc") { print "T"; } else { print "F"; }
}
"#;
        let prog2 = parse(s2).expect("parse ok");
        let stmt02 = prog2.statements.first().expect("one trace");
        match stmt02 {
            Statement::TracePoint { body, .. } => match &body[0] {
                Statement::If { condition, .. } => assert!(matches!(condition, Expr::Bool(false))),
                other => panic!("expected If, got {other:?}"),
            },
            other => panic!("expected TracePoint, got {other:?}"),
        }
    }

    #[test]
    fn parse_memcmp_hex_len_exceeds_left_should_fail() {
        // hex has 2 bytes, len=3 should error on left side
        let script = r#"
trace foo {
    if memcmp(hex("504f"), &buf[0], 3) { print "X"; }
}
"#;
        let r = parse(script);
        match r {
            Ok(_) => panic!("expected parse error for len > hex(left) size"),
            Err(ParseError::TypeError(msg)) => {
                assert!(
                    msg.contains("exceeds hex pattern size on left side"),
                    "unexpected msg: {msg}"
                );
            }
            Err(e) => panic!("unexpected error variant: {e:?}"),
        }
    }

    #[test]
    fn parse_memcmp_hex_len_exceeds_right_should_fail() {
        // hex has 2 bytes, len=5 should error on right side
        let script = r#"
trace foo {
    if memcmp(&buf[0], hex("50 4f"), 5) { print "X"; }
}
"#;
        let r = parse(script);
        match r {
            Ok(_) => panic!("expected parse error for len > hex(right) size"),
            Err(ParseError::TypeError(msg)) => {
                assert!(
                    msg.contains("exceeds hex pattern size on right side"),
                    "unexpected msg: {msg}"
                );
            }
            Err(e) => panic!("unexpected error variant: {e:?}"),
        }
    }

    #[test]
    fn parse_memcmp_hex_negative_len_should_fail() {
        let script = r#"
trace foo {
    if memcmp(&buf[0], hex("50 4f"), -1) { print "X"; }
}
"#;
        let r = parse(script);
        match r {
            Ok(_) => panic!("expected parse error for negative len"),
            Err(ParseError::TypeError(msg)) => {
                assert!(
                    msg.contains("length must be non-negative"),
                    "unexpected msg: {msg}"
                );
            }
            Err(e) => panic!("unexpected error variant: {e:?}"),
        }
    }

    #[test]
    fn parse_memcmp_hex_len_equal_should_succeed() {
        // hex has 4 bytes, len=4 OK
        let script = r#"
trace foo {
    if memcmp(&buf[0], hex("de ad be ef"), 4) { print "OK"; }
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_memcmp_hex_infers_len_left_should_succeed() {
        let script = r#"
trace foo {
    if memcmp(hex("50 4f"), &buf[0]) { print "OK"; }
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_memcmp_hex_infers_len_right_should_succeed() {
        let script = r#"
trace foo {
    if memcmp(&buf[0], hex("de ad be ef")) { print "OK"; }
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_assignment_is_rejected_with_friendly_message() {
        let script = r#"
trace foo {
    let a = 1;
    a = 2;
}
"#;
        let r = parse(script);
        match r {
            Ok(_) => panic!("expected assignment error for immutable variables"),
            Err(ParseError::TypeError(msg)) => {
                assert!(
                    msg.contains("Assignment is not supported"),
                    "unexpected msg: {msg}"
                );
            }
            Err(e) => panic!("unexpected error variant: {e:?}"),
        }
    }

    #[test]
    fn parse_starts_with_accepts_two_exprs() {
        // Both sides are expr (identifiers); grammar should accept
        let script = r#"
trace foo {
    if starts_with(name, s) { print "OK"; }
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_strncmp_accepts_two_exprs_and_len() {
        let script = r#"
trace foo {
    if strncmp(lhs, rhs, 3) { print "EQ"; }
}
"#;
        let r = parse(script);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_strncmp_negative_len_rejected() {
        // Third argument must be a non-negative integer literal
        let script = r#"
trace foo {
    if strncmp(lhs, rhs, -1) { print "X"; }
}
"#;
        let r = parse(script);
        assert!(r.is_err(), "expected parse error for negative length");
        if let Err(ParseError::TypeError(msg)) = r {
            assert!(msg.contains("non-negative"), "unexpected msg: {msg}");
        }
    }

    #[test]
    fn parse_strncmp_nonliteral_len_rejected_with_friendly_message() {
        // len is variable -> reject with friendly message
        let script = r#"
trace foo {
    let n = 3;
    if strncmp(lhs, rhs, n) { print "X"; }
}
"#;
        let r = parse(script);
        match r {
            Err(ParseError::TypeError(msg)) => {
                assert!(
                    msg.contains("third argument must be a non-negative integer literal"),
                    "{msg}"
                );
            }
            other => panic!("expected TypeError for non-literal len, got {other:?}"),
        }
    }

    #[test]
    fn parse_memcmp_missing_len_without_hex_should_fail() {
        let script = r#"
trace foo {
    if memcmp(&buf[0], &buf[1]) { print "OK"; }
}
"#;
        let r = parse(script);
        assert!(
            r.is_err(),
            "expected parse error for missing len without hex"
        );
    }

    #[test]
    fn parse_memcmp_both_hex_mismatch_should_fail() {
        let script = r#"
trace foo {
    if memcmp(hex("50"), hex("504f")) { print "OK"; }
}
"#;
        let r = parse(script);
        match r {
            Ok(_) => panic!("expected parse error for mismatched hex sizes"),
            Err(ParseError::TypeError(msg)) => {
                assert!(msg.contains("different sizes"), "unexpected msg: {msg}");
            }
            Err(e) => panic!("unexpected error variant: {e:?}"),
        }
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
        match r {
            Err(ParseError::SyntaxError(msg)) => assert!(msg.contains("too large for u64")),
            other => panic!("expected friendly SyntaxError, got {other:?}"),
        }
    }

    #[test]
    fn parse_hex_address_overflow_should_error() {
        let s = r#"trace 0x10000000000000000 { print "X"; }"#;
        let r = parse(s);
        match r {
            Err(ParseError::SyntaxError(msg)) => assert!(msg.contains("too large for u64")),
            other => panic!("expected friendly SyntaxError, got {other:?}"),
        }
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
    fn parse_nested_trace_is_rejected() {
        let s = r#"
trace foo {
    trace bar { print "X"; }
}
"#;
        let r = parse(s);
        match r {
            Err(ParseError::SyntaxError(msg)) => assert!(msg.contains("cannot be nested")),
            other => panic!("expected SyntaxError for nested trace, got {other:?}"),
        }
    }

    #[test]
    fn parse_float_literal_is_rejected() {
        let s = r#"
trace foo {
    let x = 1.23;
}
"#;
        let r = parse(s);
        match r {
            Err(ParseError::TypeError(msg)) => {
                assert!(msg.contains("float literals are not supported"))
            }
            other => panic!("expected TypeError for float literal, got {other:?}"),
        }
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

    #[test]
    fn parse_array_index_must_be_literal() {
        // Dynamic index on top-level array
        let s1 = r#"
trace foo {
    print arr[i];
}
"#;
        let r1 = parse(s1);
        assert!(r1.is_err(), "expected error for non-literal array index");
        if let Err(ParseError::UnsupportedFeature(msg)) = r1 {
            assert!(
                msg.contains("array index must be a literal integer"),
                "unexpected msg: {msg}"
            );
        }

        // Dynamic index at chain tail
        let s2 = r#"
trace foo {
    print obj.arr[i];
}
"#;
        let r2 = parse(s2);
        assert!(r2.is_err(), "expected error for non-literal chain index");
        if let Err(ParseError::UnsupportedFeature(msg)) = r2 {
            assert!(msg.contains("literal integer"), "unexpected msg: {msg}");
        }
    }

    #[test]
    fn parse_print_format_arg_mismatch_reports_error() {
        // format_expr form
        let s1 = r#"
trace foo {
    print "A {} {}", x;
}
"#;
        let r1 = parse(s1);
        match r1 {
            Err(ParseError::TypeError(msg)) => {
                assert!(msg.contains("expects 2 argument(s)"), "unexpected: {msg}");
            }
            other => panic!("expected TypeError from format arg mismatch, got {other:?}"),
        }

        // flattened string + args form
        let s2 = r#"
trace foo {
    print "B {} {}", y;
}
"#;
        let r2 = parse(s2);
        match r2 {
            Err(ParseError::TypeError(msg)) => {
                assert!(msg.contains("expects 2 argument(s)"));
            }
            other => panic!("expected TypeError from format arg mismatch, got {other:?}"),
        }
    }

    #[test]
    fn parse_print_invalid_format_specifier_errors() {
        // Missing ':' prefix inside { }
        let s1 = r#"
trace foo { print "Bad {x}", 1; }
"#;
        let r1 = parse(s1);
        match r1 {
            Err(ParseError::TypeError(msg)) => {
                assert!(msg.contains("Invalid format specifier"), "{msg}");
            }
            other => panic!("expected TypeError, got {other:?}"),
        }

        // Unsupported conversion {:q}
        let s2 = r#"
trace foo { print "Bad {:q}", 1; }
"#;
        let r2 = parse(s2);
        match r2 {
            Err(ParseError::TypeError(msg)) => {
                assert!(msg.contains("Unsupported format conversion"), "{msg}");
            }
            other => panic!("expected TypeError, got {other:?}"),
        }
    }

    #[test]
    fn parse_hex_with_tab_is_rejected() {
        let s = r#"
trace foo {
    if memcmp(&buf[0], hex("50\t4f"), 2) { print "X"; }
}
"#;
        let r = parse(s);
        match r {
            Err(ParseError::TypeError(msg)) => {
                assert!(msg.contains("non-hex character"), "{msg}");
            }
            other => panic!("expected TypeError for tab in hex literal, got {other:?}"),
        }
    }

    #[test]
    fn parse_starts_with_constant_folds_on_literals() {
        let s = r#"
trace foo {
    if starts_with("abcdef", "abc") { print "T"; } else { print "F"; }
}
"#;
        let prog = parse(s).expect("parse ok");
        let stmt0 = prog.statements.first().expect("trace");
        match stmt0 {
            Statement::TracePoint { body, .. } => match &body[0] {
                Statement::If { condition, .. } => {
                    assert!(matches!(condition, Expr::Bool(true)));
                }
                other => panic!("expected If, got {other:?}"),
            },
            other => panic!("expected TracePoint, got {other:?}"),
        }
    }

    #[test]
    fn parse_backtrace_and_bt_statements() {
        let s = r#"
trace foo {
    backtrace;
    bt;
}
"#;
        let r = parse(s);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_print_capture_len_suffix() {
        // {:s.name$} uses capture; does not consume extra arg
        let s = r#"
trace foo {
    let n = 3;
    print "tail={:s.n$}", p;
}
"#;
        let r = parse(s);
        assert!(r.is_ok(), "parse failed: {:?}", r.err());
    }

    #[test]
    fn parse_unknown_keyword_inside_trace_suggests_print() {
        let s = r#"
trace foo {
    pront "hello";
}
"#;
        let r = parse(s);
        match r {
            Err(ParseError::SyntaxError(msg)) => {
                assert!(
                    msg.contains("Unknown keyword 'pront'"),
                    "unexpected msg: {msg}"
                );
                assert!(
                    msg.contains("Did you mean 'print'"),
                    "no suggestion in msg: {msg}"
                );
            }
            other => panic!("expected friendly SyntaxError for unknown keyword, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_keyword_same_line_after_brace_suggests_print() {
        // Unknown keyword immediately after '{' on the same line
        let s = r#"trace foo {pirnt \"sa\";}"#;
        let r = parse(s);
        match r {
            Err(ParseError::SyntaxError(msg)) => {
                assert!(
                    msg.contains("Unknown keyword 'pirnt'"),
                    "unexpected msg: {msg}"
                );
                assert!(
                    msg.contains("Did you mean 'print'"),
                    "no suggestion in msg: {msg}"
                );
            }
            other => {
                panic!("expected friendly SyntaxError for same-line unknown keyword, got {other:?}")
            }
        }
    }

    #[test]
    fn parse_unknown_top_level_keyword_suggests_trace() {
        let s = r#"
traec bar {
    print "x";
}
"#;
        let r = parse(s);
        match r {
            Err(ParseError::SyntaxError(msg)) => {
                assert!(
                    msg.contains("Unknown keyword 'traec'"),
                    "unexpected msg: {msg}"
                );
                assert!(
                    msg.contains("Did you mean 'trace'"),
                    "no suggestion in msg: {msg}"
                );
            }
            other => panic!("expected friendly SyntaxError for unknown keyword, got {other:?}"),
        }
    }

    #[test]
    fn parse_builtin_then_misspelled_keyword_should_point_to_misspell() {
        // Ensure builtin calls are not flagged; the real typo should be reported
        let s = r#"
trace foo {
    starts_with("a", "b"); prnit "oops";
}
"#;
        let r = parse(s);
        match r {
            Err(ParseError::SyntaxError(msg)) => {
                assert!(
                    msg.contains("prnit"),
                    "should point to misspelled 'prnit': {msg}"
                );
                assert!(
                    !msg.contains("starts_with"),
                    "should not flag builtin call: {msg}"
                );
            }
            other => panic!("expected friendly SyntaxError for misspelled print, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_keyword_generic_expected_list() {
        let s = r#"
foobarbaz {
    print "x";
}
"#;
        let r = parse(s);
        match r {
            Err(ParseError::SyntaxError(msg)) => {
                assert!(
                    msg.contains("Unknown keyword 'foobarbaz'"),
                    "unexpected msg: {msg}"
                );
                assert!(
                    msg.contains("Expected one of"),
                    "missing expected list in msg: {msg}"
                );
            }
            other => panic!("expected friendly SyntaxError with expected list, got {other:?}"),
        }
    }
}

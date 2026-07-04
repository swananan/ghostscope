use pest::iterators::Pair;

use crate::script::ast::{infer_type, BacktraceStatement, PrintStatement, Statement, TracePattern};
use crate::script::format_validator::FormatValidator;
use tracing::{debug, info};

use super::expr::{is_alias_expr, parse_condition, parse_expr};
use super::{ParseError, Result, Rule};

fn parse_backtrace_stmt(pair: Pair<Rule>) -> Result<BacktraceStatement> {
    let mut stmt = BacktraceStatement::default();

    for arg in pair.into_inner() {
        if arg.as_rule() == Rule::backtrace_flag {
            match arg.as_str() {
                "raw" => stmt.raw = true,
                "full" => stmt.full = true,
                "inline" => stmt.inline = true,
                "noinline" => stmt.inline = false,
                other => {
                    return Err(ParseError::SyntaxError(format!(
                        "Unknown bt option '{other}'"
                    )))
                }
            }
        }
    }

    Ok(stmt)
}
pub(super) fn parse_statement(pair: Pair<Rule>) -> Result<Statement> {
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
        Rule::backtrace_stmt => Ok(Statement::Backtrace(parse_backtrace_stmt(inner)?)),
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

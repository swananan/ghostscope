use pest::iterators::Pair;

use crate::script::ast::{infer_type, BinaryOp, Expr};
use tracing::debug;

use super::{chunks_of_two, ParseError, Result, Rule};

pub(super) fn parse_expr(pair: Pair<Rule>) -> Result<Expr> {
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
fn integer_literal_value(e: &Expr) -> Option<i64> {
    use crate::script::ast::BinaryOp as BO;
    use crate::script::ast::Expr as E;

    match e {
        E::Int(value) => Some(*value),
        E::BinaryOp {
            left,
            op: BO::Add,
            right,
        } => integer_literal_value(left)?.checked_add(integer_literal_value(right)?),
        E::BinaryOp {
            left,
            op: BO::Subtract,
            right,
        } => integer_literal_value(left)?.checked_sub(integer_literal_value(right)?),
        E::BinaryOp {
            left,
            op: BO::Multiply,
            right,
        } => integer_literal_value(left)?.checked_mul(integer_literal_value(right)?),
        E::BinaryOp {
            left,
            op: BO::Divide,
            right,
        } => integer_literal_value(left)?.checked_div(integer_literal_value(right)?),
        E::BinaryOp {
            left,
            op: BO::Modulo,
            right,
        } => integer_literal_value(left)?.checked_rem(integer_literal_value(right)?),
        E::BinaryOp {
            left,
            op: BO::BitAnd,
            right,
        } => Some(integer_literal_value(left)? & integer_literal_value(right)?),
        E::BinaryOp {
            left,
            op: BO::BitXor,
            right,
        } => Some(integer_literal_value(left)? ^ integer_literal_value(right)?),
        E::BinaryOp {
            left,
            op: BO::BitOr,
            right,
        } => Some(integer_literal_value(left)? | integer_literal_value(right)?),
        E::BinaryOp {
            left,
            op: BO::ShiftLeft,
            right,
        } => {
            let shift = u32::try_from(integer_literal_value(right)?).ok()?;
            integer_literal_value(left)?.checked_shl(shift)
        }
        E::BinaryOp {
            left,
            op: BO::ShiftRight,
            right,
        } => {
            let shift = u32::try_from(integer_literal_value(right)?).ok()?;
            integer_literal_value(left)?.checked_shr(shift)
        }
        E::UnaryBitNot(inner) => Some(!integer_literal_value(inner)?),
        _ => None,
    }
}
pub(super) fn is_alias_expr(e: &Expr) -> bool {
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
            (is_alias_expr(left) && integer_literal_value(right).is_some())
                || (is_alias_expr(right) && integer_literal_value(left).is_some())
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
            let mut left = parse_bitwise_or(first)?;

            for chunk in chunks_of_two(pairs) {
                if chunk.len() != 2 {
                    return Err(ParseError::InvalidExpression);
                }
                if chunk[0].as_rule() != Rule::and_op {
                    return Err(ParseError::UnexpectedToken(chunk[0].as_rule()));
                }
                let right = parse_bitwise_or(chunk[1].clone())?;
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
fn parse_bitwise_or(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::bitwise_or => {
            let mut pairs = pair.into_inner();
            let first = pairs.next().ok_or(ParseError::InvalidExpression)?;
            let mut left = parse_bitwise_xor(first)?;

            for chunk in chunks_of_two(pairs) {
                if chunk.len() != 2 {
                    return Err(ParseError::InvalidExpression);
                }
                if chunk[0].as_rule() != Rule::bit_or_op {
                    return Err(ParseError::UnexpectedToken(chunk[0].as_rule()));
                }
                let right = parse_bitwise_xor(chunk[1].clone())?;
                let expr = Expr::BinaryOp {
                    left: Box::new(left),
                    op: BinaryOp::BitOr,
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
fn parse_bitwise_xor(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::bitwise_xor => {
            let mut pairs = pair.into_inner();
            let first = pairs.next().ok_or(ParseError::InvalidExpression)?;
            let mut left = parse_bitwise_and(first)?;

            for chunk in chunks_of_two(pairs) {
                if chunk.len() != 2 {
                    return Err(ParseError::InvalidExpression);
                }
                if chunk[0].as_rule() != Rule::bit_xor_op {
                    return Err(ParseError::UnexpectedToken(chunk[0].as_rule()));
                }
                let right = parse_bitwise_and(chunk[1].clone())?;
                let expr = Expr::BinaryOp {
                    left: Box::new(left),
                    op: BinaryOp::BitXor,
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
fn parse_bitwise_and(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::bitwise_and => {
            let mut pairs = pair.into_inner();
            let first = pairs.next().ok_or(ParseError::InvalidExpression)?;
            let mut left = parse_equality(first)?;

            for chunk in chunks_of_two(pairs) {
                if chunk.len() != 2 {
                    return Err(ParseError::InvalidExpression);
                }
                if chunk[0].as_rule() != Rule::bit_and_op {
                    return Err(ParseError::UnexpectedToken(chunk[0].as_rule()));
                }
                let right = parse_equality(chunk[1].clone())?;
                let expr = Expr::BinaryOp {
                    left: Box::new(left),
                    op: BinaryOp::BitAnd,
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
            let mut left = parse_shift(first)?;

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
                let right = parse_shift(chunk[1].clone())?;
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
fn parse_shift(pair: Pair<Rule>) -> Result<Expr> {
    match pair.as_rule() {
        Rule::shift => {
            let mut pairs = pair.into_inner();
            let first = pairs.next().ok_or(ParseError::InvalidExpression)?;
            let mut left = parse_additive(first)?;

            for chunk in chunks_of_two(pairs) {
                if chunk.len() != 2 {
                    return Err(ParseError::InvalidExpression);
                }
                let op = match chunk[0].as_str() {
                    "<<" => BinaryOp::ShiftLeft,
                    ">>" => BinaryOp::ShiftRight,
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
pub(super) fn parse_condition(pair: Pair<Rule>) -> Result<Expr> {
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
                    "%" => BinaryOp::Modulo,
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
                Rule::bit_not_unary => {
                    let u = first
                        .into_inner()
                        .next()
                        .ok_or(ParseError::InvalidExpression)?;
                    let right = parse_unary(u)?;
                    let expr = Expr::UnaryBitNot(Box::new(right));
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
            let inner = pair
                .into_inner()
                .next()
                .ok_or(ParseError::InvalidExpression)?;
            match inner.as_rule() {
                Rule::memcmp_call => parse_builtin_call(inner),
                Rule::strncmp_call => parse_builtin_call(inner),
                Rule::starts_with_call => parse_builtin_call(inner),
                Rule::hex_call => parse_builtin_call(inner),
                Rule::postfix_access => parse_postfix_access(inner),
                Rule::cast_call => parse_cast_call(inner),
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
            // grammar: strncmp("(" expr "," expr "," expr ")")
            let arg0 = parse_expr(it.next().ok_or(ParseError::InvalidExpression)?)?;
            let arg1 = parse_expr(it.next().ok_or(ParseError::InvalidExpression)?)?;
            let n_expr_parsed = parse_expr(it.next().ok_or(ParseError::InvalidExpression)?)?;
            let literal_len_opt: Option<isize> = match &n_expr_parsed {
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
            if literal_len_opt.is_some_and(|n| n < 0) {
                return Err(ParseError::TypeError(
                    "strncmp third argument must be non-negative".to_string(),
                ));
            }
            // Optional constant fold when both sides are string literals
            if let (Expr::String(a), Expr::String(b), Expr::Int(n_val)) =
                (&arg0, &arg1, &n_expr_parsed)
            {
                let ln = (*n_val).max(0) as usize;
                let eq = a
                    .as_bytes()
                    .iter()
                    .take(ln)
                    .eq(b.as_bytes().iter().take(ln));
                return Ok(Expr::Bool(eq));
            }
            Ok(Expr::BuiltinCall {
                name: "strncmp".to_string(),
                args: vec![arg0, arg1, n_expr_parsed],
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
fn parse_cast_call(pair: Pair<Rule>) -> Result<Expr> {
    let mut inner = pair.into_inner();
    let expr_pair = inner.next().ok_or(ParseError::InvalidExpression)?;
    let type_pair = inner.next().ok_or(ParseError::InvalidExpression)?;
    let raw_type = type_pair.as_str();
    let target_type = raw_type
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(|| ParseError::SyntaxError("cast target type must be a string".to_string()))?
        .to_string();

    Ok(Expr::Cast {
        expr: Box::new(parse_expr(expr_pair)?),
        target_type,
    })
}
fn parse_postfix_access(pair: Pair<Rule>) -> Result<Expr> {
    let mut inner = pair.into_inner();
    let base = inner.next().ok_or(ParseError::InvalidExpression)?;
    let mut expr = match base.as_rule() {
        Rule::postfix_base => {
            let base_inner = base
                .into_inner()
                .next()
                .ok_or(ParseError::InvalidExpression)?;
            match base_inner.as_rule() {
                Rule::cast_call => parse_cast_call(base_inner)?,
                Rule::special_var => Expr::SpecialVar(base_inner.as_str().to_string()),
                Rule::identifier => Expr::Variable(base_inner.as_str().to_string()),
                Rule::expr => parse_expr(base_inner)?,
                _ => return Err(ParseError::UnexpectedToken(base_inner.as_rule())),
            }
        }
        _ => return Err(ParseError::UnexpectedToken(base.as_rule())),
    };

    for suffix in inner {
        let suffix_inner = suffix
            .into_inner()
            .next()
            .ok_or(ParseError::InvalidExpression)?;
        match suffix_inner.as_rule() {
            Rule::member_suffix => {
                let field = suffix_inner
                    .into_inner()
                    .next()
                    .ok_or(ParseError::InvalidExpression)?
                    .as_str()
                    .to_string();
                expr = Expr::MemberAccess(Box::new(expr), field);
            }
            Rule::index_suffix => {
                let index_pair = suffix_inner
                    .into_inner()
                    .next()
                    .ok_or(ParseError::InvalidExpression)?;
                let parsed_index = parse_expr(index_pair)?;
                let parsed_index = integer_literal_value(&parsed_index)
                    .map(Expr::Int)
                    .unwrap_or(parsed_index);
                expr = Expr::ArrayAccess(Box::new(expr), Box::new(parsed_index));
            }
            _ => return Err(ParseError::UnexpectedToken(suffix_inner.as_rule())),
        }
    }

    Ok(expr)
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
                // Array tail index can be a literal or a runtime expression.
                let parsed = parse_expr(inner_pair)?;
                opt_index = Some(
                    integer_literal_value(&parsed)
                        .map(Expr::Int)
                        .unwrap_or(parsed),
                );
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
    let parsed_index = integer_literal_value(&parsed_index)
        .map(Expr::Int)
        .unwrap_or(parsed_index);

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
        Rule::postfix_access => parse_postfix_access(target)?,
        Rule::cast_call => parse_cast_call(target)?,
        Rule::complex_variable => parse_complex_variable(target)?,
        Rule::special_var => Expr::SpecialVar(target.as_str().to_string()),
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
        Rule::postfix_access => parse_postfix_access(target)?,
        Rule::cast_call => parse_cast_call(target)?,
        Rule::complex_variable => parse_complex_variable(target)?,
        Rule::special_var => Expr::SpecialVar(target.as_str().to_string()),
        Rule::identifier => Expr::Variable(target.as_str().to_string()),
        _ => return Err(ParseError::UnexpectedToken(target.as_rule())),
    };
    // Early normalization: &(*p) => p
    match parsed {
        Expr::PointerDeref(inner_expr) => Ok(*inner_expr),
        other => Ok(Expr::AddressOf(Box::new(other))),
    }
}

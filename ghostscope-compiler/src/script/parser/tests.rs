use super::{parse, ParseError};
use crate::script::ast::{BinaryOp, Expr, PrintStatement, Statement};

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
fn parse_cast_member_and_index_access() {
    let script = r#"
trace foo {
    print cast($arg0, "struct request *").id;
    print cast($arg1, "u32 *")[2];
    print *cast($arg1, "u32 *");
    print &cast($arg0, "struct request *").id;
}
"#;
    let program = parse(script).expect("parse should succeed");
    let Statement::TracePoint { body, .. } = &program.statements[0] else {
        panic!("expected trace point");
    };
    assert!(matches!(
        &body[0],
        Statement::Print(PrintStatement::ComplexVariable(Expr::MemberAccess(obj, field)))
            if field == "id" && matches!(obj.as_ref(), Expr::Cast { .. })
    ));
    assert!(matches!(
        &body[1],
        Statement::Print(PrintStatement::ComplexVariable(Expr::ArrayAccess(base, index)))
            if matches!(base.as_ref(), Expr::Cast { .. })
                && matches!(index.as_ref(), Expr::Int(2))
    ));
    assert!(matches!(
        &body[2],
        Statement::Print(PrintStatement::ComplexVariable(Expr::PointerDeref(inner)))
            if matches!(inner.as_ref(), Expr::Cast { .. })
    ));
    assert!(matches!(
        &body[3],
        Statement::Print(PrintStatement::ComplexVariable(Expr::AddressOf(inner)))
            if matches!(
                inner.as_ref(),
                Expr::MemberAccess(obj, field)
                    if field == "id" && matches!(obj.as_ref(), Expr::Cast { .. })
            )
    ));
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
    // Negative literal lengths are rejected early.
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
fn parse_strncmp_accepts_nonliteral_len() {
    let script = r#"
trace foo {
    let n = 3;
    if strncmp(lhs, rhs, n) { print "X"; }
}
"#;
    let r = parse(script);
    assert!(r.is_ok(), "parse failed: {:?}", r.err());
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
fn parse_identifiers_can_start_with_underscore() {
    let function = r#"trace __UpdateTicketInformation { print "OK"; }"#;
    assert!(parse(function).is_ok());

    let wildcard = r#"trace __builtin_* { print "W"; }"#;
    assert!(parse(wildcard).is_ok());

    let script = r#"
trace _start {
    let _ticket = __dwarf_value;
    print _ticket;
}
"#;
    assert!(parse(script).is_ok());
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
    // $pid/$tid/$host_pid/$input_pid/$timestamp in expressions and prints
    let script = r#"
trace foo {
    if $pid == 123 && $tid != 0 && $host_pid != 0 && $input_pid == 123 { print "PID_TID"; }
    print $timestamp;
    print "P:{} T:{} HP:{} IN:{} TS:{}", $pid, $tid, $host_pid, $input_pid, $timestamp;
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
fn parse_array_index_accepts_dynamic_expr() {
    // Dynamic index on top-level array
    let s1 = r#"
trace foo {
    print arr[i];
}
"#;
    let r1 = parse(s1).expect("dynamic top-level index should parse");
    match r1.statements.first().expect("trace") {
        Statement::TracePoint { body, .. } => match &body[0] {
            Statement::Print(PrintStatement::ComplexVariable(Expr::ArrayAccess(_, index))) => {
                assert!(matches!(index.as_ref(), Expr::Variable(name) if name == "i"))
            }
            other => panic!("unexpected first print body: {other:?}"),
        },
        other => panic!("expected TracePoint, got {other:?}"),
    }

    // Dynamic index at chain tail
    let s2 = r#"
trace foo {
    print obj.arr[i - (i / 0x8) * 0x8];
}
"#;
    let r2 = parse(s2).expect("dynamic chain index should parse");
    match r2.statements.first().expect("trace") {
        Statement::TracePoint { body, .. } => match &body[0] {
            Statement::Print(PrintStatement::ComplexVariable(Expr::ArrayAccess(_, index))) => {
                assert!(matches!(index.as_ref(), Expr::BinaryOp { .. }))
            }
            other => panic!("unexpected first print body: {other:?}"),
        },
        other => panic!("expected TracePoint, got {other:?}"),
    }
}

#[test]
fn parse_integer_modulo_and_bitwise_ops() {
    let script = r#"
trace foo {
    let value = 0x1 | 0x2 ^ 0x3 & 0x4 << 0x1 + 0x2 % 0x3;
    let inverse = ~value;
}
"#;
    let prog = parse(script).expect("integer and bitwise ops should parse");
    let Statement::TracePoint { body, .. } = prog.statements.first().expect("trace") else {
        panic!("expected trace point");
    };
    let Statement::VarDeclaration { value, .. } = &body[0] else {
        panic!("expected var declaration");
    };
    let Expr::BinaryOp { op, left, right } = value else {
        panic!("expected bitwise-or root");
    };
    assert_eq!(*op, BinaryOp::BitOr);
    assert!(matches!(left.as_ref(), Expr::Int(1)));
    assert!(matches!(
        right.as_ref(),
        Expr::BinaryOp {
            op: BinaryOp::BitXor,
            ..
        }
    ));
    assert!(matches!(
        &body[1],
        Statement::VarDeclaration {
            value: Expr::UnaryBitNot(_),
            ..
        }
    ));
}

#[test]
fn parse_array_index_accepts_constant_negative_literal() {
    let script = r#"
trace foo {
    print arr[-0x1];
    print obj.arr[0b10 - 0x3];
}
"#;
    let prog = parse(script).expect("parse ok");
    let trace = prog.statements.first().expect("trace");
    match trace {
        Statement::TracePoint { body, .. } => {
            match &body[0] {
                Statement::Print(PrintStatement::ComplexVariable(Expr::ArrayAccess(_, index))) => {
                    assert!(matches!(index.as_ref(), Expr::Int(-1)));
                }
                other => panic!("unexpected first print body: {other:?}"),
            }
            match &body[1] {
                Statement::Print(PrintStatement::ComplexVariable(Expr::ArrayAccess(_, index))) => {
                    assert!(matches!(index.as_ref(), Expr::Int(-1)));
                }
                other => panic!("unexpected second print body: {other:?}"),
            }
        }
        other => panic!("expected TracePoint, got {other:?}"),
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
	    bt raw;
	    bt full noinline;
	}
	"#;
    let program = parse(s).expect("parse ok");
    let Statement::TracePoint { body, .. } = &program.statements[0] else {
        panic!("expected trace");
    };
    assert_eq!(body.len(), 4);
    match &body[2] {
        Statement::Backtrace(bt) => {
            assert!(bt.raw);
            assert!(bt.inline);
        }
        other => panic!("expected backtrace, got {other:?}"),
    }
    match &body[3] {
        Statement::Backtrace(bt) => {
            assert!(bt.full);
            assert!(!bt.inline);
        }
        other => panic!("expected backtrace, got {other:?}"),
    }
}

#[test]
fn parse_backtrace_rejects_named_depth_option() {
    let s = r#"
	trace foo {
	    bt depth=8;
	}
	"#;
    let r = parse(s);
    match r {
        Err(ParseError::SyntaxError(msg)) => {
            assert!(msg.contains("no longer a script option"), "{msg}");
            assert!(msg.contains("--backtrace-depth"), "{msg}");
        }
        other => panic!("expected SyntaxError, got {other:?}"),
    }
}

#[test]
fn parse_backtrace_rejects_positional_depth_option() {
    let s = r#"
	trace foo {
	    bt 4 raw;
	}
	"#;
    let r = parse(s);
    match r {
        Err(ParseError::SyntaxError(msg)) => {
            assert!(msg.contains("no longer a script option"), "{msg}");
        }
        other => panic!("expected SyntaxError, got {other:?}"),
    }
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
fn parse_misspelled_builtin_suggests_starts_with() {
    // Misspelled builtin should suggest the correct builtin name
    let s = r#"
trace foo {
    starst_with("a", "b");
}
"#;
    let r = parse(s);
    match r {
        Err(ParseError::SyntaxError(msg)) => {
            assert!(msg.contains("Unknown keyword 'starst_with'"), "{msg}");
            assert!(msg.contains("Did you mean 'starts_with'"), "{msg}");
        }
        other => panic!("expected friendly suggestion for misspelled builtin, got {other:?}"),
    }
}

#[test]
fn parse_misspelled_builtin_suggests_memcmp() {
    let s = r#"
trace foo {
    memcpm(&buf[0], &buf[1], 16);
}
"#;
    let r = parse(s);
    match r {
        Err(ParseError::SyntaxError(msg)) => {
            assert!(msg.contains("Unknown keyword 'memcpm'"), "{msg}");
            assert!(msg.contains("Did you mean 'memcmp'"), "{msg}");
        }
        other => panic!("expected friendly suggestion for misspelled builtin, got {other:?}"),
    }
}

#[test]
fn parse_if_condition_misspelled_builtin_suggests() {
    let s = r#"
trace foo {
    if starst_with("a", "b") { print "ok"; }
}
"#;
    let r = parse(s);
    match r {
        Err(ParseError::SyntaxError(msg)) => {
            assert!(msg.contains("Unknown keyword 'starst_with'"), "{msg}");
            assert!(msg.contains("Did you mean 'starts_with'"), "{msg}");
        }
        other => panic!("expected friendly suggestion inside if(), got {other:?}"),
    }
}

#[test]
fn parse_else_if_condition_misspelled_builtin_suggests() {
    let s = r#"
trace foo {
    if 1 { print "a"; } else if starst_with("a", "b") { print "b"; }
}
"#;
    let r = parse(s);
    match r {
        Err(ParseError::SyntaxError(msg)) => {
            assert!(msg.contains("Unknown keyword 'starst_with'"), "{msg}");
            assert!(msg.contains("Did you mean 'starts_with'"), "{msg}");
        }
        other => panic!("expected friendly suggestion inside else if(), got {other:?}"),
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

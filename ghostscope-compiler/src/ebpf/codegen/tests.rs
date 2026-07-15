use super::*;
use crate::CompileOptions;
use ghostscope_protocol::trace_event::{TraceEventHeader, TraceEventMessage};

#[test]
fn print_complex_format_budget_tracks_event_size() {
    let bytes_reserved_so_far =
        std::mem::size_of::<TraceEventHeader>() + std::mem::size_of::<TraceEventMessage>();
    let expected = 32768
        - (bytes_reserved_so_far
            + std::mem::size_of::<InstructionHeader>()
            + std::mem::size_of::<EndInstructionData>());
    assert_eq!(
        print_complex_format_instruction_budget(32768, bytes_reserved_so_far),
        expected
    );
    assert!(print_complex_format_instruction_budget(32768, bytes_reserved_so_far) > 4096);
}

#[test]
fn print_complex_format_budget_shrinks_after_prior_instructions() {
    let bytes_reserved_so_far =
        std::mem::size_of::<TraceEventHeader>() + std::mem::size_of::<TraceEventMessage>() + 2048;
    let base_budget = print_complex_format_instruction_budget(
        32768,
        std::mem::size_of::<TraceEventHeader>() + std::mem::size_of::<TraceEventMessage>(),
    );
    assert_eq!(
        print_complex_format_instruction_budget(32768, bytes_reserved_so_far),
        base_budget - 2048
    );
}

#[test]
fn dynamic_payload_reservations_share_budget_fairly() {
    let reservations = allocate_dynamic_payload_reservations(&[256, 256, 256, 256], 512);
    assert_eq!(reservations, vec![128, 128, 128, 128]);
}

#[test]
fn dynamic_payload_reservations_keep_error_headroom_when_possible() {
    let reservations = allocate_dynamic_payload_reservations(&[256, 256, 256], 36);
    assert_eq!(reservations, vec![12, 12, 12]);
}

#[test]
fn dynamic_payload_reservations_never_exceed_requested_caps() {
    let reservations = allocate_dynamic_payload_reservations(&[0, 8, 11], 64);
    assert_eq!(reservations, vec![0, 8, 11]);
}

#[test]
fn build_errno_i32_truncates_i64_errors() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("create EbpfContext");
    let fn_type = context.i32_type().fn_type(&[], false);
    let function = ctx.module.add_function("errno_test", fn_type, None);
    let block = context.append_basic_block(function, "entry");
    ctx.builder.position_at_end(block);

    let errno = ctx
        .build_errno_i32(
            context.i64_type().const_int((-14i64) as u64, true),
            "errno_i32",
        )
        .expect("truncate errno");
    assert_eq!(errno.get_type().get_bit_width(), 32);
}

#[test]
fn computed_int_store_i64_compiles() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx =
        EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("create EbpfContext");
    // print {} with a pure script integer expression triggers ComputedInt path
    let expr = crate::script::Expr::BinaryOp {
        left: Box::new(crate::script::Expr::Int(41)),
        op: crate::script::BinaryOp::Add,
        right: Box::new(crate::script::Expr::Int(1)),
    };
    let stmt =
        crate::script::Statement::Print(crate::script::PrintStatement::ComplexVariable(expr));
    let program = crate::script::Program::new();
    let res = ctx.compile_program(&program, "test_func", &[stmt], None, None, None);
    assert!(res.is_ok(), "Compilation failed: {:?}", res.err());
}

#[test]
fn computed_int_in_format_compiles() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx =
        EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("create EbpfContext");
    // formatted print with expression argument should also route into ComputedInt path
    let expr = crate::script::Expr::BinaryOp {
        left: Box::new(crate::script::Expr::Int(1)),
        op: crate::script::BinaryOp::Add,
        right: Box::new(crate::script::Expr::Int(2)),
    };
    let stmt = crate::script::Statement::Print(crate::script::PrintStatement::Formatted {
        format: "sum:{}".to_string(),
        args: vec![expr],
    });
    let program = crate::script::Program::new();
    let res = ctx.compile_program(&program, "test_fmt", &[stmt], None, None, None);
    assert!(res.is_ok(), "Compilation failed: {:?}", res.err());
}

#[test]
fn memcmp_rejects_script_pointer_variable_now() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx =
        EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("create EbpfContext");

    // let p = "A";  // script pointer to const string (no longer accepted as memcmp arg)
    let decl = crate::script::Statement::VarDeclaration {
        name: "p".to_string(),
        value: crate::script::Expr::String("A".to_string()),
    };

    // if memcmp(p, hex("41"), 1) { print "OK"; }
    let if_stmt = crate::script::Statement::If {
        condition: crate::script::Expr::BuiltinCall {
            name: "memcmp".to_string(),
            args: vec![
                crate::script::Expr::Variable("p".to_string()),
                crate::script::Expr::BuiltinCall {
                    name: "hex".to_string(),
                    args: vec![crate::script::Expr::String("41".to_string())],
                },
                crate::script::Expr::Int(1),
            ],
        },
        then_body: vec![crate::script::Statement::Print(
            crate::script::PrintStatement::String("OK".to_string()),
        )],
        else_body: None,
    };

    let program = crate::script::Program::new();
    let res = ctx.compile_program(
        &program,
        "test_memcmp_ptr",
        &[decl, if_stmt],
        None,
        None,
        None,
    );
    assert!(
        res.is_err(),
        "Expected type error for script pointer variable in memcmp"
    );
}

#[test]
fn strncmp_requires_string_on_one_side_error_message() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

    // strncmp(42, 43, 2) -> neither side is string (literal/var); expect type error
    let stmt = crate::script::Statement::If {
        condition: crate::script::Expr::BuiltinCall {
            name: "strncmp".to_string(),
            args: vec![
                crate::script::Expr::Int(42),
                crate::script::Expr::Int(43),
                crate::script::Expr::Int(2),
            ],
        },
        then_body: vec![crate::script::Statement::Print(
            crate::script::PrintStatement::String("OK".to_string()),
        )],
        else_body: None,
    };
    let program = crate::script::Program::new();
    let res = ctx.compile_program(&program, "test_strncmp_err", &[stmt], None, None, None);
    assert!(
        res.is_err(),
        "expected error when neither side is string (got {res:?})",
    );
    let msg = format!("{:?}", res.err());
    assert!(msg.contains("strncmp requires at least one string argument"));
}

// No test needed here for string var copy rejection; current semantics allow
// let s = "A"; let p = s; as a string-to-string assignment.

#[test]
fn immutable_variable_redeclaration_rejected() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

    // let x = 1; let x = 2;  (same trace block)
    let d1 = crate::script::Statement::VarDeclaration {
        name: "x".to_string(),
        value: crate::script::Expr::Int(1),
    };
    let d2 = crate::script::Statement::VarDeclaration {
        name: "x".to_string(),
        value: crate::script::Expr::Int(2),
    };
    let program = crate::script::Program::new();
    let res = ctx.compile_program(&program, "immut", &[d1, d2], None, None, None);
    assert!(res.is_err(), "expected immutability error, got {res:?}");
    let msg = format!("{:?}", res.err());
    assert!(
        msg.contains("Redeclaration in the same scope") || msg.contains("immutable variable"),
        "unexpected error msg: {msg}"
    );
}

#[test]
fn immutable_alias_rebinding_rejected() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

    // let p = &arr[0]; let p = &arr[0];
    let a1 = crate::script::Statement::AliasDeclaration {
        name: "p".to_string(),
        target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::Variable(
            "arr".to_string(),
        ))),
    };
    let a2 = crate::script::Statement::AliasDeclaration {
        name: "p".to_string(),
        target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::Variable(
            "arr".to_string(),
        ))),
    };
    let program = crate::script::Program::new();
    let res = ctx.compile_program(&program, "immut_alias", &[a1, a2], None, None, None);
    assert!(
        res.is_err(),
        "expected immutability error for alias, got {res:?}"
    );
}

#[test]
fn alias_to_alias_with_const_offset_is_alias_variable() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");
    // let base = &buf[0]; let tail = base + 16;
    let s1 = crate::script::Statement::AliasDeclaration {
        name: "base".to_string(),
        target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::ArrayAccess(
            Box::new(crate::script::Expr::Variable("buf".to_string())),
            Box::new(crate::script::Expr::Int(0)),
        ))),
    };
    let s2 = crate::script::Statement::VarDeclaration {
        name: "tail".to_string(),
        value: crate::script::Expr::BinaryOp {
            left: Box::new(crate::script::Expr::Variable("base".to_string())),
            op: crate::script::BinaryOp::Add,
            right: Box::new(crate::script::Expr::Int(16)),
        },
    };
    let program = crate::script::Program::new();
    // Should treat tail as alias (not as value), thus compile_program succeeds
    let res = ctx.compile_program(&program, "alias_stage", &[s1, s2], None, None, None);
    assert!(res.is_ok(), "expected alias-to-alias staging to compile");
}

#[test]
fn alias_to_alias_with_negative_const_offset_is_alias_variable() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");
    // let base = &buf[1]; let head = base + -1;
    let base = crate::script::Statement::AliasDeclaration {
        name: "base".to_string(),
        target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::ArrayAccess(
            Box::new(crate::script::Expr::Variable("buf".to_string())),
            Box::new(crate::script::Expr::Int(1)),
        ))),
    };
    let negative_one = crate::script::Expr::BinaryOp {
        left: Box::new(crate::script::Expr::Int(0)),
        op: crate::script::BinaryOp::Subtract,
        right: Box::new(crate::script::Expr::Int(1)),
    };
    let head = crate::script::Statement::VarDeclaration {
        name: "head".to_string(),
        value: crate::script::Expr::BinaryOp {
            left: Box::new(crate::script::Expr::Variable("base".to_string())),
            op: crate::script::BinaryOp::Add,
            right: Box::new(negative_one),
        },
    };
    let program = crate::script::Program::new();
    let res = ctx.compile_program(&program, "alias_neg_stage", &[base, head], None, None, None);
    assert!(
        res.is_ok(),
        "expected alias plus negative literal staging to compile"
    );
}

#[test]
fn pointer_arithmetic_parts_fold_negative_literal_offsets() {
    let negative_one = crate::script::Expr::BinaryOp {
        left: Box::new(crate::script::Expr::Int(0)),
        op: crate::script::BinaryOp::Subtract,
        right: Box::new(crate::script::Expr::Int(1)),
    };
    let expr = crate::script::Expr::BinaryOp {
        left: Box::new(crate::script::Expr::BinaryOp {
            left: Box::new(crate::script::Expr::Variable("p".to_string())),
            op: crate::script::BinaryOp::Add,
            right: Box::new(negative_one),
        }),
        op: crate::script::BinaryOp::Add,
        right: Box::new(crate::script::Expr::Int(3)),
    };
    let (base, index) = EbpfContext::<'static, 'static>::pointer_arithmetic_parts(&expr)
        .expect("pointer arithmetic parts");
    assert!(matches!(base, crate::script::Expr::Variable(name) if name == "p"));
    assert_eq!(index, 2);
}

#[test]
fn alias_to_alias_copy_is_alias_variable() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");
    // let a = &G_STATE.lib; let b = a;
    let a = crate::script::Statement::AliasDeclaration {
        name: "a".to_string(),
        target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::MemberAccess(
            Box::new(crate::script::Expr::Variable("G_STATE".to_string())),
            "lib".to_string(),
        ))),
    };
    let b = crate::script::Statement::VarDeclaration {
        name: "b".to_string(),
        value: crate::script::Expr::Variable("a".to_string()),
    };
    let program = crate::script::Program::new();
    let res = ctx.compile_program(&program, "alias_copy", &[a, b], None, None, None);
    assert!(res.is_ok(), "expected alias-to-alias copy to compile");
}

#[test]
fn alias_self_reference_is_rejected_with_cycle_error() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

    // let a = &a; print a;
    let a = crate::script::Statement::AliasDeclaration {
        name: "a".to_string(),
        target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::Variable(
            "a".to_string(),
        ))),
    };
    let p = crate::script::Statement::Print(crate::script::PrintStatement::ComplexVariable(
        crate::script::Expr::Variable("a".to_string()),
    ));
    let program = crate::script::Program::new();
    let res = ctx.compile_program(&program, "alias_self", &[a, p], None, None, None);
    assert!(res.is_err(), "expected cycle error, got {res:?}");
    let msg = format!("{:?}", res.err());
    assert!(
        msg.contains("alias cycle") || msg.contains("depth exceeded"),
        "unexpected error: {msg}"
    );
}

#[test]
fn alias_mutual_cycle_is_rejected_with_cycle_error() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

    // let a = &b; let b = &a; print a;
    let a = crate::script::Statement::AliasDeclaration {
        name: "a".to_string(),
        target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::Variable(
            "b".to_string(),
        ))),
    };
    let b = crate::script::Statement::AliasDeclaration {
        name: "b".to_string(),
        target: crate::script::Expr::AddressOf(Box::new(crate::script::Expr::Variable(
            "a".to_string(),
        ))),
    };
    let p = crate::script::Statement::Print(crate::script::PrintStatement::ComplexVariable(
        crate::script::Expr::Variable("a".to_string()),
    ));
    let program = crate::script::Program::new();
    let res = ctx.compile_program(&program, "alias_cycle", &[a, b, p], None, None, None);
    assert!(res.is_err(), "expected cycle error, got {res:?}");
    let msg = format!("{:?}", res.err());
    assert!(
        msg.contains("alias cycle") || msg.contains("depth exceeded"),
        "unexpected error: {msg}"
    );
}

#[test]
fn strncmp_folds_with_script_string_and_literal_true() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

    // Prepare: let s = "ABC";
    let decl = crate::script::Statement::VarDeclaration {
        name: "s".to_string(),
        value: crate::script::Expr::String("ABC".to_string()),
    };
    let program = crate::script::Program::new();
    let res = ctx.compile_program(&program, "decl", &[decl], None, None, None);
    assert!(res.is_ok());

    // Expression: strncmp(s, "ABD", 2) -> true
    let expr = crate::script::Expr::BuiltinCall {
        name: "strncmp".to_string(),
        args: vec![
            crate::script::Expr::Variable("s".to_string()),
            crate::script::Expr::String("ABD".to_string()),
            crate::script::Expr::Int(2),
        ],
    };
    let v = ctx.compile_expr(&expr).expect("compile expr");
    match v {
        inkwell::values::BasicValueEnum::IntValue(iv) => {
            assert_eq!(iv.get_type().get_bit_width(), 1);
            // true expected (string repr may vary across LLVM versions, check both forms)
            let s = format!("{iv}");
            assert!(s.contains("i1 true") || s.contains("true"));
        }
        other => panic!("expected IntValue i1, got {other:?}"),
    }
}

#[test]
fn starts_with_folds_with_two_literals() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

    // Expression: starts_with("abcdef", "abc") -> true
    let expr = crate::script::Expr::BuiltinCall {
        name: "starts_with".to_string(),
        args: vec![
            crate::script::Expr::String("abcdef".to_string()),
            crate::script::Expr::String("abc".to_string()),
        ],
    };
    let v = ctx.compile_expr(&expr).expect("compile expr");
    match v {
        inkwell::values::BasicValueEnum::IntValue(iv) => {
            assert_eq!(iv.get_type().get_bit_width(), 1);
            let s = format!("{iv}");
            assert!(s.contains("i1 true") || s.contains("true"));
        }
        _ => panic!("expected i1"),
    }
}

#[test]
fn starts_with_requires_one_string_side_error() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

    // Neither side is string
    let expr = crate::script::Expr::BuiltinCall {
        name: "starts_with".to_string(),
        args: vec![crate::script::Expr::Int(1), crate::script::Expr::Int(2)],
    };
    let res = ctx.compile_expr(&expr);
    assert!(res.is_err(), "expected error");
    let msg = format!("{:?}", res.err());
    assert!(msg.contains("starts_with requires at least one string argument"));
}

#[test]
fn shadowing_rejected_in_inner_scope() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

    // let x = 1; { let x = 2; }
    let d1 = crate::script::Statement::VarDeclaration {
        name: "x".to_string(),
        value: crate::script::Expr::Int(1),
    };
    let inner = crate::script::Statement::Block(vec![crate::script::Statement::VarDeclaration {
        name: "x".to_string(),
        value: crate::script::Expr::Int(2),
    }]);
    let program = crate::script::Program::new();
    let res = ctx.compile_program(&program, "shadow", &[d1, inner], None, None, None);
    assert!(res.is_err(), "expected shadowing error");
    let msg = format!("{:?}", res.err());
    assert!(
        msg.contains("Shadowing is not allowed") || msg.contains("shadow"),
        "unexpected: {msg}"
    );
}

#[test]
fn out_of_scope_use_is_rejected() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("ctx");

    // { let y = 2; } print y;  -> y is out of scope
    let block = crate::script::Statement::Block(vec![crate::script::Statement::VarDeclaration {
        name: "y".to_string(),
        value: crate::script::Expr::Int(2),
    }]);
    let print_y =
        crate::script::Statement::Print(crate::script::PrintStatement::Variable("y".to_string()));
    let program = crate::script::Program::new();
    let res = ctx.compile_program(
        &program,
        "out_of_scope",
        &[block, print_y],
        None,
        None,
        None,
    );
    assert!(
        res.is_err(),
        "expected out-of-scope or missing analyzer error"
    );
}

#[test]
fn memcmp_rejects_bare_integer_pointer_argument() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx =
        EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("create EbpfContext");

    // let q = 0xdeadbeef;  // integer, not a pointer value
    let decl = crate::script::Statement::VarDeclaration {
        name: "q".to_string(),
        value: crate::script::Expr::Int(0xdeadbeef),
    };

    // if memcmp(q, hex("00"), 1) { print "X"; }
    let if_stmt = crate::script::Statement::If {
        condition: crate::script::Expr::BuiltinCall {
            name: "memcmp".to_string(),
            args: vec![
                crate::script::Expr::Variable("q".to_string()),
                crate::script::Expr::BuiltinCall {
                    name: "hex".to_string(),
                    args: vec![crate::script::Expr::String("00".to_string())],
                },
                crate::script::Expr::Int(1),
            ],
        },
        then_body: vec![crate::script::Statement::Print(
            crate::script::PrintStatement::String("X".to_string()),
        )],
        else_body: None,
    };

    let program = crate::script::Program::new();
    let res = ctx.compile_program(
        &program,
        "test_memcmp_int_ptr",
        &[decl, if_stmt],
        None,
        None,
        None,
    );
    assert!(res.is_err(), "Expected compilation error but got Ok");
}

#[test]
fn expr_to_name_truncates_utf8_safely() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let ctx = EbpfContext::new(&context, "test_mod", Some(0), &opts).expect("create ctx");
    // Build a long expression comprised of multibyte chars to exceed 96 chars
    let mut chain: Vec<String> = Vec::new();
    for _ in 0..50 {
        // each "错误" is 6 bytes, 2 chars -> quickly exceeds 96 chars
        chain.push("错误".to_string());
    }
    let expr = crate::script::Expr::ChainAccess(chain);
    let s = ctx.expr_to_name(&expr);
    // Ensure we got a trailing ellipsis and no panic on multibyte boundary
    assert!(s.ends_with("..."));
    assert!(s.chars().count() <= 96);
}

#[test]
fn pointer_int_arithmetic_is_rejected_with_friendly_error() {
    let context = inkwell::context::Context::create();
    let opts = CompileOptions::default();
    let mut ctx = EbpfContext::new(&context, "ptr_arith", Some(0), &opts).expect("ctx");
    ctx.create_basic_ebpf_function("f").expect("fn");

    // Create a script variable 'p' of pointer type (null pointer)
    let ptr_ty = ctx.context.ptr_type(inkwell::AddressSpace::default());
    let null_ptr = ptr_ty.const_null();
    ctx.store_variable("p", null_ptr.into()).expect("store ptr");

    // Expression: p + 1
    let expr = crate::script::Expr::BinaryOp {
        left: Box::new(crate::script::Expr::Variable("p".to_string())),
        op: crate::script::BinaryOp::Add,
        right: Box::new(crate::script::Expr::Int(1)),
    };
    let res = ctx.compile_expr(&expr);
    assert!(res.is_err(), "expected pointer-int arithmetic error");
    let msg = format!("{:?}", res.err());
    assert!(
        msg.contains("pointer and integer")
            || msg.contains("Unsupported operation between pointer and integer"),
        "unexpected error message: {msg}"
    );
}

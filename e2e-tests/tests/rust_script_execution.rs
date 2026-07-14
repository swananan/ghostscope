//! Rust program script execution tests (end-to-end)

mod common;

use common::{init, FIXTURES};

async fn run_ghostscope_with_script_for_target(
    script_content: &str,
    timeout_secs: u64,
    target: &common::targets::TargetHandle,
) -> anyhow::Result<(i32, String, String)> {
    common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .attach_to(target)
        .timeout_secs(timeout_secs)
        .enable_sysmon_for_target(false)
        .run()
        .await
}

async fn spawn_rust_global_program() -> anyhow::Result<common::targets::TargetHandle> {
    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let bin_dir = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("rust_global_program has no parent directory"))?;
    let target = common::targets::TargetLauncher::binary(&binary_path)
        .current_dir(bin_dir)
        .spawn()
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    Ok(target)
}

#[tokio::test]
async fn test_rust_tuple_projection_plan_preserves_semantic_identity() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let tuple_path = ghostscope_dwarf::VariableAccessPath::new(vec![
        ghostscope_dwarf::VariableAccessSegment::TupleIndex(0),
    ]);
    let (_, plan) = analyzer
        .plan_global_access_read_plan(&binary_path, "GLOBAL_TUPLE", &tuple_path)?
        .ok_or_else(|| anyhow::anyhow!("expected GLOBAL_TUPLE.0 read plan"))?;

    assert_eq!(plan.name, "GLOBAL_TUPLE.0");
    assert_eq!(plan.access_path, tuple_path);
    assert!(plan.type_id.is_some(), "plan: {plan:?}");
    let semantic_type = analyzer
        .semantic_type_for_plan(&plan)?
        .ok_or_else(|| anyhow::anyhow!("expected semantic type for GLOBAL_TUPLE.0"))?;
    assert_eq!(semantic_type.id, plan.type_id);
    assert_eq!(
        semantic_type.origin.map(|origin| origin.language),
        Some(ghostscope_dwarf::SourceLanguage::Rust)
    );

    let (_, pair_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "GLOBAL_PAIR",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected GLOBAL_PAIR read plan"))?;
    let pair_type = pair_plan
        .dwarf_type
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("expected GLOBAL_PAIR type"))?;
    let layout = analyzer.tuple_member_layout_in_module(&binary_path, pair_type, 1)?;
    assert_eq!(layout.offset, 4);
    assert_eq!(layout.member_type.type_name(), "i32");

    let cast_type = analyzer
        .try_resolve_c_style_semantic_type_spec_in_module(&binary_path, "Pair *")?
        .ok_or_else(|| anyhow::anyhow!("expected semantic Pair pointer type"))?;
    assert_eq!(
        cast_type.origin.as_ref().map(|origin| origin.language),
        Some(ghostscope_dwarf::SourceLanguage::Rust)
    );
    let pointee = analyzer.project_resolved_type(
        &cast_type,
        &ghostscope_dwarf::VariableAccessSegment::Dereference,
        Some(&binary_path),
    )?;
    assert_eq!(
        pointee.layout,
        ghostscope_dwarf::TypeProjectionLayout::Dereference
    );
    assert_eq!(
        pointee.resolved_type.identity.layout_dwarf_id(),
        pair_plan.type_id
    );
    assert!(matches!(
        ghostscope_dwarf::strip_type_aliases(&pointee.resolved_type.summary),
        ghostscope_dwarf::TypeInfo::StructType { name, .. } if name == "Pair"
    ));

    let pair_member = analyzer.project_resolved_type(
        &pointee.resolved_type,
        &ghostscope_dwarf::VariableAccessSegment::TupleIndex(0),
        Some(&binary_path),
    )?;
    assert_eq!(
        pair_member.layout,
        ghostscope_dwarf::TypeProjectionLayout::Member { offset: 0 }
    );
    assert_eq!(pair_member.resolved_type.summary.type_name(), "i32");
    assert!(pair_member
        .resolved_type
        .identity
        .layout_dwarf_id()
        .is_some());
    assert_eq!(
        pair_member
            .resolved_type
            .origin
            .map(|origin| origin.language),
        Some(ghostscope_dwarf::SourceLanguage::Rust)
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_tuple_fields() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace do_stuff {
    let pair_index = 1;
    print "RTUP:{}:{}", GLOBAL_TUPLE.0, GLOBAL_TUPLE.1;
    print "RPAIR:{}:{}", GLOBAL_PAIR.0, GLOBAL_PAIR.1;
    print "DPAIR:{}", GLOBAL_PAIRS[pair_index].0;
    print "CPAIR:{}", cast(&GLOBAL_PAIR, "Pair *").0;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout.lines().any(|line| {
            line.contains("RTUP:") && (line.contains(":true") || line.contains(":false"))
        }),
        "Expected typed tuple output: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            let Some((_, payload)) = line.split_once("RPAIR:") else {
                return false;
            };
            let mut fields = payload.split(':');
            let Some(left) = fields.next() else {
                return false;
            };
            let Some(right) = fields.next() else {
                return false;
            };
            left.trim().parse::<i64>().is_ok()
                && right
                    .split_whitespace()
                    .next()
                    .is_some_and(|value| value.parse::<i64>().is_ok())
        }),
        "Expected typed tuple struct output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );
    assert!(
        stdout.contains("DPAIR:13"),
        "Expected dynamic-index tuple output: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            line.split_once("CPAIR:")
                .and_then(|(_, value)| value.split_whitespace().next())
                .is_some_and(|value| value.parse::<i64>().is_ok())
        }),
        "Expected cast tuple output: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_globals() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;

    // Attach at do_stuff (DW_AT_name likely 'do_stuff'), print Rust globals and a struct field
    let script = r#"
trace do_stuff {
    print "RCNT:{}", G_COUNTER;
    print "CFA:{}", CONFIG.a;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("RCNT:"),
        "Expected RCNT output. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("CFA:"),
        "Expected CFA output. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_counter_increments() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;

    let script = r#"
trace do_stuff {
    print "RC:{}", G_COUNTER;
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let mut vals: Vec<i64> = Vec::new();
    for line in stdout.lines() {
        if let Some(pos) = line.find("RC:") {
            if let Some(num_str) = line[pos + 3..].split_whitespace().next() {
                if let Ok(v) = num_str.parse::<i64>() {
                    vals.push(v);
                }
            }
        }
    }
    assert!(vals.len() >= 2, "Insufficient RC events. STDOUT: {stdout}");
    let mut non_decreasing = true;
    for w in vals.windows(2) {
        if w[1] < w[0] {
            non_decreasing = false;
            break;
        }
    }
    assert!(
        non_decreasing,
        "Counter decreased unexpectedly. vals={vals:?}"
    );
    Ok(())
}

#[tokio::test]
async fn test_rust_script_address_of_global() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;

    let script = r#"
trace do_stuff {
    print "&RC:{}", &G_COUNTER;
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("&RC:"),
        "Expected address-of output. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("0x"),
        "Expected hex address. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_rust_script_global_enum_as_int() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;

    // Read GLOBAL_ENUM by forcing it into an integer slot via reinterpret cast.
    // This exercises the static-resolution path for globals that only have DW_OP_addr.
    let script = r#"
trace do_stuff {
    print "ENUM_RAW:{}", GLOBAL_ENUM_BITS;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let mut seen = false;
    for line in stdout.lines() {
        if line.contains("ENUM_RAW:") {
            seen = true;
            break;
        }
    }
    assert!(seen, "Expected ENUM_RAW output. STDOUT: {stdout}");

    Ok(())
}

#[tokio::test]
async fn test_rust_script_bss_counter_direct() -> anyhow::Result<()> {
    // Regression coverage: ensure we can read a pure .bss global (G_COUNTER) directly, without
    // relying on DWARF locals or pointer aliases.
    init();

    let target = spawn_rust_global_program().await?;

    let script = r#"
trace touch_globals {
    print "BSSCNT:{}", G_COUNTER;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let mut vals = Vec::new();
    for line in stdout.lines() {
        if let Some(pos) = line.find("BSSCNT:") {
            if let Some(num_str) = line[pos + "BSSCNT:".len()..].split_whitespace().next() {
                if let Ok(v) = num_str.parse::<i64>() {
                    vals.push(v);
                }
            }
        }
    }
    assert!(
        vals.len() >= 2,
        "Insufficient BSSCNT events. STDOUT: {stdout}"
    );
    for pair in vals.windows(2) {
        assert_eq!(pair[1] - pair[0], 1, "G_COUNTER should +1 per tick");
    }
    Ok(())
}

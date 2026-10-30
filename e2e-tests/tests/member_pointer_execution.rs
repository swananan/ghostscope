//! Member-pointer style C runtime tests.
//!
//! These cover nginx-like local pointer chains under optimized code. The
//! companion `member_pointer_compilation.rs` file exercises DWARF planning and
//! compile-time errors; this file attaches to a real target process.

mod common;

use common::{init, OptimizationLevel, FIXTURES};
use std::path::Path;
use std::time::Duration;

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

async fn spawn_member_pointer_binary(
    binary_path: &Path,
) -> anyhow::Result<common::targets::TargetHandle> {
    let target = common::targets::TargetLauncher::binary(binary_path)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(target)
}

#[tokio::test]
async fn test_value_backed_aggregate_o2_runtime_fields() -> anyhow::Result<()> {
    init();
    let binary_path =
        FIXTURES.get_test_binary_with_opt("member_pointer_program", OptimizationLevel::O2)?;
    let target = spawn_member_pointer_binary(&binary_path).await?;
    let script = r#"
trace member_pointer_program.c:84 {
    print "SRA_FIELDS={}:{}", s.a, s.b;
    print "SRA_DELTA={}", s.b - s.a;
    if s.b - s.a == 1 { print "SRA_FIELDS_OK"; }
}
"#;
    let result = run_ghostscope_with_script_for_target(script, 4, &target).await;
    target.terminate().await?;
    let (exit_code, stdout, stderr) = result?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    let fields = regex::Regex::new(r"SRA_FIELDS=(-?\d+):(-?\d+)")?;
    let samples: Vec<_> = fields.captures_iter(&stdout).collect();
    assert!(!samples.is_empty(), "{stdout}");
    for sample in samples {
        assert_eq!(
            sample[2].parse::<i64>()?,
            sample[1].parse::<i64>()? + 1,
            "{stdout}"
        );
    }
    assert!(
        stdout.contains("SRA_DELTA=1") && stdout.contains("SRA_FIELDS_OK"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("<unavailable") && !stdout.contains("ExprError"),
        "{stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_value_backed_aggregate_o2_runtime_padding_pointer_and_missing_field(
) -> anyhow::Result<()> {
    init();
    let binary_path =
        FIXTURES.get_test_binary_with_opt("member_pointer_program", OptimizationLevel::O2)?;
    let source = std::fs::read_to_string(
        binary_path
            .parent()
            .unwrap()
            .join("member_pointer_program.c"),
    )?;
    let line = source
        .lines()
        .position(|line| line.contains("SRA_SPLIT_PROBE"))
        .unwrap()
        + 1;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let addresses =
        analyzer.lookup_addresses_by_source_line("member_pointer_program.c", line as u32);
    anyhow::ensure!(!addresses.is_empty(), "missing split-record probe address");
    for address in &addresses {
        let pc = analyzer.resolve_pc(address)?;
        let plan = analyzer
            .plan_variable_by_name(&pc, "ec")?
            .ok_or_else(|| anyhow::anyhow!("missing ec"))?;
        anyhow::ensure!(
            matches!(plan.location, ghostscope_dwarf::VariableLocation::Pieces(_)),
            "fixture must exercise DW_OP_piece: {plan:?}"
        );
    }
    let target = spawn_member_pointer_binary(&binary_path).await?;
    let script = format!(
        r#"
trace member_pointer_program.c:{line} {{
    print "SRA_RECORD={{}}", ec;
    print "SRA_CATEGORY={{}}", *ec.category;
    print "SRA_MISSING={{}}", ec.missing;
    if ec.serial - ec.code == 0x12345677fffffff9 {{ print "SRA_RECORD_OK"; }}
}}
"#
    );
    let result = run_ghostscope_with_script_for_target(&script, 4, &target).await;
    target.terminate().await?;
    let (exit_code, stdout, stderr) = result?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout.contains("SRA_RECORD=") && stdout.contains("code:") && stdout.contains("serial:"),
        "{stdout}"
    );
    assert!(
        stdout.contains("SRA_CATEGORY=314") && stdout.contains("SRA_RECORD_OK"),
        "{stdout}"
    );
    assert!(
        stdout.contains("missing: <unavailable: optimized out>"),
        "{stdout}"
    );
    assert!(
        stdout.contains("SRA_MISSING=<unavailable: optimized out>"),
        "{stdout}"
    );
    assert!(
        !stdout.contains("ExprError") && !stdout.contains("<OUT_OF_BOUNDS>"),
        "{stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_member_pointer_o3_runtime_member_pointer_format_and_memcmp() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("member_pointer_program", OptimizationLevel::O3)?;
    let target = spawn_member_pointer_binary(&binary_path).await?;

    let script = r#"
trace member_pointer_program.c:68 {
    let key = h.key.data;
    let key_len = h.key.len;
    let half_key_len = h.key.len / 0x2;
    let tail_len = h.value.len - 0b1;
    let dyn_key_idx = h.key.len - 0x4;
    let dyn_body_idx = h.value.len - 0b10;
    let body = r.header_in.pos + 0x1;
    let body_tail = r.header_in.end + -0x3;
    let key_dyn_tail = key + dyn_key_idx;
    let body_dyn_tail = r.header_in.pos + dyn_body_idx;
    print "MP_HDR={:s.6}", h.key.data;
    print "MP_VAL={:s.5}", h.value.data;
    print "MP_REQ={:s.4}", r.request_line.data;
    print "MP_BODY={:x.0x4}", r.header_in.pos;
    print "MP_LEN={}:{}:{}", h.key.len, h.value.len, r.request_line.len;
    print "MP_LEN_CALC={}:{}", h.key.len + h.value.len, r.request_line.len - 0x5;
    print "MP_LEN_DIV={}:{}:{}", h.key.len / 0x2, (r.request_line.len + -0x5) / 0b10, (h.value.len + -0x7) / -0x2;
    print "MP_KEY_ALIAS={:s.0x6}", key;
    print "MP_KEY_TAIL={:s.0b100}", key + 0b10;
    print "MP_KEY_ADDR_TAIL={:s.0o4}", &key[0b10];
    print "MP_KEY_DYNAMIC={:s.key_len$}", key;
    print "MP_KEY_DIV_DYNAMIC={:s.half_key_len$}", key;
    print "MP_KEY_TAIL_DYNAMIC={:s.tail_len$}", key + 0b10;
    print "MP_KEY_DYN_TAIL={:s.0b100}", key_dyn_tail;
    print "MP_KEY_DYN_INDEX={:s.0x4}", &key[dyn_key_idx];
    print "MP_BODY_ALIAS={:x.0o4}", body;
    print "MP_BODY_TAIL={:s.0b11}", body_tail;
    print "MP_BODY_DYN_TAIL={:s.0x5}", body_dyn_tail;
    if h.key.len == 0x6 && h.value.len == 0o5 { print "MP_LEN_OK"; }
    if h.key.len / 0x2 == 0b11 && (h.value.len + -0x7) / -0x2 == 0x1 { print "MP_LEN_DIV_OK"; }
    if r.request_line.len - h.key.len == 0xd { print "MP_REQ_LEN_DELTA_OK"; }
    if memcmp(h.key.data, hex("582d"), 0x2) { print "MP_HDR_OK"; }
    if memcmp(r.header_in.pos, r.header_in.pos, 0b100) { print "MP_BODY_SELF_OK"; }
    if memcmp(key + 0x2, hex("44656d6f"), 0b100) { print "MP_KEY_TAIL_OK"; }
    if memcmp(&key[0b10], hex("44656d6f"), 0x4) { print "MP_KEY_ADDR_TAIL_OK"; }
    if memcmp(key_dyn_tail, hex("44656d6f"), 0b100) { print "MP_KEY_DYN_TAIL_OK"; }
    if memcmp(&key[dyn_key_idx], hex("44656d6f"), 0x4) { print "MP_KEY_DYN_INDEX_OK"; }
    if memcmp(dyn_key_idx + key, hex("44656d6f"), 0o4) { print "MP_KEY_DYN_COMMUTE_OK"; }
    if memcmp(body, hex("01026865"), 0o4) { print "MP_BODY_ALIAS_OK"; }
    if memcmp(r.header_in.end + -0x3, hex("6c6c6f"), 0x3) { print "MP_BODY_TAIL_OK"; }
    if strncmp(body_dyn_tail, "hello", 0x5) { print "MP_BODY_DYN_TAIL_OK"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("MP_HDR=X-Demo"),
        "Expected optimized header key string. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_VAL=hello"),
        "Expected optimized header value string. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_REQ=POST"),
        "Expected optimized request line prefix. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_HDR_OK"),
        "Expected optimized member pointer memcmp marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_BODY_SELF_OK"),
        "Expected optimized body self memcmp marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_KEY_ALIAS=X-Demo"),
        "Expected optimized member pointer alias string. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_LEN=6:5:19"),
        "Expected optimized member pointer length fields. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_LEN_CALC=11:14"),
        "Expected optimized member pointer length arithmetic. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_LEN_DIV=3:7:1"),
        "Expected optimized member pointer length division. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_KEY_TAIL=Demo"),
        "Expected optimized member pointer alias arithmetic string. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_KEY_ADDR_TAIL=Demo"),
        "Expected optimized address-of alias-index string. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_KEY_DYNAMIC=X-Demo"),
        "Expected optimized member pointer dynamic length string. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_KEY_DIV_DYNAMIC=X-D"),
        "Expected optimized member pointer division-based dynamic length string. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_KEY_TAIL_DYNAMIC=Demo"),
        "Expected optimized member pointer arithmetic dynamic length string. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_KEY_DYN_TAIL=Demo"),
        "Expected optimized dynamic member pointer alias tail string. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_KEY_DYN_INDEX=Demo"),
        "Expected optimized dynamic member pointer alias index string. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_BODY_ALIAS=01 02 68 65"),
        "Expected optimized body alias pointer arithmetic bytes. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_BODY_TAIL=llo"),
        "Expected optimized negative member pointer arithmetic string. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_BODY_DYN_TAIL=hello"),
        "Expected optimized dynamic body pointer arithmetic string. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_LEN_OK"),
        "Expected optimized member pointer length comparison marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_LEN_DIV_OK"),
        "Expected optimized member pointer length division comparison marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_REQ_LEN_DELTA_OK"),
        "Expected optimized member pointer length arithmetic comparison marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_KEY_TAIL_OK"),
        "Expected optimized member pointer alias arithmetic memcmp marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_KEY_ADDR_TAIL_OK"),
        "Expected optimized address-of alias-index memcmp marker. STDOUT: {stdout}"
    );
    for marker in [
        "MP_KEY_DYN_TAIL_OK",
        "MP_KEY_DYN_INDEX_OK",
        "MP_KEY_DYN_COMMUTE_OK",
        "MP_BODY_DYN_TAIL_OK",
    ] {
        assert!(
            stdout.contains(marker),
            "Expected optimized dynamic member pointer marker {marker}. STDOUT: {stdout}"
        );
    }
    assert!(
        stdout.contains("MP_BODY_ALIAS_OK"),
        "Expected optimized body alias pointer arithmetic memcmp marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MP_BODY_TAIL_OK"),
        "Expected optimized negative body pointer arithmetic memcmp marker. STDOUT: {stdout}"
    );

    use regex::Regex;
    let re_body = Regex::new(r"MP_BODY=(?:00|01) 01 02 68").unwrap();
    assert!(
        stdout.lines().any(|line| re_body.is_match(line)),
        "Expected optimized body bytes. STDOUT: {stdout}"
    );

    Ok(())
}

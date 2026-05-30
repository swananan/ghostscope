//! C scalar type execution tests
//! - Covers signed/unsigned integer widths, booleans, and floating-point formatting

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

async fn spawn_scalar_types_binary(
    binary_path: &Path,
) -> anyhow::Result<common::targets::TargetHandle> {
    let target = common::targets::TargetLauncher::binary(binary_path)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(target)
}

async fn assert_scalar_format_lengths(binary_path: &Path) -> anyhow::Result<()> {
    let target = spawn_scalar_types_binary(binary_path).await?;

    let script = r#"
trace scalar_format_anchor {
    let dyn_idx = *lenp - 0x2;
    let dyn_text_idx = *lenp - 0x4;
    let dyn_byte = bufp + dyn_idx;
    let dyn_text = textp + dyn_text_idx;
    print "HEX_DEC={:x.4}", bufp;
    print "HEX_HEX={:x.0x4}", bufp;
    print "HEX_OCT={:x.0o4}", bufp;
    print "HEX_BIN={:X.0b100}", bufp;
    print "HEX_STAR={:x.*}", *lenp, bufp;
    print "HEX_DYN_BYTE={:x.0x4}", dyn_byte;
    let n = 5;
    print "ASCII_CAPTURE={:s.n$}", textp;
    print "ASCII_DYN={:s.0x4}", dyn_text;
    print "PTR_FMT={:p}", bufp;
    if memcmp(dyn_byte, hex("ef00417f"), 0b100) { print "DYN_BYTE_MEM_OK"; }
    if strncmp(dyn_text, "ello", 0o4) { print "DYN_TEXT_STR_OK"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    for expected in [
        "HEX_DEC=de ad be ef",
        "HEX_HEX=de ad be ef",
        "HEX_OCT=de ad be ef",
        "HEX_BIN=DE AD BE EF",
        "HEX_STAR=de ad be ef 00",
        "HEX_DYN_BYTE=ef 00 41 7f",
        "ASCII_CAPTURE=Hello",
        "ASCII_DYN=ello",
        "DYN_BYTE_MEM_OK",
        "DYN_TEXT_STR_OK",
    ] {
        assert!(
            stdout.contains(expected),
            "Expected formatted output {expected}. STDOUT: {stdout}"
        );
    }
    assert!(
        stdout.contains("PTR_FMT=0x"),
        "Expected pointer formatter output. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_c_scalar_integer_prints_preserve_signedness() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("scalar_types_program")?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_anchor {
    print "SIGNED:{}:{}:{}:{}:{}", *i8p, *i16p, *i32p, *ilongp, *i64p;
    print "UNSIGNED:{}:{}:{}:{}:{}", *u8p, *u16p, *u32p, *ulongp, *u64p;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("SIGNED:-5:-1234:-12345678:-4444444444:-9000000000000000000"),
        "Expected signed scalar values to preserve negative formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("UNSIGNED:250:60000:4000000000:9000000000:18446744073709551610"),
        "Expected unsigned scalar values to preserve full-width formatting. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_c_scalar_integer_comparisons_respect_widths() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("scalar_types_program")?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_anchor {
    if *i8p < 0 { print "I8_NEG"; }
    if *i16p < -1000 { print "I16_NEG"; }
    if *i32p < -10000000 { print "I32_NEG"; }
    if *ilongp < -4000000000 { print "LONG_NEG"; }
    if *i64p < -8000000000000000000 { print "I64_NEG"; }
    if *u8p > 200 { print "U8_BIG"; }
    if *u16p > 50000 { print "U16_BIG"; }
    if *u32p > 3000000000 { print "U32_BIG"; }
    if *ulongp > 8000000000 { print "ULONG_BIG"; }
    if *u64p > 9223372036854775807 { print "U64_HIGH"; }
    if *u64p != 0 { print "U64_NONZERO"; }
    if *i32p > *u32p { print "MIXED_I32_GT_U32"; }
    if *u32p < *i32p { print "MIXED_U32_LT_I32"; }
    if *i32p < *u32p { print "MIXED_I32_LT_U32"; }
    if *i32minp < *u32p { print "MIXED_I32_MIN_LT_U32"; }
    if *i32minp > *u32p { print "MIXED_I32_MIN_GT_U32"; }
    if *u32p > -10000000000 { print "U32_GT_SCRIPT_NEG"; }
    if *u32p < -10000000000 { print "U32_LT_SCRIPT_NEG"; }
    if *i8p < *u8p { print "MIXED_I8_LT_U8"; }
    if *i8p > *u8p { print "MIXED_I8_GT_U8"; }
    if *i64p < *u64p { print "MIXED_I64_LT_U64"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    for marker in [
        "I8_NEG",
        "I16_NEG",
        "I32_NEG",
        "LONG_NEG",
        "I64_NEG",
        "U8_BIG",
        "U16_BIG",
        "U32_BIG",
        "ULONG_BIG",
        "U64_HIGH",
        "U64_NONZERO",
        "MIXED_I32_GT_U32",
        "MIXED_U32_LT_I32",
        "MIXED_I32_MIN_LT_U32",
        "U32_GT_SCRIPT_NEG",
        "MIXED_I8_LT_U8",
        "MIXED_I64_LT_U64",
    ] {
        assert!(
            stdout.contains(marker),
            "Expected comparison marker {marker}. STDOUT: {stdout}"
        );
    }
    for marker in [
        "MIXED_I32_LT_U32",
        "MIXED_I32_MIN_GT_U32",
        "U32_LT_SCRIPT_NEG",
        "MIXED_I8_GT_U8",
    ] {
        assert!(
            !stdout.contains(marker),
            "Unexpected mixed comparison marker {marker}. STDOUT: {stdout}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_c_scalar_unsigned_modulo_and_bitwise_normalize_widths() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("scalar_types_program")?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_anchor {
    print "U32_I32_MOD={}", cast(0xffffffff, "uint32_t") % cast(-1, "int32_t");
    print "U32_I32_BITOR={}", cast(0x0, "uint32_t") | cast(-1, "int32_t");
    print "U32_BITNOT={}", ~cast(0x0, "uint32_t");
    if cast(0xffffffff, "uint32_t") % cast(-1, "int32_t") == 0 {
        print "U32_I32_MOD_OK";
    }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    for expected in [
        "U32_I32_MOD=0",
        "U32_I32_BITOR=4294967295",
        "U32_BITNOT=4294967295",
        "U32_I32_MOD_OK",
    ] {
        assert!(
            stdout.contains(expected),
            "Expected unsigned-width operator output {expected}. STDOUT: {stdout}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_c_scalar_bool_and_float_prints() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("scalar_types_program")?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_anchor {
    print "BOOL:{}:{}", *truep, *falsep;
    print "FLOAT:{}:{}", *f32p, *f64p;
    print "LDOUBLE:{}", *ldp;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("BOOL:true:false"),
        "Expected _Bool formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("FLOAT:-12.5:123456.25"),
        "Expected float/double formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("LDOUBLE:<UNSUPPORTED_FLOAT_SIZE_16>"),
        "Expected long double to report the current unsupported 16-byte boundary. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_c_scalar_by_value_parameters_preserve_semantics() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("scalar_types_program")?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_by_value {
    print "BYVAL_SIGNED:{}:{}:{}", i8v, i16v, alias_i8v;
    print "BYVAL_UNSIGNED:{}:{}:{}:{}", u8v, u16v, u32v, u64v;
    if i8v < 0 { print "BYVAL_I8_NEG"; }
    if i16v < -1000 { print "BYVAL_I16_NEG"; }
    if alias_i8v < 0 { print "BYVAL_ALIAS_NEG"; }
    if u64v > 9223372036854775807 { print "BYVAL_U64_HIGH"; }
    print "BYVAL_ENUMS:{}:{}", enum_negv, enum_bigv;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("BYVAL_SIGNED:-5:-1234:-9"),
        "Expected signed by-value parameters to preserve negatives. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("BYVAL_UNSIGNED:250:60000:4000000000:18446744073709551610"),
        "Expected unsigned by-value parameters to preserve full-width values. STDOUT: {stdout}"
    );
    for marker in [
        "BYVAL_I8_NEG",
        "BYVAL_I16_NEG",
        "BYVAL_ALIAS_NEG",
        "BYVAL_U64_HIGH",
    ] {
        assert!(
            stdout.contains(marker),
            "Expected by-value marker {marker}. STDOUT: {stdout}"
        );
    }
    assert!(
        stdout.contains("BYVAL_ENUMS:scalar_signed_enum::SCALAR_ENUM_NEG(-3):scalar_big_enum::SCALAR_ENUM_BIG(4000000000)"),
        "Expected signed and large enum formatting. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_c_scalar_o3_by_value_parameters_preserve_semantics() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("scalar_types_program", OptimizationLevel::O3)?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_by_value {
    print "O3_BYVAL_SIGNED:{}:{}:{}", i8v, i16v, alias_i8v;
    print "O3_BYVAL_UNSIGNED:{}:{}:{}:{}", u8v, u16v, u32v, u64v;
    if i8v < 0 { print "O3_BYVAL_I8_NEG"; }
    if i16v < -1000 { print "O3_BYVAL_I16_NEG"; }
    if alias_i8v < 0 { print "O3_BYVAL_ALIAS_NEG"; }
    if i8v == -5 { print "O3_BYVAL_I8_EQ_NEG"; }
    if i16v == -1234 { print "O3_BYVAL_I16_EQ_NEG"; }
    if alias_i8v == -9 { print "O3_BYVAL_ALIAS_EQ_NEG"; }
    if u64v > 9223372036854775807 { print "O3_BYVAL_U64_HIGH"; }
    if i8v < u8v { print "O3_BYVAL_MIXED_I8_LT_U8"; }
    if i8v > u8v { print "O3_BYVAL_MIXED_I8_GT_U8"; }
    if u32v > -10000000000 { print "O3_BYVAL_U32_GT_SCRIPT_NEG"; }
    print "O3_BYVAL_ENUMS:{}:{}", enum_negv, enum_bigv;
    print "O3_BYVAL_ARITH:{}:{}:{}:{}", i8v + u8v, u16v - 0xea60, alias_i8v + -0x1, enum_bigv - 0xee6b2800;
    print "O3_BYVAL_DIV:{}:{}:{}", u16v / 0x3, u32v / 0x2, u64v / 0x2;
    print "O3_BYVAL_SIGNED_DIV:{}:{}", i8v / 0x2, i16v / -0x2;
    print "O3_BYVAL_DYNAMIC_DIV:{}:{}:{}", u8v / (i8v + 0xf), u32v / (u8v + 0x6), i16v / (i8v + 0x3);
    if u64v / 0x2 == 9223372036854775805 { print "O3_BYVAL_U64_DIV_OK"; }
    if i8v / 0x2 == -0x2 { print "O3_BYVAL_I8_DIV_OK"; }
    if i16v / -0x2 == 0x269 { print "O3_BYVAL_I16_DIV_OK"; }
    if u8v / (i8v + 0xf) == 0x19 { print "O3_BYVAL_DYNAMIC_U8_DIV_OK"; }
    if u32v / (u8v + 0x6) == 0xee6b28 { print "O3_BYVAL_DYNAMIC_U32_DIV_OK"; }
    if i16v / (i8v + 0x3) == 0x269 { print "O3_BYVAL_DYNAMIC_I16_DIV_OK"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("O3_BYVAL_SIGNED:-5:-1234:-9"),
        "Expected O3 signed by-value parameters to preserve negatives. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_BYVAL_UNSIGNED:250:60000:4000000000:18446744073709551610"),
        "Expected O3 unsigned by-value parameters to preserve full-width values. STDOUT: {stdout}"
    );
    for marker in [
        "O3_BYVAL_I8_NEG",
        "O3_BYVAL_I16_NEG",
        "O3_BYVAL_ALIAS_NEG",
        "O3_BYVAL_I8_EQ_NEG",
        "O3_BYVAL_I16_EQ_NEG",
        "O3_BYVAL_ALIAS_EQ_NEG",
        "O3_BYVAL_U64_HIGH",
        "O3_BYVAL_MIXED_I8_LT_U8",
        "O3_BYVAL_U32_GT_SCRIPT_NEG",
    ] {
        assert!(
            stdout.contains(marker),
            "Expected O3 by-value marker {marker}. STDOUT: {stdout}"
        );
    }
    assert!(
        !stdout.contains("O3_BYVAL_MIXED_I8_GT_U8"),
        "Unexpected O3 by-value mixed comparison marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_BYVAL_ENUMS:scalar_signed_enum::SCALAR_ENUM_NEG(-3):scalar_big_enum::SCALAR_ENUM_BIG(4000000000)"),
        "Expected O3 signed and large enum by-value formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_BYVAL_ARITH:245:0:-10:0"),
        "Expected O3 by-value arithmetic across narrow signed/unsigned and enum values. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_BYVAL_DIV:20000:2000000000:9223372036854775805"),
        "Expected O3 by-value division to preserve unsigned C semantics. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_BYVAL_SIGNED_DIV:-2:617"),
        "Expected O3 by-value signed division to truncate toward zero. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_BYVAL_DYNAMIC_DIV:25:15625000:617"),
        "Expected O3 by-value dynamic division across signed and unsigned narrow values. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_BYVAL_U64_DIV_OK"),
        "Expected O3 by-value uint64 division comparison marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_BYVAL_I8_DIV_OK") && stdout.contains("O3_BYVAL_I16_DIV_OK"),
        "Expected O3 by-value signed division comparison markers. STDOUT: {stdout}"
    );
    for marker in [
        "O3_BYVAL_DYNAMIC_U8_DIV_OK",
        "O3_BYVAL_DYNAMIC_U32_DIV_OK",
        "O3_BYVAL_DYNAMIC_I16_DIV_OK",
    ] {
        assert!(
            stdout.contains(marker),
            "Expected O3 by-value dynamic division marker {marker}. STDOUT: {stdout}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_c_scalar_float_bool_by_value_parameters() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("scalar_types_program")?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_float_bool_by_value {
    print "BYVAL_BOOL:{}:{}", bool_truev, bool_falsev;
    print "BYVAL_FLOAT:{}:{}", f32v, f64v;
    if bool_truev != bool_falsev { print "BYVAL_BOOL_DIFF"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("BYVAL_BOOL:true:false"),
        "Expected _Bool by-value parameter formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("BYVAL_FLOAT:-12.5:123456.25"),
        "Expected float and double by-value parameter formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("BYVAL_BOOL_DIFF"),
        "Expected _Bool by-value comparison marker. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_c_scalar_o3_bool_by_value_parameters() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("scalar_types_program", OptimizationLevel::O3)?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_float_bool_by_value {
    print "O3_BYVAL_BOOL:{}:{}", bool_truev, bool_falsev;
    if bool_truev != bool_falsev { print "O3_BYVAL_BOOL_DIFF"; }
    if bool_truev == true { print "O3_BYVAL_BOOL_TRUE"; }
    if bool_falsev == false { print "O3_BYVAL_BOOL_FALSE"; }
    if bool_truev == 1 { print "O3_BYVAL_BOOL_EQ_ONE"; }
    if bool_falsev == 0 { print "O3_BYVAL_BOOL_EQ_ZERO"; }
    if bool_truev && bool_truev { print "O3_BYVAL_BOOL_AND_TRUE"; }
    if bool_falsev || bool_truev { print "O3_BYVAL_BOOL_OR_TRUE"; }
    if bool_truev && bool_falsev { print "O3_BYVAL_BOOL_AND_FALSE_BAD"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("O3_BYVAL_BOOL:true:false"),
        "Expected O3 _Bool by-value parameter formatting. STDOUT: {stdout}"
    );
    for marker in [
        "O3_BYVAL_BOOL_DIFF",
        "O3_BYVAL_BOOL_TRUE",
        "O3_BYVAL_BOOL_FALSE",
        "O3_BYVAL_BOOL_EQ_ONE",
        "O3_BYVAL_BOOL_EQ_ZERO",
        "O3_BYVAL_BOOL_AND_TRUE",
        "O3_BYVAL_BOOL_OR_TRUE",
    ] {
        assert!(
            stdout.contains(marker),
            "Expected O3 float/bool by-value marker {marker}. STDOUT: {stdout}"
        );
    }
    assert!(
        !stdout.contains("O3_BYVAL_BOOL_AND_FALSE_BAD"),
        "Unexpected O3 _Bool && marker for false RHS. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_c_scalar_o3_float_by_value_parameters_report_xmm_unavailable() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("scalar_types_program", OptimizationLevel::O3)?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_float_bool_by_value {
    print "O3_BYVAL_FLOAT:{}", f32v;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_ne!(
        exit_code, 0,
        "Expected optimized XMM-backed float parameter to be reported unavailable. STDOUT: {stdout}"
    );
    assert!(
        stderr.contains("Unsupported DWARF register: 17 (XMM0)")
            && stderr.contains("uprobe pt_regs does not expose XMM register values"),
        "Expected a clear XMM/pt_regs diagnostic. STDERR: {stderr}"
    );
    Ok(())
}

#[tokio::test]
async fn test_c_scalar_stack_by_value_parameters_preserve_semantics() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("scalar_types_program")?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_stack_by_value {
    print "STACK_REGS:{}:{}", reg1, reg6;
    print "STACK_VALUES:{}:{}:{}:{}", stack_i8v, stack_u8v, stack_i32v, stack_u64v;
    if stack_i8v < 0 { print "STACK_I8_NEG"; }
    if stack_u8v > 200 { print "STACK_U8_BIG"; }
    if stack_i32v < -10000000 { print "STACK_I32_NEG"; }
    if stack_u64v > 9223372036854775807 { print "STACK_U64_HIGH"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("STACK_REGS:11:66"),
        "Expected register by-value parameters before stack slots. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("STACK_VALUES:-5:250:-12345678:18446744073709551610"),
        "Expected stack-passed by-value parameters to preserve values. STDOUT: {stdout}"
    );
    for marker in [
        "STACK_I8_NEG",
        "STACK_U8_BIG",
        "STACK_I32_NEG",
        "STACK_U64_HIGH",
    ] {
        assert!(
            stdout.contains(marker),
            "Expected stack by-value marker {marker}. STDOUT: {stdout}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_c_scalar_o3_stack_by_value_parameters_preserve_semantics() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("scalar_types_program", OptimizationLevel::O3)?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_stack_by_value {
    print "O3_STACK_REGS:{}:{}", reg1, reg6;
    print "O3_STACK_VALUES:{}:{}:{}:{}", stack_i8v, stack_u8v, stack_i32v, stack_u64v;
    if stack_i8v < 0 { print "O3_STACK_I8_NEG"; }
    if stack_u8v > 200 { print "O3_STACK_U8_BIG"; }
    if stack_i32v < -10000000 { print "O3_STACK_I32_NEG"; }
    if stack_i8v == -5 { print "O3_STACK_I8_EQ_NEG"; }
    if stack_i32v == -12345678 { print "O3_STACK_I32_EQ_NEG"; }
    if stack_u64v > 9223372036854775807 { print "O3_STACK_U64_HIGH"; }
    if stack_i8v < stack_u8v { print "O3_STACK_MIXED_I8_LT_U8"; }
    if stack_i8v > stack_u8v { print "O3_STACK_MIXED_I8_GT_U8"; }
    print "O3_STACK_DIV:{}:{}:{}", stack_u8v / 0x5, stack_u64v / 0x2, stack_i32v / -0x3;
    print "O3_STACK_SIGNED_DIV:{}", stack_i8v / 0x2;
    if stack_u64v / 0x2 == 9223372036854775805 { print "O3_STACK_U64_DIV_OK"; }
    if stack_i8v / 0x2 == -0x2 { print "O3_STACK_I8_DIV_OK"; }
    if stack_i32v / -0x3 == 4115226 { print "O3_STACK_I32_DIV_OK"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("O3_STACK_REGS:11:66"),
        "Expected O3 register by-value parameters before stack slots. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_STACK_VALUES:-5:250:-12345678:18446744073709551610"),
        "Expected O3 stack-passed by-value parameters to preserve values. STDOUT: {stdout}"
    );
    for marker in [
        "O3_STACK_I8_NEG",
        "O3_STACK_U8_BIG",
        "O3_STACK_I32_NEG",
        "O3_STACK_I8_EQ_NEG",
        "O3_STACK_I32_EQ_NEG",
        "O3_STACK_U64_HIGH",
        "O3_STACK_MIXED_I8_LT_U8",
        "O3_STACK_U64_DIV_OK",
        "O3_STACK_I8_DIV_OK",
        "O3_STACK_I32_DIV_OK",
    ] {
        assert!(
            stdout.contains(marker),
            "Expected O3 stack by-value marker {marker}. STDOUT: {stdout}"
        );
    }
    assert!(
        !stdout.contains("O3_STACK_MIXED_I8_GT_U8"),
        "Unexpected O3 stack mixed comparison marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_STACK_DIV:50:9223372036854775805:4115226"),
        "Expected O3 stack by-value division to preserve unsigned and signed semantics. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_STACK_SIGNED_DIV:-2"),
        "Expected O3 stack signed division to truncate toward zero. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_c_scalar_base_prefixed_format_lengths_on_pointer_memory() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("scalar_types_program")?;
    assert_scalar_format_lengths(&binary_path).await
}

#[tokio::test]
async fn test_c_scalar_o3_pointer_memory_format_lengths() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("scalar_types_program", OptimizationLevel::O3)?;
    assert_scalar_format_lengths(&binary_path).await
}

#[tokio::test]
async fn test_c_scalar_o3_pointer_parameters_preserve_values() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("scalar_types_program", OptimizationLevel::O3)?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_anchor {
    print "O3_SIGNED:{}:{}:{}", *i8p, *i32p, *i64p;
    print "O3_UNSIGNED:{}:{}:{}", *u8p, *u32p, *u64p;
    if *i32p > *u32p { print "O3_MIXED_I32_GT_U32"; }
    if *u32p < *i32p { print "O3_MIXED_U32_LT_I32"; }
    if *i32p < *u32p { print "O3_MIXED_I32_LT_U32"; }
    if *i32minp < *u32p { print "O3_MIXED_I32_MIN_LT_U32"; }
    if *i32minp > *u32p { print "O3_MIXED_I32_MIN_GT_U32"; }
    if *u32p > -10000000000 { print "O3_U32_GT_SCRIPT_NEG"; }
    if *u32p < -10000000000 { print "O3_U32_LT_SCRIPT_NEG"; }
    if *i8p < *u8p { print "O3_MIXED_I8_LT_U8"; }
    if *i8p > *u8p { print "O3_MIXED_I8_GT_U8"; }
    if *i64p < *u64p { print "O3_MIXED_I64_LT_U64"; }
    print "O3_PTR_DIV:{}:{}:{}", *u32p / 0x2, *u64p / 0x2, *i64p / -0x3;
    print "O3_PTR_SIGNED_DIV:{}:{}", *i8p / 0x2, *i32p / -0x3;
    if *u64p / 0x2 == 9223372036854775805 { print "O3_PTR_U64_DIV_OK"; }
    if *i8p / 0x2 == -0x2 { print "O3_PTR_I8_DIV_OK"; }
    if *i32p / -0x3 == 4115226 { print "O3_PTR_I32_DIV_OK"; }
    if *i64p / -0x3 == 3000000000000000000 { print "O3_PTR_I64_DIV_OK"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("O3_SIGNED:-5:-12345678:-9000000000000000000"),
        "Expected O3 signed pointer parameter values. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_UNSIGNED:250:4000000000:18446744073709551610"),
        "Expected O3 unsigned pointer parameter values. STDOUT: {stdout}"
    );
    for marker in [
        "O3_MIXED_I32_GT_U32",
        "O3_MIXED_U32_LT_I32",
        "O3_MIXED_I32_MIN_LT_U32",
        "O3_U32_GT_SCRIPT_NEG",
        "O3_MIXED_I8_LT_U8",
        "O3_MIXED_I64_LT_U64",
        "O3_PTR_U64_DIV_OK",
        "O3_PTR_I8_DIV_OK",
        "O3_PTR_I32_DIV_OK",
        "O3_PTR_I64_DIV_OK",
    ] {
        assert!(
            stdout.contains(marker),
            "Expected O3 comparison marker {marker}. STDOUT: {stdout}"
        );
    }
    for marker in [
        "O3_MIXED_I32_LT_U32",
        "O3_MIXED_I32_MIN_GT_U32",
        "O3_U32_LT_SCRIPT_NEG",
        "O3_MIXED_I8_GT_U8",
    ] {
        assert!(
            !stdout.contains(marker),
            "Unexpected O3 comparison marker {marker}. STDOUT: {stdout}"
        );
    }
    assert!(
        stdout.contains("O3_PTR_DIV:2000000000:9223372036854775805:3000000000000000000"),
        "Expected O3 pointer-memory division to preserve unsigned and signed values. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_PTR_SIGNED_DIV:-2:4115226"),
        "Expected O3 pointer-memory signed division to truncate toward zero. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_c_scalar_typedef_char_enum_and_float_edges() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("scalar_types_program")?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_extra_anchor {
    print "CHARS:{}:{}:{}", *charp, *scharp, *ucharp;
    print "ALIASES:{}:{}", *alias_i8p, *qualified_u16p;
    print "ENUMS:{}:{}", *enum_negp, *enum_bigp;
    print "FLOAT_EDGE:{}:{}:{}", *neg_zerop, *infp, *nanp;
    if *alias_i8p < 0 { print "ALIAS_NEG"; }
    if *qualified_u16p > 64000 { print "QUAL_U16_BIG"; }
    if *enum_negp < 0 { print "ENUM_NEG"; }
    if *enum_bigp > 3000000000 { print "ENUM_BIG"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("CHARS:65:-7:240"),
        "Expected char/signed char/unsigned char numeric formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("ALIASES:-9:65000"),
        "Expected typedef and qualified scalar formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("ENUMS:scalar_signed_enum(scalar_signed_enum::SCALAR_ENUM_NEG(-3)):scalar_big_enum(scalar_big_enum::SCALAR_ENUM_BIG(4000000000))"),
        "Expected enum variant formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("FLOAT_EDGE:-0:inf:NaN"),
        "Expected float edge formatting for -0.0, infinity, and NaN. STDOUT: {stdout}"
    );
    for marker in ["ALIAS_NEG", "QUAL_U16_BIG", "ENUM_NEG", "ENUM_BIG"] {
        assert!(
            stdout.contains(marker),
            "Expected marker {marker}. STDOUT: {stdout}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_c_scalar_o3_typedef_char_enum_and_float_edges() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("scalar_types_program", OptimizationLevel::O3)?;
    let target = spawn_scalar_types_binary(&binary_path).await?;

    let script = r#"
trace scalar_extra_anchor {
    print "O3_CHARS:{}:{}:{}", *charp, *scharp, *ucharp;
    print "O3_ALIASES:{}:{}", *alias_i8p, *qualified_u16p;
    print "O3_ENUMS:{}:{}", *enum_negp, *enum_bigp;
    print "O3_EDGE_DIV:{}:{}:{}:{}", *scharp / 0x2, *ucharp / 0x10, *qualified_u16p / 0xa, *enum_negp / 0x2;
    print "O3_FLOAT_EDGE:{}:{}:{}", *neg_zerop, *infp, *nanp;
    if *charp == 0x41 { print "O3_CHAR_HEX_A"; }
    if *scharp == -0x7 { print "O3_SCHAR_NEG_HEX"; }
    if *ucharp == 0xf0 { print "O3_UCHAR_HEX_F0"; }
    if *alias_i8p < 0 { print "O3_ALIAS_NEG"; }
    if *qualified_u16p == 0b1111110111101000 { print "O3_QUAL_U16_BIN_EQ"; }
    if *enum_negp == -0x3 { print "O3_ENUM_NEG_HEX_EQ"; }
    if *enum_bigp == 0xee6b2800 { print "O3_ENUM_BIG_HEX_EQ"; }
    if *scharp / 0x2 == -0x3 { print "O3_SCHAR_DIV_OK"; }
    if *enum_negp / 0x2 == -0x1 { print "O3_ENUM_NEG_DIV_OK"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("O3_CHARS:65:-7:240"),
        "Expected O3 char/signed char/unsigned char numeric formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_ALIASES:-9:65000"),
        "Expected O3 typedef and qualified scalar formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_ENUMS:scalar_signed_enum(scalar_signed_enum::SCALAR_ENUM_NEG(-3)):scalar_big_enum(scalar_big_enum::SCALAR_ENUM_BIG(4000000000))"),
        "Expected O3 enum variant formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_EDGE_DIV:-3:15:6500:-1"),
        "Expected O3 narrow char, qualified integer, and signed enum division. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_FLOAT_EDGE:-0:inf:NaN"),
        "Expected O3 float edge formatting for -0.0, infinity, and NaN. STDOUT: {stdout}"
    );
    for marker in [
        "O3_CHAR_HEX_A",
        "O3_SCHAR_NEG_HEX",
        "O3_UCHAR_HEX_F0",
        "O3_ALIAS_NEG",
        "O3_QUAL_U16_BIN_EQ",
        "O3_ENUM_NEG_HEX_EQ",
        "O3_ENUM_BIG_HEX_EQ",
        "O3_SCHAR_DIV_OK",
        "O3_ENUM_NEG_DIV_OK",
    ] {
        assert!(
            stdout.contains(marker),
            "Expected O3 marker {marker}. STDOUT: {stdout}"
        );
    }
    Ok(())
}

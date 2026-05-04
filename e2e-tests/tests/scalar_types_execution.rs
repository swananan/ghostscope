//! C scalar type execution tests
//! - Covers signed/unsigned integer widths, booleans, and floating-point formatting

mod common;

use common::{init, FIXTURES};
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
        .enable_sysmon_shared_lib(false)
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
    ] {
        assert!(
            stdout.contains(marker),
            "Expected comparison marker {marker}. STDOUT: {stdout}"
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

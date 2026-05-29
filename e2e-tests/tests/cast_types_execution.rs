//! Cast-focused script execution tests.

mod common;

use common::{init, OptimizationLevel, FIXTURES};
use std::path::Path;
use std::time::Duration;

async fn spawn_cast_types_binary(
    binary_path: &Path,
) -> anyhow::Result<common::targets::TargetHandle> {
    let target = common::targets::TargetLauncher::binary(binary_path)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(target)
}

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

#[tokio::test]
async fn test_cast_type_matrix_and_module_local_duplicate_names() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("cast_types_program", OptimizationLevel::Debug)?;
    let target = spawn_cast_types_binary(&binary_path).await?;

    let script = r#"
	trace cast_types_program.c:64 {
	    let idx = seq - (seq / 4) * 4;
	    let typed = cast(&node, "struct CastNode *");
	    let wordp = cast(&node.words, "uint32_t *");
	    let nested = cast(cast(cast(&node, "void *"), "const volatile CastNode *"), "CastNode *");
	    let nested_scalar = cast(cast(cast(&node, "CastNode *").negative, "u8"), "i32");
	    if typed.payload.signed_value == 700 + seq { print "CAST_ALIAS_OK"; }
	    if *wordp == seq * 10 { print "CAST_ALIAS_DEREF_OK"; }
	    if cast(&node, "CastNode *").words[idx] == seq * 10 + idx { print "CAST_TYPEDEF_PTR_OK"; }
	    if cast(&node.words, "uint32_t *")[idx] == seq * 10 + idx { print "CAST_U32_PTR_INDEX_OK"; }
	    if cast(&node.words, "uint32_t[4]")[idx] == seq * 10 + idx { print "CAST_U32_ARRAY_INDEX_OK"; }
	    if *(cast(&node.words, "uint32_t *") + idx) == seq * 10 + idx { print "CAST_PTR_ARITH_DEREF_OK"; }
	    print "CAST_PTR_ARITH_PRINT_OK {}", cast(&node.words, "uint32_t *") + 1;
	    if cast(cast(&node, "CastNode *").negative, "u8") == 255 { print "CAST_U8_WRAP_OK"; }
	    if cast(cast(&node, "CastNode *").negative, "i8") == -1 { print "CAST_I8_SIGN_OK"; }
	    if cast(cast(&node, "CastNode *").wide, "bool") == true { print "CAST_BOOL_OK"; }
	    if nested.words[idx] == seq * 10 + idx { print "CAST_NESTED_PTR_OK"; }
	    if nested_scalar == 255 { print "CAST_NESTED_SCALAR_OK"; }
	    if cast(true, "i32") == 1 { print "CAST_TRUE_I32_OK"; }
	    if cast(cast(&node, "CastNode *").wide == cast(&node, "CastNode *").wide, "i32") == 1 { print "CAST_COMPARE_I32_OK"; }
	    if cast(cast(&node, "CastNode *").kind, "enum CastKind") == 1 { print "CAST_ENUM_OK"; }
	    if cast(&cast(&node, "CastNode *").payload, "union CastPayload").signed_value == 700 + seq { print "CAST_UNION_OK"; }
	    if cast(&node, "const volatile CastNode *").qualified_next.payload.signed_value == 700 + seq { print "CAST_QUALIFIED_OK"; }
	    if cast(&dup, "struct Duplicate *").main_marker == 1000 + seq { print "CAST_MAIN_DUP_OK"; }
	}

trace cast_lib_duplicate_probe {
    if cast(dup, "struct Duplicate *").lib_marker == 2000 + seq { print "CAST_LIB_DUP_OK"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 5, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    for marker in [
        "CAST_ALIAS_OK",
        "CAST_ALIAS_DEREF_OK",
        "CAST_TYPEDEF_PTR_OK",
        "CAST_U32_PTR_INDEX_OK",
        "CAST_U32_ARRAY_INDEX_OK",
        "CAST_PTR_ARITH_DEREF_OK",
        "CAST_PTR_ARITH_PRINT_OK",
        "CAST_U8_WRAP_OK",
        "CAST_I8_SIGN_OK",
        "CAST_BOOL_OK",
        "CAST_NESTED_PTR_OK",
        "CAST_NESTED_SCALAR_OK",
        "CAST_TRUE_I32_OK",
        "CAST_COMPARE_I32_OK",
        "CAST_ENUM_OK",
        "CAST_UNION_OK",
        "CAST_QUALIFIED_OK",
        "CAST_MAIN_DUP_OK",
        "CAST_LIB_DUP_OK",
    ] {
        assert!(
            stdout.contains(marker),
            "Expected marker {marker}. STDOUT: {stdout}\nSTDERR: {stderr}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_cast_fallback_duplicate_type_reports_ambiguity() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("cast_types_program", OptimizationLevel::Debug)?;
    let target = spawn_cast_types_binary(&binary_path).await?;

    let script = r#"
	trace cast_types_program.c:64 {
	    print cast(&node, "struct FallbackDuplicate *").lib_a_marker;
	}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;
    target.terminate().await?;
    assert_ne!(
        exit_code, 0,
        "expected ambiguous type failure. STDOUT: {stdout}"
    );
    assert!(
        (stdout.contains("FallbackDuplicate") || stderr.contains("FallbackDuplicate"))
            && (stdout.contains("ambiguous") || stderr.contains("ambiguous")),
        "Expected ambiguous cast target diagnostic. STDOUT: {stdout}\nSTDERR: {stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn test_cast_unknown_type_reports_compile_error() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("cast_types_program", OptimizationLevel::Debug)?;
    let target = spawn_cast_types_binary(&binary_path).await?;

    let script = r#"
	trace cast_types_program.c:64 {
	    print cast(&node, "struct MissingCastType *").field;
	}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;
    target.terminate().await?;
    assert_ne!(exit_code, 0, "expected compile failure. STDOUT: {stdout}");
    assert!(
        stdout.contains("MissingCastType")
            || stderr.contains("MissingCastType")
            || stdout.contains("was not found")
            || stderr.contains("was not found"),
        "Expected missing cast target diagnostic. STDOUT: {stdout}\nSTDERR: {stderr}"
    );

    Ok(())
}

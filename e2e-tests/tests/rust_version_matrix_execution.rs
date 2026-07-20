//! Runtime smoke coverage for Rust values across pinned target compilers.

mod common;

use std::path::{Path, PathBuf};

use common::{
    init,
    rust_toolchain::{
        compile_compact_standalone_fixture, configured_toolchains, fixture_tempdir,
        precompiled_compat_fixture, rustc_for_toolchain, rustc_version, toolchain_id,
    },
};
use ghostscope_dwarf::{DwarfAnalyzer, RustcVersion, SourceLanguage};
use regex::Regex;

const REQUIRE_TOOLCHAINS_ENV: &str = "GHOSTSCOPE_REQUIRE_RUST_E2E_TOOLCHAINS";
const PRESERVE_FIXTURES_ENV: &str = "GHOSTSCOPE_PRESERVE_PRECOMPILED_FIXTURES";

const COMMON_SCRIPT: &str = r#"
trace observe_matrix_values {
    print "RUST_MATRIX_VALUES:{}:{}:{}:{}", string, vector, btree_map,
        hash_map;
}

trace observe_matrix_dst {
    print "RUST_MATRIX_DST:{}:{}", rc, arc;
}

trace observe_matrix_mut_str {
    print "RUST_MATRIX_MUT_STR:{}", value;
}

trace observe_matrix_enums {
    print "RUST_MATRIX_ENUMS:{}:{}:{}:{}:{}:{}", *unit, *tuple,
        *struct_value, *fieldless, *some, *none;
}

trace observe_matrix_enum_edges {
    print "RUST_MATRIX_ENUM_EDGES:{}:{}:{}", *single, *signed, *unsigned;
}

trace observe_matrix_nested {
    print "RUST_MATRIX_NESTED:{}", *value;
}

trace observe_matrix_pointer_niche {
    print "RUST_MATRIX_POINTER_NICHE:{}:{}", *some, *none;
}

trace observe_matrix_repr_c {
    print "RUST_MATRIX_REPR_C:{}:{}:{}", *unit, *tuple, *struct_value;
}
"#;

const WRAPPER_SCRIPT: &str = r#"
trace observe_matrix_rc {
    print "RUST_MATRIX_RC:{}", rc;
}
"#;

fn compile_fixture(rustc: &Path, toolchain: &str, output_dir: &Path) -> anyhow::Result<PathBuf> {
    std::fs::create_dir_all(output_dir)?;
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rust_compat_program/main.rs");
    let binary = output_dir.join("rust_compat_program");
    compile_compact_standalone_fixture(rustc, toolchain, &source, &binary)?;
    Ok(binary)
}

fn fixture_binary(rustc: &Path, toolchain: &str, temp_dir: &Path) -> anyhow::Result<PathBuf> {
    let precompiled = precompiled_compat_fixture(toolchain);
    if std::env::var_os(PRESERVE_FIXTURES_ENV).is_some() && precompiled.is_file() {
        return Ok(precompiled);
    }

    compile_fixture(rustc, toolchain, &temp_dir.join(toolchain_id(toolchain)))
}

async fn assert_target_rustc_version(
    binary: &Path,
    toolchain: &str,
    expected: RustcVersion,
) -> anyhow::Result<()> {
    let analyzer = DwarfAnalyzer::from_exec_path(binary).await?;
    let context = analyzer
        .lookup_function_addresses("observe_matrix_values")
        .into_iter()
        .find_map(|address| analyzer.resolve_pc(&address).ok())
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing function observe_matrix_values"))?;
    let metadata = analyzer
        .compilation_unit_metadata_for_context(&context)?
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing compilation-unit metadata"))?;
    anyhow::ensure!(
        metadata.language == SourceLanguage::Rust,
        "{toolchain}: expected Rust, got {:?}",
        metadata.language
    );
    anyhow::ensure!(
        metadata.rustc_version() == Some(expected),
        "{toolchain}: target producer {:?} did not report rustc {expected}",
        metadata.producer
    );
    Ok(())
}

fn assert_common_output(toolchain: &str, stdout: &str) -> anyhow::Result<()> {
    let values = marker_line(stdout, "RUST_MATRIX_VALUES", toolchain)?;
    for expected in [
        r#""matrix = string""#,
        "[10, -20]",
        "BTreeMap(size=1) {-7: 13}",
        "HashMap(size=1) {29: 17}",
    ] {
        anyhow::ensure!(
            values.contains(expected),
            "{toolchain}: missing {expected:?} in {values}"
        );
    }

    let dst = marker_line(stdout, "RUST_MATRIX_DST", toolchain)?;
    let expected = Regex::new(concat!(
        r"Rc\(strong=1, weak=0\) \{ ptr: 0x[0-9a-f]+ \([^)]*\), ",
        r"strong: 1, weak: 0 \}:",
        r"Arc\(strong=1, weak=0\) \{ ptr: 0x[0-9a-f]+ \([^)]*\), ",
        r"strong: 1, weak: 0 \}",
    ))?;
    anyhow::ensure!(
        expected.is_match(dst),
        "{toolchain}: unexpected Rc<str>/Arc<str> output: {dst}"
    );

    let mutable_text = marker_line(stdout, "RUST_MATRIX_MUT_STR", toolchain)?;
    anyhow::ensure!(
        mutable_text.contains(r#""matrix mutable""#),
        "{toolchain}: unexpected &mut str output: {mutable_text}"
    );
    Ok(())
}

fn assert_wrapper_output(toolchain: &str, stdout: &str) -> anyhow::Result<()> {
    let rc = marker_line(stdout, "RUST_MATRIX_RC", toolchain)?;
    anyhow::ensure!(
        rc.contains("Rc(strong=1, weak=0) { value: 11, strong: 1, weak: 0 }"),
        "{toolchain}: unexpected Rc output: {rc}"
    );
    Ok(())
}

fn assert_enum_output(toolchain: &str, stdout: &str) -> anyhow::Result<()> {
    let enums = marker_line(stdout, "RUST_MATRIX_ENUMS", toolchain)?;
    for expected in [
        "MatrixEnum::Unit",
        "MatrixEnum::Tuple(31, 37)",
        "MatrixEnum::Struct { value: 47, flag: 53 }",
        "MatrixFieldless::Second",
        "Option<core::num::",
        ">::Some(",
        ">::None",
        "59",
    ] {
        anyhow::ensure!(
            enums.contains(expected),
            "{toolchain}: missing {expected:?} in {enums}"
        );
    }

    let edges = marker_line(stdout, "RUST_MATRIX_ENUM_EDGES", toolchain)?;
    for expected in [
        "MatrixSingle::Only(71)",
        "MatrixSigned::Negative",
        "MatrixUnsigned::High",
    ] {
        anyhow::ensure!(
            edges.contains(expected),
            "{toolchain}: missing {expected:?} in {edges}"
        );
    }

    let nested = marker_line(stdout, "RUST_MATRIX_NESTED", toolchain)?;
    anyhow::ensure!(
        nested.contains("MatrixOuter::Wrapped(MatrixInner::Pair(7, 9))"),
        "{toolchain}: unexpected nested enum output: {nested}"
    );

    let pointer_niche = marker_line(stdout, "RUST_MATRIX_POINTER_NICHE", toolchain)?;
    let pointer_niche_pattern =
        Regex::new(concat!(r"::Some\(0x[0-9a-f]+ \(i32\*\)\)", r".*::None",))?;
    anyhow::ensure!(
        pointer_niche_pattern.is_match(pointer_niche),
        "{toolchain}: unexpected pointer niche output: {pointer_niche}"
    );

    let repr_c = marker_line(stdout, "RUST_MATRIX_REPR_C", toolchain)?;
    for expected in [
        "MatrixReprC::Unit",
        "MatrixReprC::Tuple(73, 79)",
        "MatrixReprC::Struct { left: 83, right: 89 }",
    ] {
        anyhow::ensure!(
            repr_c.contains(expected),
            "{toolchain}: missing {expected:?} in {repr_c}"
        );
    }
    Ok(())
}

fn marker_line<'a>(stdout: &'a str, marker: &str, toolchain: &str) -> anyhow::Result<&'a str> {
    stdout
        .lines()
        .find(|line| line.contains(marker))
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing {marker}: {stdout}"))
}

async fn run_toolchain(toolchain: String, require_all: bool) -> anyhow::Result<bool> {
    eprintln!("testing Rust e2e toolchain {toolchain}");
    let Some(rustc) = rustc_for_toolchain(&toolchain) else {
        anyhow::ensure!(
            !require_all,
            "required Rust toolchain {toolchain} is not installed"
        );
        eprintln!("skipping unavailable Rust e2e toolchain {toolchain}");
        return Ok(false);
    };

    let temp_dir = fixture_tempdir()?;
    let expected_version = rustc_version(&rustc, &toolchain)?;
    let binary = fixture_binary(&rustc, &toolchain, temp_dir.path())?;
    assert_target_rustc_version(&binary, &toolchain, expected_version).await?;

    // Keep runtime coverage to representative high-risk layout families.
    // The DWARF compatibility test checks every adapter audited for each
    // pinned compiler, while the complete Rust 1.88 e2e suite checks all
    // output.
    // Wrapper adapters have a 1.49 floor until their older concrete DWARF
    // shapes receive the same rust-gdb-based audit.
    let mut script = COMMON_SCRIPT.to_string();
    let include_wrappers = expected_version >= RustcVersion::new(1, 49, 0);
    if include_wrappers {
        script.push_str(WRAPPER_SCRIPT);
    }

    let target = common::targets::TargetLauncher::binary(&binary)
        .current_dir(temp_dir.path())
        .spawn()
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(750)).await;
    let result = common::runner::GhostscopeRunner::new()
        .with_script(&script)
        .with_config_content(
            r#"
[ebpf]
mem_dump_cap = 512
"#,
        )
        .attach_to(&target)
        .timeout_secs(5)
        .enable_sysmon_for_target(false)
        .run()
        .await;
    target.terminate().await?;

    let (exit_code, stdout, stderr) = result?;
    anyhow::ensure!(
        exit_code == 0,
        "{toolchain}: exit={exit_code} stderr={stderr} stdout={stdout}"
    );
    assert_common_output(&toolchain, &stdout)?;
    assert_enum_output(&toolchain, &stdout)?;
    if include_wrappers {
        assert_wrapper_output(&toolchain, &stdout)?;
    }
    anyhow::ensure!(
        !stdout.contains("ExprError"),
        "{toolchain}: unexpected ExprError: {stdout}"
    );
    anyhow::ensure!(
        !stdout.contains("<INVALID_"),
        "{toolchain}: invalid payload: {stdout}"
    );
    anyhow::ensure!(
        !stdout.contains("<truncated>"),
        "{toolchain}: truncated payload: {stdout}"
    );
    eprintln!("completed Rust e2e toolchain {toolchain}");
    Ok(true)
}

#[tokio::test]
async fn test_rust_target_compiler_runtime_matrix() -> anyhow::Result<()> {
    init();

    let require_all = std::env::var_os(REQUIRE_TOOLCHAINS_ENV).is_some();
    let mut tested = 0usize;
    let mut failures = Vec::new();

    // Each case starts a complete GhostScope process, including DWARF analysis
    // and eBPF compilation. Running all pinned compilers concurrently multiplies
    // peak memory inside same-sandbox containers without increasing coverage.
    for toolchain in configured_toolchains() {
        match run_toolchain(toolchain, require_all).await {
            Ok(true) => tested += 1,
            Ok(false) => {}
            Err(error) => failures.push(format!("{error:#}")),
        }
    }

    anyhow::ensure!(
        failures.is_empty(),
        "Rust target-compiler matrix failures:\n{}",
        failures.join("\n")
    );

    if tested == 0 {
        eprintln!("no Rust e2e toolchains were available; skipping test");
    }
    Ok(())
}

use ghostscope_dwarf::{
    BTreeEntryPresentation, DwarfAnalyzer, HashTableEntryPresentation, RustcVersion,
    SourceLanguage, ValueCapturePlan, ValuePresentation, ValueReadPlan,
};
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_TOOLCHAINS: &[&str] = &["1.49.0", "1.88.0", "1.93.0", "nightly-2026-05-30"];

#[derive(Clone, Copy)]
enum ExpectedAdapter {
    Utf8Bytes,
    OsBytes,
    Sequence,
    RingSequence,
    BTreeMap,
    BTreeSet,
    HashMap,
    HashSet,
    ReferenceCounted,
    Cell,
    RefCell,
    RefGuard,
    NonZero,
    NativeDwarf,
}

fn configured_toolchains() -> Vec<String> {
    std::env::var("GHOSTSCOPE_RUST_COMPAT_TOOLCHAINS")
        .ok()
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .collect()
        })
        .filter(|toolchains: &Vec<_>| !toolchains.is_empty())
        .unwrap_or_else(|| {
            DEFAULT_TOOLCHAINS
                .iter()
                .map(|toolchain| (*toolchain).to_string())
                .collect()
        })
}

fn require_all_toolchains() -> bool {
    std::env::var_os("GHOSTSCOPE_REQUIRE_RUST_COMPAT_TOOLCHAINS").is_some()
}

fn toolchain_is_installed(toolchain: &str) -> bool {
    Command::new("rustup")
        .args(["run", toolchain, "rustc", "--version"])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn toolchain_rustc_version(toolchain: &str) -> anyhow::Result<RustcVersion> {
    let output = Command::new("rustup")
        .args(["run", toolchain, "rustc", "--version"])
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "rustc {toolchain} --version failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    let version = stdout
        .split_ascii_whitespace()
        .nth(1)
        .and_then(RustcVersion::parse)
        .ok_or_else(|| anyhow::anyhow!("unrecognized rustc version output: {stdout:?}"))?;
    Ok(version)
}

fn compile_fixture(toolchain: &str, output: &Path) -> anyhow::Result<()> {
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rust_value_compat.rs");
    let result = Command::new("rustup")
        .arg("run")
        .arg(toolchain)
        .arg("rustc")
        .arg("--edition=2018")
        .arg("-g")
        .arg("-C")
        .arg("opt-level=0")
        .arg("-C")
        .arg("link-dead-code=yes")
        .arg(&source)
        .arg("-o")
        .arg(output)
        .output()?;
    anyhow::ensure!(
        result.status.success(),
        "rustc {toolchain} failed for {}:\n{}",
        source.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

fn adapter_matches(plan: Option<&ValueReadPlan>, expected: ExpectedAdapter) -> bool {
    let Some(plan) = plan else {
        return matches!(expected, ExpectedAdapter::NativeDwarf);
    };
    match (&plan.presentation, &plan.capture, expected) {
        (
            ValuePresentation::Utf8String,
            ValueCapturePlan::IndirectBytes { .. },
            ExpectedAdapter::Utf8Bytes,
        )
        | (
            ValuePresentation::ByteString,
            ValueCapturePlan::IndirectBytes { .. },
            ExpectedAdapter::OsBytes,
        )
        | (
            ValuePresentation::Sequence { .. },
            ValueCapturePlan::IndirectSequence { .. },
            ExpectedAdapter::Sequence,
        )
        | (
            ValuePresentation::Sequence { .. },
            ValueCapturePlan::IndirectRingSequence { .. },
            ExpectedAdapter::RingSequence,
        )
        | (
            ValuePresentation::ReferenceCountedStruct { .. },
            ValueCapturePlan::ProjectedView { .. },
            ExpectedAdapter::ReferenceCounted,
        )
        | (
            ValuePresentation::SingleField { .. },
            ValueCapturePlan::ProjectedValue { .. },
            ExpectedAdapter::Cell,
        )
        | (
            ValuePresentation::SignedStateStruct { .. },
            ValueCapturePlan::InlineView { .. },
            ExpectedAdapter::RefCell,
        )
        | (
            ValuePresentation::SignedStateStruct { .. },
            ValueCapturePlan::ProjectedView { .. },
            ExpectedAdapter::RefGuard,
        )
        | (
            ValuePresentation::Dwarf,
            ValueCapturePlan::ProjectedValue { .. },
            ExpectedAdapter::NonZero,
        ) => true,
        (
            ValuePresentation::BTree { entry, .. },
            ValueCapturePlan::IndirectBTree { .. },
            ExpectedAdapter::BTreeMap,
        ) => matches!(entry, BTreeEntryPresentation::Map { .. }),
        (
            ValuePresentation::BTree { entry, .. },
            ValueCapturePlan::IndirectBTree { .. },
            ExpectedAdapter::BTreeSet,
        ) => matches!(entry, BTreeEntryPresentation::Set { .. }),
        (
            ValuePresentation::HashTable { entry, .. },
            ValueCapturePlan::IndirectHashTable { .. },
            ExpectedAdapter::HashMap,
        ) => matches!(entry, HashTableEntryPresentation::Map { .. }),
        (
            ValuePresentation::HashTable { entry, .. },
            ValueCapturePlan::IndirectHashTable { .. },
            ExpectedAdapter::HashSet,
        ) => matches!(entry, HashTableEntryPresentation::Set { .. }),
        _ => false,
    }
}

async fn assert_parameter_adapter(
    analyzer: &DwarfAnalyzer,
    binary: &Path,
    function: &str,
    parameter: &str,
    expected: ExpectedAdapter,
    toolchain: &str,
) -> anyhow::Result<()> {
    let context = analyzer
        .lookup_function_addresses(function)
        .into_iter()
        .find_map(|address| analyzer.resolve_pc(&address).ok())
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing function {function}"))?;
    let parameter_plan = analyzer
        .plan_variable_by_name(&context, parameter)?
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing {function}::{parameter}"))?;
    let parameter_type = analyzer
        .resolved_type_for_plan(&parameter_plan)?
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing type for {function}::{parameter}"))?;
    let plan = analyzer.value_read_plan(&parameter_type, Some(binary))?;
    anyhow::ensure!(
        adapter_matches(plan.as_ref(), expected),
        "{toolchain}: unexpected adapter for {function}::{parameter}: {plan:#?}"
    );
    Ok(())
}

fn assert_target_rustc_version(analyzer: &DwarfAnalyzer, toolchain: &str) -> anyhow::Result<()> {
    let context = analyzer
        .lookup_function_addresses("observe_values")
        .into_iter()
        .find_map(|address| analyzer.resolve_pc(&address).ok())
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing function observe_values"))?;
    let metadata = analyzer
        .compilation_unit_metadata_for_context(&context)?
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing compilation-unit metadata"))?;
    anyhow::ensure!(
        metadata.language == SourceLanguage::Rust,
        "{toolchain}: expected a Rust compilation unit, got {:?}",
        metadata.language
    );

    let expected = toolchain_rustc_version(toolchain)?;
    anyhow::ensure!(
        metadata.rustc_version() == Some(expected),
        "{toolchain}: target producer {:?} did not report rustc {expected}",
        metadata.producer
    );
    Ok(())
}

#[tokio::test]
async fn rust_value_adapters_follow_pinned_toolchain_dwarf() -> anyhow::Result<()> {
    let temp_dir = tempfile::tempdir()?;
    let toolchains = configured_toolchains();
    let require_all = require_all_toolchains();
    let mut tested = 0usize;

    for toolchain in toolchains {
        if !toolchain_is_installed(&toolchain) {
            anyhow::ensure!(
                !require_all,
                "required Rust toolchain {toolchain} is not installed"
            );
            eprintln!("skipping unavailable Rust compatibility toolchain {toolchain}");
            continue;
        }

        let binary = temp_dir.path().join(format!(
            "rust-value-compat-{}",
            toolchain.replace(['.', '-'], "_")
        ));
        compile_fixture(&toolchain, &binary)?;
        let analyzer = DwarfAnalyzer::from_exec_path(&binary).await?;
        assert_target_rustc_version(&analyzer, &toolchain)?;

        for (parameter, expected) in [
            ("string", ExpectedAdapter::Utf8Bytes),
            ("os_string", ExpectedAdapter::OsBytes),
            ("text", ExpectedAdapter::Utf8Bytes),
            ("boxed_text", ExpectedAdapter::Utf8Bytes),
            ("slice", ExpectedAdapter::Sequence),
            ("vector", ExpectedAdapter::Sequence),
            ("deque", ExpectedAdapter::RingSequence),
            ("btree_map", ExpectedAdapter::BTreeMap),
            ("btree_set", ExpectedAdapter::BTreeSet),
            ("hash_map", ExpectedAdapter::HashMap),
            ("hash_set", ExpectedAdapter::HashSet),
            ("rc", ExpectedAdapter::ReferenceCounted),
            ("arc", ExpectedAdapter::ReferenceCounted),
            ("cell", ExpectedAdapter::Cell),
            ("ref_cell", ExpectedAdapter::RefCell),
            ("nonzero", ExpectedAdapter::NonZero),
            ("enum_value", ExpectedAdapter::NativeDwarf),
        ] {
            assert_parameter_adapter(
                &analyzer,
                &binary,
                "observe_values",
                parameter,
                expected,
                &toolchain,
            )
            .await?;
        }
        assert_parameter_adapter(
            &analyzer,
            &binary,
            "observe_ref",
            "value",
            ExpectedAdapter::RefGuard,
            &toolchain,
        )
        .await?;
        assert_parameter_adapter(
            &analyzer,
            &binary,
            "observe_ref_mut",
            "value",
            ExpectedAdapter::RefGuard,
            &toolchain,
        )
        .await?;
        tested += 1;
    }

    if tested == 0 {
        eprintln!("no Rust compatibility toolchains were available; skipping test");
    }
    Ok(())
}

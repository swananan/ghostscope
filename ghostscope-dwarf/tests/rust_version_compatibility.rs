use ghostscope_dwarf::{
    BTreeEntryPresentation, DwarfAnalyzer, HashTableEntryPresentation, ProjectedViewFieldCapture,
    RustcVersion, SourceLanguage, ValueCapturePlan, ValuePresentation, ValueReadPlan,
};
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_TOOLCHAINS: &str = include_str!("../../e2e-tests/rust-compat-toolchains.txt");

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

const ALL_ADAPTERS: &[(&str, ExpectedAdapter)] = &[
    ("string", ExpectedAdapter::Utf8Bytes),
    ("os_string", ExpectedAdapter::OsBytes),
    ("path_buf", ExpectedAdapter::OsBytes),
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
];

const RUST_135_ADAPTERS: &[(&str, ExpectedAdapter)] = &[
    ("string", ExpectedAdapter::Utf8Bytes),
    ("os_string", ExpectedAdapter::OsBytes),
    ("path_buf", ExpectedAdapter::OsBytes),
    ("text", ExpectedAdapter::Utf8Bytes),
    // Box<str> gained a dedicated rust-gdb provider later. Pinning it here
    // applies that provider's semantics to Rust 1.35's concrete fat-pointer
    // DIE rather than implying it was in the bundled 1.35 script.
    ("boxed_text", ExpectedAdapter::Utf8Bytes),
    ("slice", ExpectedAdapter::Sequence),
    ("vector", ExpectedAdapter::Sequence),
    ("deque", ExpectedAdapter::RingSequence),
    ("btree_map", ExpectedAdapter::BTreeMap),
    ("btree_set", ExpectedAdapter::BTreeSet),
    ("hash_map", ExpectedAdapter::HashMap),
    ("hash_set", ExpectedAdapter::HashSet),
];

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
                .lines()
                .map(|line| line.split('#').next().unwrap_or_default().trim())
                .filter(|line| !line.is_empty())
                .map(str::to_string)
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
        .arg("link-dead-code")
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

fn member_offset(projection: &ghostscope_dwarf::TypeProjection) -> anyhow::Result<u64> {
    let ghostscope_dwarf::TypeProjectionLayout::Member { offset } = projection.layout else {
        anyhow::bail!("expected member projection, got {:?}", projection.layout)
    };
    Ok(offset)
}

fn assert_reference_counted_dst_plan(
    toolchain: &str,
    type_name: &str,
    plan: &ValueReadPlan,
) -> anyhow::Result<()> {
    let ValuePresentation::ReferenceCountedStruct { implicit_weak, .. } = &plan.presentation else {
        anyhow::bail!("{toolchain}: unexpected {type_name}<str> presentation")
    };
    assert_eq!(*implicit_weak, 1);

    let ValueCapturePlan::ProjectedView {
        output_type,
        fields,
    } = &plan.capture
    else {
        anyhow::bail!("{toolchain}: unexpected {type_name}<str> capture")
    };
    let ghostscope_dwarf::TypeInfo::StructType { name, members, .. } = output_type else {
        anyhow::bail!("{toolchain}: {type_name}<str> output is not a struct")
    };
    assert_eq!(name, type_name);
    assert_eq!(
        members
            .iter()
            .map(|member| member.name.as_str())
            .collect::<Vec<_>>(),
        ["ptr", "strong", "weak"]
    );
    assert!(matches!(
        members[0].member_type,
        ghostscope_dwarf::TypeInfo::PointerType { size: 8, .. }
    ));
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0].capture, ProjectedViewFieldCapture::Address);
    assert!(fields[1..]
        .iter()
        .all(|field| field.capture == ProjectedViewFieldCapture::Value));
    Ok(())
}

fn assert_rust_135_btree_plan(parameter: &str, plan: &ValueReadPlan) -> anyhow::Result<()> {
    let ValuePresentation::BTree {
        node_capacity,
        entry,
    } = &plan.presentation
    else {
        anyhow::bail!("1.35.0: unexpected presentation for {parameter}")
    };
    assert_eq!(*node_capacity, 11);
    match (parameter, entry) {
        ("btree_map", BTreeEntryPresentation::Map { key, value }) => {
            assert_eq!((key.slot_stride, key.value_offset), (4, 0));
            assert_eq!((value.slot_stride, value.value_offset), (2, 0));
        }
        ("btree_set", BTreeEntryPresentation::Set { value }) => {
            assert_eq!((value.slot_stride, value.value_offset), (4, 0));
        }
        _ => anyhow::bail!("1.35.0: unexpected B-Tree entry for {parameter}"),
    }

    let ValueCapturePlan::IndirectBTree {
        root_pointer,
        root_height,
        length,
        node_length,
        keys,
        values,
        edges,
        node_capacity: capture_capacity,
    } = &plan.capture
    else {
        anyhow::bail!("1.35.0: unexpected capture for {parameter}")
    };
    assert_eq!(member_offset(root_pointer)?, 0);
    assert_eq!(member_offset(root_height)?, 8);
    assert_eq!(member_offset(length)?, 16);
    assert_eq!(member_offset(node_length)?, 10);
    assert_eq!((keys.offset, keys.slot_stride), (12, 4));
    match (parameter, values) {
        ("btree_map", Some(values)) => {
            assert_eq!((values.offset, values.slot_stride), (56, 2));
        }
        ("btree_set", None) => {}
        _ => anyhow::bail!("1.35.0: unexpected B-Tree values for {parameter}"),
    }
    let expected_edges_offset = match parameter {
        "btree_map" => 80,
        "btree_set" => 56,
        _ => unreachable!("validated B-Tree parameter"),
    };
    assert_eq!(
        (
            edges.offset_from_leaf,
            edges.slot_stride,
            edges.pointer_offset,
            edges.pointer_size,
            edges.edge_count,
        ),
        (expected_edges_offset, 8, 0, 8, 12)
    );
    assert_eq!(*capture_capacity, 11);
    Ok(())
}

fn assert_rust_135_sequence_plan(parameter: &str, plan: &ValueReadPlan) -> anyhow::Result<()> {
    let ValuePresentation::Sequence { element_stride, .. } = &plan.presentation else {
        anyhow::bail!("1.35.0: unexpected presentation for {parameter}")
    };
    assert_eq!(*element_stride, 4);

    match (parameter, &plan.capture) {
        (
            "slice",
            ValueCapturePlan::IndirectSequence {
                data,
                length,
                element_stride,
            },
        ) => {
            assert_eq!(member_offset(data)?, 0);
            assert_eq!(member_offset(length)?, 8);
            assert_eq!(*element_stride, 4);
        }
        (
            "vector",
            ValueCapturePlan::IndirectSequence {
                data,
                length,
                element_stride,
            },
        ) => {
            assert_eq!(member_offset(data)?, 0);
            assert_eq!(member_offset(length)?, 16);
            assert_eq!(*element_stride, 4);
        }
        (
            "deque",
            ValueCapturePlan::IndirectRingSequence {
                data,
                start,
                length,
                capacity,
                element_stride,
            },
        ) => {
            let ghostscope_dwarf::RingSequenceLength::End(end) = length.as_ref() else {
                anyhow::bail!("1.35.0: VecDeque must derive length from tail/head")
            };
            assert_eq!(member_offset(data)?, 16);
            assert_eq!(member_offset(start)?, 0);
            assert_eq!(member_offset(end)?, 8);
            assert_eq!(member_offset(capacity)?, 24);
            assert_eq!(*element_stride, 4);
        }
        _ => anyhow::bail!("1.35.0: unexpected sequence capture for {parameter}"),
    }
    Ok(())
}

async fn assert_parameter_adapter(
    analyzer: &DwarfAnalyzer,
    binary: &Path,
    function: &str,
    parameter: &str,
    expected: ExpectedAdapter,
    toolchain: &str,
) -> anyhow::Result<Option<ValueReadPlan>> {
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
        "{toolchain}: unexpected adapter for {function}::{parameter}: {plan:#?}\n\
         resolved type: {parameter_type:#?}"
    );
    Ok(plan)
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

        // Pin only the Rust 1.35 layouts audited against rust-gdb semantics.
        // The remaining adapters keep a Rust 1.49 floor until their older
        // DWARF shapes have been audited.
        let adapters = if toolchain == "1.35.0" {
            RUST_135_ADAPTERS
        } else {
            ALL_ADAPTERS
        };
        for &(parameter, expected) in adapters {
            let plan = assert_parameter_adapter(
                &analyzer,
                &binary,
                "observe_values",
                parameter,
                expected,
                &toolchain,
            )
            .await?;
            if toolchain == "1.35.0" && matches!(parameter, "slice" | "vector" | "deque") {
                assert_rust_135_sequence_plan(
                    parameter,
                    plan.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("1.35.0: missing sequence plan for {parameter}")
                    })?,
                )?;
            }
            if toolchain == "1.35.0" && matches!(parameter, "btree_map" | "btree_set") {
                assert_rust_135_btree_plan(
                    parameter,
                    plan.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("1.35.0: missing legacy plan for {parameter}")
                    })?,
                )?;
            }
            if toolchain == "1.35.0" && matches!(parameter, "hash_map" | "hash_set") {
                let plan = plan.as_ref().ok_or_else(|| {
                    anyhow::anyhow!("1.35.0: missing legacy plan for {parameter}")
                })?;
                let ValuePresentation::HashTable { occupancy, .. } = plan.presentation else {
                    anyhow::bail!("1.35.0: unexpected presentation for {parameter}")
                };
                let ValueCapturePlan::IndirectHashTable { buckets, .. } = &plan.capture else {
                    anyhow::bail!("1.35.0: unexpected capture for {parameter}")
                };
                assert_eq!(
                    occupancy,
                    ghostscope_dwarf::HashTableOccupancy::NonZeroWord { word_size: 8 }
                );
                assert!(matches!(
                    buckets,
                    ghostscope_dwarf::HashTableBucketSource::LegacyAfterControl {
                        entry_alignment: 4,
                        pointer_tag_mask: 1,
                    }
                ));
            }
        }
        if toolchain != "1.35.0" {
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
        }
        let path_expected = if matches!(toolchain.as_str(), "1.35.0" | "1.49.0") {
            ExpectedAdapter::NativeDwarf
        } else {
            ExpectedAdapter::OsBytes
        };
        assert_parameter_adapter(
            &analyzer,
            &binary,
            "observe_values",
            "path",
            path_expected,
            &toolchain,
        )
        .await?;
        for (parameter, type_name) in [("rc_text", "Rc"), ("arc_text", "Arc")] {
            let plan = assert_parameter_adapter(
                &analyzer,
                &binary,
                "observe_values",
                parameter,
                ExpectedAdapter::ReferenceCounted,
                &toolchain,
            )
            .await?;
            assert_reference_counted_dst_plan(
                &toolchain,
                type_name,
                plan.as_ref()
                    .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing {type_name}<str> plan"))?,
            )?;
        }
        tested += 1;
    }

    if tested == 0 {
        eprintln!("no Rust compatibility toolchains were available; skipping test");
    }
    Ok(())
}

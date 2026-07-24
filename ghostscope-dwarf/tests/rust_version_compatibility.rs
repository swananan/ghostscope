use ghostscope_dwarf::{
    BTreeEntryPresentation, DiscriminantValue, DwarfAnalyzer, HashTableEntryPresentation,
    ProjectedViewFieldCapture, RustcVersion, SourceLanguage, TypeInfo, ValueCapturePlan,
    ValuePresentation, ValueReadPlan, VariantCase, VariantPayloadPresentation, VariantSelector,
};
use std::path::{Path, PathBuf};
use std::process::Command;

const DEFAULT_TOOLCHAINS: &str = include_str!("../../e2e-tests/rust-compat-toolchains.txt");

#[derive(Clone, Copy)]
enum ExpectedAdapter {
    Utf8Bytes,
    CBytes,
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
    ("c_string", ExpectedAdapter::CBytes),
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
    ("c_string", ExpectedAdapter::CBytes),
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
            ValueCapturePlan::IndirectBytes {
                excluded_tail_bytes: 1,
                ..
            },
            ExpectedAdapter::CBytes,
        )
        | (
            ValuePresentation::ByteString,
            ValueCapturePlan::IndirectBytes {
                excluded_tail_bytes: 0,
                ..
            },
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

async fn resolved_parameter_type(
    analyzer: &DwarfAnalyzer,
    function: &str,
    parameter: &str,
    toolchain: &str,
) -> anyhow::Result<TypeInfo> {
    let context = analyzer
        .lookup_function_addresses(function)
        .into_iter()
        .find_map(|address| analyzer.resolve_pc(&address).ok())
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing function {function}"))?;
    let parameter_plan = analyzer
        .plan_variable_by_name(&context, parameter)?
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing {function}::{parameter}"))?;
    Ok(analyzer
        .resolved_type_for_plan(&parameter_plan)?
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing type for {function}::{parameter}"))?
        .summary)
}

fn variant_name(variant: &VariantCase) -> Option<&str> {
    match variant.members.as_slice() {
        [member] => Some(member.name.as_str()),
        _ => None,
    }
}

fn variant_payload_fields(variant: &VariantCase) -> Option<&[ghostscope_dwarf::StructMember]> {
    let [payload] = variant.members.as_slice() else {
        return None;
    };
    let TypeInfo::StructType { members, .. } = payload.member_type.underlying_type() else {
        return None;
    };
    Some(members)
}

fn variant_payload_field_names(variant: &VariantCase) -> Option<Vec<&str>> {
    Some(
        variant_payload_fields(variant)?
            .iter()
            .map(|member| member.name.as_str())
            .collect(),
    )
}

fn exact_unsigned_selector(variant: &VariantCase) -> Option<u64> {
    let VariantSelector::Ranges(ranges) = &variant.selector else {
        return None;
    };
    let [range] = ranges.as_slice() else {
        return None;
    };
    match (range.start, range.end) {
        (DiscriminantValue::Unsigned(start), DiscriminantValue::Unsigned(end)) if start == end => {
            Some(start)
        }
        _ => None,
    }
}

fn exact_nonnegative_selector(variant: &VariantCase) -> Option<u64> {
    let VariantSelector::Ranges(ranges) = &variant.selector else {
        return None;
    };
    let [range] = ranges.as_slice() else {
        return None;
    };
    match (range.start, range.end) {
        (DiscriminantValue::Unsigned(start), DiscriminantValue::Unsigned(end)) if start == end => {
            Some(start)
        }
        (DiscriminantValue::Signed(start), DiscriminantValue::Signed(end))
            if start == end && start >= 0 =>
        {
            u64::try_from(start).ok()
        }
        _ => None,
    }
}

fn assert_compat_enum_dwarf(toolchain: &str, type_info: &TypeInfo) -> anyhow::Result<()> {
    let TypeInfo::VariantType {
        name,
        size,
        members,
        variant_parts,
    } = type_info
    else {
        anyhow::bail!("{toolchain}: CompatEnum did not resolve as a DWARF variant type")
    };
    anyhow::ensure!(
        name == "CompatEnum",
        "{toolchain}: unexpected enum name {name}"
    );
    anyhow::ensure!(*size > 0, "{toolchain}: empty CompatEnum layout");
    anyhow::ensure!(members.is_empty(), "{toolchain}: unexpected common fields");
    let [part] = variant_parts.as_slice() else {
        anyhow::bail!("{toolchain}: expected one CompatEnum variant part")
    };
    let discriminant = part
        .discriminant
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing CompatEnum discriminant"))?;
    anyhow::ensure!(
        discriminant.offset == 0
            && discriminant.member_type.is_unsigned_int()
            && discriminant
                .offset
                .checked_add(discriminant.member_type.size())
                .is_some_and(|end| end <= *size),
        "{toolchain}: unexpected CompatEnum discriminant {discriminant:#?}"
    );
    for variant in &part.variants {
        for member in &variant.members {
            anyhow::ensure!(
                member
                    .offset
                    .checked_add(member.member_type.size())
                    .is_some_and(|end| end <= *size),
                "{toolchain}: CompatEnum payload member exceeds its DWARF size: {member:#?}"
            );
        }
    }
    anyhow::ensure!(
        part.variants
            .iter()
            .filter_map(variant_name)
            .collect::<Vec<_>>()
            == ["Unit", "Tuple", "Struct"],
        "{toolchain}: unexpected CompatEnum variants: {:#?}",
        part.variants
    );
    anyhow::ensure!(
        part.variants
            .iter()
            .map(|variant| variant.payload_presentation)
            .collect::<Vec<_>>()
            == [
                VariantPayloadPresentation::Unit,
                VariantPayloadPresentation::Tuple,
                VariantPayloadPresentation::Struct,
            ],
        "{toolchain}: unexpected CompatEnum payload presentations"
    );
    let payload_fields = part
        .variants
        .iter()
        .map(variant_payload_field_names)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        payload_fields
            == [
                Some(Vec::new()),
                Some(vec!["__0", "__1"]),
                Some(vec!["left", "right"]),
            ],
        "{toolchain}: unexpected CompatEnum payload fields: {payload_fields:#?}"
    );
    anyhow::ensure!(
        part.variants
            .iter()
            .map(exact_unsigned_selector)
            .collect::<Vec<_>>()
            == [Some(0), Some(1), Some(2)],
        "{toolchain}: unexpected CompatEnum selectors"
    );
    Ok(())
}

fn assert_niche_option_dwarf(toolchain: &str, type_info: &TypeInfo) -> anyhow::Result<()> {
    let TypeInfo::VariantType {
        name,
        size,
        variant_parts,
        ..
    } = type_info
    else {
        anyhow::bail!("{toolchain}: Option<NonZeroI32> did not resolve as a variant type")
    };
    anyhow::ensure!(
        name.contains("Option<") && *size == 4,
        "{toolchain}: unexpected niche Option type {name} size {size}"
    );
    let [part] = variant_parts.as_slice() else {
        anyhow::bail!("{toolchain}: expected one Option variant part")
    };
    let none = part
        .variants
        .iter()
        .find(|variant| variant_name(variant) == Some("None"))
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing Option::None"))?;
    let some = part
        .variants
        .iter()
        .find(|variant| variant_name(variant) == Some("Some"))
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing Option::Some"))?;
    anyhow::ensure!(
        exact_unsigned_selector(none) == Some(0),
        "{toolchain}: Option::None is not the zero niche"
    );
    anyhow::ensure!(
        matches!(some.selector, VariantSelector::Default),
        "{toolchain}: Option::Some is not the default niche branch"
    );
    anyhow::ensure!(
        none.payload_presentation == VariantPayloadPresentation::Unit
            && some.payload_presentation == VariantPayloadPresentation::Tuple,
        "{toolchain}: unexpected Option payload presentations"
    );
    Ok(())
}

fn assert_nested_enum_dwarf(toolchain: &str, type_info: &TypeInfo) -> anyhow::Result<()> {
    let TypeInfo::VariantType {
        name,
        size,
        members,
        variant_parts,
    } = type_info
    else {
        anyhow::bail!("{toolchain}: CompatOuter did not resolve as a variant type: {type_info:#?}")
    };
    anyhow::ensure!(
        name == "CompatOuter" && *size > 0 && members.is_empty(),
        "{toolchain}: unexpected CompatOuter type {type_info:#?}"
    );
    let [outer_part] = variant_parts.as_slice() else {
        anyhow::bail!("{toolchain}: expected one CompatOuter variant part")
    };
    anyhow::ensure!(
        outer_part
            .variants
            .iter()
            .filter_map(variant_name)
            .collect::<Vec<_>>()
            == ["Empty", "Wrapped"],
        "{toolchain}: unexpected CompatOuter variants: {outer_part:#?}"
    );
    anyhow::ensure!(
        outer_part
            .variants
            .iter()
            .map(|variant| variant.payload_presentation)
            .collect::<Vec<_>>()
            == [
                VariantPayloadPresentation::Unit,
                VariantPayloadPresentation::Tuple,
            ],
        "{toolchain}: unexpected CompatOuter payload presentations"
    );

    let wrapped = outer_part
        .variants
        .iter()
        .find(|variant| variant_name(variant) == Some("Wrapped"))
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing CompatOuter::Wrapped"))?;
    let [inner_field] = variant_payload_fields(wrapped).unwrap_or_default() else {
        anyhow::bail!("{toolchain}: unexpected CompatOuter::Wrapped payload {wrapped:#?}")
    };
    anyhow::ensure!(
        inner_field.name == "__0",
        "{toolchain}: unexpected CompatOuter::Wrapped field {inner_field:#?}"
    );

    let TypeInfo::VariantType {
        name,
        size,
        members,
        variant_parts,
    } = inner_field.member_type.underlying_type()
    else {
        anyhow::bail!("{toolchain}: CompatInner did not resolve as a nested variant type")
    };
    anyhow::ensure!(
        name == "CompatInner" && *size > 0 && members.is_empty(),
        "{toolchain}: unexpected CompatInner type {:#?}",
        inner_field.member_type
    );
    let [inner_part] = variant_parts.as_slice() else {
        anyhow::bail!("{toolchain}: expected one CompatInner variant part")
    };
    let [pair] = inner_part.variants.as_slice() else {
        anyhow::bail!("{toolchain}: expected one CompatInner variant")
    };
    anyhow::ensure!(
        inner_part.discriminant.is_none()
            && variant_name(pair) == Some("Pair")
            && matches!(pair.selector, VariantSelector::Default)
            && pair.payload_presentation == VariantPayloadPresentation::Tuple
            && variant_payload_field_names(pair) == Some(vec!["__0", "__1"]),
        "{toolchain}: unexpected CompatInner::Pair shape {pair:#?}"
    );
    Ok(())
}

fn assert_pointer_niche_dwarf(toolchain: &str, type_info: &TypeInfo) -> anyhow::Result<()> {
    let TypeInfo::VariantType {
        name,
        size,
        variant_parts,
        ..
    } = type_info
    else {
        anyhow::bail!("{toolchain}: Option<&i32> did not resolve as a variant type")
    };
    anyhow::ensure!(
        name.contains("Option<") && *size > 0,
        "{toolchain}: unexpected pointer niche type {name} size {size}"
    );
    let [part] = variant_parts.as_slice() else {
        anyhow::bail!("{toolchain}: expected one Option<&i32> variant part")
    };
    let none = part
        .variants
        .iter()
        .find(|variant| variant_name(variant) == Some("None"))
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing Option<&i32>::None"))?;
    let some = part
        .variants
        .iter()
        .find(|variant| variant_name(variant) == Some("Some"))
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing Option<&i32>::Some"))?;
    anyhow::ensure!(
        exact_nonnegative_selector(none) == Some(0)
            && matches!(some.selector, VariantSelector::Default),
        "{toolchain}: unexpected Option<&i32> niche selectors: {part:#?}"
    );
    anyhow::ensure!(
        none.payload_presentation == VariantPayloadPresentation::Unit
            && some.payload_presentation == VariantPayloadPresentation::Tuple
            && variant_payload_field_names(none) == Some(Vec::new())
            && variant_payload_field_names(some) == Some(vec!["__0"]),
        "{toolchain}: unexpected Option<&i32> payload shapes: {part:#?}"
    );
    let [pointer] = variant_payload_fields(some).unwrap_or_default() else {
        anyhow::bail!("{toolchain}: unexpected Option<&i32>::Some payload {some:#?}")
    };
    let TypeInfo::PointerType {
        target_type,
        size: pointer_size,
    } = pointer.member_type.underlying_type()
    else {
        anyhow::bail!("{toolchain}: Option<&i32>::Some payload is not a pointer")
    };
    anyhow::ensure!(
        target_type.type_name() == "i32" && *pointer_size > 0 && *pointer_size <= *size,
        "{toolchain}: unexpected Option<&i32>::Some pointer {pointer:#?}"
    );
    Ok(())
}

fn assert_repr_c_enum_dwarf(toolchain: &str, type_info: &TypeInfo) -> anyhow::Result<()> {
    let TypeInfo::VariantType {
        name,
        size,
        members,
        variant_parts,
    } = type_info
    else {
        anyhow::bail!("{toolchain}: CompatReprC did not resolve as a variant type")
    };
    anyhow::ensure!(
        name == "CompatReprC" && *size > 0 && members.is_empty(),
        "{toolchain}: unexpected CompatReprC type {type_info:#?}"
    );
    let [part] = variant_parts.as_slice() else {
        anyhow::bail!("{toolchain}: expected one CompatReprC variant part")
    };
    let discriminant = part
        .discriminant
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("{toolchain}: missing CompatReprC discriminant"))?;
    anyhow::ensure!(
        (discriminant.member_type.is_signed_int() || discriminant.member_type.is_unsigned_int())
            && discriminant
                .offset
                .checked_add(discriminant.member_type.size())
                .is_some_and(|end| end <= *size),
        "{toolchain}: unexpected CompatReprC discriminant {discriminant:#?}"
    );
    anyhow::ensure!(
        part.variants
            .iter()
            .filter_map(variant_name)
            .collect::<Vec<_>>()
            == ["Unit", "Tuple", "Struct"],
        "{toolchain}: unexpected CompatReprC variants: {part:#?}"
    );
    anyhow::ensure!(
        part.variants
            .iter()
            .map(|variant| variant.payload_presentation)
            .collect::<Vec<_>>()
            == [
                VariantPayloadPresentation::Unit,
                VariantPayloadPresentation::Tuple,
                VariantPayloadPresentation::Struct,
            ],
        "{toolchain}: unexpected CompatReprC payload presentations"
    );
    let payload_fields = part
        .variants
        .iter()
        .map(variant_payload_field_names)
        .collect::<Vec<_>>();
    anyhow::ensure!(
        payload_fields
            == [
                Some(Vec::new()),
                Some(vec!["__0", "__1"]),
                Some(vec!["left", "right"]),
            ],
        "{toolchain}: unexpected CompatReprC payload fields: {payload_fields:#?}"
    );
    anyhow::ensure!(
        part.variants
            .iter()
            .map(exact_nonnegative_selector)
            .collect::<Vec<_>>()
            == [Some(0), Some(1), Some(2)],
        "{toolchain}: unexpected CompatReprC selectors: {part:#?}"
    );
    for variant in &part.variants {
        for member in &variant.members {
            anyhow::ensure!(
                member
                    .offset
                    .checked_add(member.member_type.size())
                    .is_some_and(|end| end <= *size),
                "{toolchain}: CompatReprC member exceeds its DWARF size: {member:#?}"
            );
        }
    }
    Ok(())
}

fn assert_fieldless_enum_dwarf(toolchain: &str, type_info: &TypeInfo) -> anyhow::Result<()> {
    let TypeInfo::ScopedEnumType {
        name,
        size,
        base_type,
        variants,
    } = type_info
    else {
        anyhow::bail!("{toolchain}: CompatFieldless did not resolve as a scoped enum")
    };
    anyhow::ensure!(
        name == "CompatFieldless" && *size == 1 && base_type.is_unsigned_int(),
        "{toolchain}: unexpected fieldless enum type {type_info:#?}"
    );
    anyhow::ensure!(
        variants
            .iter()
            .map(|variant| (variant.name.as_str(), variant.value))
            .collect::<Vec<_>>()
            == [
                ("First", DiscriminantValue::Unsigned(0)),
                ("Second", DiscriminantValue::Unsigned(1)),
            ],
        "{toolchain}: unexpected fieldless enum variants {variants:#?}"
    );
    Ok(())
}

fn assert_single_variant_enum_dwarf(toolchain: &str, type_info: &TypeInfo) -> anyhow::Result<()> {
    let TypeInfo::VariantType {
        name,
        size,
        members,
        variant_parts,
    } = type_info
    else {
        anyhow::bail!("{toolchain}: CompatSingle did not resolve as a DWARF variant type")
    };
    anyhow::ensure!(
        name == "CompatSingle" && *size == 4 && members.is_empty(),
        "{toolchain}: unexpected single-variant enum type {type_info:#?}"
    );
    let [part] = variant_parts.as_slice() else {
        anyhow::bail!("{toolchain}: expected one CompatSingle variant part")
    };
    anyhow::ensure!(
        part.discriminant.is_none(),
        "{toolchain}: CompatSingle unexpectedly has a discriminant"
    );
    let [variant] = part.variants.as_slice() else {
        anyhow::bail!("{toolchain}: expected one CompatSingle variant")
    };
    anyhow::ensure!(
        variant_name(variant) == Some("Only")
            && matches!(variant.selector, VariantSelector::Default)
            && variant.payload_presentation == VariantPayloadPresentation::Tuple,
        "{toolchain}: unexpected CompatSingle variant {variant:#?}"
    );
    Ok(())
}

fn assert_signed_enum_dwarf(toolchain: &str, type_info: &TypeInfo) -> anyhow::Result<()> {
    let TypeInfo::ScopedEnumType {
        name,
        size,
        base_type,
        variants,
    } = type_info
    else {
        anyhow::bail!("{toolchain}: CompatSigned did not resolve as a scoped enum")
    };
    anyhow::ensure!(
        name == "CompatSigned" && *size == 1 && base_type.is_signed_int(),
        "{toolchain}: unexpected signed enum type {type_info:#?}"
    );
    anyhow::ensure!(
        variants
            .iter()
            .map(|variant| (variant.name.as_str(), variant.value))
            .collect::<Vec<_>>()
            == [
                ("Negative", DiscriminantValue::Signed(-1)),
                ("Positive", DiscriminantValue::Signed(1)),
            ],
        "{toolchain}: unexpected signed enum variants {variants:#?}"
    );
    Ok(())
}

fn assert_unsigned_enum_dwarf(toolchain: &str, type_info: &TypeInfo) -> anyhow::Result<()> {
    let TypeInfo::ScopedEnumType {
        name,
        size,
        base_type,
        variants,
    } = type_info
    else {
        anyhow::bail!("{toolchain}: CompatUnsigned did not resolve as a scoped enum")
    };
    anyhow::ensure!(
        name == "CompatUnsigned" && *size == 8 && base_type.is_unsigned_int(),
        "{toolchain}: unexpected unsigned enum type {type_info:#?}"
    );
    anyhow::ensure!(
        variants
            .iter()
            .map(|variant| (variant.name.as_str(), variant.value))
            .collect::<Vec<_>>()
            == [
                ("Low", DiscriminantValue::Unsigned(1)),
                ("High", DiscriminantValue::Unsigned(0x8000_0000_0000_0000)),
            ],
        "{toolchain}: unexpected unsigned enum variants {variants:#?}"
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
        let c_str_expected = if matches!(toolchain.as_str(), "1.35.0" | "1.49.0") {
            ExpectedAdapter::NativeDwarf
        } else {
            ExpectedAdapter::CBytes
        };
        for parameter in ["c_str", "boxed_c_str"] {
            assert_parameter_adapter(
                &analyzer,
                &binary,
                "observe_values",
                parameter,
                c_str_expected,
                &toolchain,
            )
            .await?;
        }
        assert_parameter_adapter(
            &analyzer,
            &binary,
            "observe_mut_str",
            "value",
            ExpectedAdapter::Utf8Bytes,
            &toolchain,
        )
        .await?;

        let enum_type =
            resolved_parameter_type(&analyzer, "observe_values", "enum_value", &toolchain).await?;
        assert_compat_enum_dwarf(&toolchain, &enum_type)?;
        let fieldless_type =
            resolved_parameter_type(&analyzer, "observe_values", "fieldless", &toolchain).await?;
        assert_fieldless_enum_dwarf(&toolchain, &fieldless_type)?;
        let single_type =
            resolved_parameter_type(&analyzer, "observe_values", "single", &toolchain).await?;
        assert_single_variant_enum_dwarf(&toolchain, &single_type)?;
        let signed_type =
            resolved_parameter_type(&analyzer, "observe_values", "signed", &toolchain).await?;
        assert_signed_enum_dwarf(&toolchain, &signed_type)?;
        let unsigned_type =
            resolved_parameter_type(&analyzer, "observe_values", "unsigned", &toolchain).await?;
        assert_unsigned_enum_dwarf(&toolchain, &unsigned_type)?;
        let option_type =
            resolved_parameter_type(&analyzer, "observe_values", "option_nonzero", &toolchain)
                .await?;
        assert_niche_option_dwarf(&toolchain, &option_type)?;

        let nested_type =
            resolved_parameter_type(&analyzer, "observe_nested_enum", "value", &toolchain).await?;
        assert_nested_enum_dwarf(&toolchain, &nested_type)?;

        let pointer_some =
            resolved_parameter_type(&analyzer, "observe_pointer_niche", "some", &toolchain).await?;
        let pointer_none =
            resolved_parameter_type(&analyzer, "observe_pointer_niche", "none", &toolchain).await?;
        anyhow::ensure!(
            pointer_some == pointer_none,
            "{toolchain}: Option<&i32> parameter types differ"
        );
        assert_pointer_niche_dwarf(&toolchain, &pointer_some)?;

        let repr_c_unit =
            resolved_parameter_type(&analyzer, "observe_repr_c_enum", "unit", &toolchain).await?;
        let repr_c_tuple =
            resolved_parameter_type(&analyzer, "observe_repr_c_enum", "tuple", &toolchain).await?;
        let repr_c_struct =
            resolved_parameter_type(&analyzer, "observe_repr_c_enum", "struct_value", &toolchain)
                .await?;
        anyhow::ensure!(
            repr_c_unit == repr_c_tuple && repr_c_unit == repr_c_struct,
            "{toolchain}: CompatReprC parameter types differ"
        );
        assert_repr_c_enum_dwarf(&toolchain, &repr_c_unit)?;

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

#[allow(dead_code)]
mod common;

use anyhow::Context;
use common::{init, runner::GhostscopeRunner, targets::TargetLauncher};
use gimli::write::{
    Address, AttributeValue as A, Dwarf, EndianVec, Expression, LineProgram, LineString, Sections,
    Unit, UnitEntryId,
};
use object::{Object, ObjectSymbol};
use regex::Regex;
use std::{collections::BTreeSet, fs, path::Path, process::Command};

const GUARDS: [&str; 5] = [
    "guard_branch",
    "guard_jump",
    "guard_call",
    "guard_return",
    "guard_linear",
];

fn run(command: &mut Command) -> anyhow::Result<()> {
    let output = command.output()?;
    anyhow::ensure!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn set_range(unit: &mut Unit, id: UnitEntryId, start: u64, size: u64) {
    unit.get_mut(id)
        .set(gimli::DW_AT_low_pc, A::Address(Address::Constant(start)));
    unit.get_mut(id).set(gimli::DW_AT_high_pc, A::Udata(size));
}

fn variable(
    unit: &mut Unit,
    parent: UnitEntryId,
    tag: gimli::DwTag,
    name: &str,
    ty: UnitEntryId,
    location: Option<Expression>,
) -> UnitEntryId {
    let id = unit.add(parent, tag);
    unit.get_mut(id)
        .set(gimli::DW_AT_name, A::String(name.as_bytes().to_vec()));
    unit.get_mut(id).set(gimli::DW_AT_type, A::UnitRef(ty));
    if let Some(location) = location {
        unit.get_mut(id)
            .set(gimli::DW_AT_location, A::Exprloc(location));
    }
    id
}

fn register_location(register: u16) -> Expression {
    let mut location = Expression::new();
    location.op_reg(gimli::Register(register));
    location
}

fn add_dwarf(binary: &Path, language: gimli::DwLang) -> anyhow::Result<()> {
    let bytes = fs::read(binary)?;
    let object = object::File::parse(bytes.as_slice())?;
    let symbol = |name: &str| -> anyhow::Result<(u64, u64)> {
        let symbol = object
            .symbols()
            .find(|symbol| symbol.name() == Ok(name))
            .with_context(|| format!("missing symbol {name}"))?;
        Ok((symbol.address(), symbol.size()))
    };
    let encoding = gimli::Encoding {
        format: gimli::Format::Dwarf32,
        version: 4,
        address_size: 8,
    };
    let mut line = LineProgram::new(
        encoding,
        gimli::LineEncoding::default(),
        LineString::String(
            binary
                .parent()
                .unwrap()
                .as_os_str()
                .as_encoded_bytes()
                .to_vec(),
        ),
        None,
        LineString::String(b"fallback.c".to_vec()),
        None,
    );
    // Each candidate is explicitly marked prologue_end. The unused spill
    // parameter below forces the heuristic to try advancing to this marker.
    for name in GUARDS {
        let (start, size) = symbol(name)?;
        let (candidate, _) = symbol(&format!("{name}_candidate"))?;
        line.begin_sequence(Some(Address::Constant(start)));
        line.generate_row();
        line.row().address_offset = candidate - start;
        line.row().line = 2;
        line.row().prologue_end = true;
        line.generate_row();
        line.end_sequence(size);
    }
    let mut dwarf = Dwarf::new();
    let unit_id = dwarf.units.add(Unit::new(encoding, line));
    let unit = dwarf.units.get_mut(unit_id);
    let root = unit.root();
    unit.get_mut(root)
        .set(gimli::DW_AT_name, A::String(b"fallback.c".to_vec()));
    unit.get_mut(root)
        .set(gimli::DW_AT_language, A::Language(language));
    let int = unit.add(root, gimli::DW_TAG_base_type);
    unit.get_mut(int)
        .set(gimli::DW_AT_name, A::String(b"int".to_vec()));
    unit.get_mut(int).set(gimli::DW_AT_byte_size, A::Udata(4));
    unit.get_mut(int)
        .set(gimli::DW_AT_encoding, A::Encoding(gimli::DW_ATE_signed));
    for name in GUARDS {
        let (start, size) = symbol(name)?;
        let function = unit.add(root, gimli::DW_TAG_subprogram);
        unit.get_mut(function)
            .set(gimli::DW_AT_name, A::String(name.as_bytes().to_vec()));
        set_range(unit, function, start, size);
        let mut frame_base = Expression::new();
        frame_base.op(gimli::DW_OP_call_frame_cfa);
        unit.get_mut(function)
            .set(gimli::DW_AT_frame_base, A::Exprloc(frame_base));
        variable(
            unit,
            function,
            gimli::DW_TAG_formal_parameter,
            "x",
            int,
            Some(register_location(5)),
        );
        let mut spill = Expression::new();
        spill.op_fbreg(-16);
        variable(
            unit,
            function,
            gimli::DW_TAG_formal_parameter,
            "spill",
            int,
            Some(spill),
        );
    }

    let widget = unit.add(root, gimli::DW_TAG_structure_type);
    unit.get_mut(widget)
        .set(gimli::DW_AT_name, A::String(b"Widget".to_vec()));
    unit.get_mut(widget)
        .set(gimli::DW_AT_byte_size, A::Udata(4));
    let member = variable(unit, widget, gimli::DW_TAG_member, "value", int, None);
    unit.get_mut(member)
        .set(gimli::DW_AT_data_member_location, A::Udata(0));
    let pointer = unit.add(root, gimli::DW_TAG_pointer_type);
    unit.get_mut(pointer)
        .set(gimli::DW_AT_type, A::UnitRef(widget));
    unit.get_mut(pointer)
        .set(gimli::DW_AT_byte_size, A::Udata(8));
    let (start, size) = symbol("outer_receiver")?;
    let outer = unit.add(root, gimli::DW_TAG_subprogram);
    unit.get_mut(outer)
        .set(gimli::DW_AT_name, A::String(b"outer_receiver".to_vec()));
    set_range(unit, outer, start, size);
    let outer_receiver = variable(
        unit,
        outer,
        gimli::DW_TAG_formal_parameter,
        "this",
        pointer,
        Some(register_location(5)),
    );
    if language == gimli::DW_LANG_C_plus_plus_14 {
        unit.get_mut(outer)
            .set(gimli::DW_AT_object_pointer, A::UnitRef(outer_receiver));
    }
    let mut state = Expression::new();
    state.op_consts(11);
    state.op(gimli::DW_OP_stack_value);
    variable(
        unit,
        outer,
        gimli::DW_TAG_variable,
        "state",
        int,
        Some(state),
    );
    for (name, location) in [
        ("inline_missing", None),
        // Invalid bytecode must exercise the diagnostic path, independently
        // of a binding that was successfully parsed as optimized out.
        ("inline_diagnostic", Some(Expression::raw(vec![0xff]))),
        ("inline_readable", Some(register_location(4))),
    ] {
        let origin = unit.add(root, gimli::DW_TAG_subprogram);
        unit.get_mut(origin)
            .set(gimli::DW_AT_name, A::String(name.as_bytes().to_vec()));
        unit.get_mut(origin)
            .set(gimli::DW_AT_inline, A::Inline(gimli::DW_INL_inlined));
        let receiver = variable(
            unit,
            origin,
            gimli::DW_TAG_formal_parameter,
            "this",
            pointer,
            None,
        );
        if language == gimli::DW_LANG_C_plus_plus_14 {
            unit.get_mut(origin)
                .set(gimli::DW_AT_object_pointer, A::UnitRef(receiver));
        }
        let inline = unit.add(outer, gimli::DW_TAG_inlined_subroutine);
        unit.get_mut(inline)
            .set(gimli::DW_AT_abstract_origin, A::UnitRef(origin));
        let pc = symbol(&format!("{name}_pc"))?.0;
        set_range(unit, inline, pc, 1);
        unit.get_mut(inline)
            .set(gimli::DW_AT_entry_pc, A::Address(Address::Constant(pc)));
        let parameter = unit.add(inline, gimli::DW_TAG_formal_parameter);
        unit.get_mut(parameter)
            .set(gimli::DW_AT_abstract_origin, A::UnitRef(receiver));
        if let Some(location) = location {
            unit.get_mut(parameter)
                .set(gimli::DW_AT_location, A::Exprloc(location));
        }
        if name == "inline_missing" {
            variable(unit, inline, gimli::DW_TAG_variable, "state", int, None);
        }
    }
    let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
    dwarf.write(&mut sections)?;
    let mut objcopy = Command::new("objcopy");
    sections.for_each(|id, data| -> anyhow::Result<()> {
        if !data.slice().is_empty() {
            let path = binary.with_extension(id.name());
            fs::write(&path, data.slice())?;
            objcopy
                .arg("--add-section")
                .arg(format!("{}={}", id.name(), path.display()));
        }
        Ok(())
    })?;
    run(objcopy.arg(binary))
}

fn build_fixture() -> anyhow::Result<(tempfile::TempDir, std::path::PathBuf)> {
    build_fixture_with_language(gimli::DW_LANG_C_plus_plus_14)
}

fn build_fixture_with_language(
    language: gimli::DwLang,
) -> anyhow::Result<(tempfile::TempDir, std::path::PathBuf)> {
    let dir = tempfile::Builder::new()
        .prefix(".ghostscope-entry-fallback-")
        .tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))?;
    let source = dir.path().join("fallback.c");
    let assembly = dir.path().join("fallback.S");
    let binary = dir.path().join("fallback");
    fs::write(
        &source,
        r#"
#include <unistd.h>
extern int guard_branch(int), guard_jump(int), guard_call(int), guard_return(int), guard_linear(int);
struct Widget { int value; };
extern void outer_receiver(struct Widget *, struct Widget *);
int main(void) {
    struct Widget outer = {17}, inner = {93};
    for (;;) {
        for (int x = -7; x <= 7; x += 14) {
            guard_branch(x); guard_jump(x); guard_call(x); guard_return(x); guard_linear(x);
        }
        outer_receiver(&outer, &inner);
        usleep(10000);
    }
}
"#,
    )?;
    fs::write(
        &assembly,
        r#"
.text
.macro function name
.globl \name
.type \name, @function
\name:
.cfi_startproc
.endm
.macro finish name
.cfi_endproc
.size \name, .-\name
.endm
.macro candidate name
.globl \name\()_candidate
\name\()_candidate:
nop
.endm
function guard_branch
test %edi, %edi
jns 1f
candidate guard_branch
1: mov %edi, %eax
ret
finish guard_branch
function guard_jump
jmp 1f
candidate guard_jump
1: mov %edi, %eax
ret
finish guard_jump
function guard_call
sub $8, %rsp
.cfi_adjust_cfa_offset 8
call guard_clobber
add $8, %rsp
.cfi_adjust_cfa_offset -8
candidate guard_call
mov %edi, %eax
ret
finish guard_call
function guard_return
mov %edi, %eax
ret
candidate guard_return
ret
finish guard_return
function guard_linear
nop
candidate guard_linear
mov %edi, %eax
ret
finish guard_linear
function guard_clobber
mov $101, %edi
ret
finish guard_clobber
function outer_receiver
.globl inline_missing_pc, inline_diagnostic_pc, inline_readable_pc
inline_missing_pc: nop
inline_diagnostic_pc: nop
inline_readable_pc: nop
ret
finish outer_receiver
.section .note.GNU-stack,"",@progbits
"#,
    )?;
    run(Command::new("cc")
        .args(["-g0", "-O2", "-no-pie", "-o"])
        .arg(&binary)
        .arg(&source)
        .arg(&assembly))?;
    add_dwarf(&binary, language)?;
    Ok((dir, binary))
}

#[tokio::test]
async fn test_function_entry_fallback_rejects_control_flow_but_allows_linear_setup(
) -> anyhow::Result<()> {
    init();
    let (_dir, binary) = build_fixture()?;
    let bytes = fs::read(&binary)?;
    let object = object::File::parse(bytes.as_slice())?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary).await?;
    let mut script = String::new();
    for name in GUARDS {
        let expected_name = if name == "guard_linear" {
            format!("{name}_candidate")
        } else {
            name.to_owned()
        };
        let expected = object
            .symbols()
            .find(|symbol| symbol.name() == Ok(expected_name.as_str()))
            .unwrap()
            .address();
        let addresses = analyzer.lookup_function_addresses(name);
        assert_eq!(addresses.len(), 1, "{name}: {addresses:?}");
        assert_eq!(addresses[0].address, expected, "{name}: {addresses:?}");
        script.push_str(&format!("trace {name} {{ print \"{name}:{{}}\", x; }}\n"));
    }
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let result = GhostscopeRunner::new()
        .attach_to(&target)
        .with_script(&script)
        .with_log_level("debug")
        .enable_sysmon_for_target(false)
        .timeout_secs(3)
        .run()
        .await;
    target.terminate().await?;
    let (exit, stdout, stderr) = result?;
    assert_eq!(exit, 0, "{stdout}\n{stderr}");
    for name in GUARDS {
        let regex = Regex::new(&format!(r"{name}:(-?\d+)"))?;
        let samples: BTreeSet<i32> = regex
            .captures_iter(&stdout)
            .map(|captures| captures[1].parse())
            .collect::<Result<_, _>>()?;
        assert_eq!(
            samples,
            BTreeSet::from([-7, 7]),
            "{name}: {stdout}\n{stderr}"
        );
        if name != "guard_linear" {
            assert!(
                stderr.contains(&format!("Non-inline '{name}' kept entry")),
                "{stderr}"
            );
        }
    }
    for flow in ["ConditionalBranch", "UnconditionalBranch", "Call", "Return"] {
        assert!(
            stderr.contains(&format!("control-flow instruction {flow}")),
            "{stderr}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_function_entry_fallback_keeps_readable_outer_this_in_inline_scopes(
) -> anyhow::Result<()> {
    init();
    let (_dir, binary) = build_fixture()?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary).await?;
    let address = analyzer
        .lookup_function_addresses("inline_diagnostic")
        .remove(0);
    let context = analyzer.resolve_pc(&address)?;
    assert_eq!(context.is_inline, Some(true));
    let visible = analyzer.visible_variables_with_diagnostics(&context)?;
    assert!(
        visible
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.name.as_deref() == Some("this")
                && diagnostic.is_inline_receiver),
        "fixture must expose the receiver evaluation error: {visible:?}"
    );
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let result = GhostscopeRunner::new()
        .attach_to(&target)
        .with_script(
            r#"
trace inline_missing { print "MISSING:{}", this.value; print "SHADOW:{}", state; }
trace inline_diagnostic { print "DIAGNOSTIC:{}", this.value; }
trace inline_readable { print "READABLE:{}", this.value; }
"#,
        )
        .enable_sysmon_for_target(false)
        .timeout_secs(3)
        .run()
        .await;
    target.terminate().await?;
    let (exit, stdout, stderr) = result?;
    assert_eq!(exit, 0, "{stdout}\n{stderr}");
    for (marker, expected) in [("MISSING", 17), ("DIAGNOSTIC", 17), ("READABLE", 93)] {
        let regex = Regex::new(&format!(r"{marker}:(-?\d+)"))?;
        let samples: BTreeSet<i32> = regex
            .captures_iter(&stdout)
            .map(|captures| captures[1].parse())
            .collect::<Result<_, _>>()?;
        assert_eq!(
            samples,
            BTreeSet::from([expected]),
            "{marker}: {stdout}\n{stderr}"
        );
    }
    let shadows: Vec<_> = stdout
        .lines()
        .filter(|line| line.contains("SHADOW:"))
        .collect();
    assert!(!shadows.is_empty(), "{stdout}\n{stderr}");
    assert!(
        shadows
            .iter()
            .all(|line| line.contains("<unavailable: optimized out>")),
        "{shadows:?}"
    );
    Ok(())
}

#[tokio::test]
async fn test_function_entry_fallback_preserves_ordinary_this_inside_inline_functions(
) -> anyhow::Result<()> {
    init();
    for language in [gimli::DW_LANG_C11, gimli::DW_LANG_Rust] {
        let (_dir, binary) = build_fixture_with_language(language)?;
        let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary).await?;
        let address = analyzer
            .lookup_function_addresses("inline_missing")
            .remove(0);
        let context = analyzer.resolve_pc(&address)?;
        assert_eq!(context.is_inline, Some(true));
        let plan = analyzer.plan_variable_by_name(&context, "this")?.unwrap();
        assert_eq!(
            plan.availability,
            ghostscope_dwarf::Availability::OptimizedOut
        );
        let address = analyzer
            .lookup_function_addresses("inline_diagnostic")
            .remove(0);
        let context = analyzer.resolve_pc(&address)?;
        assert!(matches!(
            analyzer.plan_variable_by_name(&context, "this"),
            Err(ghostscope_dwarf::VariableLookupError::Unavailable { .. })
        ));
        let target = TargetLauncher::binary(&binary).spawn().await?;
        let result = GhostscopeRunner::new()
            .attach_to(&target)
            .with_script("trace inline_missing { print \"ORDINARY_THIS:{}\", this; }")
            .enable_sysmon_for_target(false)
            .timeout_secs(2)
            .run()
            .await;
        target.terminate().await?;
        let (exit, stdout, stderr) = result?;
        assert_eq!(exit, 0, "{language:?}: {stdout}\n{stderr}");
        let samples: Vec<_> = stdout
            .lines()
            .filter(|line| line.contains("ORDINARY_THIS:"))
            .collect();
        assert!(!samples.is_empty(), "{language:?}: {stdout}\n{stderr}");
        assert!(
            samples
                .iter()
                .all(|line| line.contains("<unavailable: optimized out>")),
            "{language:?}: {samples:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_function_entry_fallback_preserves_gcc_ordinary_this_shadowing() -> anyhow::Result<()>
{
    init();
    let dir = tempfile::Builder::new()
        .prefix(".ghostscope-ordinary-this-")
        .tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))?;
    let source = dir.path().join("ordinary_this.c");
    let binary = dir.path().join("ordinary_this");
    fs::write(
        &source,
        r#"
#include <unistd.h>
__attribute__((noinline)) int ordinary_this(int this) {
    {
        int this;
        (void)sizeof(this);
        __asm__ volatile(".globl ordinary_this_pc\nordinary_this_pc:\nnop");
    }
    return this;
}
static int (*volatile call_ordinary_this)(int) = ordinary_this;
int main(void) {
    for (;;) { call_ordinary_this(17); usleep(10000); }
}
"#,
    )?;
    run(Command::new("gcc")
        .args(["-g", "-O2", "-no-pie", "-o"])
        .arg(&binary)
        .arg(&source))?;
    let bytes = fs::read(&binary)?;
    let object = object::File::parse(bytes.as_slice())?;
    let pc = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("ordinary_this_pc"))
        .unwrap()
        .address();
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary).await?;
    let context = analyzer.resolve_pc(&ghostscope_dwarf::ModuleAddress::new(binary.clone(), pc))?;
    assert!(context.inline_chain.is_empty());
    let visible = analyzer.visible_variables(&context)?;
    assert!(
        visible.iter().any(|variable| variable.name == "this"
            && variable.is_parameter
            && variable.availability.is_available()),
        "{visible:?}"
    );
    assert!(
        visible.iter().any(|variable| variable.name == "this"
            && !variable.is_parameter
            && variable.availability == ghostscope_dwarf::Availability::OptimizedOut),
        "{visible:?}"
    );
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let result = GhostscopeRunner::new()
        .attach_to(&target)
        .with_script(&format!(
            "trace 0x{pc:x} {{ print \"ORDINARY_THIS:{{}}\", this; }}"
        ))
        .enable_sysmon_for_target(false)
        .timeout_secs(2)
        .run()
        .await;
    target.terminate().await?;
    let (exit, stdout, stderr) = result?;
    assert_eq!(exit, 0, "{stdout}\n{stderr}");
    let samples: Vec<_> = stdout
        .lines()
        .filter(|line| line.contains("ORDINARY_THIS:"))
        .collect();
    assert!(!samples.is_empty(), "{stdout}\n{stderr}");
    assert!(
        samples
            .iter()
            .all(|line| line.contains("<unavailable: optimized out>")),
        "{samples:?}"
    );
    Ok(())
}

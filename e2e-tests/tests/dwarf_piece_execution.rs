#[allow(dead_code)]
mod common;

use anyhow::Context;
use common::{init, runner::GhostscopeRunner, targets::TargetLauncher};
use gimli::write::{
    Address, AttributeValue, Dwarf, EndianVec, Expression, LineProgram, Sections, Unit,
};
use object::{Object, ObjectSymbol};
use std::{fs, path::Path, process::Command};

fn run_command(command: &mut Command) -> anyhow::Result<()> {
    let output = command
        .output()
        .with_context(|| format!("failed to run {command:?}"))?;
    anyhow::ensure!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn register_piece(expression: &mut Expression, register: u16, size: u64) {
    expression.op_reg(gimli::Register(register));
    expression.op_piece(size);
}

fn memory_piece(expression: &mut Expression, size: u64) {
    expression.op_breg(gimli::Register(4), 0); // RSI points to exactly three readable bytes.
    expression.op_piece(size);
}

fn add_piece_dwarf(binary: &Path) -> anyhow::Result<u64> {
    let bytes = fs::read(binary)?;
    let object = object::File::parse(bytes.as_slice())?;
    let symbol = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("piece_probe"))
        .context("missing piece_probe")?;
    let pc = symbol.address();
    let caller = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("known_piece_caller"))
        .context("missing known_piece_caller")?;
    let return_pc = object
        .symbols()
        .find(|symbol| symbol.name() == Ok("known_piece_return"))
        .context("missing known_piece_return")?
        .address();
    let mut dwarf = Dwarf::new();
    let id = dwarf.units.add(Unit::new(
        gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 5,
            address_size: 8,
        },
        LineProgram::none(),
    ));
    let unit = dwarf.units.get_mut(id);
    let root = unit.root();
    unit.get_mut(root).set(
        gimli::DW_AT_language,
        AttributeValue::Language(gimli::DW_LANG_C11),
    );
    unit.get_mut(root).set(
        gimli::DW_AT_low_pc,
        AttributeValue::Address(Address::Constant(pc.min(caller.address()))),
    );
    unit.get_mut(root).set(
        gimli::DW_AT_high_pc,
        AttributeValue::Udata(
            (pc + symbol.size()).max(caller.address() + caller.size()) - pc.min(caller.address()),
        ),
    );
    let mut base = |name: &[u8], size, encoding| {
        let id = unit.add(root, gimli::DW_TAG_base_type);
        unit.get_mut(id)
            .set(gimli::DW_AT_name, AttributeValue::String(name.to_vec()));
        unit.get_mut(id)
            .set(gimli::DW_AT_byte_size, AttributeValue::Udata(size));
        unit.get_mut(id)
            .set(gimli::DW_AT_encoding, AttributeValue::Encoding(encoding));
        id
    };
    let unsigned = base(b"unsigned long", 8, gimli::DW_ATE_unsigned);
    let signed = base(b"int", 4, gimli::DW_ATE_signed);
    let mut structure = |name: &[u8], members: &[&[u8]]| {
        let id = unit.add(root, gimli::DW_TAG_structure_type);
        unit.get_mut(id)
            .set(gimli::DW_AT_name, AttributeValue::String(name.to_vec()));
        unit.get_mut(id).set(
            gimli::DW_AT_byte_size,
            AttributeValue::Udata(members.len() as u64 * 8),
        );
        for (index, name) in members.iter().enumerate() {
            let member = unit.add(id, gimli::DW_TAG_member);
            unit.get_mut(member)
                .set(gimli::DW_AT_name, AttributeValue::String(name.to_vec()));
            unit.get_mut(member)
                .set(gimli::DW_AT_type, AttributeValue::UnitRef(unsigned));
            unit.get_mut(member).set(
                gimli::DW_AT_data_member_location,
                AttributeValue::Udata(index as u64 * 8),
            );
        }
        id
    };
    let pair = structure(b"PiecePair", &[b"first", b"second"]);
    let mixed = structure(b"PieceMixed", &[b"first", b"middle", b"last"]);
    let function = unit.add(root, gimli::DW_TAG_subprogram);
    unit.get_mut(function).set(
        gimli::DW_AT_name,
        AttributeValue::String(b"piece_probe".to_vec()),
    );
    unit.get_mut(function).set(
        gimli::DW_AT_low_pc,
        AttributeValue::Address(Address::Constant(pc)),
    );
    unit.get_mut(function)
        .set(gimli::DW_AT_high_pc, AttributeValue::Udata(symbol.size()));

    let known_caller = unit.add(root, gimli::DW_TAG_subprogram);
    unit.get_mut(known_caller).set(
        gimli::DW_AT_name,
        AttributeValue::String(b"known_piece_caller".to_vec()),
    );
    unit.get_mut(known_caller).set(
        gimli::DW_AT_low_pc,
        AttributeValue::Address(Address::Constant(caller.address())),
    );
    unit.get_mut(known_caller)
        .set(gimli::DW_AT_high_pc, AttributeValue::Udata(caller.size()));
    let call = unit.add(known_caller, gimli::DW_TAG_call_site);
    unit.get_mut(call)
        .set(gimli::DW_AT_call_origin, AttributeValue::UnitRef(function));
    unit.get_mut(call).set(
        gimli::DW_AT_call_return_pc,
        AttributeValue::Address(Address::Constant(return_pc)),
    );
    let parameter = unit.add(call, gimli::DW_TAG_call_site_parameter);
    let mut parameter_location = Expression::new();
    parameter_location.op_reg(gimli::Register(5));
    unit.get_mut(parameter).set(
        gimli::DW_AT_location,
        AttributeValue::Exprloc(parameter_location),
    );
    let mut parameter_value = Expression::new();
    parameter_value.op_constu(0xfeed_face_7654_3210);
    unit.get_mut(parameter).set(
        gimli::DW_AT_call_value,
        AttributeValue::Exprloc(parameter_value),
    );

    let mut pair_location = Expression::new();
    register_piece(&mut pair_location, 5, 8);
    register_piece(&mut pair_location, 1, 8);
    let mut mixed_location = Expression::new();
    register_piece(&mut mixed_location, 5, 8);
    memory_piece(&mut mixed_location, 3);
    mixed_location.op_implicit_value(vec![0x11, 0x22, 0x33, 0x44, 0x55].into_boxed_slice());
    mixed_location.op_piece(5);
    register_piece(&mut mixed_location, 1, 8);
    let mut scalar_location = Expression::new();
    register_piece(&mut scalar_location, 5, 4);
    register_piece(&mut scalar_location, 1, 4);
    let mut memory_scalar = Expression::new();
    memory_piece(&mut memory_scalar, 3);
    register_piece(&mut memory_scalar, 5, 5);
    let mut signed_location = Expression::new();
    memory_piece(&mut signed_location, 3);
    signed_location.op_constu(255);
    signed_location.op(gimli::DW_OP_stack_value);
    signed_location.op_piece(1);
    let mut implicit = Expression::new();
    implicit.op_implicit_value(
        (1u64.to_le_bytes().into_iter().chain(2u64.to_le_bytes()))
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    );
    implicit.op_piece(16);
    let mut bad_read = Expression::new();
    register_piece(&mut bad_read, 5, 8);
    bad_read.op_addr(Address::Constant(1));
    bad_read.op_piece(8);
    register_piece(&mut bad_read, 1, 8);
    let mut broken_scalar = Expression::new();
    register_piece(&mut broken_scalar, 5, 4);
    broken_scalar.op_addr(Address::Constant(1));
    broken_scalar.op_piece(4);
    let mut zero_computed_scalar = Expression::new();
    register_piece(&mut zero_computed_scalar, 5, 4);
    // Anonymous mmap bytes immediately before the initialized tail are zero.
    zero_computed_scalar.op_breg(gimli::Register(4), -4);
    zero_computed_scalar.op_deref_size(4);
    zero_computed_scalar.op(gimli::DW_OP_stack_value);
    zero_computed_scalar.op_piece(4);
    let mut computed_fault = Expression::new();
    register_piece(&mut computed_fault, 5, 8);
    computed_fault.op_breg(gimli::Register(4), 0);
    computed_fault.op_deref_size(4);
    computed_fault.op(gimli::DW_OP_stack_value);
    computed_fault.op_piece(8);
    let mut computed_address_fault = Expression::new();
    register_piece(&mut computed_address_fault, 5, 8);
    computed_address_fault.op_breg(gimli::Register(4), 0);
    computed_address_fault.op_deref_size(4);
    computed_address_fault.op_piece(8);
    let mut computed_ok = Expression::new();
    register_piece(&mut computed_ok, 5, 8);
    computed_ok.op_breg(gimli::Register(4), 0);
    computed_ok.op_deref_size(2);
    computed_ok.op(gimli::DW_OP_stack_value);
    computed_ok.op_piece(8);
    let mut null_computed = Expression::new();
    register_piece(&mut null_computed, 5, 8);
    null_computed.op_constu(0);
    null_computed.op_deref_size(4);
    null_computed.op(gimli::DW_OP_stack_value);
    null_computed.op_piece(8);
    let mut null_computed_address = Expression::new();
    register_piece(&mut null_computed_address, 5, 8);
    null_computed_address.op_constu(0);
    null_computed_address.op_deref_size(4);
    null_computed_address.op_piece(8);
    let mut null_scalar = Expression::new();
    register_piece(&mut null_scalar, 5, 4);
    null_scalar.op_constu(0);
    null_scalar.op_deref_size(4);
    null_scalar.op(gimli::DW_OP_stack_value);
    null_scalar.op_piece(4);
    let mut entry_pair = Expression::new();
    register_piece(&mut entry_pair, 5, 8);
    let mut entry_register = Expression::new();
    entry_register.op_reg(gimli::Register(5));
    entry_pair.op_entry_value(entry_register.clone());
    entry_pair.op(gimli::DW_OP_stack_value);
    entry_pair.op_piece(8);
    let mut entry_after_fault = Expression::new();
    register_piece(&mut entry_after_fault, 5, 8);
    entry_after_fault.op_breg(gimli::Register(4), 0);
    entry_after_fault.op_deref_size(4);
    entry_after_fault.op_entry_value(entry_register);
    entry_after_fault.op(gimli::DW_OP_plus);
    entry_after_fault.op(gimli::DW_OP_stack_value);
    entry_after_fault.op_piece(8);
    let mut repeated_fault = Expression::new();
    register_piece(&mut repeated_fault, 5, 8);
    repeated_fault.op_breg(gimli::Register(4), 0);
    repeated_fault.op_deref_size(4);
    repeated_fault.op_addr(Address::Constant(1));
    repeated_fault.op_deref_size(4);
    repeated_fault.op(gimli::DW_OP_plus);
    repeated_fault.op(gimli::DW_OP_stack_value);
    repeated_fault.op_piece(8);
    let mut read_address = Expression::new();
    read_address.op_reg(gimli::Register(4));
    let mut missing = Expression::new();
    register_piece(&mut missing, 5, 8);
    missing.op_piece(8);
    let mut short = Expression::new();
    register_piece(&mut short, 5, 8);
    let mut simd = Expression::new();
    register_piece(&mut simd, 17, 8);
    register_piece(&mut simd, 1, 8);
    let mut bits = Expression::new();
    bits.op_reg(gimli::Register(5));
    bits.op_bit_piece(32, 0);
    for (name, ty, location) in [
        ("pair", pair, pair_location),
        ("mixed", mixed, mixed_location),
        ("scalar", unsigned, scalar_location),
        ("memory_scalar", unsigned, memory_scalar),
        ("signed_scalar", signed, signed_location),
        ("implicit", pair, implicit),
        ("bad_read", mixed, bad_read),
        ("broken_scalar", unsigned, broken_scalar),
        ("zero_computed_scalar", unsigned, zero_computed_scalar),
        ("computed_fault", pair, computed_fault),
        ("computed_address_fault", pair, computed_address_fault),
        ("computed_ok", pair, computed_ok),
        ("null_computed", pair, null_computed),
        ("null_computed_address", pair, null_computed_address),
        ("null_scalar", unsigned, null_scalar),
        ("entry_pair", pair, entry_pair),
        ("entry_after_fault", pair, entry_after_fault),
        ("repeated_fault", pair, repeated_fault),
        ("read_address", unsigned, read_address),
        ("missing", pair, missing),
        ("short", pair, short),
        ("simd", pair, simd),
        ("bits", signed, bits),
    ] {
        let variable = unit.add(function, gimli::DW_TAG_variable);
        unit.get_mut(variable).set(
            gimli::DW_AT_name,
            AttributeValue::String(name.as_bytes().to_vec()),
        );
        unit.get_mut(variable)
            .set(gimli::DW_AT_type, AttributeValue::UnitRef(ty));
        unit.get_mut(variable)
            .set(gimli::DW_AT_location, AttributeValue::Exprloc(location));
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
    run_command(objcopy.arg(binary))?;
    Ok(pc)
}

fn build_fixture() -> anyhow::Result<(tempfile::TempDir, std::path::PathBuf, u64)> {
    let dir = tempfile::Builder::new()
        .prefix("dwarf-pieces-")
        .tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))?;
    let source = dir.path().join("probe.c");
    let assembly = dir.path().join("probe.S");
    let binary = dir.path().join("piece-probe");
    fs::write(
        &source,
        r#"
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>
extern void piece_probe(uint64_t, void *, uint64_t);
extern void known_piece_caller(uint64_t, void *, uint64_t);
int main(void) {
    long page = sysconf(_SC_PAGESIZE);
    unsigned char *data = mmap(0, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (data == MAP_FAILED || mprotect(data + page, page, PROT_NONE)) return 1;
    data += page - 3;
    data[0] = 0xaa; data[1] = 0xbb; data[2] = 0xcc;
    for (;;) {
        piece_probe(UINT64_C(0xfeedface76543210), data, UINT64_C(0x0123456789abcdef));
        known_piece_caller(UINT64_C(0xfeedface76543210), data, UINT64_C(0x0123456789abcdef));
        usleep(10000);
    }
}
"#,
    )?;
    fs::write(
        &assembly,
        r#".text
.globl piece_probe
.type piece_probe, @function
piece_probe:
.cfi_startproc
nop
ret
.cfi_endproc
.size piece_probe, .-piece_probe
.globl known_piece_caller
.type known_piece_caller, @function
known_piece_caller:
.cfi_startproc
sub $8, %rsp
.cfi_adjust_cfa_offset 8
call piece_probe
.globl known_piece_return
known_piece_return:
add $8, %rsp
.cfi_adjust_cfa_offset -8
ret
.cfi_endproc
.size known_piece_caller, .-known_piece_caller
.section .note.GNU-stack,"",@progbits
"#,
    )?;
    run_command(
        Command::new("cc")
            .args(["-g0", "-O2", "-no-pie", "-o"])
            .arg(&binary)
            .arg(&source)
            .arg(&assembly),
    )?;
    let pc = add_piece_dwarf(&binary)?;
    Ok((dir, binary, pc))
}

#[tokio::test]
async fn test_dwarf_pieces_capture_register_memory_implicit_and_scalar_values() -> anyhow::Result<()>
{
    init();
    let (_dir, binary, pc) = build_fixture()?;
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let script = format!(
        r#"trace 0x{pc:x} {{
        print "PAIR:{{}}", pair;
        print "MIXED:{{}}", mixed;
        print "IMPLICIT:{{}}", implicit;
        print "SCALAR:{{}}:{{}}", scalar, scalar + 1;
        print "MEMORY_SCALAR:{{}}", memory_scalar;
        print "SIGNED:{{}}:{{}}", signed_scalar, signed_scalar / 2;
        if signed_scalar < 0 {{ print "SIGNED_NEGATIVE"; }}
        print "BAD:{{}}", bad_read;
        print "AFTER_BAD:{{}}", scalar;
    }}"#
    );
    let output = GhostscopeRunner::new()
        .with_target(&binary)
        .attach_to(&target)
        .with_script(&script)
        .timeout_secs(2)
        .run()
        .await;
    target.terminate().await?;
    let (exit_code, stdout, stderr) = output?;
    assert_eq!(exit_code, 0, "{stderr}\n{stdout}");
    for expected in [
        format!("first: {}", 0xfeed_face_7654_3210u64),
        format!("second: {}", 0x0123_4567_89ab_cdefu64),
        format!("middle: {}", 0x5544_3322_11cc_bbaau64),
        "IMPLICIT:PiecePair { first: 1, second: 2 }".to_string(),
        format!(
            "SCALAR:{}:{}",
            0x89ab_cdef_7654_3210u64, 0x89ab_cdef_7654_3211u64 as i64
        ),
        format!("MEMORY_SCALAR:{}", 0xce76_5432_10cc_bbaau64),
        format!(
            "SIGNED:{}:{}",
            0xffcc_bbaau32 as i32,
            (0xffcc_bbaau32 as i32) / 2
        ),
        "SIGNED_NEGATIVE".to_string(),
        format!("AFTER_BAD:{}", 0x89ab_cdef_7654_3210u64),
    ] {
        assert!(
            stdout.contains(&expected),
            "missing {expected:?}: {stderr}\n{stdout}"
        );
    }
    let bad_lines: Vec<_> = stdout
        .lines()
        .filter(|line| line.contains("BAD:") && !line.contains("AFTER_BAD:"))
        .collect();
    assert!(!bad_lines.is_empty(), "missing read-error output: {stdout}");
    assert!(
        bad_lines
            .iter()
            .all(|line| line.contains("memory read failed")),
        "read failure was hidden or overwritten: {bad_lines:?}"
    );
    assert!(
        bad_lines.iter().all(|line| line.contains("0x1")),
        "missing failing piece address: {bad_lines:?}"
    );
    Ok(())
}

#[tokio::test]
async fn test_dwarf_pieces_scalar_failure_does_not_return_partial_bytes() -> anyhow::Result<()> {
    init();
    let (_dir, binary, pc) = build_fixture()?;
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let output = GhostscopeRunner::new()
        .with_target(&binary)
        .attach_to(&target)
        .with_script(&format!(
            r#"trace 0x{pc:x} {{
            print "BROKEN_DIRECT:{{}}", broken_scalar;
            print "BROKEN_EXPR:{{}}", broken_scalar + 0;
            print "VALID_ZERO_DIRECT:{{}}", zero_computed_scalar;
            print "VALID_ZERO_FRAGMENT:{{}}", zero_computed_scalar + 0;
            print "HEALTHY_AFTER:{{}}", scalar;
        }}"#
        ))
        .timeout_secs(2)
        .run()
        .await;
    target.terminate().await?;
    let (exit_code, stdout, stderr) = output?;
    assert_eq!(exit_code, 0, "{stderr}\n{stdout}");
    assert!(
        stdout.contains("BROKEN_DIRECT:<unreadable: memory read failed; errno=-14; address=0x1>"),
        "{stdout}"
    );
    let expressions: Vec<_> = stdout
        .lines()
        .filter(|line| line.contains("BROKEN_EXPR:"))
        .collect();
    assert!(
        !expressions.is_empty(),
        "missing scalar expression output: {stdout}"
    );
    assert!(
        expressions
            .iter()
            .all(|line| line.trim() == "BROKEN_EXPR:0"),
        "partial scalar bytes escaped: {expressions:?}"
    );
    assert!(
        stdout.contains(&format!("VALID_ZERO_FRAGMENT:{}", 0x7654_3210u64)),
        "a successfully read zero fragment must preserve the other bytes: {stdout}"
    );
    assert!(
        stdout.contains(&format!("VALID_ZERO_DIRECT:{}", 0x7654_3210u64)),
        "a successfully read zero fragment must be printable: {stdout}"
    );
    assert!(
        stdout.contains(&format!("HEALTHY_AFTER:{}", 0x89ab_cdef_7654_3210u64)),
        "{stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_dwarf_pieces_computed_failures_preserve_first_read_diagnostics() -> anyhow::Result<()>
{
    init();
    let (_dir, binary, pc) = build_fixture()?;
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let output = GhostscopeRunner::new()
        .with_target(&binary)
        .attach_to(&target)
        .with_script(&format!(
            r#"trace 0x{pc:x} {{
            print "FAULT_ADDRESS:{{:p}}", read_address;
            print "COMPUTED_FAULT:{{}}", computed_fault;
            print "ADDRESS_FAULT:{{}}", computed_address_fault;
            print "REPEATED_FAULT:{{}}", repeated_fault;
            print "COMPUTED_OK:{{}}", computed_ok;
            print "HEALTHY_AFTER:{{}}", scalar;
        }}"#
        ))
        .timeout_secs(2)
        .run()
        .await;
    target.terminate().await?;
    let (exit_code, stdout, stderr) = output?;
    assert_eq!(exit_code, 0, "{stderr}\n{stdout}");
    let address = regex::Regex::new(r"FAULT_ADDRESS:(0x[0-9a-f]+)")?
        .captures(&stdout)
        .context("missing fault address")?[1]
        .to_string();
    for marker in ["COMPUTED_FAULT:", "ADDRESS_FAULT:", "REPEATED_FAULT:"] {
        let lines: Vec<_> = stdout
            .lines()
            .filter(|line| line.contains(marker))
            .collect();
        assert!(!lines.is_empty(), "missing {marker}: {stdout}");
        let expected = format!("memory read failed; errno=-14; address={address}>");
        assert!(
            lines.iter().all(|line| line.contains(&expected)),
            "corrupted or overwritten read diagnostics: {lines:?}"
        );
    }
    assert!(
        stdout.contains(&format!(
            "COMPUTED_OK:PiecePair {{ first: {}, second: {} }}",
            0xfeed_face_7654_3210u64, 0xbbaau64
        )),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("HEALTHY_AFTER:{}", 0x89ab_cdef_7654_3210u64)),
        "{stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_dwarf_pieces_null_computed_failures_set_execution_status() -> anyhow::Result<()> {
    init();
    let (_dir, binary, pc) = build_fixture()?;
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let mut outputs = Vec::new();
    for (variable, include_success, expected_status) in [
        ("pair", false, 0u8),
        ("null_computed", false, 2),
        ("null_computed_address", false, 2),
        ("null_computed", true, 1),
        ("null_computed_address", true, 1),
        ("scalar + 0", false, 0),
        ("null_scalar", false, 2),
        ("null_scalar + 0", false, 2),
        ("null_scalar + 0", true, 1),
    ] {
        let success = if include_success { "print pair;" } else { "" };
        let output = GhostscopeRunner::new()
            .with_target(&binary)
            .attach_to(&target)
            .with_script(&format!("trace 0x{pc:x} {{ print {variable}; {success} }}"))
            .with_cli_args([
                "--script-output",
                "jsonl",
                "--no-status",
                "--debuginfod",
                "off",
            ])
            .timeout_secs(1)
            .run()
            .await;
        outputs.push((variable, include_success, expected_status, output));
    }
    target.terminate().await?;

    for (variable, include_success, expected_status, output) in outputs {
        let (code, stdout, stderr) = output?;
        assert_eq!(code, 0, "{variable}: {stderr}\n{stdout}");
        assert!(!stdout.is_empty(), "missing {variable} events: {stderr}");
        for line in stdout.lines() {
            let event: serde_json::Value = serde_json::from_str(line)?;
            assert_eq!(
                event["execution_status"], expected_status,
                "incorrect execution status for {variable}, include_success={include_success}: {event}"
            );
            let items = event["items"].as_array().context("missing event items")?;
            let rendered: Vec<_> = items
                .iter()
                .filter_map(|item| {
                    item["formatted_value"]
                        .as_str()
                        .or_else(|| item["content"].as_str())
                })
                .collect();
            if variable == "null_scalar + 0" {
                assert!(
                    rendered
                        .iter()
                        .any(|value| *value == "0" || value.ends_with(" = 0")),
                    "failed scalar must return zero rather than partial bytes: {event}"
                );
            } else if variable == "scalar + 0" {
                assert!(
                    rendered
                        .iter()
                        .any(|value| value.contains(&(0x89ab_cdef_7654_3210u64 as i64).to_string())),
                    "successful scalar expression changed: {event}"
                );
            } else if variable != "pair" {
                assert!(
                    rendered
                        .iter()
                        .any(|value| value.contains("null pointer dereference")),
                    "missing NULL dereference diagnostic: {event}"
                );
            }
            if include_success || variable == "pair" {
                assert!(
                    rendered.iter().any(|value| value.contains("PiecePair")),
                    "missing successful value: {event}"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_dwarf_pieces_entry_value_misses_do_not_fabricate_read_diagnostics(
) -> anyhow::Result<()> {
    init();
    let (_dir, binary, pc) = build_fixture()?;
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let mut outputs = Vec::new();
    for variable in ["entry_pair", "entry_after_fault"] {
        let output = GhostscopeRunner::new()
            .with_target(&binary)
            .attach_to(&target)
            .with_script(&format!("trace 0x{pc:x} {{ print {variable}; }}"))
            .with_cli_args([
                "--script-output",
                "jsonl",
                "--no-status",
                "--debuginfod",
                "off",
            ])
            .timeout_secs(2)
            .run()
            .await;
        outputs.push((variable, output));
    }
    target.terminate().await?;

    let mut matches = 0;
    let mut misses = 0;
    for (variable, output) in outputs {
        let (code, stdout, stderr) = output?;
        assert_eq!(code, 0, "{variable}: {stderr}\n{stdout}");
        assert!(!stdout.is_empty(), "missing {variable} events: {stderr}");
        for line in stdout.lines() {
            let event: serde_json::Value = serde_json::from_str(line)?;
            let items = event["items"].as_array().context("missing event items")?;
            let rendered: Vec<_> = items
                .iter()
                .filter_map(|item| {
                    item["formatted_value"]
                        .as_str()
                        .or_else(|| item["content"].as_str())
                })
                .collect();
            if variable == "entry_after_fault" {
                assert_eq!(event["execution_status"], 2, "{event}");
                assert!(
                    rendered
                        .iter()
                        .any(|value| value.contains("memory read failed; errno=-14; address=0x")),
                    "entry-value lookup replaced the first helper failure: {event}"
                );
            } else if rendered
                .iter()
                .any(|value| value.contains("address compute failed"))
            {
                misses += 1;
                assert_eq!(event["execution_status"], 2, "{event}");
                assert!(
                    rendered
                        .iter()
                        .all(|value| !value.contains("memory read failed")
                            && !value.contains("errno=")
                            && !value.contains("address=0x")),
                    "lookup miss fabricated memory-read diagnostics: {event}"
                );
            } else {
                matches += 1;
                assert_eq!(event["execution_status"], 0, "{event}");
                let value = 0xfeed_face_7654_3210u64;
                assert!(
                    rendered
                        .iter()
                        .any(|rendered| rendered.contains(&format!("first: {value}"))
                            && rendered.contains(&format!("second: {value}"))),
                    "missing recovered entry value: {event}"
                );
            }
        }
    }
    assert!(matches > 0, "known caller never matched its lookup case");
    assert!(
        misses > 0,
        "unlisted caller never exercised the lookup miss"
    );
    Ok(())
}

#[tokio::test]
async fn test_dwarf_pieces_reject_missing_short_simd_and_bit_pieces() -> anyhow::Result<()> {
    init();
    let (_dir, binary, pc) = build_fixture()?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary).await?;
    for (variable, expected) in [
        ("missing", "unavailable or unsupported"),
        ("short", "cover 8 of 16"),
        ("simd", "SIMD/FP register"),
        ("bits", "DW_OP_bit_piece"),
    ] {
        let result = ghostscope_compiler::compile_script(
            &format!("trace 0x{pc:x} {{ print {variable}; }}"),
            &analyzer,
            None,
            Some(1),
            &ghostscope_compiler::CompileOptions::default(),
        );
        let message = match result {
            Err(error) => error.user_message().into_owned(),
            Ok(result) => {
                assert!(
                    result.uprobe_configs.is_empty(),
                    "unsupported piece produced a probe: {result:?}"
                );
                result
                    .failed_targets
                    .iter()
                    .map(|failure| failure.error_message.as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            }
        };
        assert!(message.contains(expected), "{variable}: {message}");
    }
    let result = ghostscope_compiler::compile_script(
        &format!("trace 0x{pc:x} {{ print pair; }}"),
        &analyzer,
        None,
        Some(1),
        &ghostscope_compiler::CompileOptions {
            mem_dump_cap: 8,
            ..Default::default()
        },
    );
    let message = match result {
        Err(error) => error.user_message().into_owned(),
        Ok(result) => {
            assert!(
                result.uprobe_configs.is_empty(),
                "over-budget piece produced a probe: {result:?}"
            );
            result
                .failed_targets
                .iter()
                .map(|failure| failure.error_message.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        }
    };
    assert!(message.contains("exceeding ebpf.mem_dump_cap"), "{message}");
    Ok(())
}

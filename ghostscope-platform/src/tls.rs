//! Linux native thread pointers and executable TLS layout helpers.

use std::fmt;
use std::path::Path;

const BTF_KIND_INT: u32 = 1;
const BTF_KIND_PTR: u32 = 2;
const BTF_KIND_ARRAY: u32 = 3;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;
const BTF_KIND_ENUM: u32 = 6;
const BTF_KIND_FWD: u32 = 7;
const BTF_KIND_TYPEDEF: u32 = 8;
const BTF_KIND_VOLATILE: u32 = 9;
const BTF_KIND_CONST: u32 = 10;
const BTF_KIND_RESTRICT: u32 = 11;
const BTF_KIND_FUNC: u32 = 12;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_VAR: u32 = 14;
const BTF_KIND_DATASEC: u32 = 15;
const BTF_KIND_FLOAT: u32 = 16;
const BTF_KIND_DECL_TAG: u32 = 17;
const BTF_KIND_TYPE_TAG: u32 = 18;
const BTF_KIND_ENUM64: u32 = 19;

const PT_TLS: u32 = 7;
const EM_X86_64: u16 = 62;

#[derive(Debug)]
pub enum TlsLayoutError {
    Io(std::io::Error),
    Invalid(&'static str),
    Missing(&'static str),
}

impl fmt::Display for TlsLayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Invalid(detail) => write!(f, "invalid TLS layout data: {detail}"),
            Self::Missing(detail) => write!(f, "missing TLS layout data: {detail}"),
        }
    }
}

impl std::error::Error for TlsLayoutError {}

impl From<std::io::Error> for TlsLayoutError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

#[derive(Debug)]
struct BtfRecord {
    name: String,
    kind: u32,
    members: Vec<BtfMember>,
}

#[derive(Debug)]
struct BtfMember {
    name: String,
    bit_offset: u32,
    type_id: u32,
}

/// Resolve the native saved user thread pointer through kernel BTF.
/// ARM64 uses thread.uw.tp_value (older kernels use thread.tp_value).
pub fn current_task_thread_pointer_offset() -> Result<u64, TlsLayoutError> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux")?;
    thread_pointer_offset(&parse_btf_records(&data)?, crate::TargetArch::current())
}

fn thread_pointer_offset(
    records: &[Option<BtfRecord>],
    arch: crate::TargetArch,
) -> Result<u64, TlsLayoutError> {
    let task_thread_bits = find_member_bit_offset(records, "task_struct", "thread")?;
    let thread = records
        .iter()
        .flatten()
        .find(|r| r.kind == BTF_KIND_STRUCT && r.name == "thread_struct")
        .ok_or(TlsLayoutError::Missing("thread_struct"))?;
    let offset = match arch {
        crate::TargetArch::X86_64 => find_member_bit_offset(records, "thread_struct", "fsbase")?,
        crate::TargetArch::Aarch64 => {
            if let Some(member) = thread.members.iter().find(|m| m.name == "tp_value") {
                member.bit_offset
            } else {
                let uw = thread
                    .members
                    .iter()
                    .find(|m| m.name == "uw")
                    .ok_or(TlsLayoutError::Missing("thread_struct.uw"))?;
                let record = records
                    .get(uw.type_id as usize)
                    .and_then(Option::as_ref)
                    .ok_or(TlsLayoutError::Missing("thread_struct.uw type"))?;
                let tp = record
                    .members
                    .iter()
                    .find(|m| m.name == "tp_value")
                    .ok_or(TlsLayoutError::Missing("thread_struct.uw.tp_value"))?;
                uw.bit_offset
                    .checked_add(tp.bit_offset)
                    .ok_or(TlsLayoutError::Invalid("thread pointer offset overflow"))?
            }
        }
        crate::TargetArch::Unknown => {
            return Err(TlsLayoutError::Invalid("unsupported thread pointer ABI"))
        }
    };
    if !task_thread_bits.is_multiple_of(8) || !offset.is_multiple_of(8) {
        return Err(TlsLayoutError::Invalid(
            "thread pointer is not byte-aligned",
        ));
    }
    Ok(u64::from(task_thread_bits) / 8 + u64::from(offset) / 8)
}

/// Resolve the x86 saved FS base, retained for callers inspecting that ABI.
pub fn current_task_fsbase_offset() -> Result<u64, TlsLayoutError> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux")?;
    thread_pointer_offset(&parse_btf_records(&data)?, crate::TargetArch::X86_64)
}

/// Return the executable static TLS bias from its native thread pointer.
///
/// For the initial-exec/local-exec TLS model used by the main executable on
/// x86_64 variant-II TLS, the DWARF TLS offset is relative to the module TLS
/// image, while the runtime address is `fsbase - aligned_tls_size + offset`.
pub fn static_tls_bias_for_elf(path: &Path) -> Result<Option<i64>, TlsLayoutError> {
    static_tls_bias_from_data(&std::fs::read(path)?)
}

fn static_tls_bias_from_data(data: &[u8]) -> Result<Option<i64>, TlsLayoutError> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Err(TlsLayoutError::Invalid("not an ELF file"));
    }
    if data[4] != 2 || data[5] != 1 {
        return Err(TlsLayoutError::Invalid(
            "only little-endian ELF64 is supported for TLS layout",
        ));
    }
    let machine = read_u16(data, 18)?;
    if !matches!(machine, EM_X86_64 | 183) {
        return Err(TlsLayoutError::Invalid(
            "only x86_64 and AArch64 ELF TLS layouts are supported",
        ));
    }

    let phoff = read_u64(data, 32)? as usize;
    let phentsize = read_u16(data, 54)? as usize;
    let phnum = read_u16(data, 56)? as usize;
    if phentsize < 56 {
        return Err(TlsLayoutError::Invalid(
            "ELF program header entry too small",
        ));
    }

    for index in 0..phnum {
        let offset =
            phoff
                .checked_add(index.saturating_mul(phentsize))
                .ok_or(TlsLayoutError::Invalid(
                    "ELF program header offset overflow",
                ))?;
        if offset + phentsize > data.len() {
            return Err(TlsLayoutError::Invalid("ELF program header out of bounds"));
        }
        if read_u32(data, offset)? != PT_TLS {
            continue;
        }

        let memsz = read_u64(data, offset + 40)?;
        let align = read_u64(data, offset + 48)?.max(1);
        // AArch64 variant I places the executable TLS block after the
        // two-pointer TCB, preserving the PT_TLS first-byte alignment.
        // x86_64 variant II places it before the thread pointer.
        let aligned = if machine == 183 {
            let first_byte = read_u64(data, offset + 16)? % align;
            round_up(16u64.saturating_sub(first_byte), align)?
                .checked_add(first_byte)
                .ok_or(TlsLayoutError::Invalid("TLS alignment overflow"))?
        } else {
            round_up(memsz, align)?
        };
        if aligned > i64::MAX as u64 {
            return Err(TlsLayoutError::Invalid("TLS segment too large"));
        }
        return Ok(Some(if machine == 183 {
            aligned as i64
        } else {
            -(aligned as i64)
        }));
    }

    Ok(None)
}

fn parse_btf_records(data: &[u8]) -> Result<Vec<Option<BtfRecord>>, TlsLayoutError> {
    if data.len() < 24 {
        return Err(TlsLayoutError::Invalid("BTF header too small"));
    }
    if read_u16(data, 0)? != 0xeb9f {
        return Err(TlsLayoutError::Invalid(
            "only little-endian BTF is supported",
        ));
    }

    let hdr_len = read_u32(data, 4)? as usize;
    let type_off = read_u32(data, 8)? as usize;
    let type_len = read_u32(data, 12)? as usize;
    let str_off = read_u32(data, 16)? as usize;
    let str_len = read_u32(data, 20)? as usize;
    let type_start = checked_range_start(hdr_len, type_off)?;
    let type_end = checked_range_end(type_start, type_len, data.len())?;
    let str_start = checked_range_start(hdr_len, str_off)?;
    let str_end = checked_range_end(str_start, str_len, data.len())?;
    let strings = &data[str_start..str_end];

    let mut offset = type_start;
    let mut records = vec![None];
    while offset < type_end {
        if offset + 12 > type_end {
            return Err(TlsLayoutError::Invalid("truncated BTF type header"));
        }
        let name_offset = read_u32(data, offset)?;
        let info = read_u32(data, offset + 4)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let kflag = (info & 0x8000_0000) != 0;
        offset += 12;

        let name = read_btf_string(strings, name_offset)?;
        let mut members = Vec::new();
        let extra_size = match kind {
            BTF_KIND_STRUCT | BTF_KIND_UNION => {
                for _ in 0..vlen {
                    if offset + 12 > type_end {
                        return Err(TlsLayoutError::Invalid("truncated BTF member"));
                    }
                    let member_name_offset = read_u32(data, offset)?;
                    let raw_offset = read_u32(data, offset + 8)?;
                    let bit_offset = if kflag {
                        raw_offset & 0x00ff_ffff
                    } else {
                        raw_offset
                    };
                    members.push(BtfMember {
                        name: read_btf_string(strings, member_name_offset)?,
                        bit_offset,
                        type_id: read_u32(data, offset + 4)?,
                    });
                    offset += 12;
                }
                0
            }
            BTF_KIND_INT | BTF_KIND_VAR | BTF_KIND_DECL_TAG => 4,
            BTF_KIND_ARRAY => 12,
            BTF_KIND_ENUM | BTF_KIND_FUNC_PROTO => vlen.saturating_mul(8),
            BTF_KIND_DATASEC | BTF_KIND_ENUM64 => vlen.saturating_mul(12),
            BTF_KIND_PTR | BTF_KIND_FWD | BTF_KIND_TYPEDEF | BTF_KIND_VOLATILE | BTF_KIND_CONST
            | BTF_KIND_RESTRICT | BTF_KIND_FUNC | BTF_KIND_FLOAT | BTF_KIND_TYPE_TAG => 0,
            _ => return Err(TlsLayoutError::Invalid("unknown BTF kind")),
        };

        if extra_size != 0 {
            offset = offset
                .checked_add(extra_size)
                .ok_or(TlsLayoutError::Invalid("BTF type offset overflow"))?;
            if offset > type_end {
                return Err(TlsLayoutError::Invalid("truncated BTF type payload"));
            }
        }

        records.push(Some(BtfRecord {
            name,
            kind,
            members,
        }));
    }

    Ok(records)
}

fn find_member_bit_offset(
    records: &[Option<BtfRecord>],
    struct_name: &'static str,
    member_name: &'static str,
) -> Result<u32, TlsLayoutError> {
    let record = records
        .iter()
        .flatten()
        .find(|record| record.kind == BTF_KIND_STRUCT && record.name == struct_name)
        .ok_or(TlsLayoutError::Missing(struct_name))?;

    record
        .members
        .iter()
        .find(|member| member.name == member_name)
        .map(|member| member.bit_offset)
        .ok_or(TlsLayoutError::Missing(member_name))
}

fn read_btf_string(strings: &[u8], offset: u32) -> Result<String, TlsLayoutError> {
    let start = offset as usize;
    if start >= strings.len() {
        return Err(TlsLayoutError::Invalid("BTF string offset out of bounds"));
    }
    let tail = &strings[start..];
    let nul = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(TlsLayoutError::Invalid("unterminated BTF string"))?;
    Ok(String::from_utf8_lossy(&tail[..nul]).into_owned())
}

fn checked_range_start(base: usize, offset: usize) -> Result<usize, TlsLayoutError> {
    base.checked_add(offset)
        .ok_or(TlsLayoutError::Invalid("range start overflow"))
}

fn checked_range_end(start: usize, len: usize, data_len: usize) -> Result<usize, TlsLayoutError> {
    let end = start
        .checked_add(len)
        .ok_or(TlsLayoutError::Invalid("range end overflow"))?;
    if end > data_len {
        return Err(TlsLayoutError::Invalid("range out of bounds"));
    }
    Ok(end)
}

fn round_up(value: u64, align: u64) -> Result<u64, TlsLayoutError> {
    if align <= 1 {
        return Ok(value);
    }
    let addend = align - 1;
    let rounded = value
        .checked_add(addend)
        .ok_or(TlsLayoutError::Invalid("TLS alignment overflow"))?
        / align
        * align;
    Ok(rounded)
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, TlsLayoutError> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or(TlsLayoutError::Invalid("u16 read out of bounds"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(data: &[u8], offset: usize) -> Result<u32, TlsLayoutError> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or(TlsLayoutError::Invalid("u32 read out of bounds"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64(data: &[u8], offset: usize) -> Result<u64, TlsLayoutError> {
    let bytes = data
        .get(offset..offset + 8)
        .ok_or(TlsLayoutError::Invalid("u64 read out of bounds"))?;
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executable_tls_uses_target_abi_and_segment_alignment() {
        let mut elf = vec![0; 120];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        elf[64..68].copy_from_slice(&PT_TLS.to_le_bytes());
        elf[104..112].copy_from_slice(&24u64.to_le_bytes());
        for (machine, align, vaddr, expected) in [
            (62u16, 8u64, 0u64, -24i64),
            (62, 64, 0, -64),
            (183, 8, 0, 16),
            (183, 64, 0, 64),
            (183, 64, 24, 24),
            (183, 64, 8, 72),
        ] {
            elf[18..20].copy_from_slice(&machine.to_le_bytes());
            elf[80..88].copy_from_slice(&vaddr.to_le_bytes());
            elf[112..120].copy_from_slice(&align.to_le_bytes());
            assert_eq!(static_tls_bias_from_data(&elf).unwrap(), Some(expected));
        }
    }

    fn member(name: &str, bit_offset: u32, type_id: u32) -> BtfMember {
        BtfMember {
            name: name.into(),
            bit_offset,
            type_id,
        }
    }

    fn structure(name: &str, members: Vec<BtfMember>) -> Option<BtfRecord> {
        Some(BtfRecord {
            name: name.into(),
            kind: BTF_KIND_STRUCT,
            members,
        })
    }

    #[test]
    fn native_thread_pointer_walks_nested_btf_members() {
        let records = vec![
            None,
            structure("task_struct", vec![member("thread", 800, 2)]),
            structure(
                "thread_struct",
                vec![member("uw", 160, 3), member("fsbase", 320, 0)],
            ),
            structure("", vec![member("tp_value", 64, 0)]),
        ];
        assert_eq!(
            thread_pointer_offset(&records, crate::TargetArch::Aarch64).unwrap(),
            128
        );
        assert_eq!(
            thread_pointer_offset(&records, crate::TargetArch::X86_64).unwrap(),
            140
        );
        assert!(thread_pointer_offset(&records, crate::TargetArch::Unknown).is_err());
        let records = vec![
            None,
            structure("task_struct", vec![member("thread", 800, 2)]),
            structure("thread_struct", vec![member("tp_value", 160, 0)]),
        ];
        assert_eq!(
            thread_pointer_offset(&records, crate::TargetArch::Aarch64).unwrap(),
            120
        );
    }
}

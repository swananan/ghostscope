//! Linux x86_64 TLS layout helpers.

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
}

/// Return the byte offset of `task_struct.thread.fsbase` in the running kernel.
pub fn current_task_fsbase_offset() -> Result<u64, TlsLayoutError> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux")?;
    let records = parse_btf_records(&data)?;
    let task_thread_bits = find_member_bit_offset(&records, "task_struct", "thread")?;
    let thread_fsbase_bits = find_member_bit_offset(&records, "thread_struct", "fsbase")?;

    if task_thread_bits % 8 != 0 || thread_fsbase_bits % 8 != 0 {
        return Err(TlsLayoutError::Invalid(
            "task_struct.thread.fsbase is not byte-aligned",
        ));
    }

    Ok(u64::from(task_thread_bits / 8 + thread_fsbase_bits / 8))
}

/// Return the x86_64 static TLS bias from thread pointer for an ELF module.
///
/// For the initial-exec/local-exec TLS model used by the main executable on
/// x86_64 variant-II TLS, the DWARF TLS offset is relative to the module TLS
/// image, while the runtime address is `fsbase - aligned_tls_size + offset`.
pub fn static_tls_bias_for_elf(path: &Path) -> Result<Option<i64>, TlsLayoutError> {
    let data = std::fs::read(path)?;
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Err(TlsLayoutError::Invalid("not an ELF file"));
    }
    if data[4] != 2 || data[5] != 1 {
        return Err(TlsLayoutError::Invalid(
            "only little-endian ELF64 is supported for TLS layout",
        ));
    }
    if read_u16(&data, 18)? != EM_X86_64 {
        return Err(TlsLayoutError::Invalid(
            "only x86_64 ELF TLS layout is supported",
        ));
    }

    let phoff = read_u64(&data, 32)? as usize;
    let phentsize = read_u16(&data, 54)? as usize;
    let phnum = read_u16(&data, 56)? as usize;
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
        if read_u32(&data, offset)? != PT_TLS {
            continue;
        }

        let memsz = read_u64(&data, offset + 40)?;
        let align = read_u64(&data, offset + 48)?.max(1);
        let aligned = round_up(memsz, align)?;
        if aligned > i64::MAX as u64 {
            return Err(TlsLayoutError::Invalid("TLS segment too large"));
        }
        return Ok(Some(-(aligned as i64)));
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

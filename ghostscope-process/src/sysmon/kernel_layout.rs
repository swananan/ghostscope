//! Resolve only the kernel fields used by the lifecycle probes. Offsets are
//! configured before attachment, so the prebuilt BPF objects are kernel independent.
use anyhow::{bail, Context, Result};
use std::collections::HashMap;

// Keep the array order in sync with ebpf/sysmon-bpf/src/lib.rs.
const FIELDS: &[(&str, &str)] = &[
    ("task_struct", "pid"),
    ("task_struct", "tgid"),
    ("task_struct", "signal"),
    ("signal_struct", "live"),
    ("task_struct", "thread_pid"),
    ("pid", "level"),
    ("pid", "numbers"),
    ("upid", "nr"),
    ("upid", "ns"),
    ("pid_namespace", "ns"),
    ("ns_common", "inum"),
];

pub(super) fn lifecycle_layout() -> Result<[u32; 12]> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux")
        .context("sysmon lifecycle tracking requires kernel BTF")?;
    parse_layout(&data)
}

fn parse_layout(data: &[u8]) -> Result<[u32; 12]> {
    // Let Aya validate the complete BTF first. Its field lookup API is private;
    // walk the validated wire records to extract the few offsets we need.
    aya::Btf::parse(data, object::Endianness::default())?;
    let word = |at: usize| -> Result<u32> {
        Ok(u32::from_ne_bytes(
            data.get(at..at + 4).context("truncated BTF")?.try_into()?,
        ))
    };
    let header = word(4)? as usize;
    let mut at = header + word(8)? as usize;
    let end = at + word(12)? as usize;
    let strings = header + word(16)? as usize;
    let name = |offset: u32| -> Result<&str> {
        let tail = data
            .get(strings + offset as usize..)
            .context("invalid BTF string")?;
        let len = tail
            .iter()
            .position(|b| *b == 0)
            .context("unterminated BTF string")?;
        Ok(std::str::from_utf8(&tail[..len])?)
    };
    let mut fields = HashMap::new();
    let mut upid_size = None;
    while at < end {
        let type_name = name(word(at)?)?;
        let info = word(at + 4)?;
        let kind = (info >> 24) & 31;
        let count = (info & 0xffff) as usize;
        let size = word(at + 8)?;
        at += 12;
        if kind == 4 && FIELDS.iter().any(|(structure, _)| *structure == type_name) {
            if type_name == "upid" {
                upid_size = Some(size);
            }
            for index in 0..count {
                let member = at + index * 12;
                let member_name = name(word(member)?)?;
                let bits = word(member + 8)?;
                if FIELDS.contains(&(type_name, member_name)) {
                    // These fields are ordinary byte-aligned members, never bitfields.
                    if bits % 8 != 0 || (info >> 31 != 0 && bits >> 24 != 0) {
                        bail!("unexpected bitfield {type_name}.{member_name}");
                    }
                    fields.insert((type_name, member_name), bits / 8);
                }
            }
        }
        at += match kind {
            1 | 14 | 17 => 4,
            3 => 12,
            4 | 5 | 15 | 19 => count * 12,
            6 | 13 => count * 8,
            2 | 7..=12 | 16 | 18 => 0,
            _ => bail!("unsupported BTF kind {kind}"),
        };
    }
    let mut layout = [0; 12];
    for (index, field) in FIELDS.iter().enumerate() {
        layout[index] = *fields
            .get(field)
            .with_context(|| format!("missing kernel field {}.{}", field.0, field.1))?;
    }
    layout[11] = upid_size
        .filter(|size| *size != 0)
        .context("missing upid size")?;
    Ok(layout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_fields_by_name_instead_of_assuming_kernel_offsets() {
        let mut strings = vec![0u8];
        let mut intern = |name: &str| {
            let offset = strings.len() as u32;
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
            offset
        };
        let mut records = Vec::<u32>::new();
        let mut expected = [0u32; 12];
        for structure in [
            "task_struct",
            "signal_struct",
            "pid",
            "upid",
            "pid_namespace",
            "ns_common",
        ] {
            let members: Vec<_> = FIELDS
                .iter()
                .enumerate()
                .filter(|(_, (name, _))| *name == structure)
                .collect();
            records.extend([intern(structure), (4 << 24) | members.len() as u32, 512]);
            for (index, (_, member)) in members.into_iter().rev() {
                expected[index] = (index as u32 + 1) * 8;
                records.extend([intern(member), 0, expected[index] * 8]);
            }
        }
        let types: Vec<_> = records.into_iter().flat_map(u32::to_ne_bytes).collect();
        let mut data = vec![];
        data.extend(0xeb9fu16.to_ne_bytes());
        data.extend([1, 0]);
        for word in [
            24u32,
            0,
            types.len() as u32,
            types.len() as u32,
            strings.len() as u32,
        ] {
            data.extend(word.to_ne_bytes());
        }
        data.extend(types);
        data.extend(strings);
        expected[11] = 512;
        assert_eq!(parse_layout(&data).unwrap(), expected);
        assert!(parse_layout(&data[..23]).is_err());
    }

    #[test]
    fn kernel_layout_rejects_missing_fields() {
        let btf = aya::Btf::new();
        assert!(parse_layout(&btf.to_bytes()).is_err());
    }
}

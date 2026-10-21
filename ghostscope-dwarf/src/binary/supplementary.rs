//! Discover and validate GNU and DWARF 5 supplementary objects.
use super::{DwarfReader, MappedFile};
use anyhow::{bail, Context, Result};
use gimli::Reader;
use object::{Object, ObjectSection};
use std::{collections::HashSet, ffi::OsStr, os::unix::ffi::OsStrExt, path::PathBuf, sync::Arc};

#[derive(Debug)]
enum Link {
    Gnu {
        filename: PathBuf,
        build_id: Vec<u8>,
    },
    Dwarf5 {
        filename: PathBuf,
        checksum: Vec<u8>,
    },
}

struct SupHeader {
    supplementary: bool,
    filename: PathBuf,
    checksum: Vec<u8>,
}

fn read_sup(data: &[u8], endian: gimli::RunTimeEndian) -> Result<SupHeader> {
    let mut reader = gimli::EndianSlice::new(data, endian);
    anyhow::ensure!(reader.read_u16()? == 5, "unsupported .debug_sup version");
    let supplementary = match reader.read_u8()? {
        0 => false,
        1 => true,
        flag => bail!("invalid .debug_sup file role {flag}"),
    };
    let filename_reader = reader.read_null_terminated_slice()?;
    let filename = filename_reader.to_slice()?;
    let filename = PathBuf::from(OsStr::from_bytes(&filename));
    anyhow::ensure!(
        supplementary == filename.as_os_str().is_empty(),
        "invalid .debug_sup filename for file role"
    );
    let len = usize::try_from(reader.read_uleb128()?)?;
    let checksum = reader.split(len)?.to_slice()?.to_vec();
    anyhow::ensure!(reader.is_empty(), "trailing bytes in .debug_sup");
    Ok(SupHeader {
        supplementary,
        filename,
        checksum,
    })
}

pub(crate) fn discover(
    primary: &Arc<MappedFile>,
    search_paths: &[String],
) -> Result<Option<Arc<MappedFile>>> {
    let object = primary.parse_object()?;
    let link = if let Some(section) = object.section_by_name(".debug_sup") {
        let header = read_sup(
            &section.uncompressed_data()?,
            super::dwarf_endian_from_object(&object),
        )
        .with_context(|| format!("invalid .debug_sup in {}", primary.path.display()))?;
        anyhow::ensure!(
            !header.supplementary,
            "{} is a supplementary object, not primary debug information",
            primary.path.display()
        );
        Some(Link::Dwarf5 {
            filename: header.filename,
            checksum: header.checksum,
        })
    } else if let Some((filename, build_id)) = object.gnu_debugaltlink()? {
        anyhow::ensure!(
            !filename.is_empty() && !build_id.is_empty(),
            "empty .gnu_debugaltlink filename or Build-ID in {}",
            primary.path.display()
        );
        Some(Link::Gnu {
            filename: PathBuf::from(OsStr::from_bytes(filename)),
            build_id: build_id.to_vec(),
        })
    } else {
        None
    };
    let Some(link) = link else { return Ok(None) };
    let filename = match &link {
        Link::Gnu { filename, .. } | Link::Dwarf5 { filename, .. } => filename,
    };
    let mut candidates = Vec::new();
    if filename.is_absolute() {
        candidates.push(filename.clone());
    }
    for base in [
        Some(primary.path.clone()),
        std::fs::canonicalize(&primary.path).ok(),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(parent) = base.parent() {
            candidates.push(parent.join(filename));
        }
    }
    for search in search_paths {
        let expanded = if let Some(suffix) = search.strip_prefix("~/") {
            dirs::home_dir()
                .map(|home| home.join(suffix))
                .unwrap_or_else(|| PathBuf::from(search))
        } else {
            PathBuf::from(search)
        };
        candidates.push(expanded.join(filename.strip_prefix("/").unwrap_or(filename)));
        if let Some(name) = filename.file_name() {
            candidates.push(expanded.join(name));
        }
        if let Link::Gnu { build_id, .. } = &link {
            let hex = ghostscope_debuginfod::build_id_to_hex(build_id);
            candidates.push(
                expanded
                    .join(".build-id")
                    .join(&hex[..2])
                    .join(format!("{}.debug", &hex[2..])),
            );
        }
    }
    let mut seen = HashSet::new();
    let mut failures = Vec::new();
    for candidate in candidates {
        if !seen.insert(candidate.clone()) {
            continue;
        }
        let mapped = match MappedFile::open(&candidate) {
            Ok(mapped) => mapped,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                failures.push(format!("{}: {error}", candidate.display()));
                continue;
            }
        };
        let validate = || -> Result<()> {
            let supplementary = mapped.parse_object()?;
            anyhow::ensure!(
                supplementary.format() == object.format()
                    && supplementary.is_64() == object.is_64()
                    && supplementary.endianness() == object.endianness(),
                "supplementary object format/class/byte order mismatch"
            );
            match &link {
                Link::Gnu { build_id, .. } => anyhow::ensure!(
                    supplementary.build_id()? == Some(build_id.as_slice()),
                    "supplementary Build-ID mismatch"
                ),
                Link::Dwarf5 { checksum, .. } => {
                    let section = supplementary
                        .section_by_name(".debug_sup")
                        .context("supplementary object has no .debug_sup")?;
                    let header = read_sup(
                        &section.uncompressed_data()?,
                        super::dwarf_endian_from_object(&supplementary),
                    )?;
                    anyhow::ensure!(
                        header.supplementary
                            && (checksum.is_empty() || header.checksum == *checksum),
                        "supplementary .debug_sup role/checksum mismatch"
                    );
                }
            }
            anyhow::ensure!(
                supplementary.section_by_name(".debug_info").is_some()
                    || supplementary.section_by_name(".debug_str").is_some(),
                "supplementary object has no DWARF sections"
            );
            Ok(())
        };
        match validate() {
            Ok(()) => {
                tracing::info!(
                    "Loading supplementary DWARF {} for {}",
                    mapped.path.display(),
                    primary.path.display()
                );
                return Ok(Some(Arc::new(mapped)));
            }
            Err(error) => failures.push(format!("{}: {error:#}", candidate.display())),
        }
    }
    bail!(
        "required supplementary DWARF '{}' for {} was not found or failed validation{}",
        filename.display(),
        primary.path.display(),
        if failures.is_empty() {
            String::new()
        } else {
            format!(": {}", failures.join("; "))
        }
    )
}

// Keep section readers owned by the same Arc-backed storage as the primary file.
pub(crate) fn reader(file: &Arc<MappedFile>, id: gimli::SectionId) -> Result<DwarfReader> {
    let object = file.parse_object()?;
    let endian = super::dwarf_endian_from_object(&object);
    let Some(section) = object.section_by_name(id.name()) else {
        return Ok(super::empty_dwarf_reader_with_endian(endian));
    };
    if section.compressed_file_range()?.format == object::read::CompressionFormat::None {
        if let Some((start, size)) = section.file_range() {
            return MappedFile::dwarf_reader_range(Arc::clone(file), start, size, endian)
                .context("invalid supplementary section range");
        }
    }
    Ok(super::dwarf_reader_from_arc_with_endian(
        Arc::from(section.uncompressed_data()?.as_ref()),
        endian,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_malformed_dwarf5_links_without_reading_past_the_section() {
        for bytes in [
            vec![],
            vec![5],
            vec![4, 0, 0, b'a', 0, 0],    // truncation / bad version
            vec![5, 0, 2, 0, 0],          // invalid role
            vec![5, 0, 0, 0, 0],          // missing primary filename
            vec![5, 0, 1, b'a', 0, 0],    // supplementary filename must be empty
            vec![5, 0, 0, b'a', 0, 2, 1], // truncated checksum
            vec![
                5, 0, 0, b'a', 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
        ] {
            assert!(
                read_sup(&bytes, gimli::RunTimeEndian::Little).is_err(),
                "{bytes:?}"
            );
        }
    }

    #[test]
    fn reads_big_endian_dwarf5_header_and_an_optional_checksum() {
        let header = read_sup(&[0, 5, 0, b'a', 0, 0], gimli::RunTimeEndian::Big).unwrap();
        assert!(!header.supplementary);
        assert!(header.checksum.is_empty());
        assert_eq!(header.filename, PathBuf::from("a"));
    }
}

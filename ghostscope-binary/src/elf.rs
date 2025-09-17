use crate::{BinaryError, Result};
use object::{Object, ObjectSection, ObjectSegment};
use std::path::Path;
use tracing::{debug, info, warn};

/// ELF file information
#[derive(Debug, Clone)]
pub(crate) struct ElfInfo {
    pub entry_point: u64,
    pub base_address: u64,
    pub architecture: String,
    pub is_64bit: bool,
    pub is_executable: bool,
    pub has_debug_sections: bool,
}

/// Parse ELF file and extract basic information
pub(crate) fn parse_elf<P: AsRef<Path>>(path: P) -> Result<ElfInfo> {
    let path = path.as_ref();
    info!("Parsing ELF file: {}", path.display());

    let file_data = std::fs::read(path)?;
    let object_file = object::File::parse(&*file_data)?;

    let entry_point = object_file.entry();
    let architecture = format!("{:?}", object_file.architecture());
    let is_64bit = object_file.is_64();
    let is_executable = matches!(object_file.kind(), object::ObjectKind::Executable);

    // Calculate base address
    let base_address = if is_executable {
        // For executables, base address is typically the lowest loadable segment address
        calculate_base_address(&object_file)
    } else {
        0 // For shared libraries, we'll handle relocation later
    };

    // Check for debug sections
    let has_debug_sections = has_debug_information(&object_file);

    let elf_info = ElfInfo {
        entry_point,
        base_address,
        architecture,
        is_64bit,
        is_executable,
        has_debug_sections,
    };

    debug!("ELF info: {:?}", elf_info);
    Ok(elf_info)
}

/// Calculate base address for the executable
fn calculate_base_address(object_file: &object::File) -> u64 {
    // Find the lowest virtual address of loadable segments
    let mut min_addr = u64::MAX;

    for segment in object_file.segments() {
        let addr = segment.address();
        if addr > 0 && addr < min_addr {
            min_addr = addr;
        }
    }

    if min_addr == u64::MAX {
        0
    } else {
        min_addr
    }
}

/// Check if the ELF file contains debug information
fn has_debug_information(object_file: &object::File) -> bool {
    for section in object_file.sections() {
        if let Ok(name) = section.name() {
            if name.starts_with(".debug_") {
                debug!("Found debug section: {}", name);
                return true;
            }
        }
    }
    false
}

/// Extract section data by name
pub(crate) fn get_section_data<P: AsRef<Path>>(
    path: P,
    section_name: &str,
) -> Result<Option<Vec<u8>>> {
    let path = path.as_ref();
    let file_data = std::fs::read(path)?;
    let object_file = object::File::parse(&*file_data)?;

    for section in object_file.sections() {
        if let Ok(name) = section.name() {
            if name == section_name {
                match section.data() {
                    Ok(data) => {
                        debug!("Found section '{}' with {} bytes", section_name, data.len());
                        return Ok(Some(data.to_vec()));
                    }
                    Err(e) => {
                        warn!("Failed to read section '{}': {}", section_name, e);
                        return Err(BinaryError::Object(e));
                    }
                }
            }
        }
    }

    debug!("Section '{}' not found", section_name);
    Ok(None)
}

/// Get all section names in the ELF file
pub(crate) fn list_sections<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let path = path.as_ref();
    let file_data = std::fs::read(path)?;
    let object_file = object::File::parse(&*file_data)?;

    let mut sections = Vec::new();

    for section in object_file.sections() {
        if let Ok(name) = section.name() {
            sections.push(name.to_string());
        }
    }

    debug!("Found {} sections in ELF file", sections.len());
    Ok(sections)
}

/// Check if ELF file has specific section
pub(crate) fn has_section<P: AsRef<Path>>(path: P, section_name: &str) -> Result<bool> {
    let path = path.as_ref();
    let file_data = std::fs::read(path)?;
    let object_file = object::File::parse(&*file_data)?;

    for section in object_file.sections() {
        if let Ok(name) = section.name() {
            if name == section_name {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

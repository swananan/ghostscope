use anyhow::{Context, Result};
use memmap2::MmapOptions;
use object::{Architecture, BinaryFormat, Endianness, Object};
use std::fs::File;
use std::path::{Path, PathBuf};

pub const SUPPORTED_TARGET_DESCRIPTION: &str = "64-bit little-endian x86_64 ELF";

pub fn ensure_supported_target_path(path: &Path) -> Result<()> {
    let file = File::open(path)
        .with_context(|| format!("failed to open target object {}", path.display()))?;
    // SAFETY: The file is opened read-only and the mapping is used immutably
    // only for object-header validation during this call.
    let mapped = unsafe { MmapOptions::new().map(&file) }
        .with_context(|| format!("failed to map target object {}", path.display()))?;
    let object = object::File::parse(&mapped[..])
        .with_context(|| format!("failed to parse target object {}", path.display()))?;

    ensure_supported_target_object(&object, path)
}

pub fn ensure_supported_pid_executable(pid: u32) -> Result<()> {
    let executable = PathBuf::from(format!("/proc/{pid}/exe"));
    ensure_supported_target_path(&executable)
        .with_context(|| format!("target process {pid} is not supported"))
}

pub fn ensure_supported_target_object(object: &object::File<'_>, path: &Path) -> Result<()> {
    let supported = object.format() == BinaryFormat::Elf
        && object.architecture() == Architecture::X86_64
        && object.is_64()
        && object.endianness() == Endianness::Little;

    if !supported {
        anyhow::bail!(
            "unsupported target object {}: expected {}, found format={:?}, architecture={:?}, \
             class={}, endianness={:?}",
            path.display(),
            SUPPORTED_TARGET_DESCRIPTION,
            object.format(),
            object.architecture(),
            if object.is_64() { "64-bit" } else { "32-bit" },
            object.endianness(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const EM_386: u16 = 3;
    const EM_X86_64: u16 = 62;
    const EM_AARCH64: u16 = 183;

    fn elf64(machine: u16) -> [u8; 64] {
        let mut elf = [0u8; 64];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&machine.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf
    }

    fn elf32(machine: u16) -> [u8; 52] {
        let mut elf = [0u8; 52];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 1;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&machine.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[40..42].copy_from_slice(&52u16.to_le_bytes());
        elf
    }

    fn validate_bytes(bytes: &[u8]) -> Result<()> {
        let mut file = tempfile::NamedTempFile::new()?;
        file.write_all(bytes)?;
        ensure_supported_target_path(file.path())
    }

    #[test]
    fn accepts_x86_64_elf() {
        validate_bytes(&elf64(EM_X86_64)).expect("x86_64 ELF should be supported");
    }

    #[test]
    fn rejects_aarch64_elf() {
        let error = validate_bytes(&elf64(EM_AARCH64)).expect_err("AArch64 must be rejected");
        let message = error.to_string();
        assert!(message.contains(SUPPORTED_TARGET_DESCRIPTION));
        assert!(message.contains("architecture=Aarch64"));
    }

    #[test]
    fn rejects_32_bit_x86_elf() {
        let error = validate_bytes(&elf32(EM_386)).expect_err("32-bit x86 must be rejected");
        let message = error.to_string();
        assert!(message.contains(SUPPORTED_TARGET_DESCRIPTION));
        assert!(message.contains("architecture=I386"));
        assert!(message.contains("class=32-bit"));
    }
}

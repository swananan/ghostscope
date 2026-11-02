use std::borrow::Cow;

use gimli::{Reader, ReaderOffsetId};

use crate::binary::{dwarf_reader_from_arc_with_endian, DwarfEndian, DwarfReader};

/// CFI-only adapter for gimli's missing AArch64 `B` augmentation support.
/// `B` selects the return-address authentication key and carries no payload:
/// https://github.com/ARM-software/abi-aa/blob/main/aadwarf64/aadwarf64.rst
/// GhostScope strips PAC without authenticating, so either key uses the same
/// recovery plan. Keep the original section and cursor offsets intact (including
/// PC-relative personality pointers); only the isolated augmentation string is
/// filtered. Remove this adapter when gimli understands `B` natively.
#[derive(Clone, Debug)]
pub(super) struct CfiReader {
    pub(super) inner: DwarfReader,
    aarch64: bool,
}

impl CfiReader {
    pub(super) fn new(inner: DwarfReader, aarch64: bool) -> Self {
        Self { inner, aarch64 }
    }
}

impl Reader for CfiReader {
    type Endian = DwarfEndian;
    type Offset = usize;

    fn endian(&self) -> Self::Endian {
        self.inner.endian()
    }
    fn len(&self) -> usize {
        self.inner.len()
    }
    fn empty(&mut self) {
        self.inner.empty()
    }
    fn truncate(&mut self, len: usize) -> gimli::Result<()> {
        self.inner.truncate(len)
    }
    fn offset_from(&self, base: &Self) -> usize {
        self.inner.offset_from(&base.inner)
    }
    fn offset_id(&self) -> ReaderOffsetId {
        self.inner.offset_id()
    }
    fn lookup_offset_id(&self, id: ReaderOffsetId) -> Option<usize> {
        self.inner.lookup_offset_id(id)
    }
    fn find(&self, byte: u8) -> gimli::Result<usize> {
        self.inner.find(byte)
    }
    fn skip(&mut self, len: usize) -> gimli::Result<()> {
        self.inner.skip(len)
    }
    fn split(&mut self, len: usize) -> gimli::Result<Self> {
        Ok(Self::new(self.inner.split(len)?, self.aarch64))
    }
    fn to_slice(&self) -> gimli::Result<Cow<'_, [u8]>> {
        self.inner.to_slice()
    }
    fn to_string(&self) -> gimli::Result<Cow<'_, str>> {
        self.inner.to_string()
    }
    fn to_string_lossy(&self) -> gimli::Result<Cow<'_, str>> {
        self.inner.to_string_lossy()
    }
    fn read_slice(&mut self, buf: &mut [u8]) -> gimli::Result<()> {
        self.inner.read_slice(buf)
    }

    fn read_null_terminated_slice(&mut self) -> gimli::Result<Self> {
        // In CFI, the only NUL-terminated string is the CIE augmentation.
        // gimli reads its characters independently of the section's offsets.
        let mut string = self.inner.read_null_terminated_slice()?;
        if self.aarch64 && string.to_slice()?.contains(&b'B') {
            let bytes: Vec<_> = string
                .to_slice()?
                .iter()
                .copied()
                .filter(|c| *c != b'B')
                .collect();
            string = dwarf_reader_from_arc_with_endian(bytes.into(), self.endian());
        }
        Ok(Self::new(string, self.aarch64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b_key_cie_preserves_pc_relative_personality_and_signal_flag() {
        use gimli::{BaseAddresses, EhFrame, EhFrameOffset, Pointer, UnwindSection};
        let mut bytes = vec![0; 8]; // Length and CIE ID.
        bytes.push(1); // CIE version.
        bytes.extend_from_slice(b"zBPR\0");
        bytes.extend_from_slice(&[1, 0x78, 30, 6, 0x1b]);
        let personality_offset = bytes.len();
        bytes.extend_from_slice(&0x20u32.to_le_bytes());
        bytes.extend_from_slice(&[0x1b, 0x0c, 31, 0]);
        let length = (bytes.len() - 4) as u32;
        bytes[..4].copy_from_slice(&length.to_le_bytes());
        let inner = dwarf_reader_from_arc_with_endian(bytes.into(), gimli::RunTimeEndian::Little);
        let mut frame = EhFrame::from(CfiReader::new(inner, true));
        frame.set_address_size(8);
        let cie = frame
            .cie_from_offset(
                &BaseAddresses::default().set_eh_frame(0x1000),
                EhFrameOffset(0),
            )
            .unwrap();
        assert_eq!(
            cie.personality(),
            Some(Pointer::Direct(0x1000 + personality_offset as u64 + 0x20))
        );
        assert!(!cie.is_signal_trampoline());
        assert_eq!(
            cie.fde_address_encoding(),
            Some(gimli::DW_EH_PE_pcrel | gimli::DW_EH_PE_sdata4)
        );
    }

    #[test]
    fn b_key_filter_preserves_section_offsets_and_other_flags() {
        for (aarch64, expected) in [(true, &b"zPRS"[..]), (false, &b"zBPRS"[..])] {
            let inner = dwarf_reader_from_arc_with_endian(
                b"zBPRS\0\x10\x20\x30".to_vec().into(),
                gimli::RunTimeEndian::Little,
            );
            let mut reader = CfiReader::new(inner, aarch64);
            let base = reader.clone();
            assert_eq!(
                reader
                    .read_null_terminated_slice()
                    .unwrap()
                    .to_slice()
                    .unwrap()
                    .as_ref(),
                expected
            );
            assert_eq!(reader.offset_from(&base), 6);
            assert_eq!(reader.to_slice().unwrap().as_ref(), &[0x10, 0x20, 0x30]);
        }
    }
}

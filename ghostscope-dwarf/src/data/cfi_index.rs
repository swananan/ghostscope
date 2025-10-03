//! CFI (Call Frame Information) index for fast CFA lookup
//!
//! This module provides efficient access to CFA (Canonical Frame Address) rules
//! by utilizing eh_frame_hdr's binary search table when available.

use crate::core::{CfaResult, ComputeStep, Result};
use anyhow::{anyhow, Context};
use gimli::{
    BaseAddresses, CfaRule, CieOrFde, EhFrame, EhFrameHdr, FrameDescriptionEntry, LittleEndian,
    ParsedEhFrameHdr, UnwindContext, UnwindSection,
};
use object::{Object, ObjectSection};
use std::sync::Arc;
use tracing::{debug, info, warn};

use gimli::{EndianSlice, LittleEndian as LE};

/// CFI index for fast CFA rule lookup
pub struct CfiIndex {
    /// Keep file data alive
    _file_data: Arc<[u8]>,
    /// Keep eh_frame section data alive
    _eh_frame_data: Arc<[u8]>,
    /// Keep eh_frame_hdr section data alive (if present)
    _eh_frame_hdr_data: Option<Arc<[u8]>>,
    /// Parsed eh_frame section (using 'static via Box::leak)
    eh_frame: EhFrame<EndianSlice<'static, LE>>,
    /// Parsed eh_frame_hdr for fast lookup (if available)
    eh_frame_hdr: Option<ParsedEhFrameHdr<EndianSlice<'static, LE>>>,
    /// Base addresses for DWARF sections
    bases: BaseAddresses,
    /// Whether we have eh_frame_hdr for fast lookup
    has_fast_lookup: bool,
}

impl std::fmt::Debug for CfiIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CfiIndex")
            .field("has_fast_lookup", &self.has_fast_lookup)
            .field("has_eh_frame_hdr", &self.eh_frame_hdr.is_some())
            .finish()
    }
}

impl CfiIndex {
    /// Create a new CFI index from an object file data
    pub fn from_arc_data(file_data: Arc<[u8]>) -> Result<Self> {
        let object = object::File::parse(&file_data[..]).context("Failed to parse object file")?;

        // Load eh_frame section (required)
        let eh_frame_section = object
            .section_by_name(".eh_frame")
            .ok_or_else(|| anyhow!(".eh_frame section not found"))?;

        // Get section data range
        let (eh_frame_start, eh_frame_size) = eh_frame_section
            .file_range()
            .ok_or_else(|| anyhow!(".eh_frame section has no file range"))?;
        let eh_frame_start = eh_frame_start as usize;
        let eh_frame_end = eh_frame_start + eh_frame_size as usize;

        // Create Arc slice for eh_frame and leak to 'static
        // Note: We must copy once for Box::leak (gimli's EhFrame requires 'static lifetime)
        let eh_frame_data = file_data[eh_frame_start..eh_frame_end].to_vec();
        let eh_frame_static: &'static [u8] = Box::leak(eh_frame_data.into_boxed_slice());
        let eh_frame_arc: Arc<[u8]> = Arc::from(eh_frame_static); // Zero-copy: reference leaked data
        let eh_frame = EhFrame::new(eh_frame_static, LittleEndian);

        // Try to load eh_frame_hdr for fast lookup (optional)
        let mut hdr_arc_opt: Option<Arc<[u8]>> = None;
        let (eh_frame_hdr, has_fast_lookup) = match object.section_by_name(".eh_frame_hdr") {
            Some(hdr_section_obj) => {
                let (hdr_start, hdr_size) = hdr_section_obj
                    .file_range()
                    .ok_or_else(|| anyhow!(".eh_frame_hdr section has no file range"))?;
                let hdr_start = hdr_start as usize;
                let hdr_end = hdr_start + hdr_size as usize;

                // Create Arc slice for eh_frame_hdr and leak to 'static
                let hdr_data = file_data[hdr_start..hdr_end].to_vec();
                let hdr_static: &'static [u8] = Box::leak(hdr_data.into_boxed_slice());
                let hdr_arc: Arc<[u8]> = Arc::from(hdr_static); // Zero-copy: reference leaked data
                hdr_arc_opt = Some(hdr_arc);
                let hdr_section = EhFrameHdr::new(hdr_static, LittleEndian);

                // Parse with proper address_size
                let address_size = if object.is_64() { 8 } else { 4 };
                let mut bases = BaseAddresses::default();

                // Set eh_frame_hdr section base
                bases = bases.set_eh_frame_hdr(hdr_section_obj.address());

                match hdr_section.parse(&bases, address_size) {
                    Ok(parsed) => {
                        info!("Successfully parsed .eh_frame_hdr for fast FDE lookup");
                        (Some(parsed), true)
                    }
                    Err(e) => {
                        warn!(
                            "Failed to parse .eh_frame_hdr: {:?}, falling back to linear search",
                            e
                        );
                        (None, false)
                    }
                }
            }
            None => {
                debug!(".eh_frame_hdr not found, will use linear FDE search");
                (None, false)
            }
        };

        // Setup base addresses for all sections
        let mut bases = BaseAddresses::default();

        // Set eh_frame base
        if let Some(eh_frame_section) = object.section_by_name(".eh_frame") {
            bases = bases.set_eh_frame(eh_frame_section.address());
        }

        // Set text base (for function addresses)
        if let Some(text_section) = object.section_by_name(".text") {
            bases = bases.set_text(text_section.address());
        }

        // Set eh_frame_hdr base if we have it
        if let Some(hdr_section) = object.section_by_name(".eh_frame_hdr") {
            bases = bases.set_eh_frame_hdr(hdr_section.address());
        }

        Ok(Self {
            _file_data: file_data.clone(),
            _eh_frame_data: eh_frame_arc,
            _eh_frame_hdr_data: hdr_arc_opt,
            eh_frame,
            eh_frame_hdr,
            bases,
            has_fast_lookup,
        })
    }

    /// Get CFA rule for given PC (file offset) and convert to CfaResult
    pub fn get_cfa_result(&self, pc: u64) -> Result<CfaResult> {
        debug!("Looking up CFA rule for PC 0x{:x}", pc);

        // 1. Find FDE for this address
        let fde = self.find_fde_for_address(pc)?;

        debug!(
            "Found FDE for PC 0x{:x}: initial_address=0x{:x}, range={}",
            pc,
            fde.initial_address(),
            fde.len()
        );

        // 2. Get unwind info for specific address
        let mut ctx = UnwindContext::new();
        let unwind_row = fde
            .unwind_info_for_address(&self.eh_frame, &self.bases, &mut ctx, pc)
            .context("Failed to get unwind info for address")?;

        // 3. Convert gimli CfaRule to our CfaResult
        let cfa = match unwind_row.cfa() {
            CfaRule::RegisterAndOffset { register, offset } => CfaResult::RegisterPlusOffset {
                register: register.0,
                offset: *offset,
            },
            CfaRule::Expression(expr) => {
                // Get the expression bytes from the section
                let expression = expr.get(&self.eh_frame)?;
                // Parse DWARF expression to compute steps
                // expression.0 is EndianSlice, get the underlying bytes
                use gimli::Reader;
                let temp = expression.0.to_slice().ok();
                let expr_bytes = temp.as_deref().unwrap_or(&[]);
                let steps = self.parse_dwarf_expression(expr_bytes)?;
                CfaResult::Expression { steps }
            }
        };

        debug!("CFA result at PC 0x{:x}: {:?}", pc, cfa);

        Ok(cfa)
    }

    /// Find FDE for given address using eh_frame_hdr if available
    fn find_fde_for_address(
        &self,
        address: u64,
    ) -> Result<FrameDescriptionEntry<EndianSlice<'static, LE>, usize>> {
        if let Some(hdr) = &self.eh_frame_hdr {
            // Fast path: O(log n) binary search using eh_frame_hdr
            debug!(
                "Using eh_frame_hdr binary search for address 0x{:x}",
                address
            );

            let table = hdr
                .table()
                .ok_or_else(|| anyhow!("No search table in eh_frame_hdr"))?;

            table
                .fde_for_address(
                    &self.eh_frame,
                    &self.bases,
                    address,
                    |eh_frame, bases, offset| eh_frame.cie_from_offset(bases, offset),
                )
                .context("Failed to find FDE for address")
        } else {
            // Slow path: O(n) linear search through all FDEs
            debug!("Using linear FDE search for address 0x{:x}", address);

            let mut entries = self.eh_frame.entries(&self.bases);

            while let Some(entry) = entries.next().context("Failed to iterate FDE entries")? {
                match entry {
                    CieOrFde::Fde(partial_fde) => {
                        // Parse the FDE
                        let fde = partial_fde
                            .parse(|_, bases, offset| self.eh_frame.cie_from_offset(bases, offset))
                            .context("Failed to parse FDE")?;

                        // Check if address falls within this FDE's range
                        if fde.contains(address) {
                            return Ok(fde);
                        }
                    }
                    CieOrFde::Cie(_) => {
                        // Skip CIE entries
                    }
                }
            }

            Err(anyhow!("No FDE found for address 0x{:x}", address))
        }
    }

    /// Parse DWARF expression bytes into ComputeStep sequence
    fn parse_dwarf_expression(&self, expr_bytes: &[u8]) -> Result<Vec<ComputeStep>> {
        let mut steps = Vec::new();
        let mut pc = 0;

        while pc < expr_bytes.len() {
            let opcode = expr_bytes[pc];
            pc += 1;

            match opcode {
                // DW_OP_breg0..DW_OP_breg31
                0x70..=0x8f => {
                    let register = (opcode - 0x70) as u16;
                    // Read SLEB128 offset
                    let (offset, bytes_read) = self.read_sleb128(&expr_bytes[pc..])?;
                    pc += bytes_read;

                    steps.push(ComputeStep::LoadRegister(register));
                    if offset != 0 {
                        steps.push(ComputeStep::PushConstant(offset));
                        steps.push(ComputeStep::Add);
                    }
                }
                // DW_OP_plus_uconst
                0x23 => {
                    let (value, bytes_read) = self.read_uleb128(&expr_bytes[pc..])?;
                    pc += bytes_read;
                    steps.push(ComputeStep::PushConstant(value as i64));
                    steps.push(ComputeStep::Add);
                }
                // DW_OP_lit0..DW_OP_lit31
                0x30..=0x4f => {
                    let value = (opcode - 0x30) as i64;
                    steps.push(ComputeStep::PushConstant(value));
                }
                // DW_OP_plus
                0x22 => steps.push(ComputeStep::Add),
                // DW_OP_minus
                0x1c => steps.push(ComputeStep::Sub),
                // DW_OP_mul
                0x1e => steps.push(ComputeStep::Mul),
                // DW_OP_and
                0x1a => steps.push(ComputeStep::And),
                // DW_OP_or
                0x21 => steps.push(ComputeStep::Or),
                // DW_OP_xor
                0x27 => steps.push(ComputeStep::Xor),

                _ => {
                    debug!("Unhandled DWARF opcode 0x{:02x} in CFA expression", opcode);
                    // For now, skip unknown opcodes
                }
            }
        }

        Ok(steps)
    }

    /// Read ULEB128 from byte slice
    fn read_uleb128(&self, data: &[u8]) -> Result<(u64, usize)> {
        let mut result = 0u64;
        let mut shift = 0;
        let mut bytes_read = 0;

        for &byte in data {
            bytes_read += 1;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok((result, bytes_read));
            }
            shift += 7;
        }

        Err(anyhow!("Invalid ULEB128 encoding"))
    }

    /// Read SLEB128 from byte slice
    fn read_sleb128(&self, data: &[u8]) -> Result<(i64, usize)> {
        let mut result = 0i64;
        let mut shift = 0;
        let mut bytes_read = 0;
        let mut byte = 0u8;

        for &b in data {
            byte = b;
            bytes_read += 1;
            result |= ((byte & 0x7f) as i64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }

        // Sign extend
        if shift < 64 && (byte & 0x40) != 0 {
            result |= -(1i64 << shift);
        }

        Ok((result, bytes_read))
    }

    /// Check if fast lookup is available
    pub fn has_fast_lookup(&self) -> bool {
        self.has_fast_lookup
    }

    /// Get statistics about the CFI index
    pub fn get_stats(&self) -> CfiStats {
        CfiStats {
            has_eh_frame_hdr: self.eh_frame_hdr.is_some(),
            has_fast_lookup: self.has_fast_lookup,
        }
    }
}

/// Statistics about CFI index
#[derive(Debug, Clone)]
pub struct CfiStats {
    pub has_eh_frame_hdr: bool,
    pub has_fast_lookup: bool,
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_cfi_index_creation() {
        // This would need a real ELF file for testing
        // For now, just ensure the module compiles
    }
}

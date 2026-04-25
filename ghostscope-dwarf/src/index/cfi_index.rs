//! CFI (Call Frame Information) index for fast CFA lookup
//!
//! This module provides efficient access to CFA (Canonical Frame Address) rules
//! by utilizing eh_frame_hdr's binary search table when available.

use crate::{
    binary::{dwarf_endian_from_object, DwarfReader, MappedFile},
    core::{CallerFrameRecovery, CfaResult, ComputeStep, Result},
};
use anyhow::{anyhow, Context};
use gimli::{
    BaseAddresses, CfaRule, CieOrFde, EhFrame, EhFrameHdr, FrameDescriptionEntry, ParsedEhFrameHdr,
    Register, RegisterRule, UnwindContext, UnwindSection,
};
use object::{Object, ObjectSection};
use std::{collections::BTreeMap, sync::Arc};
use tracing::{debug, info, warn};

/// CFI index for fast CFA rule lookup
#[derive(Clone)]
pub struct CfiIndex {
    /// Keep file data alive
    _file_data: Arc<MappedFile>,
    /// Parsed eh_frame section
    eh_frame: EhFrame<DwarfReader>,
    /// Parsed eh_frame_hdr for fast lookup (if available)
    eh_frame_hdr: Option<ParsedEhFrameHdr<DwarfReader>>,
    /// Base addresses for DWARF sections
    bases: BaseAddresses,
    /// Encoding used when parsing CFI DWARF expressions.
    encoding: gimli::Encoding,
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
    pub fn from_mapped_file(file_data: Arc<MappedFile>) -> Result<Self> {
        let object = file_data
            .parse_object()
            .context("Failed to parse object file")?;
        let endian = dwarf_endian_from_object(&object);
        let address_size = if object.is_64() { 8 } else { 4 };
        let encoding = gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 4,
            address_size,
        };

        // Load eh_frame section (required)
        let eh_frame_section = object
            .section_by_name(".eh_frame")
            .ok_or_else(|| anyhow!(".eh_frame section not found"))?;

        // Get section data range
        let (eh_frame_start, eh_frame_size) = eh_frame_section
            .file_range()
            .ok_or_else(|| anyhow!(".eh_frame section has no file range"))?;
        let eh_frame_reader = MappedFile::dwarf_reader_range(
            Arc::clone(&file_data),
            eh_frame_start,
            eh_frame_size,
            endian,
        )
        .ok_or_else(|| anyhow!("Invalid .eh_frame range in mapped file"))?;
        let eh_frame = EhFrame::from(eh_frame_reader);

        // Try to load eh_frame_hdr for fast lookup (optional)
        let (eh_frame_hdr, has_fast_lookup) = match object.section_by_name(".eh_frame_hdr") {
            Some(hdr_section_obj) => {
                let (hdr_start, hdr_size) = hdr_section_obj
                    .file_range()
                    .ok_or_else(|| anyhow!(".eh_frame_hdr section has no file range"))?;
                let hdr_reader = MappedFile::dwarf_reader_range(
                    Arc::clone(&file_data),
                    hdr_start,
                    hdr_size,
                    endian,
                )
                .ok_or_else(|| anyhow!("Invalid .eh_frame_hdr range in mapped file"))?;
                let hdr_section = EhFrameHdr::from(hdr_reader);

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
            _file_data: file_data,
            eh_frame,
            eh_frame_hdr,
            bases,
            encoding,
            has_fast_lookup,
        })
    }

    /// Get CFA rule for given PC (file offset) and convert to CfaResult
    pub fn get_cfa_result(&self, pc: u64) -> Result<CfaResult> {
        debug!("Looking up CFA rule for PC 0x{:x}", pc);
        let unwind_row = self.unwind_row_for_pc(pc)?;

        // 3. Convert gimli CfaRule to our CfaResult
        let cfa = match unwind_row.cfa() {
            CfaRule::RegisterAndOffset { register, offset } => CfaResult::RegisterPlusOffset {
                register: register.0,
                offset: *offset,
            },
            CfaRule::Expression(expr) => {
                let expression = expr.get(&self.eh_frame)?;
                let steps = crate::dwarf_expr::cfa::parse_expression(expression.0, self.encoding)?;
                CfaResult::Expression { steps }
            }
        };

        debug!("CFA result at PC 0x{:x}: {:?}", pc, cfa);

        Ok(cfa)
    }

    /// Recover a caller-frame register value as ComputeStep[] that can be
    /// evaluated from the current frame state.
    pub fn recover_caller_register_steps(
        &self,
        pc: u64,
        register: u16,
    ) -> Result<Option<Vec<ComputeStep>>> {
        let recovery = self.recover_caller_frame(pc, &[register])?;
        Ok(recovery.register_recovery_steps.get(&register).cloned())
    }

    /// Recover the direct caller frame at `pc` as ComputeStep[].
    pub fn recover_caller_frame(&self, pc: u64, registers: &[u16]) -> Result<CallerFrameRecovery> {
        let fde = self.find_fde_for_address(pc)?;
        let mut ctx = UnwindContext::new();
        let unwind_row = fde
            .unwind_info_for_address(&self.eh_frame, &self.bases, &mut ctx, pc)
            .context("Failed to get unwind info for address")?
            .clone();

        let cfa_steps = self.cfa_steps(unwind_row.cfa())?;
        let return_address_register = fde.cie().return_address_register().0;
        let caller_pc_steps = self
            .register_rule_steps(&unwind_row, return_address_register)?
            .ok_or_else(|| {
                anyhow!(
                    "no caller PC recovery rule for DWARF register {} at 0x{:x}",
                    return_address_register,
                    pc
                )
            })?;

        let mut register_recovery_steps = BTreeMap::new();
        for &register in registers {
            if let Some(steps) = self.register_rule_steps(&unwind_row, register)? {
                register_recovery_steps.insert(register, steps);
            }
        }

        Ok(CallerFrameRecovery {
            cfa_steps,
            return_address_register,
            caller_pc_steps,
            register_recovery_steps,
        })
    }

    /// Find FDE for given address using eh_frame_hdr if available
    fn find_fde_for_address(
        &self,
        address: u64,
    ) -> Result<FrameDescriptionEntry<DwarfReader, usize>> {
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

    fn unwind_row_for_pc(&self, pc: u64) -> Result<gimli::UnwindTableRow<usize>> {
        let fde = self.find_fde_for_address(pc)?;

        debug!(
            "Found FDE for PC 0x{:x}: initial_address=0x{:x}, range={}",
            pc,
            fde.initial_address(),
            fde.len()
        );

        let mut ctx = UnwindContext::new();
        fde.unwind_info_for_address(&self.eh_frame, &self.bases, &mut ctx, pc)
            .context("Failed to get unwind info for address")
            .cloned()
    }

    fn cfa_steps(&self, rule: &CfaRule<usize>) -> Result<Vec<ComputeStep>> {
        match rule {
            CfaRule::RegisterAndOffset { register, offset } => {
                let mut steps = vec![ComputeStep::LoadRegister(register.0)];
                if *offset != 0 {
                    steps.push(ComputeStep::PushConstant(*offset));
                    steps.push(ComputeStep::Add);
                }
                Ok(steps)
            }
            CfaRule::Expression(expr) => self.parse_unwind_expression(*expr),
        }
    }

    fn register_rule_steps(
        &self,
        unwind_row: &gimli::UnwindTableRow<usize>,
        register: u16,
    ) -> Result<Option<Vec<ComputeStep>>> {
        let cfa_steps = self.cfa_steps(unwind_row.cfa())?;
        let rule = unwind_row
            .register(Register(register))
            .or_else(|| Self::default_register_rule(register));

        match rule {
            Some(RegisterRule::Undefined) => Ok(None),
            Some(RegisterRule::SameValue) => Ok(Some(vec![ComputeStep::LoadRegister(register)])),
            Some(RegisterRule::Register(other)) => {
                Ok(Some(vec![ComputeStep::LoadRegister(other.0)]))
            }
            Some(RegisterRule::Offset(offset)) => {
                let mut steps = cfa_steps;
                if offset != 0 {
                    steps.push(ComputeStep::PushConstant(offset));
                    steps.push(ComputeStep::Add);
                }
                steps.push(ComputeStep::Dereference {
                    size: crate::core::MemoryAccessSize::U64,
                });
                Ok(Some(steps))
            }
            Some(RegisterRule::ValOffset(offset)) => {
                let mut steps = cfa_steps;
                if offset != 0 {
                    steps.push(ComputeStep::PushConstant(offset));
                    steps.push(ComputeStep::Add);
                }
                Ok(Some(steps))
            }
            Some(RegisterRule::Expression(expr)) => {
                let mut steps = self.parse_unwind_expression(expr)?;
                steps.push(ComputeStep::Dereference {
                    size: crate::core::MemoryAccessSize::U64,
                });
                Ok(Some(steps))
            }
            Some(RegisterRule::ValExpression(expr)) => {
                Ok(Some(self.parse_unwind_expression(expr)?))
            }
            Some(RegisterRule::Constant(value)) => {
                Ok(Some(vec![ComputeStep::PushConstant(value as i64)]))
            }
            Some(RegisterRule::Architectural) | None => Ok(None),
        }
    }

    fn parse_unwind_expression(
        &self,
        expr: gimli::UnwindExpression<usize>,
    ) -> Result<Vec<ComputeStep>> {
        let expression = expr.get(&self.eh_frame)?;
        crate::dwarf_expr::cfa::parse_expression(expression.0, self.encoding)
    }

    fn default_register_rule(register: u16) -> Option<RegisterRule<usize>> {
        match register {
            // x86_64 callee-saved general-purpose registers remain valid in the
            // current pt_regs snapshot when there is no explicit unwind rule.
            3 | 6 | 12..=15 => Some(RegisterRule::SameValue),
            _ => None,
        }
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

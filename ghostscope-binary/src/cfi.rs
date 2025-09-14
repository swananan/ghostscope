// Call Frame Information (CFI) parsing and management
// Provides DWARF expression queries for frame base and register unwinding

use crate::Result;
use gimli::{BaseAddresses, EhFrame, EhFrameHdr, LittleEndian, UnwindSection};
use std::cell::RefCell;
use tracing::{debug, info};

/// CFI context for managing call frame information
#[derive(Debug)]
pub(crate) struct CFIContext {
    /// Base addresses for address computations
    base_addresses: BaseAddresses,
    /// Original .eh_frame section data for lazy parsing
    eh_frame_data: Option<Vec<u8>>,
    /// Original .debug_frame section data for lazy parsing
    debug_frame_data: Option<Vec<u8>>,
    /// eh_frame_hdr data for eh_frame_hdr based lookup
    eh_frame_hdr_data: Option<Vec<u8>>,
    /// Flag to indicate if eh_frame_hdr parsing has been validated
    eh_frame_hdr_validated: bool,
    /// Cached parsing metadata to optimize repeated eh_frame_hdr parsing
    cached_has_table: RefCell<Option<bool>>,
}

impl CFIContext {
    /// Create new CFI context
    pub fn new() -> Self {
        Self {
            base_addresses: BaseAddresses::default(),
            eh_frame_data: None,
            debug_frame_data: None,
            eh_frame_hdr_data: None,
            eh_frame_hdr_validated: false,
            cached_has_table: RefCell::new(None),
        }
    }

    /// Load eh_frame_hdr section for efficient PC-to-FDE lookups
    pub fn load_eh_frame_hdr(
        &mut self,
        eh_frame_hdr_data: &[u8],
        base_addresses: BaseAddresses,
    ) -> Result<()> {
        self.base_addresses = base_addresses.clone();
        self.eh_frame_hdr_data = Some(eh_frame_hdr_data.to_vec());

        // Parse and cache metadata about the header
        let eh_frame_hdr = EhFrameHdr::new(eh_frame_hdr_data, LittleEndian);
        let parsed_hdr = eh_frame_hdr.parse(&base_addresses, 8)?; // 8 bytes for x86_64

        // Cache whether this eh_frame_hdr has a lookup table to optimize repeated parsing
        let has_table = parsed_hdr.table().is_some();
        *self.cached_has_table.borrow_mut() = Some(has_table);

        self.eh_frame_hdr_validated = true;
        info!(
            "Successfully loaded and validated eh_frame_hdr section with table: {}",
            has_table
        );
        Ok(())
    }

    /// Load CFI data from DWARF debug frame section (stored for lazy parsing)
    pub fn load_from_debug_frame(
        &mut self,
        debug_frame_data: &[u8],
        base_addresses: BaseAddresses,
    ) -> Result<()> {
        self.base_addresses = base_addresses;
        self.debug_frame_data = Some(debug_frame_data.to_vec());
        info!("Stored .debug_frame section data for lazy parsing");
        Ok(())
    }

    /// Load CFI data from DWARF eh_frame section (stored for lazy parsing)
    pub fn load_from_eh_frame(
        &mut self,
        eh_frame_data: &[u8],
        base_addresses: BaseAddresses,
    ) -> Result<()> {
        self.base_addresses = base_addresses;
        self.eh_frame_data = Some(eh_frame_data.to_vec());
        info!("Stored .eh_frame section data for lazy parsing");
        Ok(())
    }

    /// Get CFA EvaluationResult for given PC using eh_frame_hdr first, then fallback
    /// Strategy: try eh_frame_hdr table lookup first, if fails then use unwind_info_for_address
    pub fn get_cfa_expression(&self, pc: u64) -> Option<crate::expression::EvaluationResult> {
        debug!(
            "Getting CFA EvaluationResult for PC 0x{:x} - trying eh_frame_hdr first",
            pc
        );

        if self.eh_frame_data.is_none() {
            debug!("No eh_frame data available");
            return None;
        }

        // Strategy 1: Try eh_frame_hdr table lookup first (if available)
        if let Some(result) = self.try_eh_frame_hdr_lookup(pc) {
            debug!("Successfully found CFA via eh_frame_hdr table lookup");
            return Some(result);
        }

        // Strategy 2: Fallback to unwind_info_for_address (which may use internal hdr optimization)
        debug!("eh_frame_hdr lookup failed, trying unwind_info_for_address fallback");
        self.try_unwind_info_for_address(pc)
    }

    /// Try to lookup CFA using eh_frame_hdr table directly  
    /// This method directly uses the parsed FDE from eh_frame_hdr table
    fn try_eh_frame_hdr_lookup(&self, pc: u64) -> Option<crate::expression::EvaluationResult> {
        let eh_frame_hdr_data = self.eh_frame_hdr_data.as_ref()?;
        let _eh_frame_data = self.eh_frame_data.as_ref()?;

        debug!("Trying eh_frame_hdr table lookup for PC 0x{:x}", pc);

        // Check cached metadata first to avoid unnecessary parsing
        if !self.eh_frame_hdr_validated {
            debug!("eh_frame_hdr not validated, skipping lookup");
            return None;
        }

        // Use cached information to avoid parsing if we know there's no table
        if let Some(has_table) = *self.cached_has_table.borrow() {
            if !has_table {
                debug!("Cached result shows no eh_frame_hdr table available");
                return None;
            }
        }

        // Parse eh_frame_hdr (lightweight operation - mainly reading header fields)
        let eh_frame_hdr = EhFrameHdr::new(eh_frame_hdr_data, LittleEndian);
        let parsed_hdr = eh_frame_hdr.parse(&self.base_addresses, 8).ok()?;

        // Use parsed header table to find the FDE for the given PC
        if let Some(_table) = parsed_hdr.table() {
            debug!("Using eh_frame_hdr table for FDE lookup");

            // TODO: Implement direct FDE instruction parsing using fde.instructions()
            // Current implementation is complex due to CFI state machine requirements:
            // - Need to manually handle 20+ CFI instruction types (DefCfa, DefCfaRegister, DefCfaOffset, etc.)
            // - Must maintain CFI state machine (cfa_register, cfa_offset, register_rules)
            // - Require PC range matching and instruction sequence processing
            // - Handle DWARF expression evaluation for Expression/ValExpression instructions
            // - Manage AdvanceLoc/SetLoc PC advancement logic
            //
            // Performance: eh_frame_hdr parsing overhead is minimal (reading ~20 bytes)
            // The real optimization would be caching the ParsedEhFrameHdr, but lifetime constraints
            // make this complex. Current approach prioritizes code clarity over micro-optimizations.
            //
            // For now, fallback to unwind_info_for_address which handles all this complexity
            debug!("Direct FDE instruction parsing not implemented, falling back to unwind_info_for_address");
            return None;
        } else {
            debug!("No eh_frame_hdr table available");
        }

        None
    }

    /// Try to lookup CFA using gimli's unwind_info_for_address
    /// This may internally use eh_frame_hdr optimization
    fn try_unwind_info_for_address(&self, pc: u64) -> Option<crate::expression::EvaluationResult> {
        let eh_frame_data = self.eh_frame_data.as_ref()?;

        debug!("Trying unwind_info_for_address for PC 0x{:x}", pc);

        let eh_frame = EhFrame::new(eh_frame_data, LittleEndian);
        let mut unwind_context = gimli::UnwindContext::new();

        match eh_frame.unwind_info_for_address(
            &self.base_addresses,
            &mut unwind_context,
            pc,
            |section, bases, offset| section.cie_from_offset(bases, offset),
        ) {
            Ok(unwind_row) => {
                debug!("Successfully got unwind row for PC 0x{:x}", pc);

                match unwind_row.cfa() {
                    gimli::CfaRule::RegisterAndOffset { register, offset } => {
                        debug!("CFA rule: register {} + offset {}", register.0, offset);

                        return Some(crate::expression::EvaluationResult::MemoryLocation(
                            crate::expression::LocationResult::RegisterAddress {
                                register: register.0 as u16,
                                offset: Some(*offset),
                                size: None,
                            },
                        ));
                    }
                    gimli::CfaRule::Expression(expression) => {
                        debug!("CFA uses DWARF expression - not yet implemented");
                        debug!(
                            "DWARF expression offset: {:?}, length: {:?}",
                            expression.offset, expression.length
                        );
                        return None;
                    }
                }
            }
            Err(e) => {
                debug!("unwind_info_for_address failed for PC 0x{:x}: {}", pc, e);
            }
        }

        None
    }
}

impl Default for CFIContext {
    fn default() -> Self {
        Self::new()
    }
}

//! DWARF address range extraction utilities
//!
//! Provides reusable logic for extracting address ranges from DIEs,
//! supporting both single ranges (low_pc/high_pc) and multiple ranges (DW_AT_ranges)

use crate::core::Result;
use gimli::{EndianArcSlice, LittleEndian};
use tracing::{debug, trace, warn};

/// Utility for extracting address ranges from DWARF DIEs
pub struct RangeExtractor;

impl RangeExtractor {
    /// Extract all address ranges from a DIE
    ///
    /// This will try:
    /// 1. Single range from DW_AT_low_pc + DW_AT_high_pc
    /// 2. Multiple ranges from DW_AT_ranges
    /// 3. Return empty vec if no ranges found
    pub fn extract_all_ranges(
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    ) -> Result<Vec<(u64, u64)>> {
        // First try single range
        if let Some(range) = Self::extract_single_range(entry)? {
            trace!("Found single range: 0x{:x}-0x{:x}", range.0, range.1);
            return Ok(vec![range]);
        }

        // Then try DW_AT_ranges
        if let Some(ranges) = Self::extract_multiple_ranges(entry, unit, dwarf)? {
            trace!("Found {} ranges from DW_AT_ranges", ranges.len());
            return Ok(ranges);
        }

        // No ranges found
        trace!("No address ranges found for DIE");
        Ok(Vec::new())
    }

    /// Extract single address range from DW_AT_low_pc and DW_AT_high_pc
    pub fn extract_single_range(
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
    ) -> Result<Option<(u64, u64)>> {
        let mut low_pc = None;
        let mut high_pc = None;
        let mut high_pc_offset = None;

        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            match attr.name() {
                gimli::constants::DW_AT_low_pc => {
                    if let gimli::AttributeValue::Addr(addr) = attr.value() {
                        low_pc = Some(addr);
                    }
                }
                gimli::constants::DW_AT_high_pc => match attr.value() {
                    gimli::AttributeValue::Addr(addr) => high_pc = Some(addr),
                    gimli::AttributeValue::Udata(offset) => high_pc_offset = Some(offset),
                    gimli::AttributeValue::Data1(offset) => high_pc_offset = Some(offset as u64),
                    gimli::AttributeValue::Data2(offset) => high_pc_offset = Some(offset as u64),
                    gimli::AttributeValue::Data4(offset) => high_pc_offset = Some(offset as u64),
                    gimli::AttributeValue::Data8(offset) => high_pc_offset = Some(offset),
                    _ => {}
                },
                _ => {}
            }
        }

        match (low_pc, high_pc, high_pc_offset) {
            (Some(low), Some(high), _) => Ok(Some((low, high))),
            (Some(low), None, Some(offset)) => Ok(Some((low, low + offset))),
            _ => Ok(None),
        }
    }

    /// Extract multiple address ranges from DW_AT_ranges
    pub fn extract_multiple_ranges(
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    ) -> Result<Option<Vec<(u64, u64)>>> {
        // Check for DW_AT_ranges attribute
        let ranges_attr = match entry.attr(gimli::constants::DW_AT_ranges)? {
            Some(attr) => attr,
            None => return Ok(None),
        };

        debug!("Found DW_AT_ranges attribute, extracting ranges");

        // Convert attribute value to RangeListsOffset
        let ranges_offset = match ranges_attr.value() {
            gimli::AttributeValue::RangeListsRef(offset) => gimli::RangeListsOffset(offset.0),
            gimli::AttributeValue::SecOffset(offset) => gimli::RangeListsOffset(offset),
            _ => {
                warn!("Unexpected DW_AT_ranges attribute value type");
                return Ok(None);
            }
        };

        // Get base address for the compilation unit
        let base_address = unit.low_pc;

        // Parse the range list
        let mut ranges_iter = dwarf.ranges(unit, ranges_offset)?;
        let mut ranges = Vec::new();

        while let Some(range) = ranges_iter.next()? {
            let begin = range.begin;
            let end = range.end;

            if begin > end {
                continue;
            }

            let (mut adjusted_begin, mut adjusted_end) = (begin, end);

            if begin == 0 && base_address != 0 {
                adjusted_begin = base_address + begin;
                adjusted_end = base_address + end;
            }

            ranges.push((adjusted_begin, adjusted_end));
            debug!(
                "Range: 0x{:x}-0x{:x} (base: 0x{:x})",
                adjusted_begin, adjusted_end, base_address
            );
        }

        if ranges.is_empty() {
            Ok(None)
        } else {
            Ok(Some(ranges))
        }
    }
}

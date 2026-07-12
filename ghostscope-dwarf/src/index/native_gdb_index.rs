use crate::{
    binary::DwarfReader,
    core::{normalize_demangled_signature, symbol_name_matches_query, Result},
};
use gimli::Reader;
use std::sync::OnceLock;

const VERSION_9_HEADER_SIZE: usize = 7 * std::mem::size_of::<u32>();
const LEGACY_HEADER_SIZE: usize = 6 * std::mem::size_of::<u32>();
const CU_RECORD_SIZE: usize = 2 * std::mem::size_of::<u64>();
const TYPE_CU_RECORD_SIZE: usize = 3 * std::mem::size_of::<u64>();
const ADDRESS_RECORD_SIZE: usize = 2 * std::mem::size_of::<u64>() + std::mem::size_of::<u32>();
const SYMBOL_SLOT_SIZE: usize = 2 * std::mem::size_of::<u32>();
const CU_INDEX_MASK: u32 = 0x00ff_ffff;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum GdbSymbolKind {
    Type,
    Variable,
    Function,
    Other,
}

impl GdbSymbolKind {
    fn from_attributes(attributes: u32) -> Option<Self> {
        match (attributes >> 28) & 0x7 {
            1 => Some(Self::Type),
            2 => Some(Self::Variable),
            3 => Some(Self::Function),
            4 => Some(Self::Other),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct GdbSymbol {
    pub(crate) cu_offset: gimli::DebugInfoOffset,
    pub(crate) kind: GdbSymbolKind,
    pub(crate) is_static: bool,
}

#[derive(Debug, Clone, Copy)]
struct GdbIndexLayout {
    cu_list: usize,
    type_cu_list: usize,
    address_area: usize,
    symbol_table: usize,
    shortcut_table: usize,
    constant_pool: usize,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum GdbUnitKind {
    Compilation,
    Type,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct GdbUnit {
    offset: gimli::DebugInfoOffset,
    kind: GdbUnitKind,
}

#[derive(Debug, Default)]
struct GdbSymbolNames {
    functions: Vec<String>,
    variables: Vec<String>,
    types: Vec<String>,
    others: Vec<String>,
}

impl GdbSymbolNames {
    fn get(&self, kind: GdbSymbolKind) -> &[String] {
        match kind {
            GdbSymbolKind::Function => &self.functions,
            GdbSymbolKind::Variable => &self.variables,
            GdbSymbolKind::Type => &self.types,
            GdbSymbolKind::Other => &self.others,
        }
    }

    fn get_mut(&mut self, kind: GdbSymbolKind) -> &mut Vec<String> {
        match kind {
            GdbSymbolKind::Function => &mut self.functions,
            GdbSymbolKind::Variable => &mut self.variables,
            GdbSymbolKind::Type => &mut self.types,
            GdbSymbolKind::Other => &mut self.others,
        }
    }

    fn sort_and_deduplicate(&mut self) {
        for names in [
            &mut self.functions,
            &mut self.variables,
            &mut self.types,
            &mut self.others,
        ] {
            names.sort_unstable();
            names.dedup();
        }
    }
}

/// Read-only view of a GDB mapped DWARF index.
///
/// The backing reader points directly at the ELF section. All offsets and
/// vector lengths are checked before use so an unusable index can be rejected
/// and the caller can fall back to ordinary DWARF parsing.
#[derive(Debug)]
pub(crate) struct GdbIndex {
    data: DwarfReader,
    version: u32,
    layout: GdbIndexLayout,
    compilation_unit_count: usize,
    type_unit_count: usize,
    units: Vec<GdbUnit>,
    address_count: usize,
    symbol_slot_count: usize,
    symbol_names: OnceLock<GdbSymbolNames>,
}

impl GdbIndex {
    pub(crate) fn parse(data: DwarfReader) -> Result<Self> {
        let length = data.len();
        if length < LEGACY_HEADER_SIZE {
            anyhow::bail!(".gdb_index header is truncated");
        }

        let version = Self::read_u32(&data, 0)?;
        if !(7..=9).contains(&version) {
            anyhow::bail!("unsupported .gdb_index version {version}; expected 7 through 9");
        }

        let header_size = if version == 9 {
            VERSION_9_HEADER_SIZE
        } else {
            LEGACY_HEADER_SIZE
        };
        if length < header_size {
            anyhow::bail!(".gdb_index version {version} header is truncated");
        }

        let cu_list = Self::read_offset(&data, 1)?;
        let type_cu_list = Self::read_offset(&data, 2)?;
        let address_area = Self::read_offset(&data, 3)?;
        let symbol_table = Self::read_offset(&data, 4)?;
        let (shortcut_table, constant_pool) = if version == 9 {
            (Self::read_offset(&data, 5)?, Self::read_offset(&data, 6)?)
        } else {
            let constant_pool = Self::read_offset(&data, 5)?;
            (constant_pool, constant_pool)
        };
        let layout = GdbIndexLayout {
            cu_list,
            type_cu_list,
            address_area,
            symbol_table,
            shortcut_table,
            constant_pool,
        };
        Self::validate_layout(length, header_size, version, layout)?;

        let compilation_unit_count = (type_cu_list - cu_list) / CU_RECORD_SIZE;
        let type_unit_count = (address_area - type_cu_list) / TYPE_CU_RECORD_SIZE;
        let unit_count = compilation_unit_count
            .checked_add(type_unit_count)
            .ok_or_else(|| anyhow::anyhow!(".gdb_index CU count overflow"))?;
        let mut units = Vec::with_capacity(unit_count);

        // DWARF5 type and compile units share .debug_info. GDB assigns the
        // unified CU indices in section-offset order before serializing them
        // into separate CU and type-CU lists.
        for index in 0..compilation_unit_count {
            let record = cu_list + index * CU_RECORD_SIZE;
            let offset = usize::try_from(Self::read_u64(&data, record)?)?;
            units.push(GdbUnit {
                offset: gimli::DebugInfoOffset(offset),
                kind: GdbUnitKind::Compilation,
            });
        }
        for index in 0..type_unit_count {
            let record = type_cu_list + index * TYPE_CU_RECORD_SIZE;
            let offset = usize::try_from(Self::read_u64(&data, record)?)?;
            units.push(GdbUnit {
                offset: gimli::DebugInfoOffset(offset),
                kind: GdbUnitKind::Type,
            });
        }
        units.sort_unstable_by_key(|unit| unit.offset.0);
        if units
            .windows(2)
            .any(|pair| pair[0].offset == pair[1].offset)
        {
            anyhow::bail!(".gdb_index contains duplicate CU offsets");
        }
        let address_count = (symbol_table - address_area) / ADDRESS_RECORD_SIZE;
        let symbol_slot_count = (shortcut_table - symbol_table) / SYMBOL_SLOT_SIZE;
        if symbol_slot_count != 0 && !symbol_slot_count.is_power_of_two() {
            anyhow::bail!(".gdb_index symbol table size is not a power of two");
        }

        Ok(Self {
            data,
            version,
            layout,
            compilation_unit_count,
            type_unit_count,
            units,
            address_count,
            symbol_slot_count,
            symbol_names: OnceLock::new(),
        })
    }

    pub(crate) fn version(&self) -> u32 {
        self.version
    }

    pub(crate) fn compilation_unit_count(&self) -> usize {
        self.compilation_unit_count
    }

    pub(crate) fn validate_debug_info_size(&self, debug_info_size: usize) -> Result<()> {
        for index in 0..self.compilation_unit_count {
            let record = self.layout.cu_list + index * CU_RECORD_SIZE;
            let offset = usize::try_from(Self::read_u64(&self.data, record)?)?;
            let length = usize::try_from(Self::read_u64(
                &self.data,
                record + std::mem::size_of::<u64>(),
            )?)?;
            let end = offset
                .checked_add(length)
                .ok_or_else(|| anyhow::anyhow!(".gdb_index CU range overflow"))?;
            if end > debug_info_size {
                anyhow::bail!(
                    ".gdb_index CU {index} range 0x{offset:x}..0x{end:x} exceeds .debug_info size 0x{debug_info_size:x}"
                );
            }
        }
        for index in 0..self.type_unit_count {
            let record = self.layout.type_cu_list + index * TYPE_CU_RECORD_SIZE;
            let cu_offset = usize::try_from(Self::read_u64(&self.data, record)?)?;
            let type_offset = usize::try_from(Self::read_u64(
                &self.data,
                record + std::mem::size_of::<u64>(),
            )?)?;
            let type_die_offset = cu_offset
                .checked_add(type_offset)
                .ok_or_else(|| anyhow::anyhow!(".gdb_index type CU offset overflow"))?;
            if cu_offset >= debug_info_size || type_die_offset >= debug_info_size {
                anyhow::bail!(
                    ".gdb_index type CU {index} offsets 0x{cu_offset:x}/0x{type_offset:x} exceed .debug_info size 0x{debug_info_size:x}"
                );
            }
        }
        for index in 0..self.address_count {
            let (_, _, cu_index) = self.read_address(index)?;
            let Some(unit) = self.units.get(cu_index) else {
                anyhow::bail!(
                    ".gdb_index address record {index} references invalid CU index {cu_index}"
                );
            };
            if unit.kind != GdbUnitKind::Compilation {
                anyhow::bail!(
                    ".gdb_index address record {index} references type CU index {cu_index}"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn validate_unit_headers(&self, dwarf: &gimli::Dwarf<DwarfReader>) -> Result<()> {
        for (index, unit) in self.units.iter().enumerate() {
            let header = dwarf.unit_header(unit.offset).map_err(|error| {
                anyhow::anyhow!(
                    ".gdb_index CU {index} at 0x{:x} has an invalid DWARF header: {error}",
                    unit.offset.0
                )
            })?;
            let actual_kind = match header.type_() {
                gimli::UnitType::Type { .. } | gimli::UnitType::SplitType { .. } => {
                    GdbUnitKind::Type
                }
                _ => GdbUnitKind::Compilation,
            };
            if actual_kind != unit.kind {
                anyhow::bail!(
                    ".gdb_index CU {index} at 0x{:x} has the wrong DWARF unit type",
                    unit.offset.0
                );
            }
        }
        Ok(())
    }

    pub(crate) fn validate_symbol_data(&self) -> Result<()> {
        let unit_count = self.units.len();
        for slot in 0..self.symbol_slot_count {
            let (name_offset, vector_offset) = self.read_symbol_slot(slot)?;
            if name_offset == 0 && vector_offset == 0 {
                continue;
            }

            self.read_pool_string(name_offset)?;
            let (values_start, count) = self.symbol_vector(slot)?;
            for index in 0..count {
                let offset = values_start
                    .checked_add(index * std::mem::size_of::<u32>())
                    .ok_or_else(|| anyhow::anyhow!(".gdb_index CU vector offset overflow"))?;
                let attributes = Self::read_u32(&self.data, offset)?;
                let cu_index = usize::try_from(attributes & CU_INDEX_MASK)?;
                if cu_index >= unit_count {
                    anyhow::bail!(
                        ".gdb_index symbol slot {slot} references invalid CU index {cu_index}"
                    );
                }
            }
        }
        Ok(())
    }

    pub(crate) fn lookup_symbol(&self, name: &str, kind: GdbSymbolKind) -> Result<Vec<GdbSymbol>> {
        let Some(slot) = self.find_symbol_slot(name)? else {
            return Ok(Vec::new());
        };
        self.symbols_in_slot(slot, Some(kind))
    }

    pub(crate) fn lookup_matching_symbols(
        &self,
        query: &str,
        kind: GdbSymbolKind,
    ) -> Result<Vec<GdbSymbol>> {
        let normalized_query = normalize_demangled_signature(query);
        let mut symbols = Vec::new();
        for slot in 0..self.symbol_slot_count {
            let (name_offset, vector_offset) = self.read_symbol_slot(slot)?;
            if name_offset == 0 && vector_offset == 0 {
                continue;
            }
            let candidate = self.read_pool_string(name_offset)?;
            if symbol_name_matches_query(query, normalized_query.as_deref(), &candidate, None) {
                symbols.extend(self.symbols_in_slot(slot, Some(kind))?);
            }
        }
        symbols.sort_unstable_by_key(|symbol| symbol.cu_offset.0);
        symbols.dedup();
        Ok(symbols)
    }

    pub(crate) fn symbol_names(&self, kind: GdbSymbolKind) -> Result<&[String]> {
        if self.symbol_names.get().is_none() {
            let names = self.collect_symbol_names()?;
            let _ = self.symbol_names.set(names);
        }
        Ok(self
            .symbol_names
            .get()
            .expect("GDB symbol names must be initialized")
            .get(kind))
    }

    pub(crate) fn find_cu_by_address(
        &self,
        address: u64,
    ) -> Result<Option<gimli::DebugInfoOffset>> {
        let mut left = 0usize;
        let mut right = self.address_count;
        while left < right {
            let middle = left + (right - left) / 2;
            let (low, _, _) = self.read_address(middle)?;
            if low <= address {
                left = middle + 1;
            } else {
                right = middle;
            }
        }

        for index in (0..left).rev() {
            let (low, high, cu_index) = self.read_address(index)?;
            if low <= address && address < high {
                return self.unit_offset(cu_index).map(Some);
            }
            if high <= address {
                break;
            }
        }
        Ok(None)
    }

    fn validate_layout(
        length: usize,
        header_size: usize,
        version: u32,
        layout: GdbIndexLayout,
    ) -> Result<()> {
        let offsets = [
            layout.cu_list,
            layout.type_cu_list,
            layout.address_area,
            layout.symbol_table,
            layout.shortcut_table,
            layout.constant_pool,
            length,
        ];
        if layout.cu_list < header_size {
            anyhow::bail!(".gdb_index CU list overlaps its header");
        }
        if offsets.windows(2).any(|pair| pair[0] > pair[1]) {
            anyhow::bail!(".gdb_index areas are not ordered");
        }
        if layout.constant_pool > length {
            anyhow::bail!(".gdb_index constant pool is outside the section");
        }
        if (layout.type_cu_list - layout.cu_list) % CU_RECORD_SIZE != 0 {
            anyhow::bail!(".gdb_index CU list has a partial record");
        }
        if (layout.address_area - layout.type_cu_list) % TYPE_CU_RECORD_SIZE != 0 {
            anyhow::bail!(".gdb_index type CU list has a partial record");
        }
        if (layout.symbol_table - layout.address_area) % ADDRESS_RECORD_SIZE != 0 {
            anyhow::bail!(".gdb_index address area has a partial record");
        }
        if (layout.shortcut_table - layout.symbol_table) % SYMBOL_SLOT_SIZE != 0 {
            anyhow::bail!(".gdb_index symbol table has a partial slot");
        }
        if version == 9 && layout.constant_pool - layout.shortcut_table < SYMBOL_SLOT_SIZE {
            anyhow::bail!(".gdb_index shortcut table is truncated");
        }
        Ok(())
    }

    fn find_symbol_slot(&self, name: &str) -> Result<Option<usize>> {
        if self.symbol_slot_count == 0 {
            return Ok(None);
        }

        let hash = self.symbol_hash(name.as_bytes());
        let mask = self.symbol_slot_count - 1;
        let mut slot = hash as usize & mask;
        let step = ((hash as usize).wrapping_mul(17) & mask) | 1;
        for _ in 0..self.symbol_slot_count {
            let (name_offset, vector_offset) = self.read_symbol_slot(slot)?;
            if name_offset == 0 && vector_offset == 0 {
                return Ok(None);
            }
            if self.read_pool_string(name_offset)? == name {
                return Ok(Some(slot));
            }
            slot = slot.wrapping_add(step) & mask;
        }
        Ok(None)
    }

    fn symbol_hash(&self, name: &[u8]) -> u32 {
        name.iter().fold(0u32, |hash, byte| {
            let byte = if self.version >= 5 {
                byte.to_ascii_lowercase()
            } else {
                *byte
            };
            hash.wrapping_mul(67)
                .wrapping_add(u32::from(byte))
                .wrapping_sub(113)
        })
    }

    fn collect_symbol_names(&self) -> Result<GdbSymbolNames> {
        let mut names = GdbSymbolNames::default();
        for slot in 0..self.symbol_slot_count {
            let (name_offset, vector_offset) = self.read_symbol_slot(slot)?;
            if name_offset == 0 && vector_offset == 0 {
                continue;
            }
            let name = self.read_pool_string(name_offset)?;
            for symbol in self.symbols_in_slot(slot, None)? {
                names.get_mut(symbol.kind).push(name.clone());
            }
        }
        names.sort_and_deduplicate();
        Ok(names)
    }

    fn symbols_in_slot(&self, slot: usize, kind: Option<GdbSymbolKind>) -> Result<Vec<GdbSymbol>> {
        let (values_start, count) = self.symbol_vector(slot)?;

        let mut symbols = Vec::new();
        for index in 0..count {
            let offset = values_start
                .checked_add(index * std::mem::size_of::<u32>())
                .ok_or_else(|| anyhow::anyhow!(".gdb_index CU vector offset overflow"))?;
            let attributes = Self::read_u32(&self.data, offset)?;
            let Some(symbol_kind) = GdbSymbolKind::from_attributes(attributes) else {
                continue;
            };
            if kind.is_some_and(|expected| expected != symbol_kind) {
                continue;
            }
            let cu_index = usize::try_from(attributes & CU_INDEX_MASK)?;
            symbols.push(GdbSymbol {
                cu_offset: self.unit_offset(cu_index)?,
                kind: symbol_kind,
                is_static: attributes & (1 << 31) != 0,
            });
        }
        symbols.sort_unstable_by_key(|symbol| symbol.cu_offset.0);
        symbols.dedup();
        Ok(symbols)
    }

    fn symbol_vector(&self, slot: usize) -> Result<(usize, usize)> {
        let (_, vector_offset) = self.read_symbol_slot(slot)?;
        let vector = self.pool_offset(vector_offset)?;
        let count = usize::try_from(Self::read_u32(&self.data, vector)?)?;
        let values_start = vector
            .checked_add(std::mem::size_of::<u32>())
            .ok_or_else(|| anyhow::anyhow!(".gdb_index CU vector offset overflow"))?;
        let available = self
            .data
            .len()
            .checked_sub(values_start)
            .ok_or_else(|| anyhow::anyhow!(".gdb_index CU vector is truncated"))?;
        if count > available / std::mem::size_of::<u32>() {
            anyhow::bail!(".gdb_index CU vector is truncated");
        }
        Ok((values_start, count))
    }

    fn read_address(&self, index: usize) -> Result<(u64, u64, usize)> {
        if index >= self.address_count {
            anyhow::bail!(".gdb_index address index is out of bounds");
        }
        let offset = self.layout.address_area + index * ADDRESS_RECORD_SIZE;
        let low = Self::read_u64(&self.data, offset)?;
        let high = Self::read_u64(&self.data, offset + std::mem::size_of::<u64>())?;
        let cu_index = usize::try_from(Self::read_u32(
            &self.data,
            offset + 2 * std::mem::size_of::<u64>(),
        )?)?;
        Ok((low, high, cu_index))
    }

    fn unit_offset(&self, index: usize) -> Result<gimli::DebugInfoOffset> {
        self.units
            .get(index)
            .map(|unit| unit.offset)
            .ok_or_else(|| anyhow::anyhow!(".gdb_index CU index {index} is out of bounds"))
    }

    fn read_symbol_slot(&self, slot: usize) -> Result<(u32, u32)> {
        if slot >= self.symbol_slot_count {
            anyhow::bail!(".gdb_index symbol slot is out of bounds");
        }
        let offset = self.layout.symbol_table + slot * SYMBOL_SLOT_SIZE;
        Ok((
            Self::read_u32(&self.data, offset)?,
            Self::read_u32(&self.data, offset + std::mem::size_of::<u32>())?,
        ))
    }

    fn read_pool_string(&self, relative_offset: u32) -> Result<String> {
        let offset = self.pool_offset(relative_offset)?;
        let mut reader = self.reader_at(offset)?;
        let string = reader.read_null_terminated_slice()?;
        Ok(string.to_string_lossy()?.into_owned())
    }

    fn pool_offset(&self, relative_offset: u32) -> Result<usize> {
        let offset = self
            .layout
            .constant_pool
            .checked_add(usize::try_from(relative_offset)?)
            .ok_or_else(|| anyhow::anyhow!(".gdb_index constant-pool offset overflow"))?;
        if offset >= self.data.len() {
            anyhow::bail!(".gdb_index constant-pool offset is out of bounds");
        }
        Ok(offset)
    }

    fn read_offset(data: &DwarfReader, word_index: usize) -> Result<usize> {
        usize::try_from(Self::read_u32(
            data,
            word_index * std::mem::size_of::<u32>(),
        )?)
        .map_err(Into::into)
    }

    fn read_u32(data: &DwarfReader, offset: usize) -> Result<u32> {
        let mut reader = Self::reader_at_data(data, offset)?;
        Ok(reader.read_u32()?)
    }

    fn read_u64(data: &DwarfReader, offset: usize) -> Result<u64> {
        let mut reader = Self::reader_at_data(data, offset)?;
        Ok(reader.read_u64()?)
    }

    fn reader_at(&self, offset: usize) -> Result<DwarfReader> {
        Self::reader_at_data(&self.data, offset)
    }

    fn reader_at_data(data: &DwarfReader, offset: usize) -> Result<DwarfReader> {
        if offset > data.len() {
            anyhow::bail!(".gdb_index read offset is out of bounds");
        }
        let mut reader = data.clone();
        reader.skip(offset)?;
        Ok(reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::dwarf_reader_from_arc_with_endian;
    use std::sync::Arc;

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(bytes: &mut Vec<u8>, value: u64) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn fixture_with_symbol(
        symbol_name: &str,
        attributes: u32,
        type_unit: Option<(u64, u64, u64)>,
    ) -> Vec<u8> {
        let mut bytes = vec![0; VERSION_9_HEADER_SIZE];
        let cu_list = bytes.len();
        push_u64(&mut bytes, 0x120);
        push_u64(&mut bytes, 0x80);
        let type_cu_list = bytes.len();
        if let Some((cu_offset, type_offset, signature)) = type_unit {
            push_u64(&mut bytes, cu_offset);
            push_u64(&mut bytes, type_offset);
            push_u64(&mut bytes, signature);
        }
        let address_area = bytes.len();
        push_u64(&mut bytes, 0x4000);
        push_u64(&mut bytes, 0x4100);
        push_u32(&mut bytes, 0);
        let symbol_table = bytes.len();
        let slot_count = 8;
        bytes.resize(bytes.len() + slot_count * SYMBOL_SLOT_SIZE, 0);
        let shortcut_table = bytes.len();
        push_u32(&mut bytes, 0);
        push_u32(&mut bytes, 0);
        let constant_pool = bytes.len();
        push_u32(&mut bytes, 1);
        push_u32(&mut bytes, attributes);
        let name_offset = u32::try_from(bytes.len() - constant_pool).unwrap();
        bytes.extend_from_slice(symbol_name.as_bytes());
        bytes.push(0);

        write_u32(&mut bytes, 0, 9);
        for (word, value) in [
            cu_list,
            type_cu_list,
            address_area,
            symbol_table,
            shortcut_table,
            constant_pool,
        ]
        .into_iter()
        .enumerate()
        {
            write_u32(&mut bytes, (word + 1) * 4, u32::try_from(value).unwrap());
        }

        let reader = dwarf_reader_from_arc_with_endian(
            Arc::from(bytes.clone()),
            gimli::RunTimeEndian::Little,
        );
        let index = GdbIndex::parse(reader).unwrap();
        let hash = index.symbol_hash(symbol_name.as_bytes());
        let slot = hash as usize & (slot_count - 1);
        write_u32(
            &mut bytes,
            symbol_table + slot * SYMBOL_SLOT_SIZE,
            name_offset,
        );
        write_u32(&mut bytes, symbol_table + slot * SYMBOL_SLOT_SIZE + 4, 0);
        bytes
    }

    fn fixture() -> Vec<u8> {
        fixture_with_symbol("target_function", 3 << 28, None)
    }

    fn parse(bytes: Vec<u8>) -> Result<GdbIndex> {
        GdbIndex::parse(dwarf_reader_from_arc_with_endian(
            Arc::from(bytes),
            gimli::RunTimeEndian::Little,
        ))
    }

    #[test]
    fn parses_and_queries_version_9_index() {
        let index = parse(fixture()).unwrap();
        assert_eq!(index.version(), 9);
        assert_eq!(index.compilation_unit_count(), 1);
        assert_eq!(
            index
                .lookup_symbol("target_function", GdbSymbolKind::Function)
                .unwrap(),
            vec![GdbSymbol {
                cu_offset: gimli::DebugInfoOffset(0x120),
                kind: GdbSymbolKind::Function,
                is_static: false,
            }]
        );
        assert!(index
            .lookup_symbol("missing", GdbSymbolKind::Function)
            .unwrap()
            .is_empty());
        assert_eq!(
            index.find_cu_by_address(0x4080).unwrap(),
            Some(gimli::DebugInfoOffset(0x120))
        );
        assert_eq!(index.find_cu_by_address(0x4100).unwrap(), None);
        assert_eq!(
            index.symbol_names(GdbSymbolKind::Function).unwrap(),
            &["target_function".to_string()]
        );
    }

    #[test]
    fn resolves_symbols_owned_by_type_units() {
        let index = parse(fixture_with_symbol(
            "target_type",
            (1 << 28) | 1,
            Some((0x220, 0x30, 0x1234_5678_9abc_def0)),
        ))
        .unwrap();
        index.validate_debug_info_size(0x251).unwrap();
        assert_eq!(
            index
                .lookup_symbol("target_type", GdbSymbolKind::Type)
                .unwrap(),
            vec![GdbSymbol {
                cu_offset: gimli::DebugInfoOffset(0x220),
                kind: GdbSymbolKind::Type,
                is_static: false,
            }]
        );
    }

    #[test]
    fn rejects_type_unit_offsets_outside_debug_info() {
        let index = parse(fixture_with_symbol(
            "target_type",
            (1 << 28) | 1,
            Some((0x220, 0x30, 0x1234_5678_9abc_def0)),
        ))
        .unwrap();
        let error = index
            .validate_debug_info_size(0x250)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("type CU 0 offsets"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_out_of_order_areas() {
        let mut bytes = fixture();
        write_u32(&mut bytes, 3 * 4, 4);
        let error = parse(bytes).unwrap_err().to_string();
        assert!(error.contains("not ordered"), "unexpected error: {error}");
    }

    #[test]
    fn rejects_truncated_cu_vectors_before_allocating() {
        let mut bytes = fixture();
        let constant_pool = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
        write_u32(&mut bytes, constant_pool, u32::MAX);
        let index = parse(bytes).unwrap();
        let error = index
            .lookup_symbol("target_function", GdbSymbolKind::Function)
            .unwrap_err()
            .to_string();
        assert!(error.contains("truncated"), "unexpected error: {error}");
    }

    #[test]
    fn validates_symbol_vectors_before_lazy_selection() {
        let mut bytes = fixture();
        let constant_pool = u32::from_le_bytes(bytes[24..28].try_into().unwrap()) as usize;
        write_u32(&mut bytes, constant_pool, u32::MAX);
        let index = parse(bytes).unwrap();
        let error = index.validate_symbol_data().unwrap_err().to_string();
        assert!(error.contains("truncated"), "unexpected error: {error}");
    }

    #[test]
    fn validates_symbol_strings_before_lazy_selection() {
        let mut bytes = fixture();
        *bytes.last_mut().unwrap() = b'x';
        let index = parse(bytes).unwrap();
        assert!(index.validate_symbol_data().is_err());
    }

    #[test]
    fn validates_compilation_units_against_debug_info_size() {
        let index = parse(fixture()).unwrap();
        index.validate_debug_info_size(0x1a0).unwrap();
        let error = index
            .validate_debug_info_size(0x19f)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("exceeds .debug_info size"),
            "unexpected error: {error}"
        );
    }
}

//! Type name index built from the lightweight cooked index
//!
//! Supports:
//! - Finding aggregate (struct/class/union/enum) definitions by name
//! - Finding typedef DIEs by name

use crate::core::IndexFlags;
use crate::index::LightweightIndex;
use gimli::DwTag;
use std::collections::HashMap;
use tracing::info;

#[derive(Debug, Clone, Copy)]
pub struct TypeLoc {
    pub object: crate::DwarfObjectId,
    pub importing_cu: Option<crate::CuId>,
    pub cu_offset: gimli::DebugInfoOffset,
    pub die_offset: gimli::UnitOffset,
    pub tag: gimli::DwTag,
    pub is_declaration: bool,
}

#[derive(Debug, Default, Clone)]
pub struct TypeNameIndex {
    /// name -> list of candidate DIEs (across all CUs in a module)
    by_name: HashMap<String, Vec<TypeLoc>>,
}

impl TypeNameIndex {
    pub fn build_from_lightweight(ix: &LightweightIndex) -> Self {
        let mut by_name: HashMap<String, Vec<TypeLoc>> = HashMap::new();
        ix.for_each_type_map_entry(|name, entry_base, indices| {
            for &local_idx in indices {
                let idx = entry_base + local_idx;
                if let Some(entry) = ix.entry(idx) {
                    let tag = entry.tag;
                    // Include aggregates and typedefs
                    match tag {
                        gimli::constants::DW_TAG_structure_type
                        | gimli::constants::DW_TAG_class_type
                        | gimli::constants::DW_TAG_union_type
                        | gimli::constants::DW_TAG_enumeration_type
                        | gimli::constants::DW_TAG_typedef => {
                            let flags: IndexFlags = entry.flags;
                            let loc = TypeLoc {
                                object: crate::DwarfObjectId::Primary,
                                importing_cu: None,
                                cu_offset: entry.unit_offset,
                                die_offset: entry.die_offset,
                                tag,
                                is_declaration: flags.is_type_declaration,
                            };
                            by_name.entry(name.clone()).or_default().push(loc);
                        }
                        _ => {}
                    }
                }
            }
        });
        Self { by_name }
    }

    /// Index only declarations reachable through imports, preserving their
    /// namespace at the import site. Unimported supplementary units stay hidden.
    pub(crate) fn extend_imports(
        &mut self,
        dwarf: &crate::binary::DwarfData,
    ) -> crate::core::Result<()> {
        let mut units = dwarf.units();
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;
            let mut visited = std::collections::HashSet::new();
            self.walk_imports(
                dwarf,
                &unit,
                unit.header.root_offset(),
                &[],
                None,
                &mut visited,
            )?;
        }
        Ok(())
    }

    fn walk_imports(
        &mut self,
        dwarf: &crate::binary::DwarfData,
        unit: &gimli::Unit<crate::binary::DwarfReader>,
        start: gimli::UnitOffset,
        prefix: &[String],
        importing_cu: Option<crate::CuId>,
        visited: &mut std::collections::HashSet<(
            crate::DwarfObjectId,
            gimli::DebugInfoOffset,
            gimli::UnitOffset,
        )>,
    ) -> crate::core::Result<()> {
        let object = crate::binary::references::unit_object(dwarf, unit);
        let cu_offset = unit
            .header
            .debug_info_offset()
            .ok_or_else(|| anyhow::anyhow!("imported unit has no .debug_info offset"))?;
        let key = (object, cu_offset, start);
        anyhow::ensure!(
            visited.len() < 64 && visited.insert(key),
            "cyclic or excessively deep DW_AT_import chain"
        );
        let mut entries = unit.entries_at_offset(start)?;
        let mut namespaces: Vec<(isize, String)> = Vec::new();
        let mut first = true;
        while let Some(entry) = entries.next_dfs()? {
            if !first && entry.depth() <= 0 {
                break;
            }
            first = false;
            while namespaces
                .last()
                .is_some_and(|(depth, _)| *depth >= entry.depth())
            {
                namespaces.pop();
            }
            let mut context = prefix.to_vec();
            context.extend(namespaces.iter().map(|(_, name)| name.clone()));
            if entry.tag() == gimli::DW_TAG_imported_unit {
                let value = entry
                    .attr_value(gimli::DW_AT_import)
                    .ok_or_else(|| anyhow::anyhow!("DW_TAG_imported_unit without DW_AT_import"))?;
                let (_, target, root) = crate::semantics::resolve_origin_entry(dwarf, unit, value)?
                    .ok_or_else(|| anyhow::anyhow!("unresolved DW_AT_import"))?;
                self.walk_imports(
                    dwarf,
                    &target,
                    root.offset(),
                    &context,
                    importing_cu.or(Some(crate::CuId(cu_offset.0 as u64, object))),
                    visited,
                )?;
            }
            let Some(name) = crate::semantics::resolve_name_with_origins(dwarf, unit, entry)?
            else {
                continue;
            };
            if importing_cu.is_some()
                && matches!(
                    entry.tag(),
                    gimli::DW_TAG_structure_type
                        | gimli::DW_TAG_class_type
                        | gimli::DW_TAG_union_type
                        | gimli::DW_TAG_enumeration_type
                        | gimli::DW_TAG_typedef
                )
            {
                let loc = TypeLoc {
                    object,
                    importing_cu,
                    cu_offset,
                    die_offset: entry.offset(),
                    tag: entry.tag(),
                    is_declaration: matches!(
                        entry.attr_value(gimli::DW_AT_declaration),
                        Some(gimli::AttributeValue::Flag(true))
                    ),
                };
                context.push(name.clone());
                for key in [name.clone(), context.join("::")] {
                    let locations = self.by_name.entry(key).or_default();
                    if !locations.iter().any(|candidate| {
                        candidate.object == loc.object
                            && candidate.importing_cu == loc.importing_cu
                            && candidate.cu_offset == loc.cu_offset
                            && candidate.die_offset == loc.die_offset
                    }) {
                        locations.push(loc);
                    }
                }
            }
            if matches!(
                entry.tag(),
                gimli::DW_TAG_namespace
                    | gimli::DW_TAG_structure_type
                    | gimli::DW_TAG_class_type
                    | gimli::DW_TAG_union_type
            ) {
                namespaces.push((entry.depth(), name));
            }
        }
        visited.remove(&key);
        Ok(())
    }

    pub(crate) fn unit_offsets_for_name(&self, name: &str) -> Vec<gimli::DebugInfoOffset> {
        let mut offsets = self
            .by_name
            .get(name)
            .into_iter()
            .flatten()
            .filter(|location| location.object == crate::DwarfObjectId::Primary)
            .map(|location| location.cu_offset)
            .collect::<Vec<_>>();
        offsets.sort_unstable_by_key(|offset| offset.0);
        offsets.dedup();
        offsets
    }

    /// Find an aggregate definition by name and tag, preferring non-declarations
    pub fn find_aggregate_definition(&self, name: &str, tag: DwTag) -> Option<TypeLoc> {
        let cands = match self.by_name.get(name) {
            Some(v) => v,
            None => {
                info!(
                    "TypeNameIndex: MISS name='{}' tag={:?} (no entries)",
                    name, tag
                );
                return None;
            }
        };
        // First pass: non-declarations
        if let Some(loc) = cands
            .iter()
            .find(|c| c.tag == tag && !c.is_declaration)
            .cloned()
        {
            info!(
                "TypeNameIndex: HIT(def) name='{}' tag={:?} cu_off={:?} die_off={:?}",
                name, tag, loc.cu_offset, loc.die_offset
            );
            return Some(loc);
        }
        // Fallback: any matching tag
        if let Some(loc) = cands.iter().find(|c| c.tag == tag).cloned() {
            info!(
                "TypeNameIndex: HIT(decl) name='{}' tag={:?} cu_off={:?} die_off={:?}",
                name, tag, loc.cu_offset, loc.die_offset
            );
            Some(loc)
        } else {
            info!(
                "TypeNameIndex: MISS name='{}' tag={:?} (no matching tag)",
                name, tag
            );
            None
        }
    }

    /// Find a typedef by name
    pub fn find_typedef(&self, name: &str) -> Option<TypeLoc> {
        match self.by_name.get(name) {
            Some(v) => {
                if let Some(loc) = v
                    .iter()
                    .find(|c| c.tag == gimli::constants::DW_TAG_typedef)
                    .cloned()
                {
                    info!(
                        "TypeNameIndex: HIT(typedef) name='{}' cu_off={:?} die_off={:?}",
                        name, loc.cu_offset, loc.die_offset
                    );
                    Some(loc)
                } else {
                    info!("TypeNameIndex: MISS(typedef) name='{}'", name);
                    None
                }
            }
            None => {
                info!("TypeNameIndex: MISS(typedef) name='{}' (no entries)", name);
                None
            }
        }
    }
}

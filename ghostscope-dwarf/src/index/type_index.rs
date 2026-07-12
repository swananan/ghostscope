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

    pub(crate) fn unit_offsets_for_name(&self, name: &str) -> Vec<gimli::DebugInfoOffset> {
        let mut offsets = self
            .by_name
            .get(name)
            .into_iter()
            .flatten()
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

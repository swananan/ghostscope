use crate::{
    core::{normalize_demangled_signature, symbol_name_matches_query},
    index::GdbSymbolKind,
};
use std::collections::HashMap;

type SymbolsByName = HashMap<String, Vec<gimli::DebugInfoOffset>>;

/// Name accelerator used only to select compilation units.
///
/// GNU pubnames can omit local names and collapse overloads. GDB2 debug_names
/// can attribute imported DIEs to a containing CU in a different object. Neither
/// is a cooked query result: materialize the selected CUs before querying DWARF.
#[derive(Debug, Default)]
pub(crate) struct CuNameIndex {
    functions: SymbolsByName,
    variables: SymbolsByName,
    types: SymbolsByName,
    all_unit_offsets: Vec<gimli::DebugInfoOffset>,
}

impl CuNameIndex {
    pub(crate) fn new(mut all_unit_offsets: Vec<gimli::DebugInfoOffset>) -> Self {
        all_unit_offsets.sort_unstable_by_key(|offset| offset.0);
        all_unit_offsets.dedup();
        Self {
            all_unit_offsets,
            ..Self::default()
        }
    }

    pub(crate) fn insert(
        &mut self,
        name: String,
        unit_offset: gimli::DebugInfoOffset,
        kind: GdbSymbolKind,
    ) {
        let symbols = match kind {
            GdbSymbolKind::Function => &mut self.functions,
            GdbSymbolKind::Variable => &mut self.variables,
            GdbSymbolKind::Type => &mut self.types,
            GdbSymbolKind::Other => return,
        };
        let offsets = symbols.entry(name).or_default();
        if !offsets.contains(&unit_offset) {
            offsets.push(unit_offset);
        }
    }

    pub(crate) fn lookup_units(
        &self,
        query: &str,
        kind: GdbSymbolKind,
        match_variants: bool,
    ) -> Vec<gimli::DebugInfoOffset> {
        let Some(symbols) = self.symbols(kind) else {
            return Vec::new();
        };
        let mut units = if match_variants {
            let normalized_query = normalize_demangled_signature(query);
            symbols
                .iter()
                .filter(|(candidate, _)| {
                    symbol_name_matches_query(query, normalized_query.as_deref(), candidate, None)
                })
                .flat_map(|(_, offsets)| offsets.iter().copied())
                .collect::<Vec<_>>()
        } else {
            symbols.get(query).cloned().unwrap_or_default()
        };
        units.sort_unstable_by_key(|offset| offset.0);
        units.dedup();
        units
    }

    pub(crate) fn all_unit_offsets(&self) -> &[gimli::DebugInfoOffset] {
        &self.all_unit_offsets
    }

    pub(crate) fn get_stats(&self) -> (usize, usize, usize) {
        let functions = self.functions.len();
        let variables = self.variables.len();
        let types = self.types.len();
        (functions, variables, functions + variables + types)
    }

    fn symbols(&self, kind: GdbSymbolKind) -> Option<&SymbolsByName> {
        match kind {
            GdbSymbolKind::Function => Some(&self.functions),
            GdbSymbolKind::Variable => Some(&self.variables),
            GdbSymbolKind::Type => Some(&self.types),
            GdbSymbolKind::Other => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_template_leaf_selects_its_compilation_unit() {
        let expected = gimli::DebugInfoOffset(0x20);
        let mut index = CuNameIndex::new(vec![expected]);
        index.insert(
            "ns2::Box<ns1::Inner>".to_string(),
            expected,
            GdbSymbolKind::Type,
        );

        assert_eq!(
            index.lookup_units("Box<ns1::Inner>", GdbSymbolKind::Type, true),
            vec![expected]
        );
    }
}

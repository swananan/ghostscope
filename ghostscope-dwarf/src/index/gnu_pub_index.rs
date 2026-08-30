use crate::{
    core::{normalize_demangled_signature, symbol_name_matches_query},
    index::GdbSymbolKind,
};
use std::collections::HashMap;

type SymbolsByName = HashMap<String, Vec<gimli::DebugInfoOffset>>;

/// Lossy GNU pubnames accelerator used only to select compilation units.
///
/// GNU pubnames/pubtypes entries do not carry enough information to serve as
/// cooked query results: compilers may omit local names, collapse overloads,
/// and expose only a coarse symbol kind. Keep them separate from the
/// materialized DWARF index and use them solely to decide which units to parse.
#[derive(Debug, Default)]
pub(crate) struct GnuPubIndex {
    functions: SymbolsByName,
    variables: SymbolsByName,
    types: SymbolsByName,
    all_unit_offsets: Vec<gimli::DebugInfoOffset>,
}

impl GnuPubIndex {
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
        let mut index = GnuPubIndex::new(vec![expected]);
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

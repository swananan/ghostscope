//! Symbol-name helpers shared by fast parsing and query matching.

use super::demangle::{demangle_by_lang, demangled_leaf};
use gimli::DwLang;
use std::collections::HashSet;

const NOISY_FRAGMENTS: &[&str] = &[
    "std",
    "core",
    "alloc",
    "fmt",
    "basic_string",
    "allocator",
    "char_traits",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DemangledName {
    pub(crate) full: String,
    pub(crate) full_normalized: Option<String>,
    pub(crate) leaf: String,
    pub(crate) leaf_normalized: Option<String>,
}

pub(crate) fn demangled_name(lang: Option<DwLang>, symbol: &str) -> Option<DemangledName> {
    let full = demangle_by_lang(lang, symbol)?;
    let leaf = demangled_leaf(&full);
    Some(DemangledName {
        full_normalized: normalize_demangled_signature(&full),
        leaf_normalized: normalize_demangled_signature(&leaf),
        full,
        leaf,
    })
}

pub(crate) fn normalize_demangled_signature(s: &str) -> Option<String> {
    if !s.contains('(') {
        return None;
    }

    let mut out = s.replace(", ", ",");
    out = out.replace("( ", "(");
    out = out.replace(" )", ")");
    out = out.replace(" ,", ",");
    (out != s).then_some(out)
}

pub(crate) fn plain_leaf(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}

pub(crate) fn symbol_name_matches_query(
    query: &str,
    normalized_query: Option<&str>,
    raw_symbol: &str,
    demangled: Option<&DemangledName>,
) -> bool {
    if raw_symbol == query || plain_leaf(raw_symbol) == query {
        return true;
    }

    if let Some(normalized_query) = normalized_query {
        if raw_symbol == normalized_query || plain_leaf(raw_symbol) == normalized_query {
            return true;
        }
    }

    let Some(demangled) = demangled else {
        return false;
    };

    if demangled.full == query || demangled.leaf == query {
        return true;
    }
    if demangled.full_normalized.as_deref() == Some(query)
        || demangled.leaf_normalized.as_deref() == Some(query)
    {
        return true;
    }

    if let Some(normalized_query) = normalized_query {
        if demangled.full == normalized_query || demangled.leaf == normalized_query {
            return true;
        }
        if demangled.full_normalized.as_deref() == Some(normalized_query)
            || demangled.leaf_normalized.as_deref() == Some(normalized_query)
        {
            return true;
        }
    }

    false
}

pub(crate) fn extract_name_fragments(name: &str) -> Vec<String> {
    let mut fragments = HashSet::new();

    if !collect_itanium_identifiers(name, &mut fragments) {
        collect_plain_identifiers(name, &mut fragments);
    }

    if fragments.is_empty() && name.contains("::") {
        for segment in name.split("::") {
            push_fragment(&mut fragments, segment);
        }
    }

    let mut ordered: Vec<String> = fragments.into_iter().collect();
    ordered.sort_unstable();
    ordered
}

fn collect_itanium_identifiers(name: &str, fragments: &mut HashSet<String>) -> bool {
    let Some(mut rest) = name.strip_prefix("_Z") else {
        return false;
    };

    if let Some(stripped) = rest.strip_prefix('N') {
        rest = stripped;
    }

    let mut added = false;
    while !rest.is_empty() {
        if let Some(stripped) = rest.strip_prefix('E') {
            rest = stripped;
            continue;
        }

        let digits_len = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits_len == 0 {
            break;
        }

        let Ok(segment_len) = rest[..digits_len].parse::<usize>() else {
            break;
        };
        rest = &rest[digits_len..];
        if rest.len() < segment_len {
            break;
        }

        push_fragment(fragments, &rest[..segment_len]);
        added = true;
        rest = &rest[segment_len..];
    }

    added
}

fn collect_plain_identifiers(name: &str, fragments: &mut HashSet<String>) {
    let mut start = None;
    for (idx, ch) in name.char_indices() {
        let is_ident = ch.is_ascii_alphanumeric() || ch == '_';
        if is_ident {
            start.get_or_insert(idx);
        } else if let Some(begin) = start.take() {
            push_fragment(fragments, &name[begin..idx]);
        }
    }

    if let Some(begin) = start {
        push_fragment(fragments, &name[begin..]);
    }
}

fn push_fragment(fragments: &mut HashSet<String>, fragment: &str) {
    let fragment = fragment.trim_matches('_');
    if should_index_fragment(fragment) {
        fragments.insert(fragment.to_string());
    }
}

fn should_index_fragment(fragment: &str) -> bool {
    if fragment.len() < 2
        || fragment.starts_with("_R")
        || fragment.starts_with("_Z")
        || fragment.bytes().all(|b| b.is_ascii_digit())
    {
        return false;
    }

    if NOISY_FRAGMENTS.contains(&fragment) {
        return false;
    }

    if let Some(hash) = fragment.strip_prefix('h') {
        if hash.len() >= 8 && hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::{
        demangled_name, extract_name_fragments, normalize_demangled_signature,
        symbol_name_matches_query,
    };

    #[test]
    fn extracts_plain_name_fragments() {
        let fragments = extract_name_fragments("ns::Widget::run");

        assert_eq!(fragments, vec!["Widget", "ns", "run"]);
    }

    #[test]
    fn extracts_itanium_fragments_without_hash_noise() {
        let fragments = extract_name_fragments("_ZN2ns6Widget3runEv");

        assert_eq!(fragments, vec!["Widget", "ns", "run"]);
    }

    #[test]
    fn matches_demangled_full_and_leaf_queries() {
        let demangled =
            demangled_name(Some(gimli::DW_LANG_C_plus_plus_17), "_ZN2ns6Widget3runEv").unwrap();

        assert!(symbol_name_matches_query(
            "ns::Widget::run()",
            None,
            "_ZN2ns6Widget3runEv",
            Some(&demangled)
        ));
        assert!(symbol_name_matches_query(
            "run()",
            None,
            "_ZN2ns6Widget3runEv",
            Some(&demangled)
        ));
        assert!(symbol_name_matches_query(
            "ns::Widget::run()",
            normalize_demangled_signature("ns::Widget::run( )").as_deref(),
            "_ZN2ns6Widget3runEv",
            Some(&demangled)
        ));
    }
}

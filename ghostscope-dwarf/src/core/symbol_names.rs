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

    if !collect_rust_v0_identifiers(name, &mut fragments)
        && !collect_itanium_identifiers(name, &mut fragments)
    {
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

fn collect_rust_v0_identifiers(name: &str, fragments: &mut HashSet<String>) -> bool {
    let Some(inner) = strip_rust_v0_prefix(name) else {
        return false;
    };
    if inner.bytes().any(|b| b & 0x80 != 0) {
        return false;
    }
    if !matches!(inner.as_bytes().first(), Some(b'A'..=b'Z')) {
        return false;
    }

    if RustV0PathParser::new(inner).parse_root_path_fragments(fragments) {
        return true;
    }

    scan_rust_v0_identifiers(inner, fragments)
}

fn scan_rust_v0_identifiers(inner: &str, fragments: &mut HashSet<String>) -> bool {
    let bytes = inner.as_bytes();
    let mut offset = 0;
    let mut added = false;

    while offset < bytes.len() {
        let mut cursor = offset;
        let is_punycode = matches!(bytes.get(cursor), Some(b'u'))
            && matches!(bytes.get(cursor + 1), Some(b'0'..=b'9'));
        if is_punycode {
            cursor += 1;
        }
        if digit_start_is_disambiguator(bytes, cursor) {
            offset += 1;
            continue;
        }

        let digit_start = cursor;
        while matches!(bytes.get(cursor), Some(b'0'..=b'9')) {
            cursor += 1;
        }
        if cursor == digit_start {
            offset += 1;
            continue;
        }

        let Ok(segment_len) = inner[digit_start..cursor].parse::<usize>() else {
            offset += 1;
            continue;
        };
        if segment_len == 0 {
            offset += 1;
            continue;
        }
        if matches!(bytes.get(cursor), Some(b'_')) {
            cursor += 1;
        }

        let Some(segment_end) = cursor.checked_add(segment_len) else {
            break;
        };
        let Some(segment) = inner.get(cursor..segment_end) else {
            offset += 1;
            continue;
        };
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            offset += 1;
            continue;
        }

        if is_punycode {
            if let Some((ascii, _)) = segment.rsplit_once('_') {
                if !ascii.is_empty() {
                    added |= push_fragment(fragments, ascii);
                }
            }
        } else {
            added |= push_fragment(fragments, segment);
        }

        offset = segment_end;
    }

    added
}

#[derive(Clone, Copy)]
struct RustV0PathParser<'a> {
    sym: &'a str,
    next: usize,
    depth: u32,
}

impl<'a> RustV0PathParser<'a> {
    const MAX_DEPTH: u32 = 32;

    fn new(sym: &'a str) -> Self {
        Self {
            sym,
            next: 0,
            depth: 0,
        }
    }

    fn parse_root_path_fragments(mut self, fragments: &mut HashSet<String>) -> bool {
        self.parse_path_fragments(fragments).is_some()
    }

    fn parse_path_fragments(&mut self, fragments: &mut HashSet<String>) -> Option<()> {
        self.depth = self.depth.checked_add(1)?;
        if self.depth > Self::MAX_DEPTH {
            return None;
        }

        let result = match self.next_byte()? {
            b'C' => {
                self.disambiguator()?;
                let ident = self.ident_ascii()?;
                if !ident.is_empty() {
                    let _ = push_fragment(fragments, ident);
                }
                Some(())
            }
            b'N' => {
                self.namespace()?;
                self.parse_path_fragments(fragments)?;
                self.disambiguator()?;
                let ident = self.ident_ascii()?;
                if !ident.is_empty() {
                    let _ = push_fragment(fragments, ident);
                }
                Some(())
            }
            b'I' => self.parse_path_fragments(fragments),
            b'B' => {
                let mut backref = self.backref()?;
                backref.parse_path_fragments(fragments)
            }
            _ => None,
        };

        self.depth -= 1;
        result
    }

    fn peek(&self) -> Option<u8> {
        self.sym.as_bytes().get(self.next).copied()
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.next += 1;
            true
        } else {
            false
        }
    }

    fn next_byte(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.next += 1;
        Some(byte)
    }

    fn digit_10(&mut self) -> Option<u8> {
        let digit = match self.peek()? {
            b'0'..=b'9' => self.peek()? - b'0',
            _ => return None,
        };
        self.next += 1;
        Some(digit)
    }

    fn digit_62(&mut self) -> Option<u8> {
        let digit = match self.peek()? {
            d @ b'0'..=b'9' => d - b'0',
            d @ b'a'..=b'z' => 10 + (d - b'a'),
            d @ b'A'..=b'Z' => 36 + (d - b'A'),
            _ => return None,
        };
        self.next += 1;
        Some(digit)
    }

    fn integer_62(&mut self) -> Option<u64> {
        if self.eat(b'_') {
            return Some(0);
        }

        let mut value = 0u64;
        while !self.eat(b'_') {
            let digit = self.digit_62()? as u64;
            value = value.checked_mul(62)?.checked_add(digit)?;
        }
        value.checked_add(1)
    }

    fn disambiguator(&mut self) -> Option<()> {
        if self.eat(b's') {
            let _ = self.integer_62()?;
        }
        Some(())
    }

    fn namespace(&mut self) -> Option<()> {
        match self.next_byte()? {
            b'A'..=b'Z' | b'a'..=b'z' => Some(()),
            _ => None,
        }
    }

    fn ident_ascii(&mut self) -> Option<&'a str> {
        let is_punycode = self.eat(b'u');
        let mut len = self.digit_10()? as usize;
        while let Some(digit @ 0..=9) = self.digit_10() {
            len = len.checked_mul(10)?.checked_add(digit as usize)?;
        }

        let _ = self.eat(b'_');
        let start = self.next;
        self.next = self.next.checked_add(len)?;
        let ident = self.sym.get(start..self.next)?;

        if !is_punycode {
            return Some(ident);
        }

        Some(ident.rsplit_once('_').map(|(ascii, _)| ascii).unwrap_or(""))
    }

    fn backref(&mut self) -> Option<Self> {
        let start = self.next.checked_sub(1)?;
        let offset = self.integer_62()?;
        if offset >= start as u64 {
            return None;
        }
        Some(Self {
            sym: self.sym,
            next: offset as usize,
            depth: self.depth,
        })
    }
}

fn digit_start_is_disambiguator(bytes: &[u8], cursor: usize) -> bool {
    if !matches!(bytes.get(cursor), Some(b'0'..=b'9')) {
        return false;
    }

    let mut start = cursor;
    while start > 0 && bytes[start - 1].is_ascii_alphanumeric() {
        start -= 1;
    }

    start > 0 && bytes[start - 1] == b's'
}

fn strip_rust_v0_prefix(name: &str) -> Option<&str> {
    if name.len() > 2 && name.starts_with("_R") {
        Some(&name[2..])
    } else if name.len() > 1 && name.starts_with('R') {
        Some(&name[1..])
    } else if name.len() > 3 && name.starts_with("__R") {
        Some(&name[3..])
    } else {
        None
    }
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

        added |= push_fragment(fragments, &rest[..segment_len]);
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

fn push_fragment(fragments: &mut HashSet<String>, fragment: &str) -> bool {
    let fragment = fragment.trim_matches('_');
    if should_index_fragment(fragment) {
        return fragments.insert(fragment.to_string());
    }
    false
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
    fn extracts_rust_v0_fragments() {
        let fragments = extract_name_fragments("_RNvCs73fAdSrgOJL_4test4main");

        assert_eq!(fragments, vec!["main", "test"]);
    }

    #[test]
    fn extracts_rust_v0_fragments_with_digit_prefixed_crate() {
        let fragments = extract_name_fragments("_RNvC6_123foo3bar");

        assert_eq!(fragments, vec!["123foo", "bar"]);
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

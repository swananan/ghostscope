//! Demangling helpers for Rust and C++ symbols

use gimli::DwLang;

/// Demangle a symbol string using language hint when available.
/// Returns None if demangling fails or is not applicable.
pub fn demangle_by_lang(lang: Option<DwLang>, s: &str) -> Option<String> {
    let looks_rust = is_rust_mangled(s) || looks_like_legacy_rust(s);
    let looks_cpp = is_itanium_cpp_mangled(s);
    if !looks_rust && !looks_cpp {
        return None;
    }

    // Try the hinted demangler first when the symbol shape matches it cleanly.
    // Keep heuristic fallback for mixed/LTO objects whose CU language does not
    // match the linkage symbol's mangling style.
    match lang {
        Some(gimli::DW_LANG_Rust) if looks_rust => {
            if let Some(d) = demangle_rust(s) {
                return Some(d);
            }
        }
        Some(gimli::DW_LANG_C_plus_plus)
        | Some(gimli::DW_LANG_C_plus_plus_11)
        | Some(gimli::DW_LANG_C_plus_plus_14)
        | Some(gimli::DW_LANG_C_plus_plus_17)
        | Some(gimli::DW_LANG_C_plus_plus_20)
            if looks_cpp && !looks_rust =>
        {
            if let Some(d) = demangle_cpp(s) {
                return Some(d);
            }
        }
        _ => {}
    }

    // Fall back heuristically when the hint was missing, mismatched, or failed.
    if looks_rust {
        if let Some(d) = demangle_rust(s) {
            return Some(d);
        }
    }
    if looks_cpp {
        if let Some(d) = demangle_cpp(s) {
            return Some(d);
        }
    }
    None
}

pub fn is_likely_mangled(lang: Option<DwLang>, s: &str) -> bool {
    let _ = lang;
    is_rust_mangled(s) || looks_like_legacy_rust(s) || is_itanium_cpp_mangled(s)
}

/// Return a friendly leaf name from a demangled full name.
/// For Rust, strips the trailing ::hxxxxxxxx hash if present, then returns the last path segment.
pub fn demangled_leaf(full: &str) -> String {
    // Strip Rust hash suffix like ::h1234abcd... if present
    // Require at least a minimal number of hex digits to avoid truncating valid names like
    // "foo::h" or "foo::h264". Use a conservative threshold of >= 8 hex digits.
    let trimmed = match full.rfind("::h") {
        Some(pos) => {
            let start = pos + 3; // after '::h'
            if start < full.len() {
                let suffix = &full[start..];
                if suffix.len() >= 8 && suffix.chars().all(|c| c.is_ascii_hexdigit()) {
                    &full[..pos]
                } else {
                    full
                }
            } else {
                full
            }
        }
        None => full,
    };
    // Take the last path segment by '::'
    trimmed.rsplit("::").next().unwrap_or(trimmed).to_string()
}

/// Heuristic: Rust v0 mangling starts with "_R".
pub fn is_rust_mangled(s: &str) -> bool {
    s.starts_with("_R") || looks_like_legacy_rust(s)
}

fn looks_like_legacy_rust(s: &str) -> bool {
    s.starts_with("_ZN") && s.contains("17h") && s.ends_with('E')
}

/// Heuristic: Itanium C++ mangling starts with "_Z".
pub fn is_itanium_cpp_mangled(s: &str) -> bool {
    s.starts_with("_Z")
}

fn demangle_rust(s: &str) -> Option<String> {
    match rustc_demangle::try_demangle(s) {
        Ok(sym) => Some(sym.to_string()),
        Err(_) => None,
    }
}

fn demangle_cpp(s: &str) -> Option<String> {
    match cpp_demangle::Symbol::new(s) {
        Ok(sym) => Some(sym.to_string()),
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{demangle_by_lang, is_likely_mangled};

    #[test]
    fn skips_plain_names_even_with_language_hint() {
        assert!(!is_likely_mangled(
            Some(gimli::DW_LANG_Rust),
            "std::thread::spawn"
        ));
        assert!(!is_likely_mangled(
            Some(gimli::DW_LANG_C_plus_plus_17),
            "ns::Widget::run"
        ));
        assert_eq!(
            demangle_by_lang(Some(gimli::DW_LANG_Rust), "std::thread::spawn"),
            None
        );
        assert_eq!(
            demangle_by_lang(Some(gimli::DW_LANG_C_plus_plus_17), "ns::Widget::run"),
            None
        );
    }

    #[test]
    fn still_demangles_mangled_symbols() {
        let rust_name = "_RNvCs73fAdSrgOJL_4test4main";
        let cpp_name = "_ZN2ns6Widget3runEv";

        assert!(is_likely_mangled(Some(gimli::DW_LANG_Rust), rust_name));
        assert!(is_likely_mangled(
            Some(gimli::DW_LANG_C_plus_plus_17),
            cpp_name
        ));
        assert!(demangle_by_lang(Some(gimli::DW_LANG_Rust), rust_name).is_some());
        assert!(demangle_by_lang(Some(gimli::DW_LANG_C_plus_plus_17), cpp_name).is_some());
    }

    #[test]
    fn falls_back_when_cu_language_does_not_match_symbol_style() {
        let rust_name = "_RNvCs73fAdSrgOJL_4test4main";
        let cpp_name = "_ZN2ns6Widget3runEv";

        assert_eq!(
            demangle_by_lang(Some(gimli::DW_LANG_Rust), cpp_name),
            demangle_by_lang(Some(gimli::DW_LANG_C_plus_plus_17), cpp_name)
        );
        assert_eq!(
            demangle_by_lang(Some(gimli::DW_LANG_C_plus_plus_17), rust_name),
            demangle_by_lang(Some(gimli::DW_LANG_Rust), rust_name)
        );
    }
}

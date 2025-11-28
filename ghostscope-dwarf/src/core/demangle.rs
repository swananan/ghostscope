//! Demangling helpers for Rust and C++ symbols

use gimli::DwLang;

/// Demangle a symbol string using language hint when available.
/// Returns None if demangling fails or is not applicable.
pub fn demangle_by_lang(lang: Option<DwLang>, s: &str) -> Option<String> {
    // 1) Trust DW_AT_language when available
    match lang {
        Some(gimli::DW_LANG_Rust) => {
            if let Some(d) = demangle_rust(s) {
                return Some(d);
            }
        }
        Some(gimli::DW_LANG_C_plus_plus)
        | Some(gimli::DW_LANG_C_plus_plus_11)
        | Some(gimli::DW_LANG_C_plus_plus_14)
        | Some(gimli::DW_LANG_C_plus_plus_17)
        | Some(gimli::DW_LANG_C_plus_plus_20) => {
            if let Some(d) = demangle_cpp(s) {
                return Some(d);
            }
        }
        _ => {}
    }

    // 2) Fall back to heuristics if language hint missing or demangle failed
    if is_rust_mangled(s) || looks_like_legacy_rust(s) {
        demangle_rust(s)
    } else if is_itanium_cpp_mangled(s) {
        demangle_cpp(s)
    } else {
        None
    }
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

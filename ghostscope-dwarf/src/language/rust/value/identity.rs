//! Rust standard-library type identity matching.
//!
//! Short DWARF names are treated as ambiguous until a qualified name confirms
//! their standard-library namespace.

use super::RustValueAdapter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum IdentityResolution {
    Recognized(RustValueAdapter),
    RequiresQualifiedName,
    NotApplicable,
}

pub(super) fn resolve(name: &str, dwarf_qualified_name: Option<&str>) -> IdentityResolution {
    if let Some(adapter) = recognize_exact(name, name, dwarf_qualified_name) {
        return IdentityResolution::Recognized(adapter);
    }
    if !is_ambiguous_short_name(name) {
        return IdentityResolution::NotApplicable;
    }

    let Some(qualified_name) = dwarf_qualified_name else {
        return IdentityResolution::RequiresQualifiedName;
    };
    recognize_exact(qualified_name, name, Some(qualified_name))
        .map(IdentityResolution::Recognized)
        .unwrap_or(IdentityResolution::NotApplicable)
}

fn recognize_exact(
    candidate: &str,
    original_name: &str,
    dwarf_qualified_name: Option<&str>,
) -> Option<RustValueAdapter> {
    if is_std_btree_map_name(candidate) {
        Some(RustValueAdapter::BTreeMap)
    } else if is_std_btree_set_name(candidate) {
        Some(RustValueAdapter::BTreeSet)
    } else if is_std_hash_map_name(candidate) {
        Some(RustValueAdapter::HashMap)
    } else if is_std_hash_set_name(candidate) {
        Some(RustValueAdapter::HashSet)
    } else if is_std_rc_name(candidate) {
        Some(RustValueAdapter::Rc {
            pointee_is_str: has_first_generic_argument(original_name, "Rc", "str")
                || dwarf_qualified_name
                    .is_some_and(|name| has_first_generic_argument(name, "Rc", "str")),
        })
    } else if is_std_arc_name(candidate) {
        Some(RustValueAdapter::Arc {
            pointee_is_str: has_first_generic_argument(original_name, "Arc", "str")
                || dwarf_qualified_name
                    .is_some_and(|name| has_first_generic_argument(name, "Arc", "str")),
        })
    } else if is_std_ref_name(candidate) {
        Some(RustValueAdapter::Ref)
    } else if is_std_ref_mut_name(candidate) {
        Some(RustValueAdapter::RefMut)
    } else if is_std_ref_cell_name(candidate) {
        Some(RustValueAdapter::RefCell)
    } else if is_std_cell_name(candidate) {
        Some(RustValueAdapter::Cell)
    } else if is_std_nonzero_name(candidate) {
        Some(RustValueAdapter::NonZero)
    } else if is_std_path_ref_name(candidate) {
        Some(RustValueAdapter::PathReference)
    } else if is_std_c_str_ref_name(candidate) {
        Some(RustValueAdapter::CStrReference)
    } else if matches!(
        candidate,
        "&str" | "&mut str" | "&'static str" | "&'static mut str"
    ) {
        Some(RustValueAdapter::StrReference)
    } else if is_slice_name(candidate) {
        Some(RustValueAdapter::SliceReference)
    } else if is_std_box_str_name(candidate) {
        Some(RustValueAdapter::BoxStr)
    } else if is_std_box_c_str_name(candidate) {
        Some(RustValueAdapter::BoxCStr)
    } else if is_std_c_string_name(candidate) {
        Some(RustValueAdapter::CString)
    } else if is_std_string_name(candidate) {
        Some(RustValueAdapter::String)
    } else if is_std_os_string_name(candidate) {
        Some(RustValueAdapter::OsString)
    } else if is_std_path_buf_name(candidate) {
        Some(RustValueAdapter::PathBuf)
    } else if is_std_vec_name(candidate) {
        Some(RustValueAdapter::Vec)
    } else if is_std_vec_deque_name(candidate) {
        Some(RustValueAdapter::VecDeque)
    } else {
        None
    }
}

fn is_ambiguous_short_name(name: &str) -> bool {
    name == "String"
        || name == "CString"
        || name == "OsString"
        || name == "PathBuf"
        || is_short_c_str_ref_name(name)
        || is_short_vec_name(name)
        || is_short_vec_deque_name(name)
        || is_short_box_str_name(name)
        || is_short_box_c_str_name(name)
        || is_short_nonzero_name(name)
        || is_short_cell_name(name)
        || is_short_ref_cell_name(name)
        || is_short_ref_name(name)
        || is_short_ref_mut_name(name)
        || is_short_rc_name(name)
        || is_short_arc_name(name)
        || is_short_hash_map_name(name)
        || is_short_hash_set_name(name)
        || is_short_btree_map_name(name)
        || is_short_btree_set_name(name)
}

fn is_slice_name(name: &str) -> bool {
    // Rust 1.30's GDB support stripped an explicit `'static` lifetime before
    // applying the same &[T]/&mut [T] classification used by current rust-gdb.
    let Some(referenced) = name
        .strip_prefix("&'static ")
        .or_else(|| name.strip_prefix('&'))
    else {
        return false;
    };
    let referenced = referenced.strip_prefix("mut ").unwrap_or(referenced);
    let Some(element) = referenced
        .strip_prefix('[')
        .and_then(|name| name.strip_suffix(']'))
    else {
        return false;
    };

    !element.is_empty()
}

fn is_short_vec_name(name: &str) -> bool {
    is_short_generic_name(name, "Vec")
}

fn is_short_vec_deque_name(name: &str) -> bool {
    is_short_generic_name(name, "VecDeque")
}

fn is_short_box_str_name(name: &str) -> bool {
    box_str_arguments(name, "Box<").is_some()
}

fn is_short_box_c_str_name(name: &str) -> bool {
    let Some(arguments) = name
        .strip_prefix("Box<")
        .and_then(|name| name.strip_suffix('>'))
    else {
        return false;
    };
    arguments
        .split_once(',')
        .map_or(arguments, |(target, _)| target)
        .trim()
        == "CStr"
}

fn is_short_c_str_ref_name(name: &str) -> bool {
    referenced_type_name(name) == Some("CStr")
}

fn is_short_nonzero_name(name: &str) -> bool {
    is_generic_nonzero_name(name) || is_legacy_nonzero_name(name)
}

fn is_short_cell_name(name: &str) -> bool {
    is_short_generic_name(name, "Cell")
}

fn is_short_ref_cell_name(name: &str) -> bool {
    is_short_generic_name(name, "RefCell")
}

fn is_short_ref_name(name: &str) -> bool {
    is_short_generic_name(name, "Ref")
}

fn is_short_ref_mut_name(name: &str) -> bool {
    is_short_generic_name(name, "RefMut")
}

fn is_short_rc_name(name: &str) -> bool {
    is_short_generic_name(name, "Rc")
}

fn is_short_arc_name(name: &str) -> bool {
    is_short_generic_name(name, "Arc")
}

fn is_short_hash_map_name(name: &str) -> bool {
    is_short_generic_name(name, "HashMap")
}

fn is_short_hash_set_name(name: &str) -> bool {
    is_short_generic_name(name, "HashSet")
}

fn is_short_btree_map_name(name: &str) -> bool {
    is_short_generic_name(name, "BTreeMap")
}

fn is_short_btree_set_name(name: &str) -> bool {
    is_short_generic_name(name, "BTreeSet")
}

fn is_short_generic_name(name: &str, type_name: &str) -> bool {
    let prefix = format!("{type_name}<");
    name.strip_prefix(&prefix)
        .and_then(|arguments| arguments.strip_suffix('>'))
        .is_some_and(|arguments| !arguments.is_empty())
}

fn has_first_generic_argument(name: &str, type_name: &str, expected: &str) -> bool {
    let short_prefix = format!("{type_name}<");
    let qualified_marker = format!("::{type_name}<");
    let arguments = name.strip_prefix(&short_prefix).or_else(|| {
        name.split_once(&qualified_marker)
            .map(|(_, arguments)| arguments)
    });
    arguments
        .and_then(|arguments| arguments.strip_suffix('>'))
        .and_then(|arguments| arguments.split(',').next())
        .is_some_and(|argument| argument.trim() == expected)
}

fn is_std_cell_name(name: &str) -> bool {
    is_namespaced_generic_name(name, "core::", "Cell")
}

fn is_std_ref_cell_name(name: &str) -> bool {
    is_namespaced_generic_name(name, "core::", "RefCell")
}

fn is_std_ref_name(name: &str) -> bool {
    is_namespaced_generic_name(name, "core::", "Ref")
}

fn is_std_ref_mut_name(name: &str) -> bool {
    is_namespaced_generic_name(name, "core::", "RefMut")
}

fn is_std_rc_name(name: &str) -> bool {
    is_namespaced_generic_name(name, "alloc::", "Rc")
}

fn is_std_arc_name(name: &str) -> bool {
    is_namespaced_generic_name(name, "alloc::", "Arc")
}

fn is_std_hash_map_name(name: &str) -> bool {
    is_namespaced_generic_name(name, "std::collections::", "HashMap")
}

fn is_std_hash_set_name(name: &str) -> bool {
    is_namespaced_generic_name(name, "std::collections::", "HashSet")
}

fn is_std_btree_map_name(name: &str) -> bool {
    is_namespaced_generic_name(name, "alloc::", "BTreeMap")
}

fn is_std_btree_set_name(name: &str) -> bool {
    is_namespaced_generic_name(name, "alloc::", "BTreeSet")
}

fn is_namespaced_generic_name(name: &str, prefix: &str, type_name: &str) -> bool {
    let Some(path) = name.strip_prefix(prefix) else {
        return false;
    };
    let marker = format!("::{type_name}<");
    let Some((module, arguments)) = path.split_once(&marker) else {
        return false;
    };

    is_module_path(module) && !arguments.is_empty() && arguments.ends_with('>')
}

fn is_generic_nonzero_name(name: &str) -> bool {
    is_short_generic_name(name, "NonZero")
}

fn is_legacy_nonzero_name(name: &str) -> bool {
    matches!(
        name,
        "NonZeroI8"
            | "NonZeroI16"
            | "NonZeroI32"
            | "NonZeroI64"
            | "NonZeroI128"
            | "NonZeroIsize"
            | "NonZeroU8"
            | "NonZeroU16"
            | "NonZeroU32"
            | "NonZeroU64"
            | "NonZeroU128"
            | "NonZeroUsize"
    )
}

fn is_std_nonzero_name(name: &str) -> bool {
    let Some(path) = name.strip_prefix("core::") else {
        return false;
    };
    let Some((module, type_name)) = path.rsplit_once("::") else {
        return false;
    };

    is_module_path(module)
        && (is_generic_nonzero_name(type_name)
            || ((module == "num" || module.starts_with("num::"))
                && is_legacy_nonzero_name(type_name)))
}

fn is_std_box_str_name(name: &str) -> bool {
    let Some(path) = name.strip_prefix("alloc::") else {
        return false;
    };
    let Some((module, _)) = path
        .split_once("::Box<")
        .filter(|(_, arguments)| box_str_arguments(arguments, "").is_some())
    else {
        return false;
    };

    is_module_path(module)
}

fn is_std_box_c_str_name(name: &str) -> bool {
    let Some(path) = name.strip_prefix("alloc::") else {
        return false;
    };
    let Some((module, _)) = path
        .split_once("::Box<")
        .filter(|(_, arguments)| box_c_str_arguments(arguments, "").is_some())
    else {
        return false;
    };

    is_module_path(module)
}

fn box_str_arguments<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    let arguments = name.strip_prefix(prefix)?.strip_suffix('>')?;
    (arguments == "str"
        || arguments
            .strip_prefix("str,")
            .is_some_and(|allocator| !allocator.is_empty()))
    .then_some(arguments)
}

fn box_c_str_arguments<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    let arguments = name.strip_prefix(prefix)?.strip_suffix('>')?;
    let target = arguments
        .split_once(',')
        .map_or(arguments, |(target, _)| target)
        .trim();
    is_std_c_str_name(target).then_some(arguments)
}

fn is_std_c_string_name(name: &str) -> bool {
    is_namespaced_plain_name(name, "alloc::ffi::", "CString")
        || is_namespaced_plain_name(name, "std::ffi::", "CString")
}

fn is_std_c_str_ref_name(name: &str) -> bool {
    referenced_type_name(name).is_some_and(is_std_c_str_name)
}

fn referenced_type_name(name: &str) -> Option<&str> {
    let referenced = name
        .strip_prefix("&'static ")
        .or_else(|| name.strip_prefix('&'))?;
    Some(referenced.strip_prefix("mut ").unwrap_or(referenced))
}

fn is_std_c_str_name(name: &str) -> bool {
    is_namespaced_plain_name(name, "core::ffi::", "CStr")
        || is_namespaced_plain_name(name, "std::ffi::", "CStr")
}

fn is_std_string_name(name: &str) -> bool {
    is_namespaced_plain_name(name, "alloc::", "String")
}

fn is_std_os_string_name(name: &str) -> bool {
    is_namespaced_plain_name(name, "std::ffi::", "OsString")
}

fn is_std_path_ref_name(name: &str) -> bool {
    let Some(referenced) = name
        .strip_prefix("&'static ")
        .or_else(|| name.strip_prefix('&'))
    else {
        return false;
    };
    let referenced = referenced.strip_prefix("mut ").unwrap_or(referenced);
    is_std_path_name(referenced)
}

fn is_std_path_name(name: &str) -> bool {
    is_namespaced_plain_name(name, "std::", "Path")
}

fn is_std_path_buf_name(name: &str) -> bool {
    is_namespaced_plain_name(name, "std::", "PathBuf")
}

fn is_std_vec_name(name: &str) -> bool {
    is_namespaced_generic_name(name, "alloc::", "Vec")
}

fn is_std_vec_deque_name(name: &str) -> bool {
    is_namespaced_generic_name(name, "alloc::", "VecDeque")
}

fn is_namespaced_plain_name(name: &str, prefix: &str, type_name: &str) -> bool {
    let Some(path) = name.strip_prefix(prefix) else {
        return false;
    };
    let suffix = format!("::{type_name}");
    let Some(module) = path.strip_suffix(&suffix) else {
        return false;
    };
    is_module_path(module)
}

fn is_module_path(module: &str) -> bool {
    !module.is_empty()
        && module.split("::").all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        })
}

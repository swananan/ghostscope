use std::borrow::Cow;

pub(crate) fn has_path_separator(path: &str) -> bool {
    path.contains('/') || path.contains('\\')
}

pub(crate) fn file_name(path: &str) -> &str {
    path.rsplit(['/', '\\'])
        .find(|component| !component.is_empty())
        .unwrap_or(path)
}

pub(crate) fn path_component_suffix_matches(path: &str, suffix: &str) -> bool {
    let path = normalize_separators(path);
    let suffix = normalize_separators(suffix);
    component_suffix_matches(path.as_ref(), suffix.as_ref())
}

pub(crate) fn source_path_matches(candidate_path: &str, requested_file_path: &str) -> bool {
    let candidate = normalize_separators(candidate_path);
    let requested = normalize_separators(requested_file_path);

    if component_suffix_matches(candidate.as_ref(), requested.as_ref())
        || component_suffix_matches(requested.as_ref(), candidate.as_ref())
    {
        return true;
    }

    // Directory-qualified hints were already narrowed by reverse lookup; do not
    // re-admit unrelated same-basename rows that share the queried PC.
    !has_path_separator(requested.as_ref()) && file_name(candidate.as_ref()) == requested.as_ref()
}

fn normalize_separators(path: &str) -> Cow<'_, str> {
    if path.contains('\\') {
        Cow::Owned(path.replace('\\', "/"))
    } else {
        Cow::Borrowed(path)
    }
}

fn component_suffix_matches(path: &str, suffix: &str) -> bool {
    if path == suffix {
        return true;
    }
    if suffix.is_empty() || !path.ends_with(suffix) {
        return false;
    }

    let prefix_len = path.len() - suffix.len();
    if prefix_len == 0 || suffix.starts_with('/') {
        return true;
    }

    path.as_bytes().get(prefix_len - 1) == Some(&b'/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_path_matches_keeps_directory_qualified_hints_narrow() {
        assert!(source_path_matches("/a/foo.c", "/a/foo.c"));
        assert!(source_path_matches("/build/src/foo.c", "src/foo.c"));
        assert!(source_path_matches("foo.c", "/src/foo.c"));
        assert!(!source_path_matches("/b/foo.c", "/a/foo.c"));
    }

    #[test]
    fn source_path_matches_requires_component_boundaries() {
        assert!(source_path_matches("/src/foo/bar.c", "foo/bar.c"));
        assert!(!source_path_matches("/src/myfoo/bar.c", "foo/bar.c"));
        assert!(!source_path_matches("/src/foobar.c", "bar.c"));
    }

    #[test]
    fn source_path_matches_allows_basename_queries() {
        assert!(source_path_matches("/a/foo.c", "foo.c"));
        assert!(source_path_matches("C:\\project\\foo.c", "foo.c"));
        assert!(!source_path_matches("/a/foobar.c", "bar.c"));
    }
}

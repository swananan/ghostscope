use crate::TypeQualifier;

/// Parsed form of the C-style type syntax accepted by GhostScope casts.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct TypeSpec {
    pub(crate) base: String,
    pub(crate) qualifiers: Vec<TypeQualifier>,
    pub(crate) pointer_count: usize,
    pub(crate) arrays: Vec<Option<u64>>,
}

pub(crate) fn parse(type_spec: &str) -> Option<TypeSpec> {
    let mut spec = type_spec.trim();
    if spec.is_empty() {
        return None;
    }

    let mut arrays = Vec::new();
    while let Some((base, count)) = take_array_suffix(spec) {
        arrays.push(count);
        spec = base.trim_end();
    }

    let mut pointer_count = 0usize;
    while let Some(base) = spec.strip_suffix('*') {
        pointer_count += 1;
        spec = base.trim_end();
    }

    let (qualifiers, base) = strip_leading_qualifiers(spec);
    let base = ["struct ", "class ", "union ", "enum "]
        .into_iter()
        .find_map(|prefix| base.strip_prefix(prefix))
        .unwrap_or(base)
        .trim();
    if base.is_empty() {
        return None;
    }

    Some(TypeSpec {
        base: base.to_string(),
        qualifiers,
        pointer_count,
        arrays,
    })
}

fn take_array_suffix(spec: &str) -> Option<(&str, Option<u64>)> {
    let spec = spec.trim_end();
    if !spec.ends_with(']') {
        return None;
    }
    let open = spec.rfind('[')?;
    let inside = spec[open + 1..spec.len() - 1].trim();
    let count = if inside.is_empty() {
        None
    } else {
        Some(inside.parse::<u64>().ok()?)
    };
    Some((&spec[..open], count))
}

fn strip_leading_qualifiers(mut spec: &str) -> (Vec<TypeQualifier>, &str) {
    let mut qualifiers = Vec::new();
    loop {
        let trimmed = spec.trim_start();
        if let Some(rest) = trimmed.strip_prefix("const ") {
            qualifiers.push(TypeQualifier::Const);
            spec = rest;
        } else if let Some(rest) = trimmed.strip_prefix("volatile ") {
            qualifiers.push(TypeQualifier::Volatile);
            spec = rest;
        } else if let Some(rest) = trimmed.strip_prefix("restrict ") {
            qualifiers.push(TypeQualifier::Restrict);
            spec = rest;
        } else {
            return (qualifiers, trimmed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_qualified_pointer_array() {
        let spec = parse("const struct Pair *[4]").expect("type spec");
        assert_eq!(spec.base, "Pair");
        assert_eq!(spec.qualifiers, vec![TypeQualifier::Const]);
        assert_eq!(spec.pointer_count, 1);
        assert_eq!(spec.arrays, vec![Some(4)]);
    }
}

use super::{AddressQueryResult, DwarfAnalyzer};
use crate::{
    core::{ModuleAddress, Result},
    path_match,
};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct SourceLineAddressSearch {
    pub file_path: Option<String>,
    pub line_number: u32,
    pub raw_address_count: usize,
    pub addresses: Vec<ModuleAddress>,
}

#[derive(Debug, Clone)]
pub struct SourceLineQuerySearch {
    pub file_path: Option<String>,
    pub line_number: u32,
    pub raw_address_count: usize,
    pub addresses: Vec<AddressQueryResult>,
}

impl DwarfAnalyzer {
    /// Build DWARF source path candidates for a user-provided file path.
    ///
    /// This keeps DWARF path matching rules in the analyzer: exact paths first,
    /// then component-boundary suffix matches, then unique basename matches
    /// for bare filenames, and finally the original query.
    pub fn source_line_candidates(&self, file_path: &str) -> Vec<String> {
        let Ok(grouped) = self.get_grouped_file_info_by_module() else {
            return vec![file_path.to_string()];
        };

        let mut exact = Vec::new();
        let mut suffix_matches = Vec::new();
        let mut basename_matches = Vec::new();
        let mut seen_paths = HashSet::new();
        let has_separator = path_match::has_path_separator(file_path);
        let basename = path_match::file_name(file_path);

        for (_module_path, files) in grouped {
            for file in files {
                if !seen_paths.insert(file.full_path.clone()) {
                    continue;
                }

                if file.full_path == file_path {
                    exact.push(file.full_path);
                } else if has_separator
                    && (path_match::path_component_suffix_matches(&file.full_path, file_path)
                        || path_match::path_component_suffix_matches(file_path, &file.full_path))
                {
                    suffix_matches.push(file.full_path);
                } else if !has_separator && file.basename == basename {
                    basename_matches.push(file.full_path);
                }
            }
        }

        exact.sort();
        suffix_matches.sort();
        basename_matches.sort();
        let basename_candidate = if basename_matches.len() == 1 {
            basename_matches.pop()
        } else {
            None
        };

        let mut candidates = Vec::new();
        let mut seen = HashSet::new();
        for candidate in exact
            .into_iter()
            .chain(suffix_matches)
            .chain(basename_candidate)
            .chain([file_path.to_string()])
        {
            if !candidate.trim().is_empty() && seen.insert(candidate.clone()) {
                candidates.push(candidate);
            }
        }
        candidates
    }

    /// Probe source-line candidates until a candidate resolves to addresses.
    ///
    /// If a candidate resolves before target filtering but all addresses are
    /// filtered out, the first filtered match is returned with an empty address
    /// list so callers can produce a target-scoped error.
    pub fn resolve_source_line_addresses_best_effort<I, S>(
        &self,
        candidates: I,
        line_number: u32,
        target_path: Option<&str>,
    ) -> Result<SourceLineAddressSearch>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut seen = HashSet::new();
        let mut first_target_filtered: Option<SourceLineAddressSearch> = None;

        for candidate in candidates {
            let candidate = candidate.as_ref().trim();
            if candidate.is_empty() || !seen.insert(candidate.to_string()) {
                continue;
            }

            let module_addresses = self.lookup_addresses_by_source_line(candidate, line_number);
            let raw_address_count = module_addresses.len();
            if raw_address_count == 0 {
                continue;
            }

            let addresses =
                self.filter_module_addresses_to_target(module_addresses, target_path)?;
            let search = SourceLineAddressSearch {
                file_path: Some(candidate.to_string()),
                line_number,
                raw_address_count,
                addresses,
            };

            if !search.addresses.is_empty() {
                return Ok(search);
            }
            if first_target_filtered.is_none() {
                first_target_filtered = Some(search);
            }
        }

        Ok(first_target_filtered.unwrap_or(SourceLineAddressSearch {
            file_path: None,
            line_number,
            raw_address_count: 0,
            addresses: Vec::new(),
        }))
    }

    /// Probe source-line candidates and return rich debug information for the
    /// first candidate with address results.
    pub fn resolve_source_line_query_best_effort<I, S>(
        &self,
        candidates: I,
        line_number: u32,
        target_path: Option<&str>,
    ) -> Result<SourceLineQuerySearch>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let address_search =
            self.resolve_source_line_addresses_best_effort(candidates, line_number, target_path)?;
        let Some(file_path) = address_search.file_path.clone() else {
            return Ok(SourceLineQuerySearch {
                file_path: None,
                line_number,
                raw_address_count: 0,
                addresses: Vec::new(),
            });
        };

        if address_search.addresses.is_empty() {
            return Ok(SourceLineQuerySearch {
                file_path: Some(file_path),
                line_number,
                raw_address_count: address_search.raw_address_count,
                addresses: Vec::new(),
            });
        }

        let addresses = self.query_module_addresses_for_source_line_best_effort(
            address_search.addresses,
            &file_path,
            line_number,
            &format!("source line '{file_path}:{line_number}'"),
        )?;

        Ok(SourceLineQuerySearch {
            file_path: Some(file_path),
            line_number,
            raw_address_count: address_search.raw_address_count,
            addresses,
        })
    }

    /// Explain why a source-line lookup did not resolve to executable addresses.
    pub fn describe_source_line_failure(&self, file_path: &str, line_number: u32) -> String {
        let default_msg =
            format!("No addresses resolved for source line {file_path}:{line_number}");

        let grouped = match self.get_grouped_file_info_by_module() {
            Ok(grouped) => grouped,
            Err(_) => return default_msg,
        };

        let mut all_full_paths = Vec::new();
        let mut same_basename_paths = Vec::new();
        let has_sep = path_match::has_path_separator(file_path);
        let basename = path_match::file_name(file_path);

        for (_module, files) in &grouped {
            for file in files {
                all_full_paths.push(file.full_path.clone());
                if file.basename == basename {
                    same_basename_paths.push(file.full_path.clone());
                }
            }
        }

        if all_full_paths.is_empty() {
            return default_msg;
        }

        let exact_match = all_full_paths.iter().any(|path| path == file_path);
        let suffix_matches: Vec<String> = all_full_paths
            .iter()
            .filter(|path| {
                path_match::path_component_suffix_matches(path, file_path)
                    || path_match::path_component_suffix_matches(file_path, path)
            })
            .cloned()
            .collect();

        if same_basename_paths.is_empty() {
            return format!(
                "Source file not found in DWARF: {file_path}.\n- Tips: use 'srcpath map <dwarf_comp_dir> <local_dir>' or pass full DWARF path.\n- List files with: dwarf-tool source-files or 'info source-files'"
            );
        }

        if !exact_match && suffix_matches.is_empty() && has_sep && same_basename_paths.len() > 1 {
            let mut samples = same_basename_paths.clone();
            samples.sort();
            samples.dedup();
            if samples.len() > 3 {
                samples.truncate(3);
            }
            let sample_list = samples.join("\n  - ");
            return format!(
                "Multiple files named '{basename}' found; the given path '{file_path}' did not uniquely match by suffix.\nTry a more specific path or add a path mapping (srcpath map).\nExamples:\n  - {sample_list}"
            );
        }

        let mut hit_candidates = Vec::new();
        let probe_list = if !suffix_matches.is_empty() {
            suffix_matches
        } else {
            let mut paths = same_basename_paths.clone();
            paths.sort();
            paths.dedup();
            paths.truncate(20);
            paths
        };

        for candidate in &probe_list {
            if !self
                .lookup_addresses_by_source_line(candidate, line_number)
                .is_empty()
            {
                hit_candidates.push(candidate.clone());
                if hit_candidates.len() >= 3 {
                    break;
                }
            }
        }

        if !hit_candidates.is_empty() {
            let list = hit_candidates.join("\n  - ");
            return format!(
                "Ambiguous path: '{file_path}' did not resolve, but found addresses for the same line in:\n  - {list}\nPlease use a more specific path (full DWARF path) or add a mapping (srcpath map)."
            );
        }

        format!(
            "No executable addresses for {file_path}:{line_number} (file exists in DWARF but this line has no statement).\nTry a nearby line, or rebuild with debug info and lower optimization (e.g., -g -O0)."
        )
    }
}

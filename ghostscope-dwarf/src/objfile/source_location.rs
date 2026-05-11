use super::LoadedObjfile;
use crate::{core::SourceLocation, parser::SourceFile, path_match};
use std::collections::HashSet;

mod file_selection_scoring {
    pub const SEARCH_RANGE_BYTES: u64 = 100;
    pub const NON_HEADER_BONUS: i32 = 1000;
    pub const COMPILATION_UNIT_MATCH_BONUS: i32 = 500;
    pub const NON_SYSTEM_PATH_BONUS: i32 = 200;
    pub const STATEMENT_BOUNDARY_BONUS: i32 = 100;
    pub const NO_PATH_PENALTY: i32 = -1000;
}

impl LoadedObjfile {
    pub(crate) fn lookup_source_location(&self, address: u64) -> Option<SourceLocation> {
        let all_line_entries = self.line_mapping.lookup_all_lines_at_address(address);

        if all_line_entries.is_empty() {
            if let Some(line_entry) = self.line_mapping.lookup_line(address) {
                return self.create_source_location_from_entry(line_entry);
            }
            return None;
        }

        let best_entry = if all_line_entries.len() == 1 {
            let entry = all_line_entries[0];
            self.find_alternative_source_file(entry).unwrap_or(entry)
        } else {
            self.select_best_line_entry(&all_line_entries)
        };

        self.create_source_location_from_entry(best_entry)
    }

    pub(crate) fn lookup_source_location_for_source_line(
        &self,
        address: u64,
        file_path: &str,
        line_number: u32,
    ) -> Option<SourceLocation> {
        let all_line_entries = self.line_mapping.lookup_all_lines_at_address(address);
        let matching_entries: Vec<_> = all_line_entries
            .iter()
            .copied()
            .filter(|entry| {
                entry.line == u64::from(line_number)
                    && self.line_entry_matches_requested_source(entry, file_path)
            })
            .collect();

        if matching_entries.is_empty() {
            return self.lookup_source_location(address);
        }

        let best_entry = self.select_best_line_entry(&matching_entries);
        self.create_source_location_from_entry(best_entry)
    }

    fn line_entry_matches_requested_source(
        &self,
        entry: &crate::core::LineEntry,
        requested_file_path: &str,
    ) -> bool {
        let Some(candidate_path) = self.get_file_path_for_entry(entry) else {
            return false;
        };
        path_match::source_path_matches(&candidate_path, requested_file_path)
    }

    fn find_alternative_source_file<'a>(
        &'a self,
        entry: &'a crate::core::LineEntry,
    ) -> Option<&'a crate::core::LineEntry> {
        let current_file_path = self.get_file_path_for_entry(entry)?;

        let is_header = current_file_path.ends_with(".h")
            || current_file_path.ends_with(".hpp")
            || current_file_path.ends_with(".hxx")
            || current_file_path.contains("/include/")
            || current_file_path.contains("/usr/include/");

        if !is_header {
            return None;
        }

        tracing::debug!(
            "find_alternative_source_file: current entry points to header '{}', looking for main source alternative",
            current_file_path
        );

        let search_range = file_selection_scoring::SEARCH_RANGE_BYTES;
        let start_addr = entry.address.saturating_sub(search_range);
        let end_addr = entry.address.saturating_add(search_range);

        for (addr, candidate_entry) in self.line_mapping.get_entries_in_range(start_addr, end_addr)
        {
            if candidate_entry.compilation_unit != entry.compilation_unit {
                continue;
            }

            if let Some(candidate_file_path) = self.get_file_path_for_entry(candidate_entry) {
                let is_candidate_header = candidate_file_path.ends_with(".h")
                    || candidate_file_path.ends_with(".hpp")
                    || candidate_file_path.ends_with(".hxx")
                    || candidate_file_path.contains("/include/")
                    || candidate_file_path.contains("/usr/include/");

                if !is_candidate_header {
                    tracing::debug!(
                        "find_alternative_source_file: found alternative source file '{}' at address 0x{:x}",
                        candidate_file_path, addr
                    );
                    return Some(candidate_entry);
                }
            }
        }

        if let Some(cu_file_index) = self
            .scoped_file_manager
            .get_cu_file_index(&entry.compilation_unit)
        {
            for file_entry in cu_file_index.file_entries() {
                if let Some(full_path) = file_entry.get_full_path(cu_file_index) {
                    let is_source = full_path.ends_with(".c")
                        || full_path.ends_with(".cpp")
                        || full_path.ends_with(".cc")
                        || full_path.ends_with(".rs")
                        || (full_path.contains(&*entry.compilation_unit)
                            && !full_path.ends_with(".h"));

                    if is_source {
                        tracing::debug!(
                            "find_alternative_source_file: using main source file '{}' from compilation unit",
                            full_path
                        );
                        return None;
                    }
                }
            }
        }

        None
    }

    fn select_best_line_entry<'a>(
        &self,
        entries: &[&'a crate::core::LineEntry],
    ) -> &'a crate::core::LineEntry {
        if entries.len() == 1 {
            return entries[0];
        }

        tracing::debug!(
            "select_best_line_entry: {} candidates at address 0x{:x}",
            entries.len(),
            entries[0].address
        );

        let mut best = entries[0];
        let mut best_score = self.score_line_entry(best);

        for &entry in entries.iter().skip(1) {
            let score = self.score_line_entry(entry);
            tracing::debug!(
                "  candidate: {}:{} (stmt={}, score={})",
                self.get_file_path_for_entry(entry)
                    .unwrap_or("unknown".to_string()),
                entry.line,
                entry.is_stmt,
                score
            );

            // Equal-scored rows are still distinct debug-line candidates. Prefer
            // the later row to preserve the old single-entry map replacement
            // behavior for generic PC lookups.
            if score >= best_score {
                best = entry;
                best_score = score;
            }
        }

        tracing::debug!(
            "select_best_line_entry: selected {} (score={})",
            self.get_file_path_for_entry(best)
                .unwrap_or("unknown".to_string()),
            best_score
        );

        best
    }

    fn score_line_entry(&self, entry: &crate::core::LineEntry) -> i32 {
        let mut score = 0;
        let file_path = match self.get_file_path_for_entry(entry) {
            Some(path) => path,
            None => return file_selection_scoring::NO_PATH_PENALTY,
        };

        let is_header = file_path.ends_with(".h")
            || file_path.ends_with(".hpp")
            || file_path.ends_with(".hxx")
            || file_path.contains("/include/")
            || file_path.contains("/usr/include/");

        if !is_header {
            score += file_selection_scoring::NON_HEADER_BONUS;
        }

        if let Some(filename) = std::path::Path::new(&file_path).file_stem() {
            if let Some(cu_stem) = std::path::Path::new(entry.compilation_unit.as_ref()).file_stem()
            {
                if filename == cu_stem {
                    score += file_selection_scoring::COMPILATION_UNIT_MATCH_BONUS;
                }
            }
        }

        score += file_path.len() as i32;

        if entry.is_stmt {
            score += file_selection_scoring::STATEMENT_BOUNDARY_BONUS;
        }

        if !file_path.starts_with("/usr/") && !file_path.starts_with("/lib/") {
            score += file_selection_scoring::NON_SYSTEM_PATH_BONUS;
        }

        score
    }

    fn get_file_path_for_entry(&self, entry: &crate::core::LineEntry) -> Option<String> {
        if !entry.file_path.is_empty() {
            return Some(entry.file_path.clone());
        }

        if let Some(full_path) = self
            .scoped_file_manager
            .lookup_by_scoped_index(&entry.compilation_unit, entry.file_index)
        {
            return Some(full_path);
        }

        Some(entry.compilation_unit.to_string())
    }

    fn create_source_location_from_entry(
        &self,
        line_entry: &crate::core::LineEntry,
    ) -> Option<SourceLocation> {
        tracing::debug!(
            "create_source_location_from_entry: line_entry.file_path='{}', line_entry.file_index={}, compilation_unit='{}'",
            line_entry.file_path, line_entry.file_index, line_entry.compilation_unit
        );

        if line_entry.compilation_unit.contains('/')
            && (line_entry.compilation_unit.ends_with(".c")
                || line_entry.compilation_unit.ends_with(".cpp")
                || line_entry.compilation_unit.ends_with(".cc")
                || line_entry.compilation_unit.ends_with(".rs"))
        {
            if let Some(resolved_full_path) = self
                .scoped_file_manager
                .lookup_by_scoped_index(&line_entry.compilation_unit, line_entry.file_index)
            {
                if self.is_path_like(&resolved_full_path) {
                    tracing::debug!(
                        "create_source_location_from_entry: CU looks like path; using resolved full path '{}'",
                        resolved_full_path
                    );
                    return Some(SourceLocation {
                        file_path: resolved_full_path,
                        line_number: line_entry.line as u32,
                        column: Some(line_entry.column as u32),
                        address: line_entry.address,
                    });
                } else {
                    tracing::debug!(
                        "create_source_location_from_entry: resolved full path is bare filename; keeping CU '{}'",
                        line_entry.compilation_unit
                    );
                    return Some(SourceLocation {
                        file_path: line_entry.compilation_unit.to_string(),
                        line_number: line_entry.line as u32,
                        column: Some(line_entry.column as u32),
                        address: line_entry.address,
                    });
                }
            }

            return Some(SourceLocation {
                file_path: line_entry.compilation_unit.to_string(),
                line_number: line_entry.line as u32,
                column: Some(line_entry.column as u32),
                address: line_entry.address,
            });
        }

        let preferred_file_path = {
            let current_path = self
                .scoped_file_manager
                .lookup_by_scoped_index(&line_entry.compilation_unit, line_entry.file_index)
                .unwrap_or_else(|| line_entry.file_path.clone());

            tracing::debug!(
                "create_source_location_from_entry: found file via ScopedFileIndexManager: '{}'",
                current_path
            );

            if self.is_path_like(&current_path) {
                if self.is_header_file(&current_path) {
                    if let Some(alternative_path) =
                        self.find_main_source_file_in_cu(&line_entry.compilation_unit)
                    {
                        tracing::debug!(
                            "create_source_location_from_entry: replaced header '{}' with main source '{}'",
                            current_path, alternative_path
                        );
                        alternative_path
                    } else {
                        current_path
                    }
                } else {
                    current_path
                }
            } else if !line_entry.file_path.is_empty() && self.is_path_like(&line_entry.file_path) {
                tracing::debug!(
                    "create_source_location_from_entry: using line entry file_path: '{}' (scoped result was bare)",
                    line_entry.file_path
                );
                line_entry.file_path.clone()
            } else if self.is_path_like(line_entry.compilation_unit.as_ref()) {
                tracing::debug!(
                    "create_source_location_from_entry: using CU path: '{}' (scoped result was bare)",
                    line_entry.compilation_unit
                );
                line_entry.compilation_unit.to_string()
            } else {
                current_path
            }
        };

        tracing::debug!(
            "create_source_location_from_entry: final file_path='{}'",
            preferred_file_path
        );

        Some(SourceLocation {
            file_path: preferred_file_path,
            line_number: line_entry.line as u32,
            column: Some(line_entry.column as u32),
            address: line_entry.address,
        })
    }

    fn is_path_like(&self, s: &str) -> bool {
        s.contains('/')
    }

    fn is_header_file(&self, file_path: &str) -> bool {
        file_path.ends_with(".h")
            || file_path.ends_with(".hpp")
            || file_path.ends_with(".hxx")
            || file_path.contains("/include/")
            || file_path.contains("/usr/include/")
    }

    fn find_main_source_file_in_cu(&self, compilation_unit: &str) -> Option<String> {
        if let Some(cu_file_index) = self.scoped_file_manager.get_cu_file_index(compilation_unit) {
            tracing::debug!(
                "find_main_source_file_in_cu: searching for main source file in CU '{}'",
                compilation_unit
            );

            for file_entry in cu_file_index.file_entries() {
                if let Some(full_path) = file_entry.get_full_path(cu_file_index) {
                    if !self.is_header_file(&full_path) {
                        if let Some(cu_stem) = std::path::Path::new(compilation_unit).file_stem() {
                            if let Some(file_stem) = std::path::Path::new(&full_path).file_stem() {
                                if cu_stem == file_stem {
                                    tracing::debug!(
                                        "find_main_source_file_in_cu: found matching source file '{}'",
                                        full_path
                                    );
                                    return Some(full_path);
                                }
                            }
                        }
                    }
                }
            }

            for file_entry in cu_file_index.file_entries() {
                if let Some(full_path) = file_entry.get_full_path(cu_file_index) {
                    if !self.is_header_file(&full_path) {
                        tracing::debug!(
                            "find_main_source_file_in_cu: found alternative source file '{}'",
                            full_path
                        );
                        return Some(full_path);
                    }
                }
            }
        }

        None
    }

    pub(crate) fn lookup_addresses_by_source_line(
        &self,
        file_path: &str,
        line_number: u32,
    ) -> Vec<u64> {
        let addresses = self
            .line_mapping
            .lookup_addresses_by_path(file_path, line_number as u64);

        if !addresses.is_empty() {
            tracing::info!(
                "Found {} addresses for {}:{} in module {}",
                addresses.len(),
                file_path,
                line_number,
                self.module_path().display()
            );
        } else {
            tracing::debug!(
                "No addresses found for {}:{} in module {}",
                file_path,
                line_number,
                self.module_path().display()
            );
        }

        addresses
    }

    pub(crate) fn get_all_files(&self) -> Vec<SourceFile> {
        let mut source_files = Vec::new();
        let mut seen_paths = HashSet::new();

        for cu in self.compilation_units.values() {
            for file in &cu.files {
                if seen_paths.insert(file.full_path.clone()) {
                    source_files.push(file.clone());
                }
            }
        }

        source_files.sort_by(|a, b| a.full_path.cmp(&b.full_path));
        source_files
    }
}

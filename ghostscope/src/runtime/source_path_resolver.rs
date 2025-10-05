use crate::config::settings::SourceConfig;
use ghostscope_ui::events::{PathSubstitution, SourcePathInfo};
use std::path::{Path, PathBuf};
use tracing::{debug, warn};

/// Source path resolver for mapping DWARF compilation paths to runtime filesystem paths
#[derive(Debug)]
pub struct SourcePathResolver {
    // Config file rules (immutable baseline)
    config_substitutions: Vec<PathSubstitution>,
    config_search_dirs: Vec<String>,

    // Runtime-added rules (mutable)
    runtime_substitutions: Vec<PathSubstitution>,
    runtime_search_dirs: Vec<String>,
}

impl SourcePathResolver {
    /// Create new source path resolver from config
    pub fn new(config: &SourceConfig) -> Self {
        // Convert settings::PathSubstitution to events::PathSubstitution
        // This conversion is necessary to avoid circular dependencies between crates
        let config_substitutions = config
            .substitutions
            .iter()
            .map(Self::convert_substitution)
            .collect();

        Self {
            config_substitutions,
            config_search_dirs: config.search_dirs.clone(),
            runtime_substitutions: Vec::new(),
            runtime_search_dirs: Vec::new(),
        }
    }

    /// Convert config PathSubstitution to events PathSubstitution
    #[inline]
    fn convert_substitution(sub: &crate::config::settings::PathSubstitution) -> PathSubstitution {
        PathSubstitution {
            from: sub.from.clone(),
            to: sub.to.clone(),
        }
    }

    /// Resolve DWARF path to actual filesystem path
    ///
    /// Resolution strategy:
    /// 1. Try original path if it exists
    /// 2. Apply substitution rules (runtime first, then config)
    /// 3. Search in additional directories by basename
    pub fn resolve(&self, dwarf_path: &str) -> Option<PathBuf> {
        // Strategy 1: Try exact path
        let path = Path::new(dwarf_path);
        if path.exists() {
            debug!("Source path resolved (exact): {}", dwarf_path);
            return Some(path.to_path_buf());
        }

        // Strategy 2: Apply substitution rules (runtime > config) with boundary checking
        if let Some(substituted) = self.try_substitute_path(dwarf_path) {
            let new_path = PathBuf::from(&substituted);
            if new_path.exists() {
                debug!(
                    "Source path resolved (substitution): {} -> {}",
                    dwarf_path,
                    new_path.display()
                );
                return Some(new_path);
            }
        }

        // Strategy 3: Search in additional directories by basename
        // Note: Searches only in the root of each directory (non-recursive)
        // For example, /usr/local/src will find /usr/local/src/foo.c but not /usr/local/src/subdir/bar.c
        if let Some(basename) = path.file_name() {
            for search_dir in self
                .runtime_search_dirs
                .iter()
                .chain(self.config_search_dirs.iter())
            {
                let candidate = PathBuf::from(search_dir).join(basename);
                if candidate.exists() {
                    debug!(
                        "Source path resolved (search dir): {} -> {} (dir: {})",
                        dwarf_path,
                        candidate.display(),
                        search_dir
                    );
                    return Some(candidate);
                }
            }
        }

        warn!("Failed to resolve source path: {}", dwarf_path);
        None
    }

    /// Add search directory at runtime
    pub fn add_search_dir(&mut self, dir: String) {
        if !self.runtime_search_dirs.contains(&dir) {
            self.runtime_search_dirs.push(dir);
        }
    }

    /// Add path substitution at runtime
    /// If a mapping for the same 'from' prefix already exists, it will be updated with the new 'to' path
    pub fn add_substitution(&mut self, from: String, to: String) {
        // Check if a mapping for this 'from' prefix already exists
        if let Some(existing) = self
            .runtime_substitutions
            .iter_mut()
            .find(|s| s.from == from)
        {
            // Update existing mapping
            existing.to = to;
        } else {
            // Add new mapping
            self.runtime_substitutions
                .push(PathSubstitution { from, to });
        }
    }

    /// Remove rule from runtime (by pattern matching)
    /// Returns true if something was removed
    pub fn remove(&mut self, pattern: &str) -> bool {
        let mut removed = false;

        // Try to remove as search directory
        if let Some(pos) = self.runtime_search_dirs.iter().position(|d| d == pattern) {
            self.runtime_search_dirs.remove(pos);
            removed = true;
        }

        // Try to remove as substitution rule (match 'from' field)
        if let Some(pos) = self
            .runtime_substitutions
            .iter()
            .position(|s| s.from == pattern)
        {
            self.runtime_substitutions.remove(pos);
            removed = true;
        }

        removed
    }

    /// Clear all runtime rules
    pub fn clear_runtime(&mut self) {
        self.runtime_substitutions.clear();
        self.runtime_search_dirs.clear();
    }

    /// Reset to config-only rules
    pub fn reset(&mut self) {
        self.clear_runtime();
    }

    /// Try to substitute path prefix with proper boundary checking
    /// Returns the substituted path if a valid match is found
    ///
    /// Boundary checking ensures that:
    /// - `/build/my` does NOT match `/build/myproject/src/main.c`
    /// - `/build/myproject` DOES match `/build/myproject/src/main.c`
    /// - `/build/myproject` DOES match `/build/myproject` (exact match)
    fn try_substitute_path(&self, path: &str) -> Option<String> {
        // Try runtime substitutions first, then config substitutions
        for sub in self
            .runtime_substitutions
            .iter()
            .chain(self.config_substitutions.iter())
        {
            if let Some(suffix) = path.strip_prefix(&sub.from) {
                // Ensure boundary: suffix must be empty (exact match) or start with path separator
                // This prevents `/build/my` from matching `/build/myproject`
                if suffix.is_empty() || suffix.starts_with('/') {
                    return Some(format!("{}{}", sub.to, suffix));
                }
            }
        }
        None
    }

    /// Get all rules for display
    pub fn get_all_rules(&self) -> SourcePathInfo {
        let all_substitutions: Vec<PathSubstitution> = self
            .runtime_substitutions
            .iter()
            .chain(self.config_substitutions.iter())
            .cloned()
            .collect();

        let all_search_dirs: Vec<String> = self
            .runtime_search_dirs
            .iter()
            .chain(self.config_search_dirs.iter())
            .cloned()
            .collect();

        SourcePathInfo {
            substitutions: all_substitutions,
            search_dirs: all_search_dirs,
            runtime_substitution_count: self.runtime_substitutions.len(),
            runtime_search_dir_count: self.runtime_search_dirs.len(),
            config_substitution_count: self.config_substitutions.len(),
            config_search_dir_count: self.config_search_dirs.len(),
        }
    }
}

/// Apply substitutions to directory path only (for info source)
pub fn apply_substitutions_to_directory(resolver: &SourcePathResolver, directory: &str) -> String {
    resolver
        .try_substitute_path(directory)
        .unwrap_or_else(|| directory.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::{PathSubstitution as SettingsPathSubstitution, SourceConfig};

    /// Create a test resolver with given config
    fn create_test_resolver(
        config_subs: Vec<(&str, &str)>,
        config_search: Vec<&str>,
    ) -> SourcePathResolver {
        let config = SourceConfig {
            substitutions: config_subs
                .into_iter()
                .map(|(from, to)| SettingsPathSubstitution {
                    from: from.to_string(),
                    to: to.to_string(),
                })
                .collect(),
            search_dirs: config_search.into_iter().map(|s| s.to_string()).collect(),
        };
        SourcePathResolver::new(&config)
    }

    #[test]
    fn test_boundary_matching_prevents_partial_matches() {
        let resolver = create_test_resolver(vec![("/home/user", "/local/user")], vec![]);

        // Should NOT match: "/home/user" prefix but not at boundary
        let result = resolver.try_substitute_path("/home/username");
        assert_eq!(result, None);

        let result2 = resolver.try_substitute_path("/home/user2");
        assert_eq!(result2, None);

        // Should match: exact boundary
        let result3 = resolver.try_substitute_path("/home/user");
        assert_eq!(result3, Some("/local/user".to_string()));

        // Should match: with path separator
        let result4 = resolver.try_substitute_path("/home/user/project/main.c");
        assert_eq!(result4, Some("/local/user/project/main.c".to_string()));
    }

    #[test]
    fn test_runtime_substitutions_override_config() {
        let mut resolver = create_test_resolver(vec![("/build", "/config/path")], vec![]);

        // Add runtime substitution
        resolver.add_substitution("/build".to_string(), "/runtime/path".to_string());

        // Runtime should take precedence
        let result = resolver.try_substitute_path("/build/main.c");
        assert_eq!(result, Some("/runtime/path/main.c".to_string()));
    }

    #[test]
    fn test_apply_substitutions_to_directory() {
        let resolver = create_test_resolver(vec![("/usr/src/debug", "/home/user/sources")], vec![]);

        // Should substitute
        let result = apply_substitutions_to_directory(&resolver, "/usr/src/debug/myproject");
        assert_eq!(result, "/home/user/sources/myproject");

        // Should not substitute (no boundary)
        let result2 = apply_substitutions_to_directory(&resolver, "/usr/src/debug-backup");
        assert_eq!(result2, "/usr/src/debug-backup");

        // Should not substitute (no match)
        let result3 = apply_substitutions_to_directory(&resolver, "/other/path");
        assert_eq!(result3, "/other/path");
    }

    #[test]
    fn test_search_dir_management() {
        let mut resolver = create_test_resolver(vec![], vec!["/config/search"]);

        // Add runtime search dir
        resolver.add_search_dir("/runtime/search".to_string());

        // Check it's added
        let rules = resolver.get_all_rules();
        assert_eq!(rules.runtime_search_dir_count, 1);
        assert_eq!(rules.config_search_dir_count, 1);
        assert!(rules.search_dirs.contains(&"/runtime/search".to_string()));

        // Remove runtime search dir
        let removed = resolver.remove("/runtime/search");
        assert!(removed);

        let rules2 = resolver.get_all_rules();
        assert_eq!(rules2.runtime_search_dir_count, 0);
        assert!(!rules2.search_dirs.contains(&"/runtime/search".to_string()));
    }

    #[test]
    fn test_substitution_management() {
        let mut resolver = create_test_resolver(vec![("/config", "/cfg")], vec![]);

        // Add runtime substitution
        resolver.add_substitution("/runtime".to_string(), "/rt".to_string());

        let rules = resolver.get_all_rules();
        assert_eq!(rules.runtime_substitution_count, 1);
        assert_eq!(rules.config_substitution_count, 1);

        // Remove runtime substitution by 'from' pattern
        let removed = resolver.remove("/runtime");
        assert!(removed);

        let rules2 = resolver.get_all_rules();
        assert_eq!(rules2.runtime_substitution_count, 0);

        // Config substitution should remain
        assert_eq!(rules2.config_substitution_count, 1);
    }

    #[test]
    fn test_clear_and_reset() {
        let mut resolver = create_test_resolver(vec![("/config", "/cfg")], vec!["/config/dir"]);

        // Add runtime rules
        resolver.add_substitution("/runtime".to_string(), "/rt".to_string());
        resolver.add_search_dir("/runtime/dir".to_string());

        // Clear runtime
        resolver.clear_runtime();

        let rules = resolver.get_all_rules();
        assert_eq!(rules.runtime_substitution_count, 0);
        assert_eq!(rules.runtime_search_dir_count, 0);
        assert_eq!(rules.config_substitution_count, 1);
        assert_eq!(rules.config_search_dir_count, 1);

        // Reset (same as clear_runtime)
        resolver.add_substitution("/temp".to_string(), "/tmp".to_string());
        resolver.reset();

        let rules2 = resolver.get_all_rules();
        assert_eq!(rules2.runtime_substitution_count, 0);
    }

    #[test]
    fn test_duplicate_prevention() {
        let mut resolver = create_test_resolver(vec![], vec![]);

        // Add same substitution twice (same from and to)
        resolver.add_substitution("/path".to_string(), "/new".to_string());
        resolver.add_substitution("/path".to_string(), "/new".to_string());

        let rules = resolver.get_all_rules();
        assert_eq!(rules.runtime_substitution_count, 1);

        // Add same search dir twice
        resolver.add_search_dir("/search".to_string());
        resolver.add_search_dir("/search".to_string());

        let rules2 = resolver.get_all_rules();
        assert_eq!(rules2.runtime_search_dir_count, 1);
    }

    #[test]
    fn test_update_existing_substitution() {
        let mut resolver = create_test_resolver(vec![], vec![]);

        // Add initial mapping
        resolver.add_substitution("/build".to_string(), "/wrong/path".to_string());

        // Verify initial mapping
        let result = resolver.try_substitute_path("/build/main.c");
        assert_eq!(result, Some("/wrong/path/main.c".to_string()));

        let rules = resolver.get_all_rules();
        assert_eq!(rules.runtime_substitution_count, 1);

        // Update the same 'from' prefix with a new 'to' path
        resolver.add_substitution("/build".to_string(), "/correct/path".to_string());

        // Should still have only 1 substitution (updated, not duplicated)
        let rules2 = resolver.get_all_rules();
        assert_eq!(rules2.runtime_substitution_count, 1);

        // Verify the mapping was updated to use the new path
        let result2 = resolver.try_substitute_path("/build/main.c");
        assert_eq!(result2, Some("/correct/path/main.c".to_string()));

        // Verify the old path is no longer used
        assert!(rules2
            .substitutions
            .iter()
            .any(|s| s.from == "/build" && s.to == "/correct/path"));
        assert!(!rules2
            .substitutions
            .iter()
            .any(|s| s.from == "/build" && s.to == "/wrong/path"));
    }
}

use std::collections::HashMap;
use std::time::Instant;

/// File completion cache for command auto-completion
#[derive(Debug)]
pub struct FileCompletionCache {
    /// All source files with full paths
    all_files: Vec<String>,

    /// Index by basename for fast lookup: "main.c" -> [file_index, ...]
    by_basename: HashMap<String, Vec<usize>>,

    /// Index by directory for path-based completion: "src" -> [file_index, ...]
    by_directory: HashMap<String, Vec<usize>>,

    /// Quick hash for change detection
    quick_hash: u64,

    /// Number of files cached
    cached_count: usize,

    /// Last time this cache was used
    last_used: Instant,
}

impl FileCompletionCache {
    /// Create new file completion cache from source files
    pub fn new(source_files: &[String]) -> Self {
        let mut cache = Self {
            all_files: Vec::new(),
            by_basename: HashMap::new(),
            by_directory: HashMap::new(),
            quick_hash: 0,
            cached_count: 0,
            last_used: Instant::now(),
        };

        cache.rebuild_cache(source_files);
        cache
    }

    /// Get file completion for the given input
    pub fn get_file_completion(&mut self, input: &str) -> Option<String> {
        self.last_used = Instant::now();

        // Extract command and file part
        let (command_prefix, file_part) = extract_file_context(input)?;

        tracing::debug!(
            "File completion for command '{}', file part '{}'",
            command_prefix,
            file_part
        );

        // Get completion candidates
        let candidates = self.find_completion_candidates(file_part);

        if candidates.is_empty() {
            return None;
        }

        if candidates.len() == 1 {
            // Single match - return the completion
            let full_path = &self.all_files[candidates[0]];
            Some(self.calculate_completion(file_part, full_path))
        } else {
            // Multiple matches - find common prefix
            self.find_common_completion_prefix(file_part, &candidates)
        }
    }

    /// Sync cache from source panel files, returns true if updated
    pub fn sync_from_source_panel(&mut self, source_files: &[String]) -> bool {
        let new_count = source_files.len();
        let new_hash = Self::calculate_quick_hash(source_files);

        // Quick check: no change if count and hash match
        if new_count == self.cached_count && new_hash == self.quick_hash {
            return false;
        }

        tracing::debug!(
            "File completion cache updating: {} -> {} files",
            self.cached_count,
            new_count
        );
        self.rebuild_cache(source_files);
        true
    }

    /// Check if cache has been unused for too long
    pub fn should_cleanup(&self) -> bool {
        self.last_used.elapsed().as_secs() > 300 // 5 minutes
    }

    /// Get all cached file paths (for source panel reuse)
    pub fn get_all_files(&self) -> &[String] {
        &self.all_files
    }

    /// Rebuild the entire cache
    fn rebuild_cache(&mut self, source_files: &[String]) {
        self.all_files.clear();
        self.by_basename.clear();
        self.by_directory.clear();

        self.all_files.extend_from_slice(source_files);
        self.cached_count = source_files.len();
        self.quick_hash = Self::calculate_quick_hash(source_files);

        // Build basename index
        for (idx, file_path) in self.all_files.iter().enumerate() {
            if let Some(basename) = Self::extract_basename(file_path) {
                self.by_basename
                    .entry(basename.to_string())
                    .or_default()
                    .push(idx);
            }

            // Build directory index
            if let Some(dir) = Self::extract_directory(file_path) {
                self.by_directory
                    .entry(dir.to_string())
                    .or_default()
                    .push(idx);
            }
        }

        tracing::debug!(
            "File completion cache rebuilt: {} files, {} basenames, {} directories",
            self.cached_count,
            self.by_basename.len(),
            self.by_directory.len()
        );
    }

    /// Find completion candidates based on input
    fn find_completion_candidates(&self, file_input: &str) -> Vec<usize> {
        if file_input.is_empty() {
            return Vec::new();
        }

        let mut candidates = Vec::new();
        let file_input_lower = file_input.to_lowercase();

        // Strategy 1: Exact prefix match on relative paths
        for (idx, full_path) in self.all_files.iter().enumerate() {
            if let Some(relative) = Self::make_relative_path(full_path) {
                if relative.to_lowercase().starts_with(&file_input_lower) {
                    candidates.push(idx);
                }
            }
        }

        // Strategy 2: If no prefix matches, try basename matching
        if candidates.is_empty() {
            for (idx, full_path) in self.all_files.iter().enumerate() {
                if let Some(basename) = Self::extract_basename(full_path) {
                    if basename.to_lowercase().starts_with(&file_input_lower) {
                        candidates.push(idx);
                    }
                }
            }
        }

        // Strategy 3: If still no matches, try contains matching
        if candidates.is_empty() {
            for (idx, full_path) in self.all_files.iter().enumerate() {
                if full_path.to_lowercase().contains(&file_input_lower) {
                    candidates.push(idx);
                }
            }
        }

        // Limit candidates to avoid performance issues
        candidates.truncate(100);
        candidates
    }

    /// Calculate completion string for a single match
    fn calculate_completion(&self, user_input: &str, full_path: &str) -> String {
        tracing::debug!(
            "calculate_completion: user_input='{}', full_path='{}'",
            user_input,
            full_path
        );

        // Extract the part that user hasn't typed yet
        if let Some(relative) = Self::make_relative_path(full_path) {
            tracing::debug!("relative path: '{}'", relative);
            if relative
                .to_lowercase()
                .starts_with(&user_input.to_lowercase())
            {
                let completion = relative[user_input.len()..].to_string();
                tracing::debug!("relative match: completion='{}'", completion);
                return completion;
            }
        }

        // Fallback: return basename if prefix doesn't match
        if let Some(basename) = Self::extract_basename(full_path) {
            tracing::debug!("basename: '{}'", basename);
            if basename
                .to_lowercase()
                .starts_with(&user_input.to_lowercase())
            {
                let completion = basename[user_input.len()..].to_string();
                tracing::debug!("basename match: completion='{}'", completion);
                return completion;
            }
        }

        tracing::debug!("no match found, returning empty");
        String::new()
    }

    /// Find common prefix among multiple candidates
    fn find_common_completion_prefix(
        &self,
        user_input: &str,
        candidates: &[usize],
    ) -> Option<String> {
        if candidates.len() < 2 {
            return None;
        }

        // Get completion strings for all candidates
        let completions: Vec<String> = candidates
            .iter()
            .map(|&idx| {
                let full_path = &self.all_files[idx];
                self.calculate_completion(user_input, full_path)
            })
            .collect();

        // Find common prefix
        if let Some(first) = completions.first() {
            let mut common_len = first.len();

            for completion in &completions[1..] {
                let matching_chars = first
                    .chars()
                    .zip(completion.chars())
                    .take_while(|(a, b)| a.eq_ignore_ascii_case(b))
                    .count();
                common_len = common_len.min(matching_chars);
            }

            if common_len > 0 {
                let common_prefix = &first[..common_len];
                // Don't complete with just whitespace or single character
                if common_prefix.trim().len() > 1 {
                    return Some(common_prefix.to_string());
                }
            }
        }

        None
    }

    /// Calculate quick hash for change detection
    fn calculate_quick_hash(files: &[String]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        files.len().hash(&mut hasher);

        // Hash first 10 files for quick comparison
        files.iter().take(10).for_each(|f| f.hash(&mut hasher));

        hasher.finish()
    }

    /// Extract basename from full path
    fn extract_basename(path: &str) -> Option<&str> {
        path.rsplit('/').next()
    }

    /// Extract directory from full path
    fn extract_directory(path: &str) -> Option<&str> {
        if let Some(last_slash) = path.rfind('/') {
            let dir = &path[..last_slash];
            if let Some(second_last_slash) = dir.rfind('/') {
                Some(&dir[second_last_slash + 1..])
            } else {
                Some(dir)
            }
        } else {
            None
        }
    }

    /// Convert full path to relative path for completion
    fn make_relative_path(full_path: &str) -> Option<&str> {
        // Simple heuristic: find common path prefixes to strip
        // For now, just strip everything before src/, lib/, include/, or similar
        let common_dirs = ["src/", "lib/", "include/", "tests/", "test/"];

        for dir in &common_dirs {
            if let Some(pos) = full_path.find(dir) {
                return Some(&full_path[pos..]);
            }
        }

        // Fallback: use basename
        Self::extract_basename(full_path)
    }
}

/// Extract command prefix and file part from input
pub fn extract_file_context(input: &str) -> Option<(&str, &str)> {
    let input = input.trim();

    if let Some(file_part) = input.strip_prefix("info line ") {
        return Some(("info line ", extract_file_part_from_line_spec(file_part)));
    }

    if let Some(file_part) = input.strip_prefix("i l ") {
        return Some(("i l ", extract_file_part_from_line_spec(file_part)));
    }

    if let Some(file_part) = input.strip_prefix("trace ") {
        // For trace command, provide file completion if it looks like a file path or filename
        if contains_path_chars(file_part) || looks_like_filename(file_part) {
            return Some(("trace ", extract_file_part_from_line_spec(file_part)));
        }
    }

    None
}

/// Extract file part from "file:line" specification
fn extract_file_part_from_line_spec(spec: &str) -> &str {
    // Split on ':' and take the file part
    spec.split(':').next().unwrap_or(spec)
}

/// Check if input contains path-like characters
fn contains_path_chars(input: &str) -> bool {
    input.contains('/') || input.contains('.')
}

/// Check if input looks like a filename (for trace command)
fn looks_like_filename(input: &str) -> bool {
    // Accept any non-empty input that looks like it could be a filename
    !input.is_empty()
        && input
            .chars()
            .all(|c| c.is_alphanumeric() || "_-".contains(c))
}

/// Check if input needs file completion
pub fn needs_file_completion(input: &str) -> bool {
    extract_file_context(input).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_file_context() {
        assert_eq!(
            extract_file_context("info line main.c:42"),
            Some(("info line ", "main.c"))
        );

        assert_eq!(
            extract_file_context("i l src/utils.h:10"),
            Some(("i l ", "src/utils.h"))
        );

        assert_eq!(
            extract_file_context("trace main.c:100"),
            Some(("trace ", "main.c"))
        );

        assert_eq!(
            extract_file_context("trace function_name"),
            None // No path chars
        );

        assert_eq!(extract_file_context("help"), None);
    }

    #[test]
    fn test_file_completion_basic() {
        let files = vec![
            "/full/path/to/src/main.c".to_string(),
            "/full/path/to/src/utils.c".to_string(),
            "/full/path/to/include/header.h".to_string(),
        ];

        let mut cache = FileCompletionCache::new(&files);

        // Test exact match
        assert_eq!(
            cache.get_file_completion("info line main."),
            Some("c".to_string())
        );

        // Test prefix match
        assert_eq!(
            cache.get_file_completion("i l src/mai"),
            Some("n.c".to_string())
        );
    }

    #[test]
    fn test_file_completion_multiple_matches() {
        let files = vec![
            "/path/src/main.c".to_string(),
            "/path/src/main.h".to_string(),
            "/path/src/manager.c".to_string(),
        ];

        let mut cache = FileCompletionCache::new(&files);

        // Should return common prefix
        assert_eq!(
            cache.get_file_completion("info line mai"),
            Some("n.".to_string()) // Common prefix of "main.c", "main.h"
        );
    }

    #[test]
    fn test_needs_file_completion() {
        assert!(needs_file_completion("info line main.c"));
        assert!(needs_file_completion("i l src/utils.h:42"));
        assert!(needs_file_completion("trace file.c:100"));
        assert!(!needs_file_completion("trace function_name"));
        assert!(!needs_file_completion("help"));
        assert!(!needs_file_completion("enable 1"));
    }
}

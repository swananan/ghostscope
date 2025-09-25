//! Lightweight file index inspired by GDB's quick_file_names design
//!
//! This module provides an efficient file indexing system that mimics GDB's approach:
//! - Minimal memory footprint with lazy path resolution
//! - Shared line table support to avoid duplication
//! - DWARF version-aware file indexing (1-based vs 0-based)

use crate::data::path::resolve_file_path;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Minimal file entry mimicking GDB's file_entry design
#[derive(Debug, Clone)]
pub(crate) struct LightweightFileEntry {
    /// Original DWARF file index within its compilation unit
    pub file_index: u64,
    /// Directory index from DWARF (0 = comp_dir)
    pub directory_index: u64,
    /// Just the filename (basename) - borrowed from line_header
    pub filename: Arc<str>,
}

impl LightweightFileEntry {
    /// Get the full resolved path (computed on-demand like GDB's real_names)
    pub fn get_full_path(&self, index: &LightweightFileIndex) -> Option<String> {
        index.resolve_file_path(self.file_index, self.directory_index, &self.filename)
    }
}

/// Lightweight file index, inspired by GDB's quick_file_names
///
/// Key design principles:
/// - Store minimal data (filenames + indices only)
/// - Lazy path resolution (like GDB's real_names)
/// - Shared compilation directory to reduce memory
/// - Support for DWARF 4/5 version differences
#[derive(Debug)]
pub(crate) struct LightweightFileIndex {
    /// Compilation directory from DW_AT_comp_dir (shared across all files)
    comp_dir: Option<Arc<str>>,

    /// Directory table from line_header (shared, pooled strings)
    directories: Vec<Arc<str>>,

    /// File entries array (minimal storage)
    file_entries: Vec<LightweightFileEntry>,

    /// DWARF version (affects indexing: 4=1-based, 5=0-based)
    dwarf_version: u16,

    /// Lazy-computed full paths cache (like GDB's real_names)
    /// Only populated when actually requested
    resolved_paths_cache: Mutex<Vec<Option<String>>>,

    /// Statistics for debugging
    total_files: usize,
}

impl LightweightFileIndex {
    /// Create new lightweight file index
    pub fn new(comp_dir: Option<String>, dwarf_version: u16) -> Self {
        Self {
            comp_dir: comp_dir.map(|s| Arc::from(s.as_str())),
            directories: Vec::new(),
            file_entries: Vec::new(),
            dwarf_version,
            resolved_paths_cache: Mutex::new(Vec::new()),
            total_files: 0,
        }
    }

    /// Add directory to the directory table (from line_header)
    pub fn add_directory(&mut self, directory: String) {
        self.directories.push(Arc::from(directory.as_str()));
    }

    /// Add file entry (minimal data only)
    pub fn add_file_entry(&mut self, file_index: u64, directory_index: u64, filename: String) {
        let entry = LightweightFileEntry {
            file_index,
            directory_index,
            filename: Arc::from(filename.as_str()),
        };

        self.file_entries.push(entry);
        self.total_files += 1;

        // Expand cache if needed
        let mut cache = self.resolved_paths_cache.lock().unwrap();
        if cache.len() <= file_index as usize {
            cache.resize(file_index as usize + 1, None);
        }
    }

    /// Get file entry by index (handles DWARF 4/5 differences)
    pub fn get_file_entry(&self, file_index: u64) -> Option<&LightweightFileEntry> {
        let array_index = if self.dwarf_version >= 5 {
            // DWARF 5: 0-based indexing
            file_index as usize
        } else {
            // DWARF 4: 1-based indexing
            if file_index == 0 {
                return None;
            }
            (file_index - 1) as usize
        };

        self.file_entries.get(array_index)
    }

    /// Resolve full file path on-demand (lazy, like GDB's real_names)
    fn resolve_file_path(
        &self,
        file_index: u64,
        directory_index: u64,
        filename: &str,
    ) -> Option<String> {
        // Check cache first
        {
            let cache = self.resolved_paths_cache.lock().unwrap();
            if let Some(Some(cached_path)) = cache.get(file_index as usize) {
                return Some(cached_path.clone());
            }
        }

        // Compute path if not cached
        let resolved_path = self.compute_full_path(directory_index, filename);

        // Cache the result
        {
            let mut cache = self.resolved_paths_cache.lock().unwrap();
            if cache.len() <= file_index as usize {
                cache.resize(file_index as usize + 1, None);
            }
            cache[file_index as usize] = Some(resolved_path.clone());
        }

        Some(resolved_path)
    }

    /// Compute full path from directory_index and filename
    fn compute_full_path(&self, directory_index: u64, filename: &str) -> String {
        // Handle absolute paths
        let comp_dir = self.comp_dir.as_deref().unwrap_or("");

        resolve_file_path(
            self.dwarf_version,
            comp_dir,
            &self.directories,
            directory_index,
            filename,
        )
    }

    /// Get all file entries (for iteration)
    pub fn file_entries(&self) -> &[LightweightFileEntry] {
        &self.file_entries
    }
}

/// Scoped file index manager that maintains per-CU file indices
/// This replaces the heavy FileIndexManager with minimal memory overhead
#[derive(Debug)]
pub(crate) struct ScopedFileIndexManager {
    /// Per-compilation-unit file indices: cu_name -> file_index
    /// This is the primary lookup method, avoiding cross-CU conflicts
    cu_file_indices: HashMap<Arc<str>, Arc<LightweightFileIndex>>,

    /// String pool for compilation unit names to reduce memory
    cu_name_pool: HashMap<String, Arc<str>>,

    /// Statistics
    total_compilation_units: usize,
    total_files: usize,
}

impl ScopedFileIndexManager {
    /// Create new scoped file index manager
    pub fn new() -> Self {
        Self {
            cu_file_indices: HashMap::new(),
            cu_name_pool: HashMap::new(),
            total_compilation_units: 0,
            total_files: 0,
        }
    }

    /// Add compilation unit with its file index
    pub fn add_compilation_unit(&mut self, cu_name: String, file_index: LightweightFileIndex) {
        // Pool the CU name to reduce memory usage
        let pooled_cu_name = self
            .cu_name_pool
            .entry(cu_name.clone())
            .or_insert_with(|| Arc::from(cu_name.as_str()))
            .clone();

        self.total_files += file_index.total_files;
        self.cu_file_indices
            .insert(pooled_cu_name, Arc::new(file_index));
        self.total_compilation_units += 1;
    }

    /// Lookup file by scoped index (primary method, conflict-free)
    ///
    /// This is equivalent to the old FileIndexManager::lookup_by_scoped_index
    /// but with minimal memory overhead
    pub fn lookup_by_scoped_index(
        &self,
        compilation_unit: &str,
        file_index: u64,
    ) -> Option<String> {
        // Removed debug logging to reduce noise in normal operation

        let file_index_ref = self.cu_file_indices.get(compilation_unit)?;

        // Debug: list all files in this CU
        tracing::debug!("  Available files in CU '{}':", compilation_unit);
        for entry in file_index_ref.file_entries().iter() {
            tracing::debug!(
                "    file_index={}, filename='{}', dir_index={}",
                entry.file_index,
                entry.filename,
                entry.directory_index
            );
        }

        let file_entry = file_index_ref.get_file_entry(file_index)?;

        let full_path = file_entry
            .get_full_path(file_index_ref)
            .unwrap_or_else(|| file_entry.filename.to_string());

        tracing::debug!(
            "  Resolved file_index={} -> filename='{}', full_path='{}'",
            file_index,
            file_entry.filename,
            full_path
        );

        Some(full_path)
    }
    /// Get statistics (total files, total compilation units)
    pub fn get_stats(&self) -> (usize, usize) {
        (self.total_files, self.total_compilation_units)
    }

    /// Get file index for a specific compilation unit
    pub fn get_cu_file_index(&self, compilation_unit: &str) -> Option<&LightweightFileIndex> {
        self.cu_file_indices
            .get(compilation_unit)
            .map(|arc| arc.as_ref())
    }
}

impl Default for ScopedFileIndexManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lightweight_file_index_dwarf4() {
        let mut index = LightweightFileIndex::new(Some("/src".to_string()), 4);

        // Add directories
        index.add_directory("include".to_string());
        index.add_directory("lib".to_string());

        // Add files (DWARF 4: 1-based indexing)
        index.add_file_entry(1, 0, "main.c".to_string()); // comp_dir + main.c
        index.add_file_entry(2, 1, "header.h".to_string()); // include/ + header.h

        // Test file lookup
        let file1 = index.get_file_entry(1).unwrap();
        assert_eq!(file1.filename.as_ref(), "main.c");
        assert_eq!(file1.get_full_path(&index), Some("/src/main.c".to_string()));

        let file2 = index.get_file_entry(2).unwrap();
        assert_eq!(file2.filename.as_ref(), "header.h");
        // In DWARF4, directory_index=1 refers to directories[0]="include", combined with comp_dir="/src"
        assert_eq!(
            file2.get_full_path(&index),
            Some("/src/include/header.h".to_string())
        );
    }

    #[test]
    fn test_lightweight_file_index_dwarf5() {
        let mut index = LightweightFileIndex::new(Some("/src".to_string()), 5);

        // Add directories - in DWARF5, directories[0] should be comp_dir for this test to work
        index.add_directory("/src".to_string()); // directories[0] = comp_dir
        index.add_directory("include".to_string()); // directories[1] = include

        // Add files (DWARF 5: 0-based indexing)
        index.add_file_entry(0, 0, "main.c".to_string()); // directories[0] + main.c = /src/main.c
        index.add_file_entry(1, 1, "header.h".to_string()); // directories[1] + header.h

        // Test file lookup
        let file0 = index.get_file_entry(0).unwrap();
        assert_eq!(file0.filename.as_ref(), "main.c");
        assert_eq!(file0.get_full_path(&index), Some("/src/main.c".to_string()));

        let file1 = index.get_file_entry(1).unwrap();
        assert_eq!(file1.filename.as_ref(), "header.h");
        // In DWARF5, directory_index=1 refers to directories[1]="include", combined with comp_dir="/src"
        assert_eq!(
            file1.get_full_path(&index),
            Some("/src/include/header.h".to_string())
        );
    }

    #[test]
    fn test_scoped_manager_no_conflicts() {
        let mut manager = ScopedFileIndexManager::new();

        // Create file indices for two CUs with same file_index but different files
        let mut main_index = LightweightFileIndex::new(Some("/src".to_string()), 4);
        main_index.add_file_entry(1, 0, "main.c".to_string());

        let mut lib_index = LightweightFileIndex::new(Some("/lib".to_string()), 4);
        lib_index.add_file_entry(1, 0, "lib.c".to_string());

        manager.add_compilation_unit("main.c".to_string(), main_index);
        manager.add_compilation_unit("lib.c".to_string(), lib_index);

        // Both should be findable without conflict
        let main_file = manager.lookup_by_scoped_index("main.c", 1).unwrap();
        let lib_file = manager.lookup_by_scoped_index("lib.c", 1).unwrap();

        assert_eq!(main_file, "/src/main.c");
        assert_eq!(lib_file, "/lib/lib.c");
    }
}

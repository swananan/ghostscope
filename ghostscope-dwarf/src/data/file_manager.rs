//! Source file management system (inspired by ghostscope-binary)

use crate::core::Result;
use gimli::{EndianSlice, LittleEndian};
use std::collections::HashMap;
use tracing::debug;

/// Compilation unit information with associated directories and files
#[derive(Debug, Clone)]
pub struct CompilationUnit {
    /// Name of the compilation unit (typically the main source file)
    pub name: String,
    /// Base directory for this compilation unit
    pub base_directory: String,
    /// All include directories for this compilation unit
    pub include_directories: Vec<String>,
    /// Files within this compilation unit
    pub files: Vec<SourceFile>,
    /// DWARF version for proper file index handling
    pub dwarf_version: u16,
}

/// Source file information extracted from DWARF debug info
#[derive(Debug, Clone)]
pub struct SourceFile {
    /// File index from DWARF line program
    pub file_index: u64,
    /// Compilation unit this file belongs to
    pub compilation_unit: String,
    /// Directory index (0 = current directory)
    pub directory_index: u64,
    /// Directory path (resolved from include_directories)
    pub directory_path: String,
    /// Just the filename (basename)
    pub filename: String,
    /// Full resolved path
    pub full_path: String,
}

/// Comprehensive source file manager for DWARF debug information
/// Properly manages the hierarchy: Compilation Units -> Directories -> Files
#[derive(Debug)]
pub struct SourceFileManager {
    /// All compilation units indexed by name
    compilation_units: HashMap<String, CompilationUnit>,
    /// All source files indexed by (compilation_unit, file_index) for fast lookup
    files_by_index: HashMap<(String, u64), SourceFile>,
    /// Statistics counters
    total_files: usize,
    total_compilation_units: usize,
}

impl SourceFileManager {
    pub fn new() -> Self {
        Self {
            compilation_units: HashMap::new(),
            files_by_index: HashMap::new(),
            total_files: 0,
            total_compilation_units: 0,
        }
    }

    /// Build source file manager from DWARF data
    pub fn build_from_dwarf(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Self> {
        tracing::debug!("Building source file manager from DWARF");

        let mut file_manager = Self::new();

        // Parse all compilation units
        let mut units = dwarf.units();
        while let Some(header) = units.next()? {
            let unit = dwarf.unit(header)?;

            match Self::extract_files_from_unit(dwarf, &unit) {
                Ok(compilation_unit) => {
                    file_manager.add_compilation_unit(compilation_unit);
                }
                Err(e) => {
                    debug!("Failed to extract files from unit: {}", e);
                    // Continue with other units
                }
            }
        }

        tracing::debug!(
            "Built source file manager: {} files, {} compilation units",
            file_manager.total_files,
            file_manager.total_compilation_units
        );

        Ok(file_manager)
    }

    /// Add a compilation unit with its files
    pub fn add_compilation_unit(&mut self, unit: CompilationUnit) {
        debug!(
            "Adding compilation unit: {} with {} files",
            unit.name,
            unit.files.len()
        );

        // Update file indices for fast lookup (with compilation unit scope)
        for file in &unit.files {
            // Add to index lookups with (compilation_unit, file_index) key
            self.files_by_index
                .insert((unit.name.clone(), file.file_index), file.clone());
            self.total_files += 1;
        }

        self.compilation_units.insert(unit.name.clone(), unit);
        self.total_compilation_units += 1;
    }

    /// Get all source files as a flat list
    pub fn get_all_files(&self) -> Vec<&SourceFile> {
        self.files_by_index.values().collect()
    }

    /// Get file path by scoped index (compilation_unit, file_index)
    pub fn get_file_path_by_scoped_index(
        &self,
        compilation_unit: &str,
        file_index: u64,
    ) -> Option<String> {
        self.files_by_index
            .get(&(compilation_unit.to_string(), file_index))
            .map(|file| file.full_path.clone())
    }

    /// Get file path by index (legacy compatibility - tries to find any match)
    pub fn get_file_path_by_index(&self, index: u64) -> Option<String> {
        // Try to find any file with this index (may be ambiguous)
        for ((_, file_index), file) in &self.files_by_index {
            if *file_index == index {
                return Some(file.full_path.clone());
            }
        }
        None
    }

    /// Get compilation unit by name
    pub fn get_compilation_unit(&self, name: &str) -> Option<&CompilationUnit> {
        self.compilation_units.get(name)
    }

    /// Get all compilation units
    pub fn get_all_compilation_units(&self) -> Vec<&CompilationUnit> {
        self.compilation_units.values().collect()
    }

    /// Get statistics (total files, total compilation units)
    pub fn get_stats(&self) -> (usize, usize) {
        (self.total_files, self.total_compilation_units)
    }

    /// Extract source file information from a compilation unit's line program
    fn extract_files_from_unit(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
    ) -> Result<CompilationUnit> {
        // Get compilation unit name
        let cu_name =
            Self::get_compilation_unit_name(dwarf, unit).unwrap_or_else(|| "unknown".to_string());

        debug!("Extracting files from compilation unit: {}", cu_name);

        let mut compilation_unit = CompilationUnit {
            name: cu_name.clone(),
            base_directory: Self::get_comp_dir(dwarf, unit).unwrap_or_default(),
            include_directories: Vec::new(),
            files: Vec::new(),
            dwarf_version: 4, // Default for file_manager (legacy usage)
        };

        // Extract file information from line program
        if let Some(line_program) = unit.line_program.clone() {
            let header = line_program.header();

            // Extract include directories
            for (dir_index, dir_entry) in header.include_directories().into_iter().enumerate() {
                if let Ok(dir_path) = dwarf.attr_string(unit, *dir_entry) {
                    let dir_str = dir_path.to_string_lossy().into_owned();
                    debug!("Include directory [{}]: '{}'", dir_index + 1, dir_str);
                    compilation_unit.include_directories.push(dir_str);
                }
            }

            // Extract files from line program
            for (file_index, file_entry) in header.file_names().into_iter().enumerate() {
                match Self::extract_source_file(
                    dwarf,
                    unit,
                    file_index as u64,
                    file_entry,
                    header,
                    &cu_name,
                    &compilation_unit.include_directories,
                ) {
                    Ok(source_file) => {
                        compilation_unit.files.push(source_file);
                    }
                    Err(e) => {
                        // Skip system files like "<built-in>"
                        debug!("Skipping file entry {}: {}", file_index, e);
                    }
                }
            }
        }

        debug!(
            "Extracted {} files from compilation unit {}",
            compilation_unit.files.len(),
            cu_name
        );

        Ok(compilation_unit)
    }

    /// Extract individual source file information
    fn extract_source_file(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        file_index: u64,
        file_entry: &gimli::FileEntry<EndianSlice<'static, LittleEndian>>,
        _header: &gimli::LineProgramHeader<EndianSlice<'static, LittleEndian>>,
        compilation_unit: &str,
        include_directories: &[String],
    ) -> anyhow::Result<SourceFile> {
        // Get directory path
        let dir_index = file_entry.directory_index();
        let directory_path = if dir_index == 0 {
            // Directory index 0 means the compilation unit's base directory
            Self::get_comp_dir(dwarf, unit).unwrap_or_else(|| ".".to_string())
        } else {
            // Directory index > 0 refers to include_directories array (1-based indexing)
            let actual_index = (dir_index - 1) as usize;
            include_directories
                .get(actual_index)
                .cloned()
                .unwrap_or_else(|| ".".to_string())
        };

        // Get filename
        let filename = dwarf
            .attr_string(unit, file_entry.path_name())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".to_string());

        // Filter out system files
        if filename == "<built-in>" {
            return Err(anyhow::anyhow!("Skipping system file"));
        }

        // Create full path
        let full_path = if directory_path == "." {
            filename.clone()
        } else {
            format!("{}/{}", directory_path, filename)
        };

        Ok(SourceFile {
            file_index,
            compilation_unit: compilation_unit.to_string(),
            directory_index: dir_index,
            directory_path,
            filename,
            full_path,
        })
    }

    /// Get compilation directory (DW_AT_comp_dir)
    fn get_comp_dir(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
    ) -> Option<String> {
        let mut entries = unit.entries();
        if let Ok(Some((_, entry))) = entries.next_dfs() {
            if entry.tag() == gimli::DW_TAG_compile_unit {
                if let Some(comp_dir_attr) = entry.attr_value(gimli::DW_AT_comp_dir).ok().flatten()
                {
                    if let Ok(comp_dir) = dwarf.attr_string(unit, comp_dir_attr) {
                        return Some(comp_dir.to_string_lossy().into_owned());
                    }
                }
            }
        }
        None
    }

    /// Get compilation unit name from DWARF unit
    fn get_compilation_unit_name(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
    ) -> Option<String> {
        let mut entries = unit.entries();
        if let Ok(Some((_, entry))) = entries.next_dfs() {
            if entry.tag() == gimli::DW_TAG_compile_unit {
                if let Some(name_attr) = entry.attr_value(gimli::DW_AT_name).ok().flatten() {
                    if let Ok(name) = dwarf.attr_string(unit, name_attr) {
                        return Some(name.to_string_lossy().into_owned());
                    }
                }
            }
        }
        None
    }

    /// Create SourceFileManager from unified builder data
    pub fn from_builder_data(
        compilation_units: HashMap<String, CompilationUnit>,
        files_by_index: HashMap<(String, u64), SourceFile>,
        total_files: usize,
        total_compilation_units: usize,
    ) -> Self {
        Self {
            compilation_units,
            files_by_index,
            total_files,
            total_compilation_units,
        }
    }
}

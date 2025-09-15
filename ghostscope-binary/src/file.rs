use crate::Result;
use gimli::{Dwarf, EndianSlice, LittleEndian};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, warn};

/// Compilation unit information with associated directories and files
#[derive(Debug, Clone)]
pub(crate) struct CompilationUnit {
    /// Name of the compilation unit (typically the main source file)
    pub name: String,
    /// Base directory for this compilation unit
    pub base_directory: String,
    /// All include directories for this compilation unit
    pub include_directories: Vec<String>,
    /// Files within this compilation unit
    pub files: Vec<SourceFile>,
}

/// Directory information within a compilation unit
#[derive(Debug, Clone)]
pub(crate) struct Directory {
    /// Directory path
    pub path: String,
    /// Files within this directory
    pub files: Vec<SourceFile>,
}

/// Source file information extracted from DWARF debug info
#[derive(Debug, Clone)]
pub(crate) struct SourceFile {
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
pub(crate) struct SourceFileManager {
    /// All compilation units indexed by name
    compilation_units: HashMap<String, CompilationUnit>,
    /// All source files indexed by file_index for fast lookup
    files_by_index: HashMap<u64, SourceFile>,
    /// Fast lookup by full path
    files_by_path: HashMap<String, u64>,
    /// Fast lookup by basename
    files_by_basename: HashMap<String, Vec<u64>>,
    /// Statistics counters
    total_files: usize,
    total_compilation_units: usize,
}

impl SourceFileManager {
    pub fn new() -> Self {
        Self {
            compilation_units: HashMap::new(),
            files_by_index: HashMap::new(),
            files_by_path: HashMap::new(),
            files_by_basename: HashMap::new(),
            total_files: 0,
            total_compilation_units: 0,
        }
    }

    /// Add a compilation unit with its files
    pub fn add_compilation_unit(&mut self, unit: CompilationUnit) {
        debug!(
            "Adding compilation unit: {} with {} files",
            unit.name,
            unit.files.len()
        );

        // Update file indices for fast lookup
        for file in &unit.files {
            // Add to index lookups
            self.files_by_index.insert(file.file_index, file.clone());
            self.files_by_path
                .insert(file.full_path.clone(), file.file_index);
            self.files_by_basename
                .entry(file.filename.clone())
                .or_default()
                .push(file.file_index);

            self.total_files += 1;
        }

        self.compilation_units.insert(unit.name.clone(), unit);
        self.total_compilation_units += 1;
    }

    /// Get all source files as a flat list
    pub fn get_all_files(&self) -> Vec<&SourceFile> {
        self.files_by_index.values().collect()
    }

    /// Get file by DWARF file index
    pub fn get_file_by_index(&self, index: u64) -> Option<&SourceFile> {
        self.files_by_index.get(&index)
    }

    /// Get file by full path
    pub fn get_file_by_path(&self, path: &str) -> Option<&SourceFile> {
        self.files_by_path
            .get(path)
            .and_then(|&index| self.files_by_index.get(&index))
    }

    /// Get files by basename
    pub fn get_files_by_basename(&self, basename: &str) -> Vec<&SourceFile> {
        self.files_by_basename
            .get(basename)
            .map(|indices| {
                indices
                    .iter()
                    .filter_map(|&index| self.files_by_index.get(&index))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get compilation unit by name
    pub fn get_compilation_unit(&self, name: &str) -> Option<&CompilationUnit> {
        self.compilation_units.get(name)
    }

    /// Get all compilation units
    pub fn get_all_compilation_units(&self) -> Vec<&CompilationUnit> {
        self.compilation_units.values().collect()
    }

    /// Get statistics (total files, total compilation units, unique basenames)
    pub fn get_stats(&self) -> (usize, usize, usize) {
        (
            self.total_files,
            self.total_compilation_units,
            self.files_by_basename.len(),
        )
    }

    /// Extract source file information from a compilation unit's line program
    pub fn extract_files_from_unit(
        dwarf: &Dwarf<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
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
        };

        // Extract file information from line program
        if let Some(line_program) = unit.line_program.clone() {
            let header = line_program.header();

            // Extract include directories (DWARF: 1-based indices refer to this list)
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
        dwarf: &Dwarf<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
        file_index: u64,
        file_entry: &gimli::FileEntry<EndianSlice<LittleEndian>>,
        header: &gimli::LineProgramHeader<EndianSlice<LittleEndian>>,
        compilation_unit: &str,
        include_directories: &[String],
    ) -> anyhow::Result<SourceFile> {
        // Get directory path
        let dir_index = file_entry.directory_index();
        debug!("File entry directory_index: {}", dir_index);
        debug!("Available include_directories: {:?}", include_directories);

        let mut directory_path = if dir_index == 0 {
            // Directory index 0 means the compilation unit's base directory (DW_AT_comp_dir)
            let comp_dir = Self::get_comp_dir(dwarf, unit).unwrap_or_else(|| ".".to_string());
            debug!("Using compilation directory for index 0: '{}'", comp_dir);
            comp_dir
        } else {
            // Directory index > 0 refers to include_directories array (1-based indexing)
            let actual_index = (dir_index - 1) as usize;
            if let Some(dir_path) = include_directories.get(actual_index) {
                debug!(
                    "Using include directory [{}]: '{}'",
                    actual_index + 1,
                    dir_path
                );
                dir_path.clone()
            } else {
                debug!(
                    "Directory index {} not found in include_directories, using '.'",
                    dir_index
                );
                ".".to_string()
            }
        };

        // If directory_path is relative, resolve against comp_dir
        if !directory_path.starts_with('/') {
            if let Some(comp_dir) = Self::get_comp_dir(dwarf, unit) {
                directory_path = format!("{}/{}", comp_dir, directory_path);
            }
        }

        // Get filename
        let filename = dwarf
            .attr_string(unit, file_entry.path_name())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".to_string());

        // Filter out system files
        if filename == "<built-in>" {
            debug!("Skipping system file: '{}'", filename);
            return Err(anyhow::anyhow!("Skipping system file"));
        }

        debug!(
            "Extracted file: directory='{}', filename='{}'",
            directory_path, filename
        );

        // Create full path
        let mut full_path = if directory_path == "." {
            filename.clone()
        } else {
            format!("{}/{}", directory_path, filename)
        };

        debug!("Final full path: '{}'", full_path);

        // Fallback: if the file does not exist at computed path, try other include dirs
        // This helps when some toolchains put comp_dir into include_directories[1]
        if !Path::new(&full_path).exists() {
            if let Some(comp_dir) = Self::get_comp_dir(dwarf, unit) {
                for dir in include_directories {
                    let candidate_dir = if dir.starts_with('/') {
                        dir.clone()
                    } else {
                        format!("{}/{}", comp_dir, dir)
                    };
                    let candidate = format!("{}/{}", candidate_dir, filename);
                    if Path::new(&candidate).exists() {
                        debug!("Resolved missing path via include dir: '{}'", candidate);
                        full_path = candidate;
                        directory_path = candidate_dir;
                        break;
                    }
                }
            }
            if !Path::new(&full_path).exists() {
                warn!(
                    "File path does not exist on filesystem: '{}'. Keeping DWARF-derived path.",
                    full_path
                );
            }
        }

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
        dwarf: &Dwarf<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
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
        dwarf: &Dwarf<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
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
}

/// Simple file information for backward compatibility
#[derive(Debug, Clone)]
pub struct SimpleFileInfo {
    pub full_path: String,
    pub basename: String,
    pub directory: String,
}

impl From<&SourceFile> for SimpleFileInfo {
    fn from(source_file: &SourceFile) -> Self {
        Self {
            full_path: source_file.full_path.clone(),
            basename: source_file.filename.clone(),
            directory: source_file.directory_path.clone(),
        }
    }
}

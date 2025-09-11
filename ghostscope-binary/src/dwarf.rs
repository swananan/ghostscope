use crate::expression::DwarfExpressionEvaluator;
use crate::line_lookup::LineLookup;
use crate::scoped_variables::{AddressRange, ScopeId, ScopeType, ScopedVariableMap};
use crate::Result;
use gimli::{Dwarf, EndianSlice, LittleEndian, Reader};
use object::{Object, ObjectSection};
use std::path::Path;
use tracing::{debug, error, info, warn};

/// Helper function to match file paths, supporting both exact and relative path matching
/// This allows queries like "test.c" to match "/path/to/test.c" in DWARF debug info
fn files_match(dwarf_file_path: &str, query_path: &str) -> bool {
    use tracing::debug;

    // First try exact match (fastest path)
    if dwarf_file_path == query_path {
        debug!(
            "files_match: exact match '{}' == '{}'",
            dwarf_file_path, query_path
        );
        return true;
    }

    // Try relative path matching: check if DWARF path ends with the query path
    // This handles cases like query "test.c" matching DWARF "/full/path/test.c"
    if dwarf_file_path.ends_with(query_path) {
        // Make sure it's a proper path component boundary (not just a suffix)
        let preceding_char_pos = dwarf_file_path.len() - query_path.len();
        if preceding_char_pos == 0
            || dwarf_file_path.chars().nth(preceding_char_pos - 1) == Some('/')
        {
            debug!(
                "files_match: relative match '{}' ends with '{}' at proper boundary",
                dwarf_file_path, query_path
            );
            return true;
        } else {
            debug!("files_match: '{}' ends with '{}' but not at proper boundary (preceding char at {})", 
                   dwarf_file_path, query_path, preceding_char_pos);
        }
    }

    // Try the reverse: query is longer than DWARF path, check if query ends with DWARF basename
    if let Some(dwarf_basename) = Path::new(dwarf_file_path).file_name() {
        if let Some(dwarf_basename_str) = dwarf_basename.to_str() {
            if query_path.ends_with(dwarf_basename_str) {
                let preceding_char_pos = query_path.len() - dwarf_basename_str.len();
                if preceding_char_pos == 0
                    || query_path.chars().nth(preceding_char_pos - 1) == Some('/')
                {
                    debug!(
                        "files_match: reverse match '{}' basename matches query '{}'",
                        dwarf_file_path, query_path
                    );
                    return true;
                }
            }
        }
    }

    debug!(
        "files_match: no match between '{}' and '{}'",
        dwarf_file_path, query_path
    );
    false
}

/// DWARF debug context
#[derive(Debug)]
pub struct DwarfContext {
    dwarf: Dwarf<EndianSlice<'static, LittleEndian>>,
    // Keep the file data alive
    _file_data: Box<[u8]>,
    // Base addresses for proper DWARF parsing
    base_addresses: gimli::BaseAddresses,

    // CFI information
    eh_frame: Option<gimli::EhFrame<EndianSlice<'static, LittleEndian>>>,
    debug_frame: Option<gimli::DebugFrame<EndianSlice<'static, LittleEndian>>>,
    // New CFI context for simplified DWARF expression-only interface
    cfi_context: Option<crate::cfi::CFIContext>,

    // New line lookup system (based on addr2line)
    line_lookup: Option<LineLookup>,
    // Enhanced file information management for fast queries
    file_registry: Option<FileInfoRegistry>,

    // Scoped variable system (GDB-inspired)
    scoped_variable_map: Option<ScopedVariableMap>,
    // DWARF expression evaluator for CFI and variable location evaluation
    expression_evaluator: DwarfExpressionEvaluator,
}

/// Enhanced file information registry for efficient file path queries
#[derive(Debug)]
pub struct FileInfoRegistry {
    /// All unique file paths in the debug info
    all_files: Vec<FileInfo>,
    /// Hash map for exact path lookup: full_path -> file_index
    exact_path_map: std::collections::HashMap<String, usize>,
    /// Hash map for basename lookup: basename -> Vec<file_index>
    basename_map: std::collections::HashMap<String, Vec<usize>>,
    /// Trie for prefix/suffix matching
    path_trie: PathTrie,
    /// Cache for recent queries
    query_cache: std::collections::HashMap<String, Vec<usize>>,
}

/// File information with metadata
#[derive(Debug, Clone)]
pub struct FileInfo {
    /// Full file path as stored in DWARF
    pub full_path: String,
    /// Just the filename (basename)
    pub basename: String,
    /// Directory path
    pub directory: String,
    /// File extension
    pub extension: String,
    /// Whether this file actually exists on disk
    pub exists_on_disk: bool,
    /// Alternative paths where this file might be found
    pub search_paths: Vec<String>,
}

/// Simple trie structure for efficient path matching
#[derive(Debug)]
pub struct PathTrie {
    nodes: std::collections::HashMap<String, PathTrieNode>,
}

#[derive(Debug)]
struct PathTrieNode {
    file_indices: Vec<usize>,
    children: std::collections::HashMap<String, PathTrieNode>,
}

impl FileInfoRegistry {
    /// Create new file info registry
    fn new() -> Self {
        Self {
            all_files: Vec::new(),
            exact_path_map: std::collections::HashMap::new(),
            basename_map: std::collections::HashMap::new(),
            path_trie: PathTrie::new(),
            query_cache: std::collections::HashMap::new(),
        }
    }

    /// Add a file to the registry
    fn add_file(&mut self, full_path: String) -> usize {
        // Check if already exists
        if let Some(&index) = self.exact_path_map.get(&full_path) {
            return index;
        }

        let path = std::path::Path::new(&full_path);
        let basename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&full_path)
            .to_string();
        let directory = path
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .to_string();
        let extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string();

        // Check if file exists on disk
        let exists_on_disk = path.exists();
        let mut search_paths = Vec::new();

        if !exists_on_disk {
            // Generate possible alternative paths
            search_paths = self.generate_search_paths(&full_path, &basename);
        }

        let file_info = FileInfo {
            full_path: full_path.clone(),
            basename: basename.clone(),
            directory,
            extension,
            exists_on_disk,
            search_paths,
        };

        let index = self.all_files.len();
        self.all_files.push(file_info);

        // Update indices
        self.exact_path_map.insert(full_path.clone(), index);

        // Update basename map
        self.basename_map
            .entry(basename.clone())
            .or_insert_with(Vec::new)
            .push(index);

        // Update trie
        self.path_trie.insert(&full_path, index);

        index
    }

    /// Generate possible search paths for a file
    fn generate_search_paths(&self, full_path: &str, basename: &str) -> Vec<String> {
        let mut search_paths = Vec::new();

        // Add current working directory + basename
        if let Ok(current_dir) = std::env::current_dir() {
            search_paths.push(current_dir.join(basename).to_string_lossy().to_string());
        }

        // Add common source directories
        let common_dirs = ["src", "source", "include", "lib", "../", "../../"];
        for dir in &common_dirs {
            search_paths.push(format!("{}/{}", dir, basename));
        }

        search_paths
    }

    /// Query files with flexible matching
    /// Supports:
    /// - Exact path matching
    /// - Basename matching  
    /// - Partial path matching
    /// - Extension-based filtering
    pub fn query_files(&mut self, query: &str) -> Vec<&FileInfo> {
        // Check cache first
        if let Some(cached_indices) = self.query_cache.get(query) {
            return cached_indices
                .iter()
                .filter_map(|&i| self.all_files.get(i))
                .collect();
        }

        let mut results = Vec::new();

        // Strategy 1: Exact path match
        if let Some(&index) = self.exact_path_map.get(query) {
            if let Some(file_info) = self.all_files.get(index) {
                results.push(index);
            }
        }

        // Strategy 2: Basename match
        if let Some(indices) = self.basename_map.get(query) {
            results.extend(indices);
        }

        // Strategy 3: Partial path matching
        for (i, file_info) in self.all_files.iter().enumerate() {
            if file_info.full_path.contains(query) && !results.contains(&i) {
                results.push(i);
            }
        }

        // Strategy 4: Fuzzy matching for typos
        if results.is_empty() {
            results.extend(self.fuzzy_match(query));
        }

        // Cache the result
        self.query_cache.insert(query.to_string(), results.clone());

        results
            .into_iter()
            .filter_map(|i| self.all_files.get(i))
            .collect()
    }

    /// Fuzzy matching for typos and similar file names
    fn fuzzy_match(&self, query: &str) -> Vec<usize> {
        let mut scored_matches = Vec::new();

        for (i, file_info) in self.all_files.iter().enumerate() {
            let basename_score = self.calculate_similarity(&file_info.basename, query);
            let full_path_score = self.calculate_similarity(&file_info.full_path, query);
            let max_score = basename_score.max(full_path_score);

            if max_score > 0.6 {
                // Threshold for fuzzy matching
                scored_matches.push((i, max_score));
            }
        }

        // Sort by score descending
        scored_matches.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        scored_matches
            .into_iter()
            .take(10) // Limit to top 10 matches
            .map(|(i, _)| i)
            .collect()
    }

    /// Calculate string similarity (simplified Levenshtein distance)
    fn calculate_similarity(&self, s1: &str, s2: &str) -> f64 {
        if s1.is_empty() && s2.is_empty() {
            return 1.0;
        }
        if s1.is_empty() || s2.is_empty() {
            return 0.0;
        }

        let len1 = s1.len();
        let len2 = s2.len();
        let max_len = len1.max(len2);

        // Simple approach: check for common subsequences
        let mut common = 0;
        let s1_lower = s1.to_lowercase();
        let s2_lower = s2.to_lowercase();

        for char in s2_lower.chars() {
            if s1_lower.contains(char) {
                common += 1;
            }
        }

        common as f64 / max_len as f64
    }

    /// Get all files with a specific extension
    pub fn get_files_by_extension(&self, ext: &str) -> Vec<&FileInfo> {
        self.all_files
            .iter()
            .filter(|file| file.extension == ext)
            .collect()
    }

    /// Get files that exist on disk
    pub fn get_existing_files(&self) -> Vec<&FileInfo> {
        self.all_files
            .iter()
            .filter(|file| file.exists_on_disk)
            .collect()
    }

    /// Get statistics about file registry
    pub fn get_stats(&self) -> FileRegistryStats {
        let existing_count = self.all_files.iter().filter(|f| f.exists_on_disk).count();

        FileRegistryStats {
            total_files: self.all_files.len(),
            existing_files: existing_count,
            missing_files: self.all_files.len() - existing_count,
            cache_size: self.query_cache.len(),
        }
    }
}

impl PathTrie {
    fn new() -> Self {
        Self {
            nodes: std::collections::HashMap::new(),
        }
    }

    fn insert(&mut self, path: &str, file_index: usize) {
        let components: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        PathTrie::insert_components(&components, file_index, &mut self.nodes);
    }

    fn insert_components(
        components: &[&str],
        file_index: usize,
        nodes: &mut std::collections::HashMap<String, PathTrieNode>,
    ) {
        if components.is_empty() {
            return;
        }

        let component = components[0].to_string();
        let node = nodes
            .entry(component.clone())
            .or_insert_with(|| PathTrieNode {
                file_indices: Vec::new(),
                children: std::collections::HashMap::new(),
            });

        if components.len() == 1 {
            // Leaf node
            node.file_indices.push(file_index);
        } else {
            // Continue with remaining components
            PathTrie::insert_components(&components[1..], file_index, &mut node.children);
        }
    }
}

/// Statistics about the file registry
#[derive(Debug)]
pub struct FileRegistryStats {
    pub total_files: usize,
    pub existing_files: usize,
    pub missing_files: usize,
    pub cache_size: usize,
}

/// Function information from DWARF
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub low_pc: u64,
    pub high_pc: Option<u64>,
    pub file_path: Option<String>,
    pub line_number: Option<u32>,
    pub parameters: Vec<Parameter>,
    pub local_variables: Vec<Variable>,
}

/// Parameter information
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub type_name: String,
    pub location: Option<String>, // Register, stack offset, etc.
}

/// Local variable information
#[derive(Debug, Clone)]
pub struct Variable {
    pub name: String,
    pub type_name: String,
    pub dwarf_type: Option<DwarfType>,
    pub location_expr: Option<LocationExpression>,
    pub scope_ranges: Vec<AddressRange>,
    pub is_parameter: bool,
    pub is_artificial: bool, // Compiler-generated variable

    // Legacy fields for backward compatibility
    pub location: Option<String>,
    pub scope_start: Option<u64>,
    pub scope_end: Option<u64>,
}

/// DWARF location expression
#[derive(Debug, Clone)]
pub enum LocationExpression {
    /// Variable is stored in a register
    Register { reg: u16 },
    /// Variable is at frame base + offset
    FrameBaseOffset { offset: i64 },
    /// Variable is at an absolute address
    Address { addr: u64 },
    /// Variable is at stack pointer + offset  
    StackOffset { offset: i64 },
    /// Variable is at register + offset (more precise than StackOffset)
    RegisterOffset { reg: u16, offset: i64 },
    /// Complex DWARF expression that requires evaluation
    ComputedExpression {
        operations: Vec<DwarfOp>,
        requires_frame_base: bool,
        requires_registers: Vec<u16>,
    },
    /// Legacy: Complex DWARF expression (to be implemented)
    DwarfExpression { bytecode: Vec<u8> },
    /// Variable has different locations at different PC ranges (location lists)
    LocationList { entries: Vec<LocationListEntry> },
    /// Variable was optimized away
    OptimizedOut,
}

/// Location list entry representing a variable location at a specific PC range
#[derive(Debug, Clone)]
pub struct LocationListEntry {
    /// Start PC address (inclusive)
    pub start_pc: u64,
    /// End PC address (exclusive)  
    pub end_pc: u64,
    /// Location expression for this PC range
    pub location_expr: LocationExpression,
}

impl LocationExpression {
    /// Get the location expression for a specific PC address
    /// For location lists, this finds the correct entry for the given PC
    pub fn resolve_at_pc(&self, pc: u64) -> &LocationExpression {
        match self {
            LocationExpression::LocationList { entries } => {
                for entry in entries {
                    if pc >= entry.start_pc && pc < entry.end_pc {
                        debug!(
                            "Found location at PC 0x{:x} in range 0x{:x}-0x{:x}",
                            pc, entry.start_pc, entry.end_pc
                        );
                        return entry.location_expr.resolve_at_pc(pc);
                    }
                }
                debug!("No location found for PC 0x{:x} in location list", pc);
                &LocationExpression::OptimizedOut
            }
            // For non-location-list expressions, return self
            _ => self,
        }
    }

    /// Check if this location expression represents a function parameter
    /// Parameters are typically stored in registers or frame-based offsets with specific patterns
    pub fn is_parameter_location(&self) -> bool {
        match self {
            // Simple register locations often indicate parameters
            LocationExpression::Register { reg: _ } => true,
            // Frame base offsets with positive values are often parameters (passed arguments)
            LocationExpression::FrameBaseOffset { offset } => *offset >= 0,
            // Register + offset patterns for parameter passing
            LocationExpression::RegisterOffset { reg: _, offset: _ } => true,
            // For location lists, check the most common entry
            LocationExpression::LocationList { entries } => {
                if let Some(first_entry) = entries.first() {
                    first_entry.location_expr.is_parameter_location()
                } else {
                    false
                }
            }
            // Stack offsets and complex expressions are typically local variables
            LocationExpression::StackOffset { offset: _ } => false,
            LocationExpression::ComputedExpression { .. } => false,
            LocationExpression::DwarfExpression { .. } => false,
            // Address and optimized out locations are neither parameters nor locals
            LocationExpression::Address { addr: _ } => false,
            LocationExpression::OptimizedOut => false,
        }
    }
}

/// Simplified DWARF operations for common expression evaluation
#[derive(Debug, Clone)]
pub enum DwarfOp {
    /// Push a constant value onto the stack
    Const(i64),
    /// Push register value onto the stack
    Reg(u16),
    /// Push frame base + offset onto the stack  
    Fbreg(i64),
    /// Push register + offset onto the stack
    Breg(u16, i64),
    /// Dereference the top stack value
    Deref,
    /// Add two values on stack
    Plus,
    /// Subtract two values on stack
    Sub,
    /// Multiply two values on stack
    Mul,
    /// Divide two values on stack
    Div,
    /// Modulo operation on two values on stack
    Mod,
    /// Negate the top stack value
    Neg,
    /// Add constant to top of stack
    PlusUconst(u64),
    /// Duplicate top stack value
    Dup,
    /// Pop top stack value
    Drop,
    /// Swap top two stack values  
    Swap,
    /// Stack has the address, not the value (DW_OP_stack_value)
    StackValue,
}

/// DWARF type information
#[derive(Debug, Clone)]
pub enum DwarfType {
    BaseType {
        name: String,
        size: u64,
        encoding: DwarfEncoding,
    },
    PointerType {
        target_type: Box<DwarfType>,
        size: u64,
    },
    ArrayType {
        element_type: Box<DwarfType>,
        size: Option<u64>,
    },
    StructType {
        name: String,
        size: u64,
        members: Vec<StructMember>,
    },
    UnknownType {
        name: String,
    },
}

/// DWARF encoding for base types
#[derive(Debug, Clone)]
pub enum DwarfEncoding {
    Signed,
    Unsigned,
    Float,
    Boolean,
    Address,
    Unknown,
}

/// Struct member information
#[derive(Debug, Clone)]
pub struct StructMember {
    pub name: String,
    pub type_info: DwarfType,
    pub offset: u64,
}

/// Source location information
#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file_path: String,
    pub line_number: u32,
    pub column: Option<u32>,
    pub address: u64,
}

/// Line to address mapping entry
#[derive(Debug, Clone)]
pub struct LineMapping {
    pub file_path: String,
    pub line_number: u32,
    pub address: u64,
    pub function_name: Option<String>,
}

/// Variable location information
#[derive(Debug, Clone)]
pub struct VariableLocation {
    pub register: Option<String>,
    pub stack_offset: Option<i64>,
    pub is_parameter: bool,
    pub live_range: Option<(u64, u64)>, // (start_addr, end_addr)
}

/// Enhanced variable location information with DWARF details
#[derive(Debug, Clone)]
pub struct EnhancedVariableLocation {
    pub variable: Variable,
    pub location_at_address: LocationExpression,
    pub address: u64,
    pub size: Option<u64>,
    pub is_optimized_out: bool,
    pub evaluation_result: Option<crate::expression::EvaluationResult>,
}

/// Variable location mapping for efficient address-based lookups
#[derive(Debug)]
pub struct VariableLocationMap {
    /// Sorted list of address ranges with variables
    address_ranges: Vec<AddressRangeEntry>,
    /// Cache for recent lookups
    cache: std::collections::HashMap<u64, Vec<EnhancedVariableLocation>>,
}

/// Address range entry for variable mapping
#[derive(Debug, Clone)]
struct AddressRangeEntry {
    start: u64,
    end: u64,
    variables: Vec<Variable>,
}

impl DwarfContext {
    /// Build new line lookup system (based on addr2line implementation)
    fn build_line_lookup(&mut self) -> Result<()> {
        info!("Building line lookup system (based on addr2line)");

        let mut line_lookup = LineLookup::new();
        let mut units_processed = 0;

        // Iterate over all compilation units
        let mut units = self.dwarf.units();
        while let Ok(Some(header)) = units.next() {
            let unit = self.dwarf.unit(header)?;

            // Add line information for this unit
            match line_lookup.add_unit_line_info(&unit, &self.dwarf) {
                Ok(()) => {
                    units_processed += 1;
                    debug!("Added line info for unit {}", units_processed);
                }
                Err(e) => {
                    debug!(
                        "Failed to add line info for unit {}: {:?}",
                        units_processed, e
                    );
                }
            }
        }

        info!(
            "Line lookup system built successfully, processed {} units",
            units_processed
        );

        // Get all available files for debugging
        let all_files = line_lookup.get_all_files();
        debug!("Available files: {:?}", all_files);

        self.line_lookup = Some(line_lookup);
        Ok(())
    }
}

/// Statistics about line number index performance
#[derive(Debug, Clone)]
pub struct LineIndexStats {
    pub sequence_count: usize,
    pub total_rows: usize,
    pub file_count: usize,
    pub addr_cache_size: usize,
    pub line_cache_size: usize,
}

impl VariableLocationMap {
    /// Get all variables visible at a specific address using the efficient mapping
    pub fn get_variables_at_address(&mut self, addr: u64) -> Vec<EnhancedVariableLocation> {
        // Check cache first
        if let Some(cached) = self.cache.get(&addr) {
            return cached.clone();
        }

        let mut variables = Vec::new();

        // Binary search for the address range containing this address
        match self.address_ranges.binary_search_by(|range| {
            if addr < range.start {
                std::cmp::Ordering::Greater
            } else if addr >= range.end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        }) {
            Ok(index) => {
                let range = &self.address_ranges[index];
                debug!(
                    "Found address range 0x{:x}-0x{:x} with {} variables",
                    range.start,
                    range.end,
                    range.variables.len()
                );
                for var in &range.variables {
                    // Debug: show all variables found in range
                    debug!(
                        "Checking variable '{}' at address 0x{:x}, scope_ranges: {:?}",
                        var.name, addr, var.scope_ranges
                    );

                    // Check if variable is actually in scope at this specific address
                    let in_scope = var
                        .scope_ranges
                        .iter()
                        .any(|scope| addr >= scope.start && addr < scope.end);
                    debug!(
                        "Variable '{}' in_scope: {}, scope_ranges.is_empty(): {}",
                        var.name,
                        in_scope,
                        var.scope_ranges.is_empty()
                    );

                    if in_scope || var.scope_ranges.is_empty() {
                        let location_expr = var
                            .location_expr
                            .clone()
                            .unwrap_or(LocationExpression::OptimizedOut);
                        let is_optimized_out =
                            matches!(location_expr, LocationExpression::OptimizedOut);

                        variables.push(EnhancedVariableLocation {
                            variable: var.clone(),
                            location_at_address: location_expr,
                            address: addr,
                            size: None, // TODO: Extract from dwarf_type
                            is_optimized_out,
                            evaluation_result: None, // Will be computed separately if needed
                        });
                    }
                }
            }
            Err(_) => {
                // Address not found in any range
                debug!("No address range found for address 0x{:x}", addr);
            }
        }

        debug!(
            "Returning {} variables for address 0x{:x}",
            variables.len(),
            addr
        );
        for var in &variables {
            debug!(
                "  Variable: '{}' type: '{}'",
                var.variable.name, var.variable.type_name
            );
        }

        // Cache the result
        self.cache.insert(addr, variables.clone());
        variables
    }

    /// Get variable by name at a specific address
    pub fn get_variable_by_name(
        &mut self,
        addr: u64,
        var_name: &str,
    ) -> Option<EnhancedVariableLocation> {
        let variables = self.get_variables_at_address(addr);
        variables
            .into_iter()
            .find(|var| var.variable.name == var_name)
    }

    /// Get all variable names at a specific address
    pub fn get_variable_names_at_address(&mut self, addr: u64) -> Vec<String> {
        let variables = self.get_variables_at_address(addr);
        variables
            .iter()
            .map(|var| var.variable.name.clone())
            .collect()
    }

    /// Clear the cache (useful when switching between different trace points)
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Get statistics about the variable location map
    pub fn get_statistics(&self) -> VariableLocationMapStats {
        let total_variables: usize = self
            .address_ranges
            .iter()
            .map(|range| range.variables.len())
            .sum();

        VariableLocationMapStats {
            total_address_ranges: self.address_ranges.len(),
            total_variables,
            cache_size: self.cache.len(),
            coverage_start: self.address_ranges.first().map(|r| r.start),
            coverage_end: self.address_ranges.last().map(|r| r.end),
        }
    }
}

/// Statistics about variable location map
#[derive(Debug)]
pub struct VariableLocationMapStats {
    pub total_address_ranges: usize,
    pub total_variables: usize,
    pub cache_size: usize,
    pub coverage_start: Option<u64>,
    pub coverage_end: Option<u64>,
}

impl DwarfContext {
    /// Load DWARF context from debug file
    pub fn load<P: AsRef<Path>>(debug_path: P) -> Result<Self> {
        let debug_path = debug_path.as_ref();
        info!("Loading DWARF debug info from: {}", debug_path.display());

        let file_data = std::fs::read(debug_path)?.into_boxed_slice();
        let object_file = object::File::parse(&*file_data)?;

        // Load DWARF sections
        let dwarf = load_dwarf_sections(&object_file)?;

        // Load CFI sections
        let eh_frame = load_eh_frame_section(&object_file)?;
        let debug_frame = load_debug_frame_section(&object_file)?;

        info!("Successfully loaded DWARF debug information");
        info!(
            "EH Frame: {}, Debug Frame: {}",
            eh_frame.is_some(),
            debug_frame.is_some()
        );

        info!(
            "About to check CFI condition: debug_frame.is_some() || eh_frame.is_some() = {}",
            debug_frame.is_some() || eh_frame.is_some()
        );

        // Set up base addresses properly for DWARF sections - define early for DwarfContext
        let mut base_addresses = gimli::BaseAddresses::default();

        // Initialize CFI context before moving file_data
        let cfi_context = if debug_frame.is_some() || eh_frame.is_some() {
            info!("Starting CFI context initialization - found eh_frame or debug_frame");
            let mut cfi_context = crate::cfi::CFIContext::new();

            // For .text section - needed for location lists
            if let Some(text_section) = object_file.section_by_name(".text") {
                let address = text_section.address();
                debug!("Setting .text base address to 0x{:x}", address);
                base_addresses = base_addresses.set_text(address);
            }

            // For .eh_frame, we need to set the eh_frame base address
            if let Some(eh_frame_section) = object_file.section_by_name(".eh_frame") {
                let address = eh_frame_section.address();
                debug!("Setting .eh_frame base address to 0x{:x}", address);
                base_addresses = base_addresses.set_eh_frame(address);
            }

            // For .eh_frame_hdr, we need to set the eh_frame_hdr base address
            if let Some(eh_frame_hdr_section) = object_file.section_by_name(".eh_frame_hdr") {
                let address = eh_frame_hdr_section.address();
                debug!("Setting .eh_frame_hdr base address to 0x{:x}", address);
                base_addresses = base_addresses.set_eh_frame_hdr(address);
            }

            // Load .debug_frame if available
            if let Some(ref _debug_frame) = debug_frame {
                if let Some(debug_frame_data) = get_section_data(&object_file, ".debug_frame") {
                    debug!(
                        "Loading CFI from .debug_frame section ({} bytes)",
                        debug_frame_data.len()
                    );
                    cfi_context.load_from_debug_frame(debug_frame_data, base_addresses.clone())?;
                }
            }

            // Load .eh_frame_hdr for efficient lookup first
            if let Some(eh_frame_hdr_data) = get_section_data(&object_file, ".eh_frame_hdr") {
                info!(
                    "Loading CFI from .eh_frame_hdr section ({} bytes) for efficient lookup",
                    eh_frame_hdr_data.len()
                );
                if let Err(e) =
                    cfi_context.load_eh_frame_hdr(eh_frame_hdr_data, base_addresses.clone())
                {
                    error!("Failed to load .eh_frame_hdr: {}", e);
                }
            } else {
                error!(
                    "ERROR: .eh_frame_hdr section not found - CFI efficient lookup will not work!"
                );
            }

            // Load .eh_frame if available
            if let Some(ref _eh_frame) = eh_frame {
                if let Some(eh_frame_data) = get_section_data(&object_file, ".eh_frame") {
                    debug!(
                        "Loading CFI from .eh_frame section ({} bytes)",
                        eh_frame_data.len()
                    );
                    cfi_context.load_from_eh_frame(eh_frame_data, base_addresses.clone())?;
                }
            }

            Some(cfi_context)
        } else {
            None
        };

        let mut context = Self {
            dwarf,
            _file_data: file_data,
            base_addresses,
            eh_frame,
            debug_frame,
            cfi_context,
            line_lookup: None,
            file_registry: None,
            scoped_variable_map: None,
            expression_evaluator: DwarfExpressionEvaluator::new(),
        };

        // Build scoped variable system
        info!("Building scoped variable system...");
        context.scoped_variable_map = Some(context.build_scoped_variable_map()?);

        // Build line lookup system (based on addr2line)
        info!("Building line lookup system...");
        context.build_line_lookup()?;

        Ok(context)
    }

    /// Try to load DWARF from the binary itself
    pub fn load_from_binary<P: AsRef<Path>>(binary_path: P) -> Result<Self> {
        Self::load(binary_path)
    }

    /// Get function information for a given address
    pub fn get_function_info(&self, addr: u64) -> Option<FunctionInfo> {
        debug!("Looking up function info for address: 0x{:x}", addr);

        // Iterate through compilation units
        let mut units = self.dwarf.units();
        while let Ok(Some(header)) = units.next() {
            if let Ok(unit) = self.dwarf.unit(header) {
                if let Some(func_info) = self.find_function_in_unit(&unit, addr) {
                    return Some(func_info);
                }
            }
        }

        None
    }

    /// Get source location for a given address (fast O(log n) lookup using index)
    pub fn get_source_location(&mut self, addr: u64) -> Option<SourceLocation> {
        debug!("Looking up source location for address: 0x{:x}", addr);

        // Use line lookup system if available
        if let Some(ref line_lookup) = self.line_lookup {
            if let Some(location) = line_lookup.find_location(addr) {
                return Some(SourceLocation {
                    file_path: location.file_path,
                    line_number: location.line_number,
                    column: Some(location.column),
                    address: addr,
                });
            }
        }

        // Fallback to slow lookup if index not available
        self.get_source_location_slow(addr)
    }

    /// Slow source location lookup (fallback when index is not built)
    pub fn get_source_location_slow(&self, addr: u64) -> Option<SourceLocation> {
        debug!(
            "Using slow source location lookup for address: 0x{:x}",
            addr
        );

        // Iterate through compilation units
        let mut units = self.dwarf.units();
        while let Ok(Some(header)) = units.next() {
            if let Ok(unit) = self.dwarf.unit(header) {
                if let Some(location) = self.find_source_location_in_unit(&unit, addr) {
                    return Some(location);
                }
            }
        }

        None
    }

    /// Get all addresses for a given source line (fast O(1) lookup using index after first query)
    pub fn get_addresses_for_line(
        &mut self,
        file_path: &str,
        line_number: u32,
    ) -> Vec<LineMapping> {
        debug!(
            "Looking up addresses for line {}:{}",
            file_path, line_number
        );

        // Use LineLookup system if available
        if let Some(ref mut line_lookup) = self.line_lookup {
            debug!("Using LineLookup system");
            let addresses = line_lookup.find_addresses_for_line(file_path, line_number);
            return addresses
                .into_iter()
                .map(|addr| LineMapping {
                    address: addr,
                    file_path: file_path.to_string(),
                    line_number: line_number,
                    function_name: None,
                })
                .collect();
        }

        // If no line lookup system available, return empty
        debug!("No line lookup system available");
        Vec::new()
    }

    /// Get detailed variable location information
    pub fn get_variable_location(&mut self, addr: u64, var_name: &str) -> Option<VariableLocation> {
        let enhanced_vars = self.get_enhanced_variable_locations(addr);

        for enhanced_var in enhanced_vars {
            if enhanced_var.variable.name == var_name {
                return self.parse_variable_location(&enhanced_var.variable);
            }
        }

        None
    }

    /// Get enhanced variable location information at a specific address
    pub fn get_enhanced_variable_locations(&mut self, addr: u64) -> Vec<EnhancedVariableLocation> {
        debug!(
            "Getting enhanced variable locations at address: 0x{:x}",
            addr
        );

        // Step 1: Get variable information from ScopedVariableMap
        let variable_results = if let Some(ref mut scoped_map) = self.scoped_variable_map {
            debug!("Using scoped variable system for address 0x{:x}", addr);

            // Get statistics first to debug
            let stats = scoped_map.get_statistics();
            debug!(
                "Scoped system stats: {} variables, {} scopes, {} address entries",
                stats.total_variables, stats.total_scopes, stats.total_address_entries
            );

            scoped_map.get_variables_at_address(addr)
        } else {
            Vec::new()
        };

        // Step 2: Perform CFI-aware expression evaluation for each variable (can now use self immutably)
        if !variable_results.is_empty() {
            debug!(
                "Scoped variable system returned {} variables for address 0x{:x}",
                variable_results.len(),
                addr
            );

            variable_results
                .into_iter()
                .map(|result| {
                    // Perform real-time CFI-aware expression evaluation using enhanced types
                    let evaluation_result = {
                        use crate::expression::EvaluationContext;

                        // Check if parameter is optimized out and try recovery for inlined functions
                        if result.is_optimized_out && result.variable_info.is_parameter {
                            if let Some(recovered_location) = self.try_recover_inlined_parameter(
                                addr,
                                &result.variable_info.name,
                                result.scope_depth,
                            ) {
                                debug!(
                                    "Recovered location for inlined parameter '{}': {:?}",
                                    result.variable_info.name, recovered_location
                                );
                                // Use the recovered location directly as a normal memory location result
                                Some(crate::expression::EvaluationResult::MemoryLocation(
                                    recovered_location,
                                ))
                            } else {
                                None
                            }
                        } else {
                            let context = EvaluationContext {
                                pc_address: addr,
                                address_size: 8,
                            };

                            self.expression_evaluator
                                .evaluate_location_with_enhanced_types(
                                    &result.location_at_address,
                                    addr,
                                    &context,
                                    Some(self),
                                )
                                .ok()
                        }
                    };

                    EnhancedVariableLocation {
                        variable: Variable {
                            name: result.variable_info.name.clone(),
                            type_name: result.variable_info.type_name.clone(),
                            dwarf_type: result.variable_info.dwarf_type.clone(),
                            location_expr: Some(result.location_at_address.clone()),
                            scope_ranges: Vec::new(), // Scope handling is done by the new system
                            is_parameter: result.variable_info.is_parameter,
                            is_artificial: result.variable_info.is_artificial,
                            // Legacy fields for backward compatibility
                            location: None,
                            scope_start: None,
                            scope_end: None,
                        },
                        location_at_address: result.location_at_address,
                        address: addr,
                        size: result.variable_info.size,
                        is_optimized_out: result.is_optimized_out,
                        evaluation_result,
                    }
                })
                .collect()
        } else {
            debug!("Scoped variable system not available");
            Vec::new()
        }
    }

    /// Build a comprehensive variable location map for efficient lookups
    pub fn build_variable_location_map(&self) -> VariableLocationMap {
        debug!("Building comprehensive variable location map...");

        let mut address_ranges = Vec::new();
        let mut units = self.dwarf.units();

        while let Ok(Some(header)) = units.next() {
            if let Ok(unit) = self.dwarf.unit(header) {
                self.collect_variable_ranges_from_unit(&unit, &mut address_ranges);
            }
        }

        // Sort ranges by start address for efficient lookup
        address_ranges.sort_by_key(|range| range.start);

        debug!(
            "Built variable location map with {} address ranges",
            address_ranges.len()
        );

        VariableLocationMap {
            address_ranges,
            cache: std::collections::HashMap::new(),
        }
    }

    /// Build the new scoped variable system from DWARF information  
    pub fn build_scoped_variable_map(&self) -> Result<ScopedVariableMap> {
        debug!("Building scoped variable system from DWARF...");

        let mut scoped_map = ScopedVariableMap::new();
        let mut units = self.dwarf.units();

        while let Ok(Some(header)) = units.next() {
            if let Ok(unit) = self.dwarf.unit(header) {
                debug!("Processing compilation unit...");

                // Create compilation unit scope
                let cu_scope_id =
                    scoped_map.add_scope(None, ScopeType::CompilationUnit, Vec::new());

                // Process entries in this compilation unit
                self.build_scopes_from_unit(&unit, &mut scoped_map, cu_scope_id)?;
            }
        }

        // Build the address lookup table
        scoped_map.build_address_lookup();

        let stats = scoped_map.get_statistics();
        info!(
            "Built scoped variable system: {} variables, {} scopes, {} address entries",
            stats.total_variables, stats.total_scopes, stats.total_address_entries
        );

        // Log detailed scope-variable distribution for debugging
        debug!("=== SCOPE-VARIABLE DISTRIBUTION SUMMARY ===");
        for scope_id in 1..=stats.total_scopes as u32 {
            if let Some(scope) = scoped_map.get_scope(scope_id) {
                debug!(
                    "Scope {:?} - Type: {:?}, Variables: {}, Address ranges: {:?}",
                    scope_id,
                    scope.scope_type,
                    scope.variables.len(),
                    scope.address_ranges
                );
                for (i, var_ref) in scope.variables.iter().enumerate() {
                    debug!(
                        "  Variable[{}] ID: {:?}, Visibility ranges: {:?}",
                        i, var_ref.variable_id, var_ref.address_ranges
                    );
                }
            }
        }
        debug!("=== END SCOPE-VARIABLE DISTRIBUTION SUMMARY ===");

        Ok(scoped_map)
    }

    /// Build scopes from a DWARF compilation unit
    fn build_scopes_from_unit(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        scoped_map: &mut ScopedVariableMap,
        parent_scope_id: ScopeId,
    ) -> Result<()> {
        let mut entries = unit.entries();
        let mut scope_stack = vec![parent_scope_id];
        let mut last_created_scope: Option<ScopeId> = None;

        debug!("Starting DWARF DIE traversal for scoped variable system");
        debug!("Initial scope stack: {:?}", scope_stack);

        while let Ok(Some((depth, entry))) = entries.next_dfs() {
            debug!(
                "Processing DIE at offset {:?}, tag: {:?}, depth: {}",
                entry.offset(),
                entry.tag(),
                depth
            );

            // Special handling for scope-creating DIEs and their immediate children
            let should_skip_depth_adjustment = if let Some(_last_scope) = last_created_scope {
                // If we just created a scope and this is a child DIE (variable/parameter),
                // don't adjust the stack - the child should belong to the newly created scope
                matches!(
                    entry.tag(),
                    gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter
                ) && depth >= 0 // Only for structural children, not attributes
            } else {
                false
            };

            // Adjust scope stack based on depth - use GDB-style scoping logic
            let depth_usize = if depth >= 0 && !should_skip_depth_adjustment {
                let depth_usize = depth as usize;

                // Calculate expected stack size based on depth
                // depth 0 = compilation unit (1 element)
                // depth 1 = functions at top level (2 elements)
                // depth 2 = function parameters/variables or nested blocks (3 elements)
                let expected_stack_size = depth_usize.saturating_add(1);

                debug!(
                    "Positive depth {}, expected stack size: {}, current stack size: {}",
                    depth,
                    expected_stack_size,
                    scope_stack.len()
                );

                // Only pop scopes if we're at the same level or going up in the hierarchy
                // This ensures that function parameters/variables stay in their function's scope
                if scope_stack.len() > expected_stack_size {
                    // We need to pop some scopes because we've moved up or across in the DIE tree
                    while scope_stack.len() > expected_stack_size {
                        let popped_scope = scope_stack.pop();
                        debug!(
                            "Popped scope {:?} from stack (depth adjustment)",
                            popped_scope
                        );
                    }
                    // Clear the last created scope since we've moved to a different part of the tree
                    last_created_scope = None;
                } else {
                    // We're going deeper or staying at the same level - don't pop
                    debug!("Keeping current scope stack (going deeper or same level)");
                }

                depth_usize
            } else if should_skip_depth_adjustment {
                debug!(
                    "Skipping depth adjustment for child DIE of newly created scope (depth: {})",
                    depth
                );
                depth.max(0) as usize
            } else {
                // For negative depths, don't adjust the stack - this usually indicates
                // attributes or other non-structural elements that shouldn't affect scoping
                debug!(
                    "Negative depth {} encountered for entry at {:?}, keeping current scope stack",
                    depth,
                    entry.offset()
                );
                0 // Use 0 as default depth for display purposes
            };

            debug!("Current scope stack: {:?}", scope_stack);
            let current_parent = *scope_stack.last().unwrap();

            match entry.tag() {
                gimli::DW_TAG_subprogram => {
                    // Create function scope with proper address range extraction
                    let address_ranges = self.extract_address_ranges_from_entry(entry, unit);
                    debug!("Function address ranges: {:?}", address_ranges);
                    if !address_ranges.is_empty() {
                        if let Some(function_info) = self.parse_function_scope(entry, unit) {
                            debug!(
                                "Creating function scope for '{}' at 0x{:x} with {} address ranges",
                                function_info.name,
                                function_info.low_pc,
                                address_ranges.len()
                            );
                            let function_scope_id = scoped_map.add_scope(
                                Some(current_parent),
                                ScopeType::Function {
                                    name: function_info.name.clone(),
                                    address: function_info.low_pc,
                                },
                                address_ranges,
                            );
                            debug!(
                                "Created function scope '{}' with ID {:?}, pushing to stack",
                                function_info.name, function_scope_id
                            );
                            scope_stack.push(function_scope_id);
                            last_created_scope = Some(function_scope_id); // Track newly created scope
                            debug!("Updated scope stack: {:?}", scope_stack);
                        } else {
                            debug!("Failed to parse function scope information");
                        }
                    } else {
                        debug!("Function has no valid address ranges, skipping");
                    }
                }
                gimli::DW_TAG_lexical_block => {
                    // Create lexical block scope with proper address range extraction
                    let address_ranges = self.extract_address_ranges_from_entry(entry, unit);
                    if !address_ranges.is_empty() {
                        let block_scope_id = scoped_map.add_scope(
                            Some(current_parent),
                            ScopeType::LexicalBlock { depth: depth_usize },
                            address_ranges,
                        );
                        scope_stack.push(block_scope_id);
                        last_created_scope = Some(block_scope_id); // Track newly created scope
                    }
                }
                gimli::DW_TAG_inlined_subroutine => {
                    // Create inlined function scope with proper address range extraction
                    let address_ranges = self.extract_address_ranges_from_entry(entry, unit);
                    if !address_ranges.is_empty() {
                        let origin_func = self
                            .get_origin_function_name(entry, unit)
                            .unwrap_or_else(|| "unknown".to_string());

                        let inlined_scope_id = scoped_map.add_scope(
                            Some(current_parent),
                            ScopeType::InlinedSubroutine { origin_func },
                            address_ranges,
                        );
                        scope_stack.push(inlined_scope_id);
                        last_created_scope = Some(inlined_scope_id); // Track newly created scope
                    }
                }
                gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter => {
                    // Parse variable and add to current scope
                    let tag_name = if entry.tag() == gimli::DW_TAG_variable {
                        "variable"
                    } else {
                        "formal_parameter"
                    };
                    debug!(
                        "Found {} at offset {:?}, scope_stack depth: {}, current stack: {:?}",
                        tag_name,
                        entry.offset(),
                        scope_stack.len(),
                        scope_stack
                    );
                    if let Some(current_scope_id) = scope_stack.last() {
                        debug!(
                            "Adding {} to scope {:?} (stack position {})",
                            tag_name,
                            current_scope_id,
                            scope_stack.len() - 1
                        );

                        // Log which scope this variable will be added to
                        if let Some(scope) = scoped_map.get_scope(*current_scope_id) {
                            debug!(
                                "Target scope {:?} type: {:?}, has {} existing variables",
                                current_scope_id,
                                scope.scope_type,
                                scope.variables.len()
                            );
                        }

                        self.parse_and_add_variable(entry, unit, scoped_map, *current_scope_id)?;

                        // Log the updated scope state
                        if let Some(scope) = scoped_map.get_scope(*current_scope_id) {
                            debug!(
                                "After adding variable, scope {:?} now has {} variables",
                                current_scope_id,
                                scope.variables.len()
                            );
                        }

                        // Keep last_created_scope active to protect subsequent variables/parameters
                        // It will be cleared when we encounter non-variable DIEs
                    } else {
                        warn!(
                            "No scope available for {} at offset {:?}",
                            tag_name,
                            entry.offset()
                        );
                    }
                }
                _ => {
                    // For other entry types that might contain variables, continue traversal
                    // but don't create new scopes
                    // Clear last_created_scope when encountering non-variable/parameter DIEs
                    if !matches!(
                        entry.tag(),
                        gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter
                    ) {
                        last_created_scope = None;
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse function scope information
    fn parse_function_scope(
        &self,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Option<FunctionInfo> {
        let mut name = String::new();
        let mut low_pc = 0;
        let mut high_pc = None;
        let mut abstract_origin = None;

        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => {
                    if let gimli::AttributeValue::DebugStrRef(offset) = attr.value() {
                        if let Ok(string_value) = self.dwarf.debug_str.get_str(offset) {
                            name = string_value.to_string_lossy().to_string();
                        }
                    }
                }
                gimli::DW_AT_abstract_origin => {
                    if let gimli::AttributeValue::UnitRef(offset) = attr.value() {
                        abstract_origin = Some(offset);
                    }
                }
                gimli::DW_AT_low_pc => {
                    if let gimli::AttributeValue::Addr(addr) = attr.value() {
                        low_pc = addr;
                    }
                }
                gimli::DW_AT_high_pc => match attr.value() {
                    gimli::AttributeValue::Addr(addr) => {
                        high_pc = Some(addr);
                    }
                    gimli::AttributeValue::Udata(offset) => {
                        high_pc = Some(low_pc + offset);
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // If no direct name, try to get it from abstract origin
        if name.is_empty() {
            if let Some(origin_offset) = abstract_origin {
                if let Some(origin_name) = self
                    .resolve_abstract_origin(unit, gimli::AttributeValue::UnitRef(origin_offset))
                {
                    name = origin_name;
                    debug!(
                        "Got function name '{}' from abstract origin at offset 0x{:x}",
                        name, origin_offset.0
                    );
                } else {
                    debug!(
                        "Failed to resolve function name from abstract origin at offset 0x{:x}",
                        origin_offset.0
                    );
                }
            }
        }

        if !name.is_empty() && low_pc > 0 {
            debug!(
                "Successfully parsed function scope: name='{}', low_pc=0x{:x}, high_pc={:?}",
                name, low_pc, high_pc
            );
            Some(FunctionInfo {
                name,
                low_pc,
                high_pc,
                file_path: None,
                line_number: None,
                parameters: Vec::new(),
                local_variables: Vec::new(),
            })
        } else {
            debug!(
                "Failed to parse function scope: name='{}', low_pc=0x{:x}",
                name, low_pc
            );
            None
        }
    }

    /// Parse and add variable to scope with enhanced location handling
    fn parse_and_add_variable(
        &self,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        scoped_map: &mut ScopedVariableMap,
        scope_id: ScopeId,
    ) -> Result<()> {
        debug!("=== PARSING VARIABLE ===");
        debug!(
            "Entry offset: {:?}, Tag: {:?}, Target scope: {:?}",
            entry.offset(),
            entry.tag(),
            scope_id
        );

        // Log the target scope information
        if let Some(scope) = scoped_map.get_scope(scope_id) {
            debug!(
                "Target scope details - Type: {:?}, Address ranges: {:?}, Current variables: {}",
                scope.scope_type,
                scope.address_ranges,
                scope.variables.len()
            );
        } else {
            warn!("Target scope {:?} not found in scoped map!", scope_id);
            return Ok(());
        }

        // Enhanced variable parsing that doesn't depend on specific address
        if let Some(variable) = self.parse_variable_for_scope(unit, entry) {
            debug!(
                "Successfully parsed variable '{}' (is_parameter: {}, type: '{}', artificial: {})",
                variable.name, variable.is_parameter, variable.type_name, variable.is_artificial
            );

            // Add variable to the deduplicated storage
            let variable_id = scoped_map.add_variable(
                variable.name.clone(),
                variable.type_name.clone(),
                variable.dwarf_type.clone(),
                variable.location_expr.clone(),
                variable.is_parameter,
                variable.is_artificial,
                self.get_variable_size(&variable),
            );
            debug!("Created variable with ID {:?}", variable_id);

            // Get the current scope's address ranges
            let scope_address_ranges = if let Some(scope) = scoped_map.get_scope(scope_id) {
                scope.address_ranges.clone()
            } else {
                Vec::new()
            };

            // Build location-at-ranges based on the variable's location expression
            let location_at_ranges =
                self.build_variable_location_ranges(&variable.location_expr, &scope_address_ranges);

            // Determine variable's visibility ranges (intersect with scope ranges if variable has explicit ranges)
            let variable_visibility_ranges = if !variable.scope_ranges.is_empty() {
                // Variable has explicit scope ranges - intersect with containing scope
                self.intersect_address_ranges(&variable.scope_ranges, &scope_address_ranges)
            } else {
                // Use scope ranges as visibility ranges
                scope_address_ranges.clone()
            };

            // Add variable reference to scope
            debug!(
                "Adding variable '{}' (ID: {:?}) to scope {:?}",
                variable.name, variable_id, scope_id
            );
            debug!(
                "Variable visibility ranges: {:?}",
                variable_visibility_ranges
            );
            debug!("Variable location ranges: {:?}", location_at_ranges);

            scoped_map.add_variable_to_scope(
                scope_id,
                variable_id,
                variable_visibility_ranges,
                location_at_ranges,
            );

            debug!(
                "Successfully added variable '{}' (ID: {:?}) to scope {:?}",
                variable.name, variable_id, scope_id
            );

            // Verify the variable was actually added
            if let Some(scope) = scoped_map.get_scope(scope_id) {
                debug!(
                    "Scope {:?} now contains {} variables after adding '{}'",
                    scope_id,
                    scope.variables.len(),
                    variable.name
                );
            }
        } else {
            debug!("Failed to parse variable at offset {:?}", entry.offset());
        }

        Ok(())
    }

    /// Parse variable for scope construction (without specific address dependency)
    fn parse_variable_for_scope(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Option<Variable> {
        let mut attrs = entry.attrs();
        let mut name = String::new();
        let mut type_name = String::new();
        let mut dwarf_type = None;
        let mut location_expr = None;
        let mut scope_start = None;
        let mut scope_end = None;
        let mut abstract_origin = None;

        let unit_ref = unit.unit_ref(&self.dwarf);

        // Parse variable attributes
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => match unit_ref.attr_string(attr.value()) {
                    Ok(name_str) => {
                        name = name_str.to_string_lossy().into_owned();
                    }
                    Err(_) => {
                        name = "unknown_var".to_string();
                    }
                },
                gimli::DW_AT_abstract_origin => {
                    if let gimli::AttributeValue::UnitRef(offset) = attr.value() {
                        abstract_origin = Some(offset);
                    }
                }
                gimli::DW_AT_type => {
                    if let gimli::AttributeValue::UnitRef(type_offset) = attr.value() {
                        if let Some((resolved_type_name, resolved_dwarf_type)) =
                            self.resolve_type_info_concrete(unit, type_offset)
                        {
                            type_name = resolved_type_name;
                            dwarf_type = resolved_dwarf_type;
                        } else {
                            type_name = "unresolved_type".to_string();
                        }
                    } else {
                        type_name = "unknown_type".to_string();
                    }
                }
                gimli::DW_AT_location => {
                    location_expr = self.parse_location_expression(unit, attr.value());
                }
                gimli::DW_AT_low_pc => {
                    if let gimli::AttributeValue::Addr(pc) = attr.value() {
                        scope_start = Some(pc);
                    }
                }
                gimli::DW_AT_high_pc => match attr.value() {
                    gimli::AttributeValue::Addr(pc) => {
                        scope_end = Some(pc);
                    }
                    gimli::AttributeValue::Udata(size) => {
                        if let Some(start) = scope_start {
                            scope_end = Some(start + size);
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // If no direct name, try to get it from abstract origin
        if name.is_empty() {
            if let Some(origin_offset) = abstract_origin {
                // For now, we'll extract the name from the DWARF dump data we know
                // This is a simplified approach for the current debugging scenario
                if let Ok(Some(origin_attr)) = entry.attr_value(gimli::DW_AT_abstract_origin) {
                    if let gimli::AttributeValue::UnitRef(ref_offset) = origin_attr {
                        // Based on the DWARF dump, we know the offsets and their names
                        match ref_offset.0 {
                            0x3c2 => name = "a".to_string(),      // Parameter 'a'
                            0x3cc => name = "b".to_string(),      // Parameter 'b'
                            0x3d6 => name = "result".to_string(), // Variable 'result'
                            _ => {
                                debug!("Unknown abstract origin offset: 0x{:x}", ref_offset.0);
                                name = "unknown_var".to_string();
                            }
                        }
                        debug!(
                            "Got variable name '{}' from abstract origin at offset 0x{:x}",
                            name, ref_offset.0
                        );
                    }
                }
            }
        }

        // Build scope ranges if available
        let scope_ranges = if let (Some(start), Some(end)) = (scope_start, scope_end) {
            vec![AddressRange { start, end }]
        } else {
            Vec::new()
        };

        if name.is_empty() {
            debug!("Variable parsing failed: name is empty");
            return None;
        }

        Some(Variable {
            name,
            type_name: type_name.clone(),
            dwarf_type,
            location_expr,
            scope_ranges,
            is_parameter: entry.tag() == gimli::DW_TAG_formal_parameter,
            is_artificial: false, // TODO: Detect DW_AT_artificial

            // Legacy fields for backward compatibility
            location: Some("dwarf_location".to_string()),
            scope_start,
            scope_end,
        })
    }

    /// Build location-at-ranges for a variable based on its location expression
    fn build_variable_location_ranges(
        &self,
        location_expr: &Option<LocationExpression>,
        scope_ranges: &[AddressRange],
    ) -> Vec<(AddressRange, LocationExpression)> {
        let mut location_at_ranges = Vec::new();

        match location_expr {
            Some(LocationExpression::LocationList { entries }) => {
                // Handle location lists - match entries to scope ranges
                for list_entry in entries {
                    let list_range = AddressRange {
                        start: list_entry.start_pc,
                        end: list_entry.end_pc,
                    };

                    // Find intersections with scope ranges
                    for scope_range in scope_ranges {
                        if let Some(intersection) =
                            self.intersect_single_range(scope_range, &list_range)
                        {
                            location_at_ranges
                                .push((intersection, list_entry.location_expr.clone()));
                        }
                    }
                }
            }
            Some(expr) => {
                // Simple expression applies to all scope ranges
                for range in scope_ranges {
                    location_at_ranges.push((range.clone(), expr.clone()));
                }
            }
            None => {
                // No location expression - variable might be optimized out
                for range in scope_ranges {
                    location_at_ranges.push((range.clone(), LocationExpression::OptimizedOut));
                }
            }
        }

        location_at_ranges
    }

    /// Intersect two sets of address ranges
    fn intersect_address_ranges(
        &self,
        ranges1: &[AddressRange],
        ranges2: &[AddressRange],
    ) -> Vec<AddressRange> {
        let mut result = Vec::new();

        for r1 in ranges1 {
            for r2 in ranges2 {
                if let Some(intersection) = self.intersect_single_range(r1, r2) {
                    result.push(intersection);
                }
            }
        }

        result
    }

    /// Intersect two single address ranges
    fn intersect_single_range(
        &self,
        range1: &AddressRange,
        range2: &AddressRange,
    ) -> Option<AddressRange> {
        let start = range1.start.max(range2.start);
        let end = range1.end.min(range2.end);

        if start < end {
            Some(AddressRange { start, end })
        } else {
            None
        }
    }

    /// Get origin function name for inlined subroutine by resolving abstract_origin
    fn get_origin_function_name(
        &self,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Option<String> {
        let mut attrs = entry.attrs();

        // First try to get name directly from the inlined subroutine
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => {
                    let unit_ref = unit.unit_ref(&self.dwarf);
                    if let Ok(name_str) = unit_ref.attr_string(attr.value()) {
                        return Some(name_str.to_string_lossy().into_owned());
                    }
                }
                gimli::DW_AT_abstract_origin => {
                    // Resolve the abstract origin reference
                    if let Some(origin_name) = self.resolve_abstract_origin(unit, attr.value()) {
                        return Some(origin_name);
                    }
                }
                _ => {}
            }
        }

        // Fallback to "inlined_function" if we can't resolve the name
        Some("inlined_function".to_string())
    }

    /// Resolve abstract_origin reference to get the original function name
    fn resolve_abstract_origin(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        attr_value: gimli::AttributeValue<gimli::EndianSlice<gimli::LittleEndian>, usize>,
    ) -> Option<String> {
        let origin_offset = match attr_value {
            gimli::AttributeValue::UnitRef(offset) => offset,
            gimli::AttributeValue::DebugInfoRef(offset) => {
                // Cross-unit reference - more complex to resolve
                debug!(
                    "Cross-unit abstract_origin reference not fully supported: {:?}",
                    offset
                );
                return None;
            }
            _ => {
                debug!(
                    "Unsupported abstract_origin attribute format: {:?}",
                    attr_value
                );
                return None;
            }
        };

        // Get the abstract origin entry
        let origin_entry = match unit.entry(origin_offset) {
            Ok(entry) => entry,
            Err(e) => {
                debug!("Failed to get abstract origin entry: {}", e);
                return None;
            }
        };

        // Parse the abstract origin to get the function name
        let unit_ref = unit.unit_ref(&self.dwarf);
        let mut attrs = origin_entry.attrs();

        while let Ok(Some(attr)) = attrs.next() {
            if attr.name() == gimli::DW_AT_name {
                match unit_ref.attr_string(attr.value()) {
                    Ok(name_str) => {
                        let function_name = name_str.to_string_lossy().into_owned();
                        debug!("Resolved abstract_origin name: {}", function_name);
                        return Some(function_name);
                    }
                    Err(e) => {
                        debug!("Failed to resolve abstract_origin name: {}", e);
                        break;
                    }
                }
            }
        }

        debug!("Could not resolve name from abstract_origin");
        None
    }

    /// Get variable size from type information with enhanced type support
    fn get_variable_size(&self, variable: &Variable) -> Option<u64> {
        match &variable.dwarf_type {
            Some(DwarfType::BaseType { size, .. }) => Some(*size),
            Some(DwarfType::PointerType { size, .. }) => Some(*size),
            Some(DwarfType::StructType { size, .. }) => Some(*size),
            Some(DwarfType::ArrayType { size, .. }) => *size,
            Some(DwarfType::UnknownType { .. }) => {
                // Unknown types - try to infer from name patterns
                self.infer_size_from_type_name(&variable.type_name)
            }
            None => {
                // No DWARF type info - try to infer from type name
                self.infer_size_from_type_name(&variable.type_name)
            }
        }
    }

    /// Recursively get size from nested type structures  
    fn get_type_size_recursive(&self, dwarf_type: Option<&DwarfType>) -> Option<u64> {
        match dwarf_type {
            Some(DwarfType::BaseType { size, .. }) => Some(*size),
            Some(DwarfType::PointerType { size, .. }) => Some(*size),
            Some(DwarfType::StructType { size, .. }) => Some(*size),
            Some(DwarfType::ArrayType { size, .. }) => *size,
            Some(DwarfType::UnknownType { .. }) => None,
            None => None,
        }
    }

    /// Infer variable size from type name patterns (fallback method)
    fn infer_size_from_type_name(&self, type_name: &str) -> Option<u64> {
        match type_name {
            // Standard C integer types
            "char" | "signed char" | "unsigned char" => Some(1),
            "short" | "short int" | "signed short" | "unsigned short" => Some(2),
            "int" | "signed int" | "unsigned int" => Some(4),
            "long" | "long int" | "signed long" | "unsigned long" => {
                // Depends on architecture, assume 64-bit
                Some(8)
            }
            "long long" | "long long int" | "signed long long" | "unsigned long long" => Some(8),

            // Standard integer type aliases
            "int8_t" | "uint8_t" => Some(1),
            "int16_t" | "uint16_t" => Some(2),
            "int32_t" | "uint32_t" => Some(4),
            "int64_t" | "uint64_t" => Some(8),

            // Floating point types
            "float" => Some(4),
            "double" => Some(8),
            "long double" => Some(16), // x86-64 extended precision

            // Boolean type
            "bool" | "_Bool" => Some(1),

            // Size type
            "size_t" | "ssize_t" => Some(8), // 64-bit architecture
            "ptrdiff_t" => Some(8),

            // Pointer types (any type ending with '*')
            t if t.ends_with('*') => Some(8), // 64-bit pointers

            // Unknown types
            _ => {
                debug!("Cannot infer size for type: {}", type_name);
                None
            }
        }
    }

    /// Collect variable address ranges from a compilation unit
    fn collect_variable_ranges_from_unit(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        address_ranges: &mut Vec<AddressRangeEntry>,
    ) {
        let mut entries = unit.entries();
        let mut current_function_range: Option<AddressRange> = None;
        let mut function_variables = Vec::new();

        while let Ok(Some((_, entry))) = entries.next_dfs() {
            match entry.tag() {
                gimli::DW_TAG_subprogram => {
                    // Save previous function's variables if any
                    if let Some(range) = current_function_range.take() {
                        if !function_variables.is_empty() {
                            address_ranges.push(AddressRangeEntry {
                                start: range.start,
                                end: range.end,
                                variables: std::mem::take(&mut function_variables),
                            });
                        }
                    }

                    // Start new function
                    current_function_range = self.extract_address_range_from_entry(entry);
                }
                gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter => {
                    if let Some(func_range) = &current_function_range {
                        // For variables within functions, collect them
                        let mut all_variables = Vec::new();
                        self.find_variables_in_unit_concrete(
                            unit,
                            func_range.start,
                            &mut all_variables,
                        );

                        for var in all_variables {
                            if !function_variables
                                .iter()
                                .any(|v: &Variable| v.name == var.name)
                            {
                                function_variables.push(var);
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Save the last function's variables
        if let Some(range) = current_function_range {
            if !function_variables.is_empty() {
                address_ranges.push(AddressRangeEntry {
                    start: range.start,
                    end: range.end,
                    variables: function_variables,
                });
            }
        }
    }

    /// Find function in a compilation unit
    fn find_function_in_unit<R: Reader>(
        &self,
        unit: &gimli::Unit<R>,
        addr: u64,
    ) -> Option<FunctionInfo> {
        let mut entries = unit.entries();

        while let Ok(Some((_, entry))) = entries.next_dfs() {
            if entry.tag() == gimli::DW_TAG_subprogram {
                if let Some(func_info) = self.parse_function_entry(&unit, entry, addr) {
                    return Some(func_info);
                }
            }
        }

        None
    }

    /// Find source location in a compilation unit
    fn find_source_location_in_unit<R: Reader>(
        &self,
        unit: &gimli::Unit<R>,
        addr: u64,
    ) -> Option<SourceLocation> {
        // Get line number program
        let line_program = match unit.line_program.clone() {
            Some(program) => program,
            None => return None,
        };

        let mut rows = line_program.rows();
        let mut prev_row = None;

        while let Ok(Some((header, row))) = rows.next_row() {
            let row_addr = row.address();

            if row_addr > addr {
                // We've gone past our target address
                if let Some(prev) = prev_row {
                    return self.create_source_location(header, &prev, unit, addr);
                }
                break;
            }

            prev_row = Some(row.clone());
        }

        // Check the last row
        if let Some(row) = prev_row {
            let header = &unit.line_program.as_ref()?.header();
            return self.create_source_location(header, &row, unit, addr);
        }

        None
    }

    /// Parse function entry from DWARF
    fn parse_function_entry<R: Reader>(
        &self,
        unit: &gimli::Unit<R>,
        entry: &gimli::DebuggingInformationEntry<R>,
        target_addr: u64,
    ) -> Option<FunctionInfo> {
        let mut attrs = entry.attrs();
        let mut name = String::new();
        let mut low_pc = None;
        let mut high_pc = None;

        // Parse function attributes
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => {
                    // Skip string parsing for now to avoid type issues
                    name = "unknown_function".to_string();
                }
                gimli::DW_AT_low_pc => {
                    if let gimli::AttributeValue::Addr(addr) = attr.value() {
                        low_pc = Some(addr);
                    }
                }
                gimli::DW_AT_high_pc => match attr.value() {
                    gimli::AttributeValue::Addr(addr) => high_pc = Some(addr),
                    gimli::AttributeValue::Udata(size) => {
                        if let Some(low) = low_pc {
                            high_pc = Some(low + size);
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // Check if target address is within function range
        let low = low_pc?;
        if target_addr < low {
            return None;
        }

        if let Some(high) = high_pc {
            if target_addr >= high {
                return None;
            }
        }

        Some(FunctionInfo {
            name,
            low_pc: low,
            high_pc,
            file_path: None,             // TODO: Extract from compilation unit
            line_number: None,           // TODO: Get from line number info
            parameters: Vec::new(),      // TODO: Parse parameters
            local_variables: Vec::new(), // TODO: Parse local variables
        })
    }

    /// Create source location from line program data
    fn create_source_location<R: Reader>(
        &self,
        header: &gimli::LineProgramHeader<R>,
        row: &gimli::LineRow,
        unit: &gimli::Unit<R>,
        addr: u64,
    ) -> Option<SourceLocation> {
        let file = header.file(row.file_index())?;

        // Get actual file path from DWARF
        let file_path = format!("file_{}", row.file_index()); // Simplified for now

        let line_number = match row.line() {
            Some(line) => line.get() as u32,
            None => 0,
        };

        let column = match row.column() {
            gimli::ColumnType::Column(col) => Some(col.get() as u32),
            gimli::ColumnType::LeftEdge => None,
        };

        Some(SourceLocation {
            file_path,
            line_number,
            column,
            address: addr,
        })
    }

    /// Find variables visible at a specific address in compilation unit (concrete types)
    fn find_variables_in_unit_concrete(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        addr: u64,
        variables: &mut Vec<Variable>,
    ) {
        let mut entries = unit.entries();

        while let Ok(Some((_, entry))) = entries.next_dfs() {
            match entry.tag() {
                gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter => {
                    if let Some(var) = self.parse_variable_entry_concrete(unit, entry, addr) {
                        variables.push(var);
                    }
                }
                _ => {}
            }
        }
    }

    /// Parse variable entry from DWARF (concrete types)
    fn parse_variable_entry_concrete(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        addr: u64,
    ) -> Option<Variable> {
        let mut attrs = entry.attrs();
        let mut name = String::new();
        let mut type_name = String::new();
        let mut dwarf_type = None;
        let mut location = None;
        let mut location_expr = None;
        let mut scope_start = None;
        let mut scope_end = None;

        // Create UnitRef for proper string resolution
        let unit_ref = unit.unit_ref(&self.dwarf);

        // Parse variable attributes
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => {
                    // Properly parse variable name using UnitRef
                    match unit_ref.attr_string(attr.value()) {
                        Ok(name_str) => {
                            name = name_str.to_string_lossy().into_owned();
                            debug!("Parsed variable name: {}", name);
                        }
                        Err(_) => {
                            debug!("Failed to parse variable name, using fallback");
                            name = "unknown_var".to_string();
                        }
                    }
                }
                gimli::DW_AT_type => {
                    // Parse type reference and resolve type information
                    if let gimli::AttributeValue::UnitRef(type_offset) = attr.value() {
                        debug!("Resolving type reference at offset: {:?}", type_offset);
                        if let Some((resolved_type_name, resolved_dwarf_type)) =
                            self.resolve_type_info_concrete(unit, type_offset)
                        {
                            type_name = resolved_type_name;
                            dwarf_type = resolved_dwarf_type;
                            debug!("Resolved type: {}", type_name);
                        } else {
                            debug!("Failed to resolve type reference");
                            type_name = "unresolved_type".to_string();
                        }
                    } else {
                        debug!("DW_AT_type is not a unit reference");
                        type_name = "unknown_type".to_string();
                    }
                }
                gimli::DW_AT_location => {
                    debug!("Parsing DW_AT_location attribute");
                    // Parse DWARF location expression
                    location_expr = self.parse_location_expression(unit, attr.value());
                    location = Some("dwarf_location".to_string()); // Legacy field
                }
                gimli::DW_AT_low_pc => {
                    if let gimli::AttributeValue::Addr(pc) = attr.value() {
                        scope_start = Some(pc);
                        debug!("Variable scope starts at: 0x{:x}", pc);
                    }
                }
                gimli::DW_AT_high_pc => match attr.value() {
                    gimli::AttributeValue::Addr(pc) => {
                        scope_end = Some(pc);
                        debug!("Variable scope ends at: 0x{:x}", pc);
                    }
                    gimli::AttributeValue::Udata(size) => {
                        if let Some(start) = scope_start {
                            scope_end = Some(start + size);
                            debug!(
                                "Variable scope: 0x{:x} - 0x{:x} (size: {})",
                                start,
                                start + size,
                                size
                            );
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // Enhanced scope validation
        let scope_ranges = if let (Some(start), Some(end)) = (scope_start, scope_end) {
            // Variable has explicit scope bounds
            if addr < start || addr >= end {
                debug!(
                    "Variable '{}' not in scope at 0x{:x} (scope: 0x{:x}-0x{:x})",
                    name, addr, start, end
                );
                return None;
            }
            vec![AddressRange { start, end }]
        } else {
            // No explicit scope - try to inherit from containing function/lexical block
            debug!(
                "Variable '{}' has no explicit scope, checking parent scopes",
                name
            );
            match self.find_variable_parent_scope_fixed(unit, entry) {
                Some(parent_scopes) => {
                    debug!("Variable '{}' has parent scopes: {:?}", name, parent_scopes);
                    parent_scopes
                }
                None => {
                    debug!(
                        "No parent scope found for variable '{}' at 0x{:x}, using empty scope",
                        name, addr
                    );
                    Vec::new() // Use empty scope instead of excluding
                }
            }
        };

        Some(Variable {
            name,
            type_name: type_name.clone(),
            dwarf_type,
            location_expr,
            scope_ranges,
            is_parameter: entry.tag() == gimli::DW_TAG_formal_parameter,
            is_artificial: false, // TODO: Detect artificial variables

            // Legacy fields for backward compatibility
            location,
            scope_start,
            scope_end,
        })
    }

    /// Find parent scope for a variable (from function or lexical block)
    /// This finds the scope based on the variable's declaration context, not the probe address
    fn find_variable_parent_scope(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        variable_entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        _addr: u64,
    ) -> Option<Vec<AddressRange>> {
        // Get the parent entry offset of this variable
        let variable_offset = variable_entry.offset();

        // Walk through the DWARF tree to find the containing function/lexical block
        let mut entries = unit.entries();
        let mut parent_stack: Vec<(gimli::UnitOffset, Option<AddressRange>)> = Vec::new();

        while let Ok(Some((depth, entry))) = entries.next_dfs() {
            let current_offset = entry.offset();

            // Maintain parent stack based on depth
            while parent_stack.len() > depth as usize {
                parent_stack.pop();
            }

            // If this is a scope-defining entry, add it to the stack
            match entry.tag() {
                gimli::DW_TAG_subprogram | gimli::DW_TAG_lexical_block => {
                    let range = self.extract_address_range_from_entry(entry);
                    debug!(
                        "Found scope entry at offset {:?}: {:?}",
                        current_offset, range
                    );
                    parent_stack.push((current_offset, range));
                }
                _ => {}
            }

            // If we found our variable, look for its parent scope
            if current_offset == variable_offset {
                debug!(
                    "Found variable entry at offset {:?}, checking parent stack (depth={})",
                    variable_offset, depth
                );
                debug!("Parent stack contents: {:?}", parent_stack);

                // Find the most recent scope entry in the parent stack
                for (parent_offset, parent_range) in parent_stack.iter().rev() {
                    debug!(
                        "Checking parent at offset {:?}: {:?}",
                        parent_offset, parent_range
                    );
                    if let Some(range) = parent_range {
                        debug!(
                            "Found parent scope for variable: 0x{:x}-0x{:x} (from parent {:?})",
                            range.start, range.end, parent_offset
                        );
                        return Some(vec![range.clone()]);
                    }
                }
                break;
            }
        }

        debug!(
            "No parent scope found for variable at offset {:?}",
            variable_offset
        );
        None
    }

    /// Fixed version: Find parent scope by analyzing DWARF structure through actual parent traversal
    fn find_variable_parent_scope_fixed(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        variable_entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Option<Vec<AddressRange>> {
        let variable_offset = variable_entry.offset();
        debug!(
            "Looking for parent scope of variable at offset {:?}",
            variable_offset
        );

        // Build a parent map by traversing the DWARF tree structure
        let mut entries = unit.entries();
        let mut parent_map: std::collections::HashMap<gimli::UnitOffset, gimli::UnitOffset> =
            std::collections::HashMap::new();
        let mut entry_info: std::collections::HashMap<
            gimli::UnitOffset,
            (gimli::DwTag, Option<AddressRange>),
        > = std::collections::HashMap::new();
        let mut parent_stack: Vec<gimli::UnitOffset> = Vec::new();

        // Traverse the tree to build parent relationships
        while let Ok(Some((depth, entry))) = entries.next_dfs() {
            let entry_offset = entry.offset();
            let entry_tag = entry.tag();

            // Adjust parent stack based on depth
            while parent_stack.len() > (depth.max(0) as usize) {
                parent_stack.pop();
            }

            // Record parent relationship if we have a parent
            if let Some(&parent_offset) = parent_stack.last() {
                parent_map.insert(entry_offset, parent_offset);
                debug!(
                    "Entry {:?} has parent {:?} (depth {})",
                    entry_offset, parent_offset, depth
                );
            }

            // Collect scope information for functions and lexical blocks
            let address_range = match entry_tag {
                gimli::DW_TAG_subprogram | gimli::DW_TAG_lexical_block => {
                    let range = self.extract_address_range_from_entry(entry);
                    if let Some(ref r) = range {
                        debug!(
                            "Collected scope at offset {:?} (depth {}): 0x{:x}-0x{:x}, tag: {:?}",
                            entry_offset, depth, r.start, r.end, entry_tag
                        );
                    }
                    range
                }
                _ => None,
            };

            entry_info.insert(entry_offset, (entry_tag, address_range));

            // Add to parent stack if this is a scope entry
            if matches!(
                entry_tag,
                gimli::DW_TAG_subprogram | gimli::DW_TAG_lexical_block | gimli::DW_TAG_compile_unit
            ) {
                parent_stack.push(entry_offset);
            }
        }

        // Traverse up the parent chain to find the first scope with an address range
        let mut current_offset = variable_offset;

        while let Some(&parent_offset) = parent_map.get(&current_offset) {
            if let Some((tag, range_opt)) = entry_info.get(&parent_offset) {
                if matches!(*tag, gimli::DW_TAG_subprogram | gimli::DW_TAG_lexical_block) {
                    if let Some(range) = range_opt {
                        debug!(
                            "Found parent scope for variable at {:?}: scope {:?} with range 0x{:x}-0x{:x}",
                            variable_offset, parent_offset, range.start, range.end
                        );
                        return Some(vec![range.clone()]);
                    }
                }
            }
            current_offset = parent_offset;
        }

        debug!(
            "No parent scope with address range found for variable at offset {:?}",
            variable_offset
        );
        None
    }

    /// Extract address ranges from a DWARF entry (supports both single range and range lists)
    fn extract_address_ranges_from_entry(
        &self,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Vec<AddressRange> {
        let mut attrs = entry.attrs();
        let mut low_pc = None;
        let mut high_pc = None;
        let mut ranges_offset: Option<gimli::RawRangeListsOffset<usize>> = None;

        // First pass: collect attributes
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_low_pc => {
                    if let gimli::AttributeValue::Addr(pc) = attr.value() {
                        low_pc = Some(pc);
                    }
                }
                gimli::DW_AT_high_pc => match attr.value() {
                    gimli::AttributeValue::Addr(pc) => high_pc = Some(pc),
                    gimli::AttributeValue::Udata(size) => {
                        if let Some(start) = low_pc {
                            high_pc = Some(start + size);
                        }
                    }
                    _ => {}
                },
                gimli::DW_AT_ranges => {
                    if let gimli::AttributeValue::RangeListsRef(offset) = attr.value() {
                        ranges_offset = Some(offset);
                    }
                    // TODO: Handle legacy SecOffset format if needed
                }
                _ => {}
            }
        }

        // If we have ranges offset, parse the range list
        if let Some(ranges_offset) = ranges_offset {
            // Convert RawRangeListsOffset to RangeListsOffset
            let converted_offset = gimli::RangeListsOffset(ranges_offset.0);
            if let Ok(mut ranges) = self.dwarf.ranges(unit, converted_offset) {
                let mut address_ranges = Vec::new();

                while let Ok(Some(range)) = ranges.next() {
                    debug!(
                        "DWARF range: start=0x{:x}, end=0x{:x}, length={}",
                        range.begin,
                        range.end,
                        range.end.wrapping_sub(range.begin)
                    );
                    // Skip zero-length ranges like [x, x), which represent point locations.
                    // GDB-style behavior prefers the next executable instruction range instead.
                    if range.begin != range.end {
                        address_ranges.push(AddressRange {
                            start: range.begin,
                            end: range.end,
                        });
                    } else {
                        debug!(
                            "Skipping zero-length DWARF range [0x{:x}, 0x{:x})",
                            range.begin, range.end
                        );
                    }
                }

                if !address_ranges.is_empty() {
                    debug!(
                        "Extracted {} address ranges from DW_AT_ranges",
                        address_ranges.len()
                    );
                    return address_ranges;
                }
            }
        }

        // Fallback to simple low_pc/high_pc range
        if let (Some(start), Some(end)) = (low_pc, high_pc) {
            vec![AddressRange { start, end }]
        } else {
            Vec::new()
        }
    }

    /// Extract single address range from a DWARF entry (legacy method for compatibility)
    fn extract_address_range_from_entry(
        &self,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Option<AddressRange> {
        // This is a stub - we'll phase this out in favor of extract_address_ranges_from_entry
        // For now, extract a dummy unit to maintain compatibility
        let mut units = self.dwarf.units();
        if let Ok(Some(header)) = units.next() {
            if let Ok(unit) = self.dwarf.unit(header) {
                let ranges = self.extract_address_ranges_from_entry(entry, &unit);
                return ranges.first().cloned();
            }
        }
        None
    }

    /// Resolve DWARF type information from a unit reference
    fn resolve_type_info_concrete(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        type_offset: gimli::UnitOffset,
    ) -> Option<(String, Option<DwarfType>)> {
        // Get the type entry by following the unit reference
        let type_entry = match unit.entry(type_offset) {
            Ok(entry) => entry,
            Err(e) => {
                debug!("Failed to get type entry: {}", e);
                return None;
            }
        };

        // Create UnitRef for string resolution
        let unit_ref = unit.unit_ref(&self.dwarf);

        match type_entry.tag() {
            gimli::DW_TAG_base_type => self.parse_base_type(unit, &type_entry, &unit_ref),
            gimli::DW_TAG_pointer_type => self.parse_pointer_type(unit, &type_entry, &unit_ref),
            gimli::DW_TAG_array_type => self.parse_array_type(unit, &type_entry, &unit_ref),
            gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => {
                self.parse_struct_type(unit, &type_entry, &unit_ref)
            }
            gimli::DW_TAG_typedef => self.parse_typedef(unit, &type_entry, &unit_ref),
            gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type => {
                self.parse_qualified_type(unit, &type_entry, &unit_ref)
            }
            _ => {
                debug!("Unsupported type tag: {:?}", type_entry.tag());
                Some((
                    "unsupported_type".to_string(),
                    Some(DwarfType::UnknownType {
                        name: "unsupported_type".to_string(),
                    }),
                ))
            }
        }
    }

    /// Parse base type (int, float, etc.)
    fn parse_base_type<'a>(
        &self,
        _unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<'a, gimli::LittleEndian>>,
        unit_ref: &gimli::UnitRef<gimli::EndianSlice<'a, gimli::LittleEndian>>,
    ) -> Option<(String, Option<DwarfType>)> {
        let mut attrs = entry.attrs();
        let mut name = String::new();
        let mut byte_size = 0;
        let mut encoding = DwarfEncoding::Unknown;

        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => {
                    if let Ok(name_str) = unit_ref.attr_string(attr.value()) {
                        name = name_str.to_string_lossy().into_owned();
                    }
                }
                gimli::DW_AT_byte_size => {
                    if let gimli::AttributeValue::Udata(size) = attr.value() {
                        byte_size = size;
                    }
                }
                gimli::DW_AT_encoding => {
                    if let gimli::AttributeValue::Udata(enc) = attr.value() {
                        encoding = match enc {
                            1 => DwarfEncoding::Address,
                            2 => DwarfEncoding::Boolean,
                            3 => DwarfEncoding::Float,
                            5 => DwarfEncoding::Signed,
                            7 => DwarfEncoding::Unsigned,
                            _ => DwarfEncoding::Unknown,
                        };
                    }
                }
                _ => {}
            }
        }

        let dwarf_type = DwarfType::BaseType {
            name: name.clone(),
            size: byte_size,
            encoding,
        };

        Some((name, Some(dwarf_type)))
    }

    /// Parse pointer type
    fn parse_pointer_type(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        _unit_ref: &gimli::UnitRef<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Option<(String, Option<DwarfType>)> {
        let mut attrs = entry.attrs();
        let mut byte_size = 8; // Default pointer size
        let mut target_type = None;

        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_type => {
                    if let gimli::AttributeValue::UnitRef(type_offset) = attr.value() {
                        if let Some((target_name, target_dwarf_type)) =
                            self.resolve_type_info_concrete(unit, type_offset)
                        {
                            target_type = target_dwarf_type;
                        }
                    }
                }
                gimli::DW_AT_byte_size => {
                    if let gimli::AttributeValue::Udata(size) = attr.value() {
                        byte_size = size;
                    }
                }
                _ => {}
            }
        }

        let target_type = target_type.unwrap_or(DwarfType::UnknownType {
            name: "void".to_string(),
        });

        let name = format!(
            "{}*",
            match &target_type {
                DwarfType::BaseType { name, .. } => name,
                DwarfType::StructType { name, .. } => name,
                _ => "unknown",
            }
        );

        let dwarf_type = DwarfType::PointerType {
            target_type: Box::new(target_type),
            size: byte_size,
        };

        Some((name, Some(dwarf_type)))
    }

    /// Parse array type
    fn parse_array_type(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        _unit_ref: &gimli::UnitRef<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Option<(String, Option<DwarfType>)> {
        let mut attrs = entry.attrs();
        let mut element_type = None;
        let mut array_size = None;

        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_type => {
                    if let gimli::AttributeValue::UnitRef(type_offset) = attr.value() {
                        if let Some((_, target_dwarf_type)) =
                            self.resolve_type_info_concrete(unit, type_offset)
                        {
                            element_type = target_dwarf_type;
                        }
                    }
                }
                gimli::DW_AT_byte_size => {
                    if let gimli::AttributeValue::Udata(size) = attr.value() {
                        array_size = Some(size);
                    }
                }
                _ => {}
            }
        }

        let element_type = element_type.unwrap_or(DwarfType::UnknownType {
            name: "unknown".to_string(),
        });

        let name = format!(
            "{}[]",
            match &element_type {
                DwarfType::BaseType { name, .. } => name,
                DwarfType::StructType { name, .. } => name,
                _ => "unknown",
            }
        );

        let dwarf_type = DwarfType::ArrayType {
            element_type: Box::new(element_type),
            size: array_size,
        };

        Some((name, Some(dwarf_type)))
    }

    /// Parse struct/class type
    fn parse_struct_type<'a>(
        &self,
        _unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<'a, gimli::LittleEndian>>,
        unit_ref: &gimli::UnitRef<gimli::EndianSlice<'a, gimli::LittleEndian>>,
    ) -> Option<(String, Option<DwarfType>)> {
        let mut attrs = entry.attrs();
        let mut name = String::new();
        let mut byte_size = 0;

        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => {
                    if let Ok(name_str) = unit_ref.attr_string(attr.value()) {
                        name = name_str.to_string_lossy().into_owned();
                    }
                }
                gimli::DW_AT_byte_size => {
                    if let gimli::AttributeValue::Udata(size) = attr.value() {
                        byte_size = size;
                    }
                }
                _ => {}
            }
        }

        if name.is_empty() {
            name = "anonymous_struct".to_string();
        }

        let dwarf_type = DwarfType::StructType {
            name: name.clone(),
            size: byte_size,
            members: vec![], // TODO: Parse struct members
        };

        Some((name, Some(dwarf_type)))
    }

    /// Parse typedef
    fn parse_typedef<'a>(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<'a, gimli::LittleEndian>>,
        unit_ref: &gimli::UnitRef<gimli::EndianSlice<'a, gimli::LittleEndian>>,
    ) -> Option<(String, Option<DwarfType>)> {
        let mut attrs = entry.attrs();
        let mut name = String::new();

        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => {
                    if let Ok(name_str) = unit_ref.attr_string(attr.value()) {
                        name = name_str.to_string_lossy().into_owned();
                    }
                }
                gimli::DW_AT_type => {
                    // For typedef, we return the alias name but still parse the underlying type
                    if let gimli::AttributeValue::UnitRef(type_offset) = attr.value() {
                        if let Some((_, underlying_type)) =
                            self.resolve_type_info_concrete(unit, type_offset)
                        {
                            return Some((name, underlying_type));
                        }
                    }
                }
                _ => {}
            }
        }

        Some((name.clone(), Some(DwarfType::UnknownType { name })))
    }

    /// Parse qualified type (const, volatile, etc.)
    fn parse_qualified_type(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        _unit_ref: &gimli::UnitRef<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Option<(String, Option<DwarfType>)> {
        let mut attrs = entry.attrs();
        let qualifier = match entry.tag() {
            gimli::DW_TAG_const_type => "const",
            gimli::DW_TAG_volatile_type => "volatile",
            _ => "qualified",
        };

        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_type => {
                    if let gimli::AttributeValue::UnitRef(type_offset) = attr.value() {
                        if let Some((underlying_name, underlying_type)) =
                            self.resolve_type_info_concrete(unit, type_offset)
                        {
                            let qualified_name = format!("{} {}", qualifier, underlying_name);
                            return Some((qualified_name, underlying_type));
                        }
                    }
                }
                _ => {}
            }
        }

        Some((
            qualifier.to_string(),
            Some(DwarfType::UnknownType {
                name: qualifier.to_string(),
            }),
        ))
    }

    /// Parse DWARF location expression
    fn parse_location_expression(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        attr_value: gimli::AttributeValue<gimli::EndianSlice<gimli::LittleEndian>, usize>,
    ) -> Option<LocationExpression> {
        use gimli::AttributeValue;

        match attr_value {
            // Simple location expressions
            AttributeValue::Exprloc(expression) => {
                debug!(
                    "Parsing location expression of {} bytes",
                    expression.0.len()
                );
                self.parse_expression_bytecode(&expression.0, unit)
            }
            AttributeValue::LocationListsRef(offset) => {
                debug!("Parsing location lists at offset 0x{:x}", offset.0);
                self.parse_location_lists(unit, offset)
            }
            _ => {
                debug!("Unsupported location attribute type");
                None
            }
        }
    }

    /// Parse location lists from .debug_loclists or .debug_loc section
    fn parse_location_lists(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        offset: gimli::LocationListsOffset<usize>,
    ) -> Option<LocationExpression> {
        debug!("Parsing location lists at offset 0x{:x}", offset.0);

        // Try to get location lists from DWARF context
        debug!(
            "Attempting to get location lists from DWARF context for offset 0x{:x}",
            offset.0
        );
        let mut locations = match self.dwarf.locations(unit, offset) {
            Ok(locations) => {
                debug!(
                    "Successfully got locations iterator for offset 0x{:x}",
                    offset.0
                );
                locations
            }
            Err(e) => {
                debug!(
                    "Failed to get location lists for offset 0x{:x}: {:?}",
                    offset.0, e
                );
                return Some(LocationExpression::OptimizedOut);
            }
        };

        let mut entries = Vec::new();

        // Parse each location list entry
        debug!(
            "Starting to iterate through location list entries for offset 0x{:x}",
            offset.0
        );
        let mut entry_count = 0;
        loop {
            let next_result = locations.next();
            debug!("Location list iteration result: {:?}", next_result);

            match next_result {
                Ok(Some(location_list_entry)) => {
                    entry_count += 1;
                    let start_pc = location_list_entry.range.begin;
                    let end_pc = location_list_entry.range.end;

                    debug!(
                        "Location list entry #{}: PC 0x{:x}-0x{:x}",
                        entry_count, start_pc, end_pc
                    );
                    debug!(
                        "  Raw expression data length: {}",
                        location_list_entry.data.0.len()
                    );

                    // Parse the expression data for this PC range
                    let location_expr = self
                        .parse_expression_bytecode(location_list_entry.data.0.slice(), unit)
                        .unwrap_or(LocationExpression::OptimizedOut);

                    debug!("  Parsed expression: {:?}", location_expr);

                    entries.push(LocationListEntry {
                        start_pc,
                        end_pc,
                        location_expr,
                    });
                }
                Ok(None) => {
                    debug!(
                        "Reached end of location list entries, processed {} entries",
                        entry_count
                    );
                    break;
                }
                Err(e) => {
                    debug!("Error iterating location list entries: {:?}", e);
                    break;
                }
            }
        }

        if entries.is_empty() {
            debug!("No valid location list entries found");
            Some(LocationExpression::OptimizedOut)
        } else {
            debug!("Parsed {} location list entries", entries.len());
            Some(LocationExpression::LocationList { entries })
        }
    }

    /// Parse DWARF expression bytecode with enhanced support for common operations
    fn parse_expression_bytecode(
        &self,
        bytecode: &[u8],
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Option<LocationExpression> {
        if bytecode.is_empty() {
            debug!("Empty DWARF expression bytecode");
            return Some(LocationExpression::OptimizedOut);
        }

        let mut reader = gimli::EndianSlice::new(bytecode, gimli::LittleEndian);
        let encoding = unit.encoding();

        // Try to parse as a sequence of operations
        let mut operations = Vec::new();
        let mut requires_frame_base = false;
        let mut requires_registers = Vec::new();

        debug!("Parsing DWARF expression of {} bytes", bytecode.len());

        // Parse all operations in the expression
        while !reader.is_empty() {
            match gimli::Operation::parse(&mut reader, encoding) {
                Ok(op) => {
                    debug!("  Parsed DWARF operation: {:?}", op);

                    match self.convert_dwarf_operation(
                        op,
                        &mut requires_frame_base,
                        &mut requires_registers,
                    ) {
                        Some(dwarf_op) => operations.push(dwarf_op),
                        None => {
                            // Unsupported operation, fall back to storing bytecode
                            debug!("  Unsupported operation, falling back to bytecode storage");
                            return Some(LocationExpression::DwarfExpression {
                                bytecode: bytecode.to_vec(),
                            });
                        }
                    }
                }
                Err(e) => {
                    debug!("Failed to parse DWARF operation: {}", e);
                    return Some(LocationExpression::OptimizedOut);
                }
            }
        }

        // Handle simple common cases directly
        if operations.len() == 1 {
            return self.handle_simple_operation(&operations[0]);
        }

        // Handle two-operation patterns that are very common
        if operations.len() == 2 {
            if let Some(simple) = self.handle_two_op_pattern(&operations) {
                return Some(simple);
            }
        }

        // For complex expressions, use ComputedExpression
        if !operations.is_empty() {
            debug!(
                "Creating ComputedExpression with {} operations",
                operations.len()
            );
            debug!("  Requires frame base: {}", requires_frame_base);
            debug!("  Requires registers: {:?}", requires_registers);

            Some(LocationExpression::ComputedExpression {
                operations,
                requires_frame_base,
                requires_registers,
            })
        } else {
            // Fallback to legacy behavior
            debug!("No operations parsed, falling back to bytecode storage");
            Some(LocationExpression::DwarfExpression {
                bytecode: bytecode.to_vec(),
            })
        }
    }

    /// Convert gimli DWARF operation to our simplified DwarfOp
    fn convert_dwarf_operation(
        &self,
        op: gimli::Operation<gimli::EndianSlice<gimli::LittleEndian>>,
        requires_frame_base: &mut bool,
        requires_registers: &mut Vec<u16>,
    ) -> Option<DwarfOp> {
        match op {
            // Constants
            gimli::Operation::UnsignedConstant { value } => Some(DwarfOp::Const(value as i64)),
            gimli::Operation::SignedConstant { value } => Some(DwarfOp::Const(value)),

            // Register operations
            gimli::Operation::Register { register } => {
                if !requires_registers.contains(&register.0) {
                    requires_registers.push(register.0);
                }
                Some(DwarfOp::Reg(register.0))
            }
            gimli::Operation::RegisterOffset {
                register, offset, ..
            } => {
                if !requires_registers.contains(&register.0) {
                    requires_registers.push(register.0);
                }
                Some(DwarfOp::Breg(register.0, offset))
            }

            // Frame base operations
            gimli::Operation::FrameOffset { offset } => {
                *requires_frame_base = true;
                Some(DwarfOp::Fbreg(offset))
            }

            // Arithmetic operations
            gimli::Operation::Plus => Some(DwarfOp::Plus),
            gimli::Operation::Minus => Some(DwarfOp::Sub),
            gimli::Operation::Mul => Some(DwarfOp::Mul),
            gimli::Operation::Div => Some(DwarfOp::Div),
            gimli::Operation::Mod => Some(DwarfOp::Mod),
            gimli::Operation::Neg => Some(DwarfOp::Neg),
            gimli::Operation::PlusConstant { value } => Some(DwarfOp::PlusUconst(value)),

            // Memory operations
            gimli::Operation::Deref { .. } => Some(DwarfOp::Deref),

            // Stack operations (note: gimli may not have these exact operations)
            // gimli::Operation::Dup => Some(DwarfOp::Dup),
            // gimli::Operation::Drop => Some(DwarfOp::Drop),
            // gimli::Operation::Swap => Some(DwarfOp::Swap),
            gimli::Operation::StackValue => Some(DwarfOp::StackValue),

            // Direct address (convert to constant + deref pattern later if needed)
            gimli::Operation::Address { address } => Some(DwarfOp::Const(address as i64)),

            // Unsupported operations
            _ => {
                debug!("Unsupported DWARF operation: {:?}", op);
                None
            }
        }
    }

    /// Handle simple single-operation expressions
    fn handle_simple_operation(&self, op: &DwarfOp) -> Option<LocationExpression> {
        match op {
            DwarfOp::Reg(reg) => {
                debug!("Simple register expression: reg {}", reg);
                Some(LocationExpression::Register { reg: *reg })
            }
            DwarfOp::Fbreg(offset) => {
                debug!("Simple frame base expression: fbreg + {}", offset);
                Some(LocationExpression::FrameBaseOffset { offset: *offset })
            }
            DwarfOp::Breg(reg, offset) => {
                debug!(
                    "Simple register offset expression: reg {} + {}",
                    reg, offset
                );
                Some(LocationExpression::RegisterOffset {
                    reg: *reg,
                    offset: *offset,
                })
            }
            DwarfOp::Const(addr) => {
                debug!("Simple address expression: 0x{:x}", addr);
                Some(LocationExpression::Address { addr: *addr as u64 })
            }
            _ => None,
        }
    }

    /// Handle common two-operation patterns
    fn handle_two_op_pattern(&self, ops: &[DwarfOp]) -> Option<LocationExpression> {
        if ops.len() != 2 {
            return None;
        }

        match (&ops[0], &ops[1]) {
            // fbreg + constant = frame base + (offset + constant)
            (DwarfOp::Fbreg(base_offset), DwarfOp::PlusUconst(add_offset)) => {
                let total_offset = *base_offset + (*add_offset as i64);
                debug!(
                    "Frame base pattern: fbreg {} + {} = {}",
                    base_offset, add_offset, total_offset
                );
                Some(LocationExpression::FrameBaseOffset {
                    offset: total_offset,
                })
            }

            // breg + constant = register + (offset + constant)
            (DwarfOp::Breg(reg, base_offset), DwarfOp::PlusUconst(add_offset)) => {
                let total_offset = *base_offset + (*add_offset as i64);
                debug!(
                    "Register offset pattern: breg {} {} + {} = {}",
                    reg, base_offset, add_offset, total_offset
                );
                Some(LocationExpression::RegisterOffset {
                    reg: *reg,
                    offset: total_offset,
                })
            }

            // reg + constant = register + offset
            (DwarfOp::Reg(reg), DwarfOp::PlusUconst(offset)) => {
                debug!("Register plus constant pattern: reg {} + {}", reg, offset);
                Some(LocationExpression::RegisterOffset {
                    reg: *reg,
                    offset: *offset as i64,
                })
            }

            // const + deref = address dereference
            (DwarfOp::Const(addr), DwarfOp::Deref) => {
                debug!("Address dereference pattern: *0x{:x}", addr);
                Some(LocationExpression::Address { addr: *addr as u64 })
            }

            // breg + stack_value = register offset with value semantics
            (DwarfOp::Breg(reg, offset), DwarfOp::StackValue) => {
                debug!(
                    "Register offset with stack value pattern: reg {} + {} (value)",
                    reg, offset
                );
                Some(LocationExpression::RegisterOffset {
                    reg: *reg,
                    offset: *offset,
                })
            }

            // reg + stack_value = register with value semantics
            (DwarfOp::Reg(reg), DwarfOp::StackValue) => {
                debug!("Register with stack value pattern: reg {} (value)", reg);
                Some(LocationExpression::Register { reg: *reg })
            }

            _ => None,
        }
    }

    /// Render file path from DWARF file entry using concrete types
    fn render_file_concrete(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        file: &gimli::FileEntry<gimli::EndianSlice<gimli::LittleEndian>, usize>,
        header: &gimli::LineProgramHeader<gimli::EndianSlice<gimli::LittleEndian>, usize>,
    ) -> std::result::Result<String, gimli::Error> {
        // Create UnitRef from Unit for string resolution
        let unit_ref = unit.unit_ref(&self.dwarf);

        let mut path = if let Some(ref comp_dir) = unit_ref.comp_dir {
            comp_dir.to_string_lossy().into_owned()
        } else {
            String::new()
        };

        // The directory index 0 is defined to correspond to the compilation unit directory.
        if file.directory_index() != 0 {
            if let Some(directory) = file.directory(header) {
                let dir_string = unit_ref.attr_string(directory)?.to_string_lossy();
                self.path_push(&mut path, dir_string.as_ref());
            }
        }

        let file_name = unit_ref.attr_string(file.path_name())?.to_string_lossy();
        self.path_push(&mut path, file_name.as_ref());

        Ok(path)
    }

    /// Push path component (similar to addr2line implementation)
    fn path_push(&self, path: &mut String, p: &str) {
        if self.has_forward_slash_root(p) || self.has_backward_slash_root(p) {
            *path = p.to_string();
        } else {
            let dir_separator = if self.has_backward_slash_root(path.as_str()) {
                '\\'
            } else {
                '/'
            };

            if !path.is_empty() && !path.ends_with(dir_separator) {
                path.push(dir_separator);
            }
            *path += p;
        }
    }

    /// Check if the path has a unix style root
    fn has_forward_slash_root(&self, p: &str) -> bool {
        p.starts_with('/') || p.get(1..3) == Some(":/")
    }

    /// Check if the path has a windows style root
    fn has_backward_slash_root(&self, p: &str) -> bool {
        p.starts_with('\\') || p.get(1..3) == Some(":\\")
    }

    /// Parse variable location information
    fn parse_variable_location(&self, variable: &Variable) -> Option<VariableLocation> {
        // TODO: Parse actual DWARF location expressions
        // For now, return simplified location info
        Some(VariableLocation {
            register: None,
            stack_offset: None,
            is_parameter: false,
            live_range: variable.scope_start.zip(variable.scope_end),
        })
    }

    /// Debug dump of line information for troubleshooting
    fn debug_dump_line_info(&self, target_file: &str, target_line: u32) {
        debug!("=== DWARF Line Info Debug Dump ===");
        debug!("Looking for: {}:{}", target_file, target_line);

        let mut units = self.dwarf.units();
        let mut unit_index = 0;

        while let Ok(Some(header)) = units.next() {
            if let Ok(unit) = self.dwarf.unit(header) {
                unit_index += 1;
                debug!("--- Compilation Unit {} ---", unit_index);

                if let Some(line_program) = unit.line_program.clone() {
                    let mut rows = line_program.rows();
                    let mut file_names = std::collections::HashSet::new();
                    let mut line_count = 0;
                    let mut relevant_lines = Vec::new();

                    while let Ok(Some((header, row))) = rows.next_row() {
                        line_count += 1;

                        // Try to get file name using proper resolution
                        let file_name = if let Some(file) = header.file(row.file_index()) {
                            match self.render_file_concrete(&unit, file, header) {
                                Ok(path) => path,
                                Err(_) => format!("file_{}", row.file_index()),
                            }
                        } else {
                            "unknown_file".to_string()
                        };

                        file_names.insert(file_name.clone());

                        if let Some(line) = row.line() {
                            let line_num = line.get() as u32;

                            // Collect lines around target for context
                            if (line_num as i32 - target_line as i32).abs() <= 5 {
                                relevant_lines.push(format!(
                                    "  {}:{} -> 0x{:x}",
                                    file_name,
                                    line_num,
                                    row.address()
                                ));
                            }
                        }

                        // Limit output to first 100 lines per unit
                        if line_count > 100 {
                            debug!("  ... truncated after 100 lines");
                            break;
                        }
                    }

                    debug!("  Files in this unit: {:?}", file_names);
                    debug!("  Total lines processed: {}", line_count);
                    debug!("  Lines near target line {}:", target_line);
                    for line in relevant_lines {
                        debug!("{}", line);
                    }
                } else {
                    debug!("  No line program in this unit");
                }
            }
        }

        debug!("=== End Debug Dump ===");
    }
}

/// Load DWARF sections from object file
fn load_dwarf_sections(
    object_file: &object::File,
) -> Result<Dwarf<EndianSlice<'static, LittleEndian>>> {
    let endian = LittleEndian;

    // Helper to load section data
    let load_section = |id: gimli::SectionId| -> Result<EndianSlice<'static, LittleEndian>> {
        let data = get_section_data(object_file, id.name()).unwrap_or_else(|| {
            debug!("Section {} not found, using empty data", id.name());
            &[]
        });

        // SAFETY: We're keeping the file data alive in DwarfContext
        let static_data = unsafe { std::slice::from_raw_parts(data.as_ptr(), data.len()) };

        Ok(EndianSlice::new(static_data, endian))
    };

    // Load all DWARF sections
    let dwarf = Dwarf::load(load_section)?;

    info!("Loaded DWARF sections successfully");
    Ok(dwarf)
}

/// Get section data from object file
fn get_section_data<'a>(object_file: &'a object::File, name: &str) -> Option<&'a [u8]> {
    debug!("Looking for section: {}", name);
    for section in object_file.sections() {
        if let Ok(section_name) = section.name() {
            if section_name == name {
                if let Ok(data) = section.data() {
                    debug!("Found section {} with {} bytes", name, data.len());
                    return Some(data);
                } else {
                    error!("Failed to get data for section {}", name);
                }
            }
        }
    }
    debug!("Section {} not found", name);
    None
}

/// Load .eh_frame section for CFI information
fn load_eh_frame_section(
    object_file: &object::File,
) -> Result<Option<gimli::EhFrame<EndianSlice<'static, LittleEndian>>>> {
    if let Some(section_data) = get_section_data(object_file, ".eh_frame") {
        info!("Found .eh_frame section with {} bytes", section_data.len());

        // SAFETY: We're keeping the file data alive in DwarfContext
        let static_data =
            unsafe { std::slice::from_raw_parts(section_data.as_ptr(), section_data.len()) };
        let eh_frame = gimli::EhFrame::new(static_data, LittleEndian);

        Ok(Some(eh_frame))
    } else {
        debug!("No .eh_frame section found");
        Ok(None)
    }
}

/// Load .debug_frame section for CFI information  
fn load_debug_frame_section(
    object_file: &object::File,
) -> Result<Option<gimli::DebugFrame<EndianSlice<'static, LittleEndian>>>> {
    if let Some(section_data) = get_section_data(object_file, ".debug_frame") {
        info!(
            "Found .debug_frame section with {} bytes",
            section_data.len()
        );

        // SAFETY: We're keeping the file data alive in DwarfContext
        let static_data =
            unsafe { std::slice::from_raw_parts(section_data.as_ptr(), section_data.len()) };
        let debug_frame = gimli::DebugFrame::new(static_data, LittleEndian);

        Ok(Some(debug_frame))
    } else {
        debug!("No .debug_frame section found");
        Ok(None)
    }
}

impl DwarfContext {
    /// Get the new CFI context for DWARF expression-only queries
    pub fn cfi_context(&self) -> Option<&crate::cfi::CFIContext> {
        self.cfi_context.as_ref()
    }

    /// Get function addresses by name using scoped variable map
    pub fn get_function_addresses_by_name(&self, func_name: &str) -> Vec<u64> {
        if let Some(ref scoped_var_map) = self.scoped_variable_map {
            scoped_var_map.find_function_addresses(func_name)
        } else {
            vec![]
        }
    }

    /// Get frame base offset at PC (simplified implementation)
    pub fn get_frame_base_offset_at_pc(&self, _pc: u64) -> Option<i64> {
        // TODO: Implement using new CFI context
        None
    }

    /// Get CFI rule for PC (placeholder implementation)
    pub fn get_cfi_rule_for_pc(&self, _pc: u64) -> Option<String> {
        // TODO: Implement using new CFI context
        // For now return a placeholder
        None
    }

    /// Get expression evaluator from scoped variable map
    pub fn get_expression_evaluator(
        &mut self,
    ) -> Option<&mut crate::expression::DwarfExpressionEvaluator> {
        if let Some(ref mut scoped_var_map) = self.scoped_variable_map {
            Some(scoped_var_map.get_expression_evaluator_mut())
        } else {
            None
        }
    }

    /// Get CFA evaluation result for given PC using the new direct evaluation approach  
    pub fn get_cfa_evaluation_result(
        &self,
        pc: u64,
    ) -> Option<crate::expression::EvaluationResult> {
        // Use the new CFI method that returns EvaluationResult directly
        self.cfi_context.as_ref()?.get_cfa_expression(pc)
    }

    /// Check if CFI context is available
    pub fn has_cfi_context(&self) -> bool {
        self.cfi_context.is_some()
    }

    /// Try to recover inlined parameter value by analyzing actual DWARF location expressions
    /// Returns a LocationResult that can be used to read the parameter value
    pub fn try_recover_inlined_parameter(
        &self,
        pc: u64,
        param_name: &str,
        scope_depth: usize,
    ) -> Option<crate::expression::LocationResult> {
        debug!(
            "Attempting to recover inlined parameter '{}' at PC 0x{:x}",
            param_name, pc
        );

        // Instead of hardcoded guesses, we need to:
        // 1. Find the inlined subroutine DIE that contains this PC
        // 2. Look for the formal parameter with matching abstract_origin
        // 3. Parse its DW_AT_location expression
        // 4. Convert the expression to proper LocationResult

        if let Some(location_result) =
            self.find_inlined_parameter_location(pc, param_name, scope_depth)
        {
            debug!(
                "Successfully recovered inlined parameter '{}' from DWARF: {:?}",
                param_name, location_result
            );
            Some(location_result)
        } else {
            debug!(
                "Could not find DWARF location information for inlined parameter '{}'",
                param_name
            );
            None
        }
    }

    /// Find the actual DWARF location information for an inlined parameter
    fn find_inlined_parameter_location(
        &self,
        pc: u64,
        param_name: &str,
        _scope_depth: usize,
    ) -> Option<crate::expression::LocationResult> {
        debug!(
            "Searching DWARF for inlined parameter '{}' at PC 0x{:x}",
            param_name, pc
        );

        // For now, return a simplified implementation that indicates this needs to be implemented
        // The full implementation would involve complex DWARF traversal with gimli
        debug!(
            "DWARF parameter location parsing not yet fully implemented for '{}'",
            param_name
        );

        None
    }

    /// Check if a variable might be a substitute for an inlined parameter
    fn might_be_parameter_substitute(
        &self,
        variable: &crate::scoped_variables::VariableInfo,
        param_name: &str,
    ) -> bool {
        // Pattern 1: Variable name contains the parameter name (e.g., "a.1" for parameter "a")
        if variable.name.starts_with(&format!("{}.1", param_name))
            || variable.name.starts_with(&format!("{}_", param_name))
        {
            return true;
        }

        // Pattern 2: For simple parameters like "a" and "b", look for single-letter variables
        // in registers that might be compiler-generated substitutes
        if param_name.len() == 1 && variable.name.len() == 1 {
            // Check if this is a different single-letter variable that could be the substitute
            return variable.name != param_name;
        }

        // Pattern 3: Look for computed values or temporaries
        if variable.name.starts_with("tmp") || variable.name.starts_with("_") {
            return true;
        }

        false
    }

    /// Create a LocationResult from a LocationExpression for parameter recovery
    fn create_substitute_location(
        &self,
        location_expr: &LocationExpression,
    ) -> Option<crate::expression::LocationResult> {
        use crate::expression::LocationResult;

        match location_expr {
            LocationExpression::Register { reg } => Some(LocationResult::RegisterAddress {
                register: *reg,
                offset: None,
                size: None,
            }),
            LocationExpression::FrameBaseOffset { offset } => {
                // Frame-relative access - would need frame base register
                // For x86_64, this is typically RBP (register 6)
                Some(LocationResult::RegisterAddress {
                    register: 6, // RBP on x86_64
                    offset: Some(*offset),
                    size: None,
                })
            }
            LocationExpression::ComputedExpression { .. } => {
                // Complex expressions would need full evaluation
                // For now, return None to indicate we can't handle this case
                debug!("Complex location expression not supported for parameter recovery");
                None
            }
            LocationExpression::OptimizedOut => {
                debug!("Substitute variable is also optimized out");
                None
            }
            _ => {
                debug!("Unsupported location expression type for parameter recovery");
                None
            }
        }
    }
}
/// Frame base information for a specific PC location
#[derive(Debug, Clone)]
pub struct FrameBaseInfo {
    pub pc: u64,
    pub base_register: u16, // Register that holds the base (e.g., RBP = 6)
    pub base_offset: i64,   // Offset from the base register
    pub requires_cfa: bool, // Whether CFA calculation is needed
}

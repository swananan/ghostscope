use crate::expression::{DwarfExpressionEvaluator, EvaluationContext, EvaluationResult};
use crate::file::{SimpleFileInfo, SourceFileManager};
use crate::line_lookup::LineLookup;
use crate::scoped_variables::{
    AddressRange, ScopeId, ScopeType, ScopedVariableMap, VariableResult,
};
use crate::Result;
use ghostscope_platform::{CallingConvention, CodeReader, X86_64SystemV};
use gimli::{Dwarf, EndianSlice, LittleEndian, Reader};
use object::{Object, ObjectSection};
use std::path::Path;
use tracing::{debug, error, info, warn};

/// Abstract variable information from abstract origin (names and types)
#[derive(Debug, Clone)]
struct AbstractVariableInfo {
    name: String,
    type_name: String,
    dwarf_type: Option<DwarfType>,
    is_parameter: bool,
    abstract_origin_offset: gimli::UnitOffset<usize>,
}

/// Concrete variable information from inlined subroutine children (location expressions)
#[derive(Debug, Clone)]
struct ConcreteVariableInfo {
    abstract_origin_ref: gimli::UnitOffset<usize>,
    location_expr: LocationExpression,
    concrete_offset: gimli::UnitOffset<usize>,
}

/// DWARF debug context
#[derive(Debug)]
pub struct DwarfContext {
    dwarf: Dwarf<EndianSlice<'static, LittleEndian>>,
    // Keep the file data alive
    _file_data: Box<[u8]>,
    // Base addresses for proper DWARF parsing
    base_addresses: gimli::BaseAddresses,

    // CFI context for simplified DWARF expression-only interface
    cfi_context: Option<crate::cfi::CFIContext>,

    // New line lookup system (based on addr2line)
    line_lookup: Option<LineLookup>,

    // Scoped variable system (GDB-inspired)
    scoped_variable_map: Option<ScopedVariableMap>,
    // Source file manager for all files in debug info
    source_file_manager: Option<SourceFileManager>,
    // DWARF expression evaluator for CFI and variable location evaluation
    expression_evaluator: DwarfExpressionEvaluator,

    // Flag to indicate if valid debug information is available
    has_valid_debug_info: bool,
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
pub(crate) struct Parameter {
    pub name: String,
    pub type_name: String,
    pub location: Option<String>, // Register, stack offset, etc.
}

/// Local variable information
#[derive(Debug, Clone)]
pub struct Variable {
    pub name: String,
    pub type_name: String,
    pub dwarf_type: Option<ghostscope_protocol::DwarfType>,
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
pub(crate) struct LocationListEntry {
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
// Re-export DWARF types from protocol crate for compatibility
pub use ghostscope_protocol::DwarfType;

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

        // Check if we have valid debug information by examining DWARF sections
        let has_valid_debug_info = check_debug_sections_exist(&object_file);

        let mut context = Self {
            dwarf,
            _file_data: file_data,
            base_addresses,
            cfi_context,
            line_lookup: None,
            scoped_variable_map: None,
            source_file_manager: None,
            expression_evaluator: DwarfExpressionEvaluator::new(),
            has_valid_debug_info,
        };

        // Parse all DWARF debug information in a single pass
        info!("Parsing DWARF debug information (files and variables)...");
        context.parse_debug_info_unified()?;

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
                    line_number,
                    function_name: None,
                })
                .collect();
        }

        // If no line lookup system available, return empty
        debug!("No line lookup system available");
        Vec::new()
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

                            // Use standard DWARF expression evaluation
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

    /// Get all file information from the DWARF debug data
    pub fn get_all_file_info(&self) -> Result<Vec<SimpleFileInfo>> {
        // Use SourceFileManager as the primary and only source
        if let Some(ref source_file_manager) = self.source_file_manager {
            let file_infos = source_file_manager
                .get_all_files()
                .into_iter()
                .map(|source_file| source_file.into())
                .collect();
            Ok(file_infos)
        } else {
            // No fallback needed - source file manager should always be available
            // after parse_debug_info has been called
            warn!("Source file manager not available - debug info not parsed");
            Ok(Vec::new())
        }
    }

    /// Parse all DWARF debug information in a single pass (unified entry point)
    /// This method extracts both file information and scoped variables in one traversal
    fn parse_debug_info_unified(&mut self) -> Result<()> {
        info!("Starting comprehensive DWARF debug information parsing...");

        let mut source_file_manager = SourceFileManager::new();
        let mut scoped_map = ScopedVariableMap::new();
        let mut units = self.dwarf.units();

        // Parse all compilation units in a single pass
        while let Ok(Some(header)) = units.next() {
            if let Ok(unit) = self.dwarf.unit(header) {
                debug!("Processing compilation unit...");

                // Extract source files from this unit
                match crate::file::SourceFileManager::extract_files_from_unit(&self.dwarf, &unit) {
                    Ok(compilation_unit) => {
                        debug!(
                            "Extracted {} files from compilation unit: {}",
                            compilation_unit.files.len(),
                            compilation_unit.name
                        );
                        source_file_manager.add_compilation_unit(compilation_unit);
                    }
                    Err(e) => {
                        warn!("Failed to extract files from compilation unit: {}", e);
                    }
                }

                // Create compilation unit scope for variables
                let cu_scope_id =
                    scoped_map.add_scope(None, ScopeType::CompilationUnit, Vec::new());

                // Process variable scopes in this compilation unit
                if let Err(e) = self.build_scopes_from_unit(&unit, &mut scoped_map, cu_scope_id) {
                    warn!("Failed to build scopes from compilation unit: {}", e);
                }
            }
        }

        // Build the address lookup table for scoped variables
        scoped_map.build_address_lookup();

        // Store the results
        self.source_file_manager = Some(source_file_manager);
        self.scoped_variable_map = Some(scoped_map);

        // Log statistics
        if let Some(ref file_manager) = self.source_file_manager {
            let (total_files, total_compilation_units, unique_basenames) = file_manager.get_stats();
            info!(
                "Parsed {} files from {} compilation units ({} unique basenames)",
                total_files, total_compilation_units, unique_basenames
            );
        }

        if let Some(ref scoped_map) = self.scoped_variable_map {
            let stats = scoped_map.get_statistics();
            info!(
                "Parsed {} variables in {} scopes with {} address entries",
                stats.total_variables, stats.total_scopes, stats.total_address_entries
            );
        }

        Ok(())
    }

    /// Build scopes from a DWARF compilation unit
    fn build_scopes_from_unit(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        scoped_map: &mut ScopedVariableMap,
        parent_scope_id: ScopeId,
    ) -> Result<()> {
        debug!("Starting DWARF DIE traversal (entries_tree) for scoped variable system");
        let mut scope_stack = vec![parent_scope_id];

        // Build a tree cursor starting from the root of this unit
        let mut tree = unit.entries_tree(None)?;
        let root = tree.root()?;

        // Traverse only the children of the unit root (compilation unit)
        let mut children = root.children();
        while let Some(child) = children.next()? {
            self.traverse_die_tree(unit, child, scoped_map, &mut scope_stack)?;
        }

        Ok(())
    }

    /// Structured DFS over DIE tree with explicit scope push/pop
    fn traverse_die_tree(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        node: gimli::EntriesTreeNode<gimli::EndianSlice<gimli::LittleEndian>>,
        scoped_map: &mut ScopedVariableMap,
        scope_stack: &mut Vec<ScopeId>,
    ) -> Result<()> {
        let entry = node.entry();
        let current_parent = *scope_stack.last().unwrap();

        debug!(
            "[traverse] offset={:?}, tag={} (0x{:x}), stack_depth={}",
            entry.offset(),
            self.format_dwarf_tag(entry.tag()),
            entry.tag().0,
            scope_stack.len() - 1
        );

        match entry.tag() {
            gimli::DW_TAG_subprogram => {
                let die_name = self.extract_die_name(entry, unit);
                let address_ranges = self
                    .extract_function_ranges(entry, unit, &die_name)
                    .unwrap_or_else(|_| Vec::new());
                if !address_ranges.is_empty() {
                    if let Some(function_info) = self.parse_function_scope(entry, unit) {
                        let function_scope_id = scoped_map.add_scope(
                            Some(current_parent),
                            ScopeType::Function {
                                name: function_info.name.clone(),
                                address: function_info.low_pc,
                            },
                            address_ranges,
                        );
                        debug!(
                            "[traverse] PUSH function '{}' -> scope_id={:?}",
                            function_info.name, function_scope_id
                        );
                        scope_stack.push(function_scope_id);

                        let mut children = node.children();
                        while let Some(child) = children.next()? {
                            self.traverse_die_tree(unit, child, scoped_map, scope_stack)?;
                        }

                        let popped = scope_stack.pop();
                        debug!("[traverse] POP function scope_id={:?}", popped);
                        return Ok(());
                    }
                }

                // Even if no scope created, still traverse children
                let mut children = node.children();
                while let Some(child) = children.next()? {
                    self.traverse_die_tree(unit, child, scoped_map, scope_stack)?;
                }
            }
            gimli::DW_TAG_lexical_block => {
                let die_name = self.extract_die_name(entry, unit);
                let address_ranges = self
                    .extract_function_ranges(entry, unit, &die_name)
                    .unwrap_or_else(|_| Vec::new());
                if !address_ranges.is_empty() {
                    let block_scope_id = scoped_map.add_scope(
                        Some(current_parent),
                        ScopeType::LexicalBlock {
                            depth: scope_stack.len(),
                        },
                        address_ranges,
                    );
                    debug!(
                        "[traverse] PUSH lexical_block depth={} -> scope_id={:?}",
                        scope_stack.len(),
                        block_scope_id
                    );
                    scope_stack.push(block_scope_id);

                    let mut children = node.children();
                    while let Some(child) = children.next()? {
                        self.traverse_die_tree(unit, child, scoped_map, scope_stack)?;
                    }

                    let popped = scope_stack.pop();
                    debug!("[traverse] POP lexical_block scope_id={:?}", popped);
                    return Ok(());
                }

                // No range -> still traverse children
                let mut children = node.children();
                while let Some(child) = children.next()? {
                    self.traverse_die_tree(unit, child, scoped_map, scope_stack)?;
                }
            }
            gimli::DW_TAG_inlined_subroutine => {
                let origin_func = self
                    .get_origin_function_name(entry, unit)
                    .unwrap_or_else(|| "unknown".to_string());
                let address_ranges = self
                    .extract_inlined_ranges(entry, unit, &origin_func)
                    .unwrap_or_else(|_| Vec::new());
                if !address_ranges.is_empty() {
                    let inlined_scope_id = scoped_map.add_scope(
                        Some(current_parent),
                        ScopeType::InlinedSubroutine { origin_func },
                        address_ranges,
                    );
                    debug!(
                        "[traverse] PUSH inlined_subroutine -> scope_id={:?}",
                        inlined_scope_id
                    );
                    scope_stack.push(inlined_scope_id);

                    let mut children = node.children();
                    while let Some(child) = children.next()? {
                        self.traverse_die_tree(unit, child, scoped_map, scope_stack)?;
                    }

                    let popped = scope_stack.pop();
                    debug!("[traverse] POP inlined_subroutine scope_id={:?}", popped);
                    return Ok(());
                }

                // No ranges -> still traverse children
                let mut children = node.children();
                while let Some(child) = children.next()? {
                    self.traverse_die_tree(unit, child, scoped_map, scope_stack)?;
                }
            }
            gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter => {
                if let Some(current_scope_id) = scope_stack.last().cloned() {
                    debug!(
                        "[traverse] add {} to scope_id={:?}",
                        self.format_dwarf_tag(entry.tag()),
                        current_scope_id
                    );
                    self.parse_and_add_variable(entry, unit, scoped_map, current_scope_id)?;
                }
            }
            _ => {
                // Default: just walk children
                let mut children = node.children();
                while let Some(child) = children.next()? {
                    self.traverse_die_tree(unit, child, scoped_map, scope_stack)?;
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
        let die_name = self.extract_die_name(entry, unit);
        debug!("Processing function DIE: {}", die_name);

        let mut name = String::new();
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
                // Address ranges are now handled by extract_function_ranges
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

        // Use layered address extraction instead of duplicate parsing
        match self.extract_function_ranges(entry, unit, &die_name) {
            Ok(ranges) if !ranges.is_empty() && !name.is_empty() => {
                let low_pc = ranges.first().unwrap().start;
                let high_pc = ranges.last().unwrap().end;

                debug!(
                    "Successfully parsed function scope: name='{}', ranges count={}, first_range=[0x{:x}, 0x{:x})",
                    name, ranges.len(), low_pc, high_pc
                );

                Some(FunctionInfo {
                    name,
                    low_pc,
                    high_pc: Some(high_pc),
                    file_path: None,
                    line_number: None,
                    parameters: Vec::new(),
                    local_variables: Vec::new(),
                })
            }
            Ok(_) => {
                info!(
                    "Skipping function declaration (no address ranges): '{}'",
                    name
                );
                None
            }
            Err(e) => {
                debug!(
                    "Failed to parse function scope due to address extraction error: name='{}', error={}",
                    name, e
                );
                None
            }
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

        // Inspect concrete DIE for quick telemetry: has DW_AT_location? abstract_origin?
        let mut has_concrete_location = false;
        let mut concrete_location_kind = "none";
        let mut abstract_origin_offset: Option<gimli::UnitOffset> = None;
        {
            let mut attrs = entry.attrs();
            while let Ok(Some(attr)) = attrs.next() {
                match attr.name() {
                    gimli::DW_AT_location => {
                        has_concrete_location = true;
                        concrete_location_kind = match attr.value() {
                            gimli::AttributeValue::Exprloc(_) => "exprloc",
                            gimli::AttributeValue::LocationListsRef(_) => "loclist",
                            _ => "other",
                        };
                    }
                    gimli::DW_AT_abstract_origin => {
                        if let gimli::AttributeValue::UnitRef(off) = attr.value() {
                            abstract_origin_offset = Some(off);
                        }
                    }
                    _ => {}
                }
            }
        }

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
        if let Some(mut variable) = self.parse_variable_for_scope(unit, entry) {
            // If no location_expr but we have an abstract_origin, try resolve via existing origin mapping
            if variable.location_expr.is_none() {
                if let Some(origin_off) = abstract_origin_offset {
                    let off_val = origin_off.0 as u64;
                    let candidates = scoped_map.find_variables_by_abstract_origin(off_val);
                    if !candidates.is_empty() {
                        for cand_id in candidates {
                            if let Some(cand) = scoped_map.get_variable_info(cand_id) {
                                if let Some(expr) = &cand.location_expr {
                                    debug!(
                                        "Resolved missing location via origin mapping 0x{:x} from var_id={:?}",
                                        off_val, cand_id
                                    );
                                    variable.location_expr = Some(expr.clone());
                                    break;
                                }
                            }
                        }
                    } else {
                        debug!(
                            "No existing variables registered for origin 0x{:x} to borrow location from",
                            off_val
                        );
                    }
                }
            }
            debug!(
                "Variable merge result: has_location_expr={}, concrete_has_location={}, concrete_loc_kind={}, origin_offset={:?}",
                variable.location_expr.is_some(),
                has_concrete_location,
                concrete_location_kind,
                abstract_origin_offset
            );
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

            // If this variable originated from an abstract_origin/specification, register mapping
            // Prefer abstract_origin if present on entry; otherwise if parse merged from spec/origin, we cannot know exact offset here
            let mut origin_off: Option<u64> = None;
            let mut spec_off: Option<u64> = None;
            let mut attrs = entry.attrs();
            while let Ok(Some(attr)) = attrs.next() {
                if attr.name() == gimli::DW_AT_abstract_origin {
                    if let gimli::AttributeValue::UnitRef(off) = attr.value() {
                        origin_off = Some(off.0 as u64);
                    }
                } else if attr.name() == gimli::DW_AT_specification {
                    if let gimli::AttributeValue::UnitRef(off) = attr.value() {
                        spec_off = Some(off.0 as u64);
                    }
                }
            }
            if let Some(off) = origin_off {
                scoped_map.register_origin_mapping(off, variable_id);
                debug!(
                    "Registered origin mapping: origin_off=0x{:x} -> var_id={:?}",
                    off, variable_id
                );
            }
            if let Some(off) = spec_off {
                scoped_map.register_origin_mapping(off, variable_id);
                debug!(
                    "Registered specification mapping: spec_off=0x{:x} -> var_id={:?}",
                    off, variable_id
                );
            }

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
        let mut specification = None;
        let mut is_artificial = false;

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
                gimli::DW_AT_specification => {
                    if let gimli::AttributeValue::UnitRef(offset) = attr.value() {
                        specification = Some(offset);
                    }
                }
                gimli::DW_AT_type => {
                    if let gimli::AttributeValue::UnitRef(type_offset) = attr.value() {
                        debug!(
                            "Variable '{}' has type reference at offset {:?}",
                            name, type_offset
                        );
                        if let Some((resolved_type_name, resolved_dwarf_type)) =
                            self.resolve_type_info_concrete(unit, type_offset)
                        {
                            type_name = resolved_type_name;
                            dwarf_type = resolved_dwarf_type;
                            debug!(
                                "Successfully resolved type for '{}': {} {:?}",
                                name, type_name, dwarf_type
                            );
                        } else {
                            type_name = "unresolved_type".to_string();
                            debug!(
                                "Failed to resolve type for variable '{}' at offset {:?}",
                                name, type_offset
                            );
                        }
                    } else {
                        type_name = "unknown_type".to_string();
                        debug!(
                            "Variable '{}' has non-UnitRef type attribute: {:?}",
                            name,
                            attr.value()
                        );
                    }
                }
                gimli::DW_AT_location => {
                    location_expr = self.parse_location_expression(unit, attr.value());
                }
                gimli::DW_AT_artificial => {
                    // Any presence of the flag means true
                    is_artificial = true;
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

        // If fields are missing, try to resolve via specification then abstract_origin
        if name.is_empty() || type_name.is_empty() || location_expr.is_none() {
            let mut to_visit: Vec<gimli::UnitOffset> = Vec::new();
            if let Some(spec) = specification {
                to_visit.push(spec);
            }
            if let Some(origin) = abstract_origin {
                to_visit.push(origin);
            }

            // Limit the chain length defensively
            let mut visited = 0usize;
            while let Some(off) = to_visit.pop() {
                if visited > 8 {
                    break;
                }
                visited += 1;
                if let Ok(origin_entry) = unit.entry(off) {
                    let mut oattrs = origin_entry.attrs();
                    while let Ok(Some(oattr)) = oattrs.next() {
                        match oattr.name() {
                            gimli::DW_AT_name if name.is_empty() => {
                                if let Ok(s) = unit_ref.attr_string(oattr.value()) {
                                    name = s.to_string_lossy().into_owned();
                                }
                            }
                            gimli::DW_AT_type if type_name.is_empty() => {
                                if let gimli::AttributeValue::UnitRef(t_off) = oattr.value() {
                                    if let Some((resolved_type_name, resolved_dwarf_type)) =
                                        self.resolve_type_info_concrete(unit, t_off)
                                    {
                                        type_name = resolved_type_name;
                                        dwarf_type = resolved_dwarf_type;
                                    }
                                }
                            }
                            gimli::DW_AT_location if location_expr.is_none() => {
                                location_expr = self.parse_location_expression(unit, oattr.value());
                            }
                            gimli::DW_AT_artificial => {
                                is_artificial = true;
                            }
                            gimli::DW_AT_specification => {
                                if let gimli::AttributeValue::UnitRef(next) = oattr.value() {
                                    to_visit.push(next);
                                }
                            }
                            gimli::DW_AT_abstract_origin => {
                                if let gimli::AttributeValue::UnitRef(next) = oattr.value() {
                                    to_visit.push(next);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                if !name.is_empty() && !type_name.is_empty() && location_expr.is_some() {
                    break;
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
            dwarf_type: dwarf_type.clone(),
            location_expr,
            scope_ranges,
            is_parameter: entry.tag() == gimli::DW_TAG_formal_parameter,
            is_artificial,

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

                    // Special handling for point ranges (start == end), common in inlined params
                    if list_range.start == list_range.end {
                        let point = list_range.start;
                        for scope_range in scope_ranges {
                            let contains_point = if scope_range.start == scope_range.end {
                                point == scope_range.start
                            } else {
                                point >= scope_range.start && point < scope_range.end
                            };
                            if contains_point {
                                location_at_ranges.push((
                                    AddressRange {
                                        start: point,
                                        end: point,
                                    },
                                    list_entry.location_expr.clone(),
                                ));
                            }
                        }
                    } else {
                        // Regular non-empty range: intersect with scope ranges
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

    /// Parse inlined subroutine scope with complete abstract_origin handling
    fn parse_inlined_subroutine_scope(
        &self,
        inlined_entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        scoped_map: &mut ScopedVariableMap,
        inlined_scope_id: ScopeId,
    ) -> Result<()> {
        debug!(
            "=== PARSING INLINED SUBROUTINE SCOPE at offset {:?} ===",
            inlined_entry.offset()
        );

        // First, get abstract_origin reference if it exists
        let mut abstract_origin_offset = None;
        let mut attrs = inlined_entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            if attr.name() == gimli::DW_AT_abstract_origin {
                if let gimli::AttributeValue::UnitRef(offset) = attr.value() {
                    abstract_origin_offset = Some(offset);
                    debug!("Found abstract_origin reference: {:?}", offset);
                    break;
                }
            }
        }

        // Parse parameters and variables from abstract origin (for names/types)
        let mut abstract_params_vars = Vec::new();
        if let Some(origin_offset) = abstract_origin_offset {
            debug!("Parsing abstract origin at offset {:?}", origin_offset);
            abstract_params_vars =
                self.parse_abstract_origin_parameters_variables(unit, origin_offset)?;
            debug!(
                "Found {} abstract parameters/variables from origin",
                abstract_params_vars.len()
            );
        }

        // Parse direct children of inlined subroutine (for concrete location expressions)
        let mut concrete_params_vars = Vec::new();
        let mut cursor_tree = unit.entries_tree(Some(inlined_entry.offset()))?;
        if let Ok(inlined_node) = cursor_tree.root() {
            let mut children = inlined_node.children();
            while let Some(child) = children.next()? {
                let child_entry = child.entry();
                match child_entry.tag() {
                    gimli::DW_TAG_formal_parameter | gimli::DW_TAG_variable => {
                        debug!(
                            "Found concrete {} at offset {:?}",
                            if child_entry.tag() == gimli::DW_TAG_formal_parameter {
                                "parameter"
                            } else {
                                "variable"
                            },
                            child_entry.offset()
                        );

                        if let Some(concrete_var) =
                            self.parse_concrete_parameter_variable(unit, child_entry)
                        {
                            concrete_params_vars.push(concrete_var);
                        }
                    }
                    _ => {
                        // Skip other types of children for now
                    }
                }
            }
        }

        debug!(
            "Found {} concrete parameters/variables",
            concrete_params_vars.len()
        );

        // Merge abstract and concrete information
        self.merge_and_add_inlined_variables(
            &abstract_params_vars,
            &concrete_params_vars,
            scoped_map,
            inlined_scope_id,
        )?;

        Ok(())
    }

    /// Parse abstract origin to get parameter and variable names/types
    fn parse_abstract_origin_parameters_variables(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        origin_offset: gimli::UnitOffset<usize>,
    ) -> Result<Vec<AbstractVariableInfo>> {
        let mut result = Vec::new();

        // Navigate to the abstract origin entry
        let mut cursor = unit.entries_at_offset(origin_offset)?;
        cursor.next_entry()?;

        if let Some(origin_entry) = cursor.current() {
            debug!(
                "Processing abstract origin entry at offset {:?}, tag: {:?}",
                origin_entry.offset(),
                origin_entry.tag()
            );

            // Parse children of the abstract function
            let mut cursor_tree = unit.entries_tree(Some(origin_offset))?;
            if let Ok(origin_node) = cursor_tree.root() {
                let mut children = origin_node.children();
                while let Some(child) = children.next()? {
                    let child_entry = child.entry();
                    match child_entry.tag() {
                        gimli::DW_TAG_formal_parameter | gimli::DW_TAG_variable => {
                            if let Some(abstract_var) =
                                self.parse_abstract_variable(unit, child_entry)
                            {
                                debug!(
                                    "Parsed abstract {}: name='{}', type='{}'",
                                    if child_entry.tag() == gimli::DW_TAG_formal_parameter {
                                        "parameter"
                                    } else {
                                        "variable"
                                    },
                                    abstract_var.name,
                                    abstract_var.type_name
                                );
                                result.push(abstract_var);
                            }
                        }
                        _ => {
                            // Skip non-variable/parameter children
                        }
                    }
                }
            }
        }

        Ok(result)
    }

    /// Parse abstract variable info (name, type from abstract origin)
    fn parse_abstract_variable(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Option<AbstractVariableInfo> {
        let mut name = String::new();
        let mut type_name = "unknown_type".to_string();
        let mut dwarf_type = None;
        let is_parameter = entry.tag() == gimli::DW_TAG_formal_parameter;

        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => {
                    let unit_ref = unit.unit_ref(&self.dwarf);
                    if let Ok(name_str) = unit_ref.attr_string(attr.value()) {
                        name = name_str.to_string_lossy().into_owned();
                    }
                }
                gimli::DW_AT_type => {
                    if let gimli::AttributeValue::UnitRef(type_offset) = attr.value() {
                        if let Some((resolved_type_name, resolved_dwarf_type)) =
                            self.resolve_type_info_concrete(unit, type_offset)
                        {
                            type_name = resolved_type_name;
                            dwarf_type = resolved_dwarf_type;
                        }
                    }
                }
                _ => {}
            }
        }

        if !name.is_empty() {
            Some(AbstractVariableInfo {
                name,
                type_name,
                dwarf_type,
                is_parameter,
                abstract_origin_offset: entry.offset(),
            })
        } else {
            None
        }
    }

    /// Parse concrete parameter/variable (location expression from concrete instance)
    fn parse_concrete_parameter_variable(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Option<ConcreteVariableInfo> {
        let mut abstract_origin_ref = None;
        let mut location_expr = None;

        debug!(
            "Parsing concrete parameter/variable at offset {:?}",
            entry.offset()
        );

        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_abstract_origin => {
                    if let gimli::AttributeValue::UnitRef(offset) = attr.value() {
                        abstract_origin_ref = Some(offset);
                        debug!("Found abstract_origin reference: {:?}", offset);
                    }
                }
                gimli::DW_AT_location => {
                    debug!("Found DW_AT_location attribute");
                    location_expr = self.parse_location_expression(unit, attr.value());
                    debug!("Parsed location expression: {:?}", location_expr);
                }
                _ => {}
            }
        }

        if let Some(origin_ref) = abstract_origin_ref {
            debug!(
                "Creating ConcreteVariableInfo with origin {:?} and location {:?}",
                origin_ref,
                location_expr
                    .as_ref()
                    .unwrap_or(&LocationExpression::OptimizedOut)
            );
            Some(ConcreteVariableInfo {
                abstract_origin_ref: origin_ref,
                location_expr: location_expr.unwrap_or(LocationExpression::OptimizedOut),
                concrete_offset: entry.offset(),
            })
        } else {
            debug!(
                "No abstract_origin found for concrete parameter at offset {:?}",
                entry.offset()
            );
            None
        }
    }

    /// Merge abstract and concrete information, then add to scoped map
    fn merge_and_add_inlined_variables(
        &self,
        abstract_vars: &[AbstractVariableInfo],
        concrete_vars: &[ConcreteVariableInfo],
        scoped_map: &mut ScopedVariableMap,
        inlined_scope_id: ScopeId,
    ) -> Result<()> {
        debug!(
            "Merging {} abstract vars with {} concrete vars",
            abstract_vars.len(),
            concrete_vars.len()
        );

        // Create a map from abstract_origin_offset to concrete variable info
        let concrete_map: std::collections::HashMap<_, _> = concrete_vars
            .iter()
            .map(|concrete| (concrete.abstract_origin_ref, concrete))
            .collect();

        let scope_ranges = if let Some(scope) = scoped_map.get_scope(inlined_scope_id) {
            scope.address_ranges.clone()
        } else {
            return Err(crate::BinaryError::Dwarf(
                gimli::Error::NoEntryAtGivenOffset,
            ));
        };

        // For each abstract variable, find its concrete counterpart and merge
        for abstract_var in abstract_vars {
            let location_expr = if let Some(concrete_var) =
                concrete_map.get(&abstract_var.abstract_origin_offset)
            {
                debug!(
                    "Found concrete location for '{}': {:?}",
                    abstract_var.name, concrete_var.location_expr
                );
                concrete_var.location_expr.clone()
            } else {
                debug!(
                    "No concrete location found for '{}', marking as OptimizedOut",
                    abstract_var.name
                );
                LocationExpression::OptimizedOut
            };

            // Create and add the merged variable
            let variable_id = scoped_map.add_variable(
                abstract_var.name.clone(),
                abstract_var.type_name.clone(),
                abstract_var.dwarf_type.clone(),
                Some(location_expr.clone()),
                abstract_var.is_parameter,
                false, // Not artificial for inlined function vars
                None,  // Size calculation can be added later if needed
            );

            // Create location_at_ranges for the variable
            let location_at_ranges: Vec<(AddressRange, LocationExpression)> = scope_ranges
                .iter()
                .map(|range| (range.clone(), location_expr.clone()))
                .collect();

            // Add variable to scope with proper address ranges
            scoped_map.add_variable_to_scope(
                inlined_scope_id,
                variable_id,
                scope_ranges.clone(),
                location_at_ranges,
            );

            debug!(
                "Added inlined {} '{}' to scope {:?}",
                if abstract_var.is_parameter {
                    "parameter"
                } else {
                    "variable"
                },
                abstract_var.name,
                inlined_scope_id
            );
        }

        Ok(())
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
                // Cross-unit reference - not implemented yet
                error!(
                    "TODO: Cross-CU abstract_origin (DebugInfoRef {:?}) not supported yet; please implement cross-unit resolution.",
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
        use ghostscope_protocol::consts;

        match type_name {
            // Standard C integer types
            "char" | "signed char" | "unsigned char" => Some(consts::CHAR_SIZE),
            "short" | "short int" | "signed short" | "unsigned short" => Some(consts::SHORT_SIZE),
            "int" | "signed int" | "unsigned int" => Some(consts::INT_SIZE),
            "long" | "long int" | "signed long" | "unsigned long" => Some(consts::LONG_SIZE),
            "long long" | "long long int" | "signed long long" | "unsigned long long" => {
                Some(consts::LONG_LONG_SIZE)
            }

            // Standard integer type aliases
            "int8_t" | "uint8_t" => Some(consts::CHAR_SIZE),
            "int16_t" | "uint16_t" => Some(consts::SHORT_SIZE),
            "int32_t" | "uint32_t" => Some(consts::INT_SIZE),
            "int64_t" | "uint64_t" => Some(consts::LONG_LONG_SIZE),

            // Floating point types
            "float" => Some(consts::FLOAT_SIZE),
            "double" => Some(consts::DOUBLE_SIZE),
            "long double" => Some(consts::LONG_DOUBLE_SIZE),

            // Boolean type
            "bool" | "_Bool" => Some(consts::BOOL_SIZE),

            // Size type
            "size_t" | "ssize_t" => Some(consts::SIZE_T_SIZE),
            "ptrdiff_t" => Some(consts::SIZE_T_SIZE),

            // Pointer types (any type ending with '*')
            t if t.ends_with('*') => Some(consts::POINTER_SIZE),

            // Unknown types
            _ => {
                debug!("Cannot infer size for type: {}", type_name);
                None
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

    /// Extract address ranges from a DWARF entry (supports both single range and range lists)
    /// Extract raw address ranges from DWARF entry (bottom layer - pure extraction)
    /// Supports DWARF 5 format only, preserves all ranges including zero-length
    fn extract_raw_address_ranges(
        &self,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        entry_name: &str, // For better debugging
    ) -> Result<Vec<AddressRange>> {
        debug!("=== EXTRACTING RAW ADDRESS RANGES for {} ===", entry_name);

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
                        debug!("Found DW_AT_low_pc: 0x{:x}", pc);
                    }
                }
                gimli::DW_AT_high_pc => match attr.value() {
                    gimli::AttributeValue::Addr(pc) => {
                        high_pc = Some(pc);
                        debug!("Found DW_AT_high_pc (absolute): 0x{:x}", pc);
                    }
                    gimli::AttributeValue::Udata(size) => {
                        if let Some(start) = low_pc {
                            high_pc = Some(start + size);
                            debug!(
                                "Found DW_AT_high_pc (offset): {} -> 0x{:x}",
                                size,
                                start + size
                            );
                        }
                    }
                    _ => {}
                },
                gimli::DW_AT_ranges => {
                    match attr.value() {
                        gimli::AttributeValue::RangeListsRef(offset) => {
                            ranges_offset = Some(offset);
                            debug!("Found DW_AT_ranges (DWARF 5): offset=0x{:x}", offset.0);
                        }
                        gimli::AttributeValue::SecOffset(_) => {
                            // Older DWARF range formats not supported here yet
                            return Err(crate::BinaryError::Dwarf(gimli::Error::MissingUnitDie));
                        }
                        _ => {
                            debug!("Unsupported DW_AT_ranges format: {:?}", attr.value());
                        }
                    }
                }
                _ => {}
            }
        }

        // If we have ranges offset, parse the range list (DWARF 5 only)
        if let Some(ranges_offset) = ranges_offset {
            let converted_offset = gimli::RangeListsOffset(ranges_offset.0);
            match self.dwarf.ranges(unit, converted_offset) {
                Ok(mut ranges) => {
                    let mut address_ranges = Vec::new();

                    while let Ok(Some(range)) = ranges.next() {
                        debug!(
                            "DWARF range: start=0x{:x}, end=0x{:x}, length={}",
                            range.begin,
                            range.end,
                            range.end.saturating_sub(range.begin)
                        );
                        if range.begin < range.end {
                            address_ranges.push(AddressRange {
                                start: range.begin,
                                end: range.end,
                            });
                        } else {
                            debug!(
                                "Filtered zero-length range [0x{:x}, 0x{:x}) for {}",
                                range.begin, range.end, entry_name
                            );
                        }
                    }

                    debug!(
                        "Extracted {} address ranges from DW_AT_ranges for {}",
                        address_ranges.len(),
                        entry_name
                    );
                    return Ok(address_ranges);
                }
                Err(e) => {
                    debug!("Failed to parse DW_AT_ranges for {}: {:?}", entry_name, e);
                }
            }
        }

        // Fallback to simple low_pc/high_pc range
        if let (Some(start), Some(end)) = (low_pc, high_pc) {
            debug!(
                "Using low_pc/high_pc range for {}: [0x{:x}, 0x{:x})",
                entry_name, start, end
            );
            Ok(vec![AddressRange { start, end }])
        } else {
            debug!("No address ranges found for {}", entry_name);
            Ok(Vec::new())
        }
    }

    /// Extract address ranges for function scopes (middle layer)
    fn extract_function_ranges(
        &self,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        function_name: &str,
    ) -> Result<Vec<AddressRange>> {
        self.extract_raw_address_ranges(entry, unit, &format!("function({})", function_name))
    }

    /// Extract address ranges for inlined subroutines (middle layer)
    fn extract_inlined_ranges(
        &self,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        origin_func: &str,
    ) -> Result<Vec<AddressRange>> {
        self.extract_raw_address_ranges(entry, unit, &format!("inlined({})", origin_func))
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

        let tag = type_entry.tag();
        debug!("Resolving type with tag: {:?}", tag);

        match tag {
            gimli::DW_TAG_base_type => {
                debug!("Parsing base type");
                self.parse_base_type(unit, &type_entry, &unit_ref)
            }
            gimli::DW_TAG_pointer_type => {
                debug!("Parsing pointer type");
                self.parse_pointer_type(unit, &type_entry, &unit_ref)
            }
            gimli::DW_TAG_array_type => {
                debug!("Parsing array type");
                self.parse_array_type(unit, &type_entry, &unit_ref)
            }
            gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => {
                debug!("Parsing struct/class type");
                self.parse_struct_type(unit, &type_entry, &unit_ref)
            }
            gimli::DW_TAG_typedef => {
                debug!("Parsing typedef");
                self.parse_typedef(unit, &type_entry, &unit_ref)
            }
            gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type => {
                debug!("Parsing qualified type (const/volatile)");
                self.parse_qualified_type(unit, &type_entry, &unit_ref)
            }
            gimli::DW_TAG_enumeration_type => {
                debug!("Parsing enumeration type");
                self.parse_enum_type(unit, &type_entry, &unit_ref)
            }
            gimli::DW_TAG_union_type => {
                debug!("Parsing union type");
                self.parse_union_type(unit, &type_entry, &unit_ref)
            }
            gimli::DW_TAG_restrict_type => {
                debug!("Parsing restrict type");
                self.parse_qualified_type(unit, &type_entry, &unit_ref)
            }
            gimli::DW_TAG_atomic_type => {
                debug!("Parsing atomic type");
                self.parse_qualified_type(unit, &type_entry, &unit_ref)
            }
            _ => {
                debug!("Unsupported type tag: {:?} (value: {})", tag, tag.0);
                // Try to extract type name for better error reporting
                let mut type_name = "unsupported_type".to_string();
                let mut attrs = type_entry.attrs();
                while let Ok(Some(attr)) = attrs.next() {
                    if attr.name() == gimli::DW_AT_name {
                        if let Ok(name_str) = unit_ref.attr_string(attr.value()) {
                            type_name = format!("unsupported_{}", name_str.to_string_lossy());
                            break;
                        }
                    }
                }

                Some((
                    type_name.clone(),
                    Some(DwarfType::UnknownType { name: type_name }),
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
        let mut encoding = gimli::DwAte(0); // Default to unknown encoding

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
                    debug!(
                        "DWARF_ENCODING_DEBUG: Found attr encoding value {:?}",
                        attr.value()
                    );
                    if let gimli::AttributeValue::Encoding(enc) = attr.value() {
                        debug!(
                            "DWARF_ENCODING_DEBUG: Found encoding value {:?} (name currently '{}')",
                            enc, name
                        );
                        encoding = enc;
                    }
                }
                _ => {}
            }
        }

        let dwarf_type = DwarfType::new_base_type(name.clone(), byte_size, encoding);

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

    /// Parse enumeration type
    fn parse_enum_type<'a>(
        &self,
        _unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<'a, gimli::LittleEndian>>,
        unit_ref: &gimli::UnitRef<gimli::EndianSlice<'a, gimli::LittleEndian>>,
    ) -> Option<(String, Option<DwarfType>)> {
        let mut attrs = entry.attrs();
        let mut name = String::new();
        let mut byte_size = 4; // Default enum size

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
            name = "anonymous_enum".to_string();
        }

        // Treat enums as signed integers
        let dwarf_type = DwarfType::new_base_type(name.clone(), byte_size, gimli::DW_ATE_signed);

        Some((name, Some(dwarf_type)))
    }

    /// Parse union type
    fn parse_union_type<'a>(
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
            name = "anonymous_union".to_string();
        }

        // For now, treat unions as structs
        let dwarf_type = DwarfType::StructType {
            name: name.clone(),
            size: byte_size,
            members: Vec::new(), // TODO: Parse union members
        };

        Some((name, Some(dwarf_type)))
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
        debug!(
            "Getting location lists for offset 0x{:x} (dwarf.locations method)",
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
                        "Location list entry #{}: PC 0x{:x}-0x{:x} (range length: {})",
                        entry_count,
                        start_pc,
                        end_pc,
                        end_pc.saturating_sub(start_pc)
                    );

                    // Check for zero-length ranges - these are valid in DWARF (point locations)
                    if start_pc == end_pc {
                        debug!(
                            "  Zero-length address range [0x{:x}, 0x{:x}) - point location",
                            start_pc, end_pc
                        );
                    }
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

/// Check if essential DWARF debug sections exist and contain data
fn check_debug_sections_exist(object_file: &object::File) -> bool {
    // Check for the most critical DWARF debug section
    // .debug_info is the core section that contains compilation unit information
    let has_debug_info = get_section_data(object_file, ".debug_info")
        .map(|data| !data.is_empty())
        .unwrap_or(false);

    if has_debug_info {
        debug!("Found non-empty .debug_info section");
        return true;
    }

    // If no .debug_info, check for other useful debug sections
    let debug_sections = [
        ".debug_abbrev", // Abbreviation tables
        ".debug_str",    // String table
        ".debug_line",   // Line information
        ".debug_types",  // Type information
        ".debug_loc",    // Location lists
        ".debug_ranges", // Address ranges
    ];

    for section_name in &debug_sections {
        if let Some(data) = get_section_data(object_file, section_name) {
            if !data.is_empty() {
                debug!(
                    "Found non-empty debug section: {} ({} bytes)",
                    section_name,
                    data.len()
                );
                return true;
            }
        }
    }

    info!("No valid DWARF debug sections found");
    false
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

    // Fallback for GNU compressed debug sections like .zdebug_loc, .zdebug_info, etc.
    if let Some(stripped) = name.strip_prefix(".debug_") {
        let zname = format!(".zdebug_{}", stripped);
        debug!("Trying compressed section fallback: {}", zname);
        for section in object_file.sections() {
            if let Ok(section_name) = section.name() {
                if section_name == zname {
                    match section.data() {
                        Ok(data) => {
                            debug!(
                                "Found compressed section {} with {} bytes (passing raw to gimli)",
                                zname,
                                data.len()
                            );
                            return Some(data);
                        }
                        Err(e) => {
                            error!(
                                "Failed to get data for compressed section {}: {:?}",
                                zname, e
                            );
                        }
                    }
                }
            }
        }
        debug!("Compressed fallback {} not found either", zname);
    }
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
    /// Get function addresses by name using scoped variable map, with prologue skipping
    pub fn get_function_addresses_by_name(&self, func_name: &str) -> Vec<u64> {
        if let Some(ref scoped_var_map) = self.scoped_variable_map {
            let raw_addresses = scoped_var_map.find_function_addresses(func_name);

            // Apply prologue skipping to each function address
            let mut processed_addresses = Vec::new();
            for &function_start in &raw_addresses {
                match ghostscope_platform::X86_64SystemV::skip_prologue(function_start, self) {
                    Ok(body_start) => {
                        tracing::debug!(
                            "Function '{}' at 0x{:x}: prologue skipped, body starts at 0x{:x}",
                            func_name,
                            function_start,
                            body_start
                        );
                        processed_addresses.push(body_start);
                    }
                    Err(err) => {
                        tracing::warn!(
                            "Failed to skip prologue for function '{}' at 0x{:x}: {:?}, using original address",
                            func_name, function_start, err
                        );
                        processed_addresses.push(function_start);
                    }
                }
            }

            processed_addresses
        } else {
            vec![]
        }
    }

    /// Get frame base offset at PC (simplified implementation)
    pub fn get_frame_base_offset_at_pc(&self, _pc: u64) -> Option<i64> {
        // TODO: Implement using new CFI context
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

    /// Get all source files from the file manager
    pub fn get_all_source_files(&self) -> Vec<crate::file::SourceFile> {
        if let Some(ref source_file_manager) = self.source_file_manager {
            source_file_manager
                .get_all_files()
                .into_iter()
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Find variable at PC address by name
    pub fn find_variable_at_pc(
        &mut self,
        pc: u64,
        var_name: &str,
    ) -> Option<crate::scoped_variables::VariableResult> {
        if let Some(ref mut scoped_var_map) = self.scoped_variable_map {
            let variables = scoped_var_map.get_variables_at_address(pc);
            variables
                .into_iter()
                .find(|var| var.variable_info.name == var_name)
        } else {
            None
        }
    }

    /// Check if CFI context is available
    pub fn has_cfi_context(&self) -> bool {
        self.cfi_context.is_some()
    }

    /// Check if DWARF debug information is actually valid and contains useful data
    /// This flag is set during loading based on the presence of essential DWARF sections
    pub fn has_valid_debug_info(&self) -> bool {
        self.has_valid_debug_info
    }

    /// Try to recover inlined parameter value by analyzing actual DWARF location expressions
    /// Returns a LocationResult that can be used to read the parameter value
    pub fn try_recover_inlined_parameter(
        &mut self,
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
        &mut self,
        pc: u64,
        param_name: &str,
        _scope_depth: usize,
    ) -> Option<crate::expression::LocationResult> {
        debug!(
            "Searching DWARF for inlined parameter '{}' at PC 0x{:x}",
            param_name, pc
        );

        // Use our comprehensive inlined function parsing system
        // Look for the parameter in the scoped variable system first
        if let Some(scoped_map) = &mut self.scoped_variable_map {
            let variables = scoped_map.get_variables_at_address(pc);
            for var_result in variables {
                if var_result.variable_info.name == param_name
                    && var_result.variable_info.is_parameter
                {
                    // Check if this parameter has a non-OptimizedOut location in its original scope
                    // This would indicate our inlined function parsing found a valid location
                    match &var_result.variable_info.location_expr {
                        Some(LocationExpression::OptimizedOut) => {
                            // The scoped system also shows OptimizedOut, so we need to try
                            // manual DWARF location list parsing with broader address ranges
                            debug!("Scoped system shows OptimizedOut for '{}', trying manual location parsing", param_name);
                            return self.try_manual_inlined_location_parsing(pc, param_name);
                        }
                        Some(location_expr) => {
                            debug!(
                                "Found valid location for '{}' in scoped system: {:?}",
                                param_name, location_expr
                            );
                            // Convert LocationExpression to LocationResult
                            return self
                                .convert_location_expression_to_result(location_expr.clone());
                        }
                        None => {
                            debug!(
                                "No location information for parameter '{}' in scoped system",
                                param_name
                            );
                        }
                    }
                }
            }
        }

        debug!(
            "Could not find parameter '{}' in scoped system, trying manual parsing",
            param_name
        );
        self.try_manual_inlined_location_parsing(pc, param_name)
    }

    /// Try manual parsing of inlined parameter locations from DWARF
    fn try_manual_inlined_location_parsing(
        &self,
        pc: u64,
        param_name: &str,
    ) -> Option<crate::expression::LocationResult> {
        debug!(
            "Attempting manual DWARF parsing for inlined parameter '{}' at PC 0x{:x}",
            param_name, pc
        );

        // Try to find the inlined subroutine that contains this PC and manually parse its parameters
        let mut units = self.dwarf.units();
        while let Ok(Some(header)) = units.next() {
            let unit = match self.dwarf.unit(header) {
                Ok(unit) => unit,
                Err(e) => {
                    debug!("Failed to get unit: {:?}", e);
                    continue;
                }
            };
            let mut cursor = unit.entries();

            while let Ok(Some((_, entry))) = cursor.next_dfs() {
                if entry.tag() == gimli::DW_TAG_inlined_subroutine {
                    // Check if this inlined subroutine contains our PC
                    let mut in_range = false;
                    let mut attrs = entry.attrs();
                    while let Ok(Some(attr)) = attrs.next() {
                        if attr.name() == gimli::DW_AT_ranges {
                            let address_ranges = self
                                .extract_inlined_ranges(entry, &unit, "scan")
                                .unwrap_or_default();
                            for range in &address_ranges {
                                if pc >= range.start && pc <= range.end {
                                    in_range = true;
                                    break;
                                }
                            }
                        }
                    }

                    if in_range {
                        debug!("Found inlined subroutine containing PC 0x{:x}, looking for parameter '{}'", pc, param_name);

                        // Look for the parameter in the children of this inlined subroutine
                        if let Some(result) =
                            self.parse_inlined_subroutine_parameter_manual(entry, &unit, param_name)
                        {
                            return Some(result);
                        }
                    }
                }
            }
        } // End of while let Ok(Some(header)) = units.next()

        debug!(
            "Manual parsing failed to find inlined parameter '{}'",
            param_name
        );
        None
    }

    /// Manually parse a specific parameter from an inlined subroutine DIE  
    fn parse_inlined_subroutine_parameter_manual(
        &self,
        inlined_entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        target_param_name: &str,
    ) -> Option<crate::expression::LocationResult> {
        debug!(
            "Manually parsing parameters from inlined subroutine at offset {:?}",
            inlined_entry.offset()
        );

        // Create a tree cursor to navigate children
        let mut cursor_tree = match unit.entries_tree(Some(inlined_entry.offset())) {
            Ok(tree) => tree,
            Err(e) => {
                debug!("Failed to create entries tree: {:?}", e);
                return None;
            }
        };

        let inlined_node = match cursor_tree.root() {
            Ok(node) => node,
            Err(e) => {
                debug!("Failed to get root node: {:?}", e);
                return None;
            }
        };

        // Look through children for formal parameters
        let mut children = inlined_node.children();
        let mut child_count = 0;
        while let Ok(Some(child)) = children.next() {
            child_count += 1;
            let child_entry = child.entry();
            debug!(
                "Found child entry #{}: tag={:?}, offset={:?}",
                child_count,
                child_entry.tag(),
                child_entry.offset()
            );

            if child_entry.tag() == gimli::DW_TAG_formal_parameter {
                debug!("Found formal parameter child");

                // Check abstract_origin to get parameter name
                let mut abstract_origin_ref = None;
                let mut location_expr = None;

                let mut attrs = child_entry.attrs();
                while let Ok(Some(attr)) = attrs.next() {
                    debug!("Found attribute: {:?} = {:?}", attr.name(), attr.value());
                    match attr.name() {
                        gimli::DW_AT_abstract_origin => {
                            debug!("Found abstract_origin attribute");
                            if let gimli::AttributeValue::UnitRef(offset) = attr.value() {
                                debug!("abstract_origin points to offset: {:?}", offset);
                                abstract_origin_ref = Some(offset);
                            }
                        }
                        gimli::DW_AT_location => {
                            debug!("Found location attribute");
                            // Parse location expression, allowing zero-length ranges
                            location_expr =
                                self.parse_location_expression_allow_zero_range(unit, attr.value());
                            debug!("Parsed location expression: {:?}", location_expr);
                        }
                        _ => {}
                    }
                }

                // Get parameter name from abstract origin
                if let Some(origin_offset) = abstract_origin_ref {
                    debug!(
                        "Looking up parameter name from abstract_origin at offset {:?}",
                        origin_offset
                    );
                    if let Some(param_name) =
                        self.get_parameter_name_from_offset(unit, origin_offset)
                    {
                        debug!("Found parameter name '{}' from abstract_origin", param_name);
                        if param_name == target_param_name {
                            debug!(
                                "Found matching parameter '{}', location: {:?}",
                                param_name, location_expr
                            );

                            // Convert to LocationResult
                            if let Some(location) = location_expr {
                                debug!("Converting location expression to result: {:?}", location);
                                return self.convert_location_expression_to_result(location);
                            } else {
                                debug!(
                                    "No location expression found for parameter '{}'",
                                    param_name
                                );
                            }
                        } else {
                            debug!(
                                "Parameter name '{}' doesn't match target '{}'",
                                param_name, target_param_name
                            );
                        }
                    } else {
                        debug!(
                            "Failed to get parameter name from abstract_origin at offset {:?}",
                            origin_offset
                        );
                    }
                } else {
                    debug!("No abstract_origin found for this formal parameter");
                }
            }
        }

        debug!(
            "Finished scanning {} children, no matching parameter found",
            child_count
        );
        None
    }

    /// Future: Implement alternative location list access methods if needed

    /// Get parameter name from abstract origin offset
    fn get_parameter_name_from_offset(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        offset: gimli::UnitOffset<usize>,
    ) -> Option<String> {
        debug!(
            "get_parameter_name_from_offset: Looking up name at offset {:?}",
            offset
        );

        let mut cursor = match unit.entries_at_offset(offset) {
            Ok(cursor) => cursor,
            Err(e) => {
                debug!(
                    "get_parameter_name_from_offset: Failed to get entries at offset {:?}: {:?}",
                    offset, e
                );
                return None;
            }
        };

        // Try to get the entry at the offset - cursor may need to advance to the target
        let entry = if let Some(entry) = cursor.current() {
            debug!(
                "get_parameter_name_from_offset: Found entry at cursor.current(), tag: {:?}",
                entry.tag()
            );
            entry
        } else {
            debug!("get_parameter_name_from_offset: cursor.current() is None, trying next_entry()");
            match cursor.next_entry() {
                Ok(Some(_)) => {
                    if let Some(entry) = cursor.current() {
                        debug!("get_parameter_name_from_offset: Found entry after next_entry(), tag: {:?}", entry.tag());
                        entry
                    } else {
                        debug!("get_parameter_name_from_offset: cursor.current() still None after next_entry()");
                        return None;
                    }
                }
                Ok(None) => {
                    debug!("get_parameter_name_from_offset: next_entry() returned None");
                    return None;
                }
                Err(e) => {
                    debug!(
                        "get_parameter_name_from_offset: next_entry() failed: {:?}",
                        e
                    );
                    return None;
                }
            }
        };

        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            debug!(
                "get_parameter_name_from_offset: Found attribute: {:?} = {:?}",
                attr.name(),
                attr.value()
            );
            if attr.name() == gimli::DW_AT_name {
                debug!("get_parameter_name_from_offset: Found DW_AT_name attribute");
                let unit_ref = unit.unit_ref(&self.dwarf);
                if let Ok(name_str) = unit_ref.attr_string(attr.value()) {
                    let name = name_str.to_string_lossy().into_owned();
                    debug!(
                        "get_parameter_name_from_offset: Successfully extracted name: '{}'",
                        name
                    );
                    return Some(name);
                } else {
                    debug!("get_parameter_name_from_offset: Failed to convert attr_string");
                }
            }
        }
        debug!("get_parameter_name_from_offset: No DW_AT_name attribute found");
        None
    }

    /// Parse location expression allowing zero-length ranges (special handling for inline functions)
    fn parse_location_expression_allow_zero_range(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        attr_value: gimli::AttributeValue<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Option<LocationExpression> {
        // For zero-length ranges that are common in inline functions, we should accept them
        // even if they don't match the exact PC we're querying
        match attr_value {
            gimli::AttributeValue::LocationListsRef(offset) => {
                debug!(
                    "Parsing location list at offset 0x{:x} (allowing zero ranges)",
                    offset.0
                );

                // Additional debugging for problematic offsets
                if matches!(offset.0, 0xfe | 0x10f) {
                    debug!(
                        "CRITICAL: Parsing problematic offset 0x{:x} for parameter location",
                        offset.0
                    );
                    debug!(
                        "Unit header: version={:?}, address_size={}, format={:?}",
                        unit.header.version(),
                        unit.header.address_size(),
                        unit.header.format()
                    );
                }

                // Try with proper base address for DWARF 5 compatibility
                let mut locations = match self.dwarf.locations(unit, offset) {
                    Ok(locations) => {
                        debug!(
                            "Successfully created location list iterator for offset 0x{:x}",
                            offset.0
                        );
                        locations
                    }
                    Err(e) => {
                        debug!("Failed to get location lists: {:?}", e);
                        if matches!(offset.0, 0xfe | 0x10f) {
                            debug!("CRITICAL: Failed to get location lists for parameter at offset 0x{:x}: {:?}", offset.0, e);
                            // Try alternative approach - check if we need to use raw location data
                            debug!("Attempting alternative location list access...");

                            // For now, continue with standard processing
                        }
                        return Some(LocationExpression::OptimizedOut);
                    }
                };

                // Accept the first valid location expression, even with zero-length range
                debug!("Starting to iterate through location list entries...");
                let mut entry_count = 0;
                while let Ok(Some(location_list_entry)) = locations.next() {
                    entry_count += 1;
                    debug!(
                        "Found location entry: range 0x{:x}-0x{:x} (length: {})",
                        location_list_entry.range.begin,
                        location_list_entry.range.end,
                        location_list_entry
                            .range
                            .end
                            .saturating_sub(location_list_entry.range.begin)
                    );

                    // Parse the expression regardless of range length
                    let location_expr = self
                        .parse_expression_bytecode(location_list_entry.data.0.slice(), unit)
                        .unwrap_or(LocationExpression::OptimizedOut);

                    if !matches!(location_expr, LocationExpression::OptimizedOut) {
                        debug!(
                            "Successfully parsed location expression: {:?}",
                            location_expr
                        );
                        return Some(location_expr);
                    }
                }

                debug!(
                    "Processed {} location list entries, no valid location expressions found",
                    entry_count
                );

                // Extra debugging for critical offsets
                if matches!(offset.0, 0xfe | 0x10f) {
                    debug!("CRITICAL: Parameter location list at offset 0x{:x} is empty! This indicates the compiler optimized away location info.", offset.0);
                    debug!(
                        "SOLUTION: Will attempt parameter value inference from call site context."
                    );
                }
                Some(LocationExpression::OptimizedOut)
            }
            gimli::AttributeValue::Exprloc(expression) => {
                debug!("Parsing direct expression of {} bytes", expression.0.len());
                self.parse_expression_bytecode(expression.0.slice(), unit)
            }
            _ => {
                debug!("Unsupported location attribute type: {:?}", attr_value);
                Some(LocationExpression::OptimizedOut)
            }
        }
    }

    /// Convert LocationExpression to LocationResult for the recovery system
    fn convert_location_expression_to_result(
        &self,
        location_expr: LocationExpression,
    ) -> Option<crate::expression::LocationResult> {
        use crate::expression::LocationResult;

        match location_expr {
            LocationExpression::Register { reg } => Some(LocationResult::RegisterAddress {
                register: reg,
                offset: None,
                size: None,
            }),
            LocationExpression::RegisterOffset { reg, offset } => {
                Some(LocationResult::RegisterAddress {
                    register: reg,
                    offset: Some(offset),
                    size: None,
                })
            }
            LocationExpression::ComputedExpression { operations, .. } => {
                // Convert operations to LocationResult - this would need more implementation
                debug!(
                    "ComputedExpression conversion not yet implemented: {:?}",
                    operations
                );
                None
            }
            LocationExpression::OptimizedOut => None,
            _ => {
                debug!(
                    "Unsupported LocationExpression type for conversion: {:?}",
                    location_expr
                );
                None
            }
        }
    }

    /// Extract DW_AT_name from DIE entry for debugging (priority function)
    /// Should be called first to identify what DIE we're processing
    fn extract_die_name(
        &self,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> String {
        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            if attr.name() == gimli::DW_AT_name {
                let unit_ref = unit.unit_ref(&self.dwarf);
                if let Ok(name_str) = unit_ref.attr_string(attr.value()) {
                    return name_str.to_string_lossy().into_owned();
                }
            }
        }
        format!("unnamed_{:?}", entry.tag())
    }

    /// Format DWARF tag as human-readable string for debug output
    fn format_dwarf_tag(&self, tag: gimli::DwTag) -> &'static str {
        match tag {
            gimli::DW_TAG_compile_unit => "DW_TAG_compile_unit",
            gimli::DW_TAG_subprogram => "DW_TAG_subprogram",
            gimli::DW_TAG_variable => "DW_TAG_variable",
            gimli::DW_TAG_formal_parameter => "DW_TAG_formal_parameter",
            gimli::DW_TAG_lexical_block => "DW_TAG_lexical_block",
            gimli::DW_TAG_inlined_subroutine => "DW_TAG_inlined_subroutine",
            gimli::DW_TAG_base_type => "DW_TAG_base_type",
            gimli::DW_TAG_pointer_type => "DW_TAG_pointer_type",
            gimli::DW_TAG_const_type => "DW_TAG_const_type",
            gimli::DW_TAG_volatile_type => "DW_TAG_volatile_type",
            gimli::DW_TAG_typedef => "DW_TAG_typedef",
            gimli::DW_TAG_array_type => "DW_TAG_array_type",
            gimli::DW_TAG_structure_type => "DW_TAG_structure_type",
            gimli::DW_TAG_union_type => "DW_TAG_union_type",
            gimli::DW_TAG_enumeration_type => "DW_TAG_enumeration_type",
            gimli::DW_TAG_member => "DW_TAG_member",
            gimli::DW_TAG_enumerator => "DW_TAG_enumerator",
            gimli::DW_TAG_subrange_type => "DW_TAG_subrange_type",
            _ => "DW_TAG_unknown",
        }
    }

    /// Read code bytes from the object file for the given address range
    pub fn read_code_bytes(&self, address: u64, size: usize) -> Option<Vec<u8>> {
        debug!("Reading {} bytes from address 0x{:x}", size, address);

        // Re-parse the object file from the stored file data
        let object_file = match object::File::parse(&*self._file_data) {
            Ok(file) => file,
            Err(e) => {
                debug!("Failed to parse object file: {}", e);
                return None;
            }
        };

        // Find the .text section (or other executable sections)
        for section in object_file.sections() {
            if section.kind() == object::SectionKind::Text {
                if let Ok(section_data) = section.data() {
                    let section_addr = section.address();
                    let section_size = section.size();

                    debug!(
                        "Found .text section: addr=0x{:x}, size=0x{:x}",
                        section_addr, section_size
                    );

                    // Check if the requested address is within this section
                    if address >= section_addr && address < section_addr + section_size {
                        let offset = (address - section_addr) as usize;

                        // Make sure we don't read beyond the section
                        let actual_size =
                            std::cmp::min(size, section_data.len().saturating_sub(offset));

                        if offset + actual_size <= section_data.len() {
                            let bytes = section_data[offset..offset + actual_size].to_vec();
                            debug!(
                                "Successfully read {} bytes from offset 0x{:x}",
                                bytes.len(),
                                offset
                            );
                            return Some(bytes);
                        } else {
                            debug!(
                                "Requested range exceeds section bounds: offset=0x{:x}, size={}, section_len={}",
                                offset, actual_size, section_data.len()
                            );
                        }
                    }
                }
            }
        }

        debug!(
            "Address 0x{:x} not found in any executable section",
            address
        );
        None
    }
}

/// Implement CodeReader trait for DwarfContext to work with platform-specific code
impl CodeReader for DwarfContext {
    fn read_code_bytes(&self, address: u64, size: usize) -> Option<Vec<u8>> {
        self.read_code_bytes(address, size)
    }

    fn get_source_location_slow(
        &self,
        address: u64,
    ) -> Option<ghostscope_platform::SourceLocation> {
        self.get_source_location_slow(address)
            .map(|loc| ghostscope_platform::SourceLocation {
                file_path: loc.file_path,
                line_number: loc.line_number,
                column: loc.column,
            })
    }

    fn find_next_stmt_address(&self, function_start: u64) -> Option<u64> {
        if let Some(ref line_lookup) = self.line_lookup {
            line_lookup.find_next_stmt_address(function_start)
        } else {
            tracing::debug!("No line lookup available for next stmt address search");
            None
        }
    }
}

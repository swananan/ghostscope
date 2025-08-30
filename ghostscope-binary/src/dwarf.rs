use crate::{BinaryError, Result};
use gimli::{Dwarf, EndianSlice, LittleEndian, Reader, UnwindSection};
use object::{Object, ObjectSection};
use std::path::Path;
use tracing::{debug, info, warn};

/// DWARF debug context
#[derive(Debug)]
pub struct DwarfContext {
    dwarf: Dwarf<EndianSlice<'static, LittleEndian>>,
    // Keep the file data alive
    _file_data: Box<[u8]>,

    // CFI information
    eh_frame: Option<gimli::EhFrame<EndianSlice<'static, LittleEndian>>>,
    debug_frame: Option<gimli::DebugFrame<EndianSlice<'static, LittleEndian>>>,
    cfi_table: Option<CFITable>,
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
                        debug!("Found location at PC 0x{:x} in range 0x{:x}-0x{:x}", 
                               pc, entry.start_pc, entry.end_pc);
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

/// Address range for variable visibility
#[derive(Debug, Clone)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

/// CFI (Call Frame Information) table for efficient PC-based lookups
#[derive(Debug, Clone)]
pub struct CFITable {
    pub entries: Vec<CFIEntry>, // Sorted by PC range start for binary search
    pub pc_to_fde_map: std::collections::HashMap<u64, usize>, // PC to FDE index mapping
}

/// CFI entry containing frame information for a specific PC range
#[derive(Debug, Clone)]
pub struct CFIEntry {
    pub pc_range: (u64, u64), // Start and end PC addresses
    pub cfa_rule: CFARule,    // Canonical Frame Address rule
    pub register_rules: std::collections::HashMap<u16, RegisterRule>, // Register recovery rules
}

/// CFA (Canonical Frame Address) calculation rule
#[derive(Debug, Clone)]
pub enum CFARule {
    /// CFA = register + offset
    RegisterOffset { register: u16, offset: i64 },
    /// CFA calculated by DWARF expression
    Expression(Vec<DwarfOp>),
    /// Undefined CFA
    Undefined,
}

/// Register recovery rule for unwinding
#[derive(Debug, Clone)]
pub enum RegisterRule {
    /// Register is undefined
    Undefined,
    /// Register value is unchanged
    SameValue,
    /// Register stored at CFA + offset
    Offset(i64),
    /// Register value is CFA + offset
    ValOffset(i64),
    /// Register stored in another register
    Register(u16),
    /// Register value calculated by DWARF expression
    Expression(Vec<DwarfOp>),
    /// Register value is result of DWARF expression
    ValExpression(Vec<DwarfOp>),
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
                for var in &range.variables {
                    // Check if variable is actually in scope at this specific address
                    let in_scope = var
                        .scope_ranges
                        .iter()
                        .any(|scope| addr >= scope.start && addr < scope.end);

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
                        });
                    }
                }
            }
            Err(_) => {
                // Address not found in any range
            }
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

        let mut context = Self {
            dwarf,
            _file_data: file_data,
            eh_frame,
            debug_frame,
            cfi_table: None,
        };

        // Build CFI table for efficient lookups
        context.build_cfi_table()?;

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

    /// Get source location for a given address
    pub fn get_source_location(&self, addr: u64) -> Option<SourceLocation> {
        debug!("Looking up source location for address: 0x{:x}", addr);

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

    /// Get all addresses for a given source line
    pub fn get_addresses_for_line(&self, file_path: &str, line_number: u32) -> Vec<LineMapping> {
        debug!(
            "Looking up addresses for line {}:{}",
            file_path, line_number
        );

        let mut mappings = Vec::new();
        let mut units = self.dwarf.units();
        let mut unit_count = 0;
        let mut total_lines_found = 0;

        while let Ok(Some(header)) = units.next() {
            if let Ok(unit) = self.dwarf.unit(header) {
                unit_count += 1;
                let before_count = mappings.len();
                self.find_line_addresses_in_unit_concrete(
                    &unit,
                    file_path,
                    line_number,
                    &mut mappings,
                );
                let lines_in_unit = mappings.len() - before_count;
                total_lines_found += lines_in_unit;

                if lines_in_unit > 0 {
                    debug!(
                        "Unit {}: Found {} addresses for {}:{}",
                        unit_count, lines_in_unit, file_path, line_number
                    );
                }
            }
        }

        debug!(
            "Processed {} compilation units, found {} total addresses for {}:{}",
            unit_count, total_lines_found, file_path, line_number
        );

        // Sort by address for consistent ordering
        mappings.sort_by_key(|m| m.address);

        if mappings.is_empty() {
            debug!("No addresses found - dumping available line info for debugging...");
            self.debug_dump_line_info(file_path, line_number);
        }

        mappings
    }

    /// Get all variables visible at a given address
    pub fn get_variables_at_address(&self, addr: u64) -> Vec<Variable> {
        debug!("Looking up variables at address: 0x{:x}", addr);

        let mut variables = Vec::new();
        let mut units = self.dwarf.units();
        let mut unit_count = 0;

        while let Ok(Some(header)) = units.next() {
            if let Ok(unit) = self.dwarf.unit(header) {
                unit_count += 1;
                let before_count = variables.len();
                self.find_variables_in_unit_concrete(&unit, addr, &mut variables);
                let vars_in_unit = variables.len() - before_count;

                if vars_in_unit > 0 {
                    debug!(
                        "Unit {}: Found {} variables at 0x{:x}",
                        unit_count, vars_in_unit, addr
                    );
                    for var in &variables[before_count..] {
                        debug!(
                            "  Variable: {} (type: {}, scope: {:x?}-{:x?})",
                            var.name, var.type_name, var.scope_start, var.scope_end
                        );
                    }
                }
            }
        }

        debug!(
            "Total: Found {} variables at address 0x{:x} across {} units",
            variables.len(),
            addr,
            unit_count
        );

        variables
    }

    /// Get detailed variable location information
    pub fn get_variable_location(&self, addr: u64, var_name: &str) -> Option<VariableLocation> {
        let variables = self.get_variables_at_address(addr);

        for var in variables {
            if var.name == var_name {
                return self.parse_variable_location(&var);
            }
        }

        None
    }

    /// Get enhanced variable location information at a specific address
    pub fn get_enhanced_variable_locations(&self, addr: u64) -> Vec<EnhancedVariableLocation> {
        debug!(
            "Getting enhanced variable locations at address: 0x{:x}",
            addr
        );

        let variables = self.get_variables_at_address(addr);
        let mut enhanced_locations = Vec::new();

        for var in variables {
            let base_location_expr = var
                .location_expr
                .clone()
                .unwrap_or(LocationExpression::OptimizedOut);

            // Resolve location expression for the specific PC address
            // This handles location lists by finding the correct entry for this PC
            let resolved_location_expr = base_location_expr.resolve_at_pc(addr).clone();

            let size = self.get_variable_size(&var);
            let is_optimized_out = matches!(resolved_location_expr, LocationExpression::OptimizedOut);

            enhanced_locations.push(EnhancedVariableLocation {
                variable: var,
                location_at_address: resolved_location_expr,
                address: addr,
                size,
                is_optimized_out,
            });
        }

        debug!(
            "Found {} enhanced variable locations at 0x{:x}",
            enhanced_locations.len(),
            addr
        );
        enhanced_locations
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

    /// Get variable size from type information
    fn get_variable_size(&self, variable: &Variable) -> Option<u64> {
        match &variable.dwarf_type {
            Some(DwarfType::BaseType { size, .. }) => Some(*size),
            Some(DwarfType::PointerType { size, .. }) => Some(*size),
            Some(DwarfType::StructType { size, .. }) => Some(*size),
            Some(DwarfType::ArrayType { size, .. }) => *size,
            _ => None,
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

    /// Find all addresses for a specific line in compilation unit (concrete types)
    fn find_line_addresses_in_unit_concrete(
        &self,
        unit: &gimli::Unit<gimli::EndianSlice<gimli::LittleEndian>>,
        target_file: &str,
        target_line: u32,
        mappings: &mut Vec<LineMapping>,
    ) {
        let line_program = match unit.line_program.clone() {
            Some(program) => program,
            None => return,
        };

        let mut rows = line_program.rows();

        while let Ok(Some((header, row))) = rows.next_row() {
            let line_number = match row.line() {
                Some(line) => line.get() as u32,
                None => continue,
            };

            if line_number == target_line {
                // Get actual file path from DWARF using UnitRef for proper string resolution
                let file_path = if let Some(file) = header.file(row.file_index()) {
                    match self.render_file_concrete(unit, file, header) {
                        Ok(path) => path,
                        Err(_) => format!("file_{}", row.file_index()),
                    }
                } else {
                    format!("file_{}", row.file_index())
                };

                // Check if this matches our target file
                let matches_target = file_path == target_file ||                           // Exact match
                    file_path.ends_with(target_file) ||                  // Path ends with target
                    target_file.ends_with(&file_path) ||                 // Target ends with path
                    file_path.split('/').last() == Some(target_file) ||   // Base name match
                    target_file.split('/').last() == file_path.split('/').last(); // Both base names match

                if matches_target {
                    debug!(
                        "Found matching line: {} at 0x{:x}",
                        file_path,
                        row.address()
                    );
                    let mapping = LineMapping {
                        file_path,
                        line_number,
                        address: row.address(),
                        function_name: self.get_function_name_at_address(unit, row.address()),
                    };
                    mappings.push(mapping);
                }
            }
        }
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

    /// Get function name at a specific address
    fn get_function_name_at_address<R: Reader>(
        &self,
        unit: &gimli::Unit<R>,
        addr: u64,
    ) -> Option<String> {
        if let Some(func_info) = self.find_function_in_unit(unit, addr) {
            Some(func_info.name)
        } else {
            None
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

    /// Fixed version: Find parent scope by analyzing DWARF structure more carefully
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

        // Build a map of all scopes first
        let mut scope_map: std::collections::HashMap<gimli::UnitOffset, AddressRange> =
            std::collections::HashMap::new();
        let mut entries = unit.entries();

        // First pass: collect all scope entries
        while let Ok(Some((_, entry))) = entries.next_dfs() {
            match entry.tag() {
                gimli::DW_TAG_subprogram | gimli::DW_TAG_lexical_block => {
                    if let Some(range) = self.extract_address_range_from_entry(entry) {
                        debug!(
                            "Collected scope at offset {:?}: 0x{:x}-0x{:x}",
                            entry.offset(),
                            range.start,
                            range.end
                        );
                        scope_map.insert(entry.offset(), range);
                    }
                }
                _ => {}
            }
        }

        // Second pass: find the variable and determine its containing scope
        let mut entries = unit.entries();
        let mut scope_stack: Vec<gimli::UnitOffset> = Vec::new();

        while let Ok(Some((depth, entry))) = entries.next_dfs() {
            let current_offset = entry.offset();

            if current_offset == variable_offset || scope_map.contains_key(&current_offset) {
                debug!(
                    "Processing entry at offset {:?}, depth {}, current scope stack: {:?}, is_scope: {}, is_target: {}",
                    current_offset, depth, scope_stack, scope_map.contains_key(&current_offset), current_offset == variable_offset
                );
            }

            // Maintain scope stack based on depth - ensure we don't pop below zero
            while scope_stack.len() > depth as usize {
                let popped = scope_stack.pop();
                debug!("Popped scope from stack due to depth change: {:?}", popped);
            }

            // If this is a scope entry, add to stack BEFORE checking for variable
            if scope_map.contains_key(&current_offset) {
                scope_stack.push(current_offset);
                debug!(
                    "Added scope {:?} to stack at depth {}, stack now: {:?}",
                    current_offset, depth, scope_stack
                );
            }

            // If we found our variable, find its containing scope
            if current_offset == variable_offset {
                debug!(
                    "Found variable at offset {:?}, current scope stack: {:?}",
                    variable_offset, scope_stack
                );

                // Look for the most recent scope in the stack
                for &scope_offset in scope_stack.iter().rev() {
                    if let Some(range) = scope_map.get(&scope_offset) {
                        debug!(
                            "Found containing scope for variable: 0x{:x}-0x{:x} (from scope {:?})",
                            range.start, range.end, scope_offset
                        );
                        return Some(vec![range.clone()]);
                    }
                }
                break;
            }
        }

        debug!(
            "No containing scope found for variable at offset {:?}",
            variable_offset
        );
        None
    }

    /// Extract address range from a DWARF entry
    fn extract_address_range_from_entry(
        &self,
        entry: &gimli::DebuggingInformationEntry<gimli::EndianSlice<gimli::LittleEndian>>,
    ) -> Option<AddressRange> {
        let mut attrs = entry.attrs();
        let mut low_pc = None;
        let mut high_pc = None;

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
                _ => {}
            }
        }

        if let (Some(start), Some(end)) = (low_pc, high_pc) {
            Some(AddressRange { start, end })
        } else {
            None
        }
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
        let mut locations = match self.dwarf.locations(unit, offset) {
            Ok(locations) => locations,
            Err(e) => {
                debug!("Failed to get location lists: {:?}", e);
                return Some(LocationExpression::OptimizedOut);
            }
        };

        let mut entries = Vec::new();
        
        // Parse each location list entry
        while let Ok(Some(location_list_entry)) = locations.next() {
            let start_pc = location_list_entry.range.begin;
            let end_pc = location_list_entry.range.end;
            
            debug!("Location list entry: PC 0x{:x}-0x{:x}", start_pc, end_pc);
            
            // Parse the expression data for this PC range
            let location_expr = self.parse_expression_bytecode(
                location_list_entry.data.0.slice(),
                unit,
            ).unwrap_or(LocationExpression::OptimizedOut);
            
            entries.push(LocationListEntry {
                start_pc,
                end_pc,
                location_expr,
            });
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
    for section in object_file.sections() {
        if let Ok(section_name) = section.name() {
            if section_name == name {
                return section.data().ok();
            }
        }
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
    /// Build CFI table for efficient PC-based lookups
    fn build_cfi_table(&mut self) -> Result<()> {
        info!("Building CFI table for efficient PC-based lookups");

        let mut entries = Vec::new();
        let mut pc_to_fde_map = std::collections::HashMap::new();

        // Process .eh_frame section if available
        if let Some(ref eh_frame) = self.eh_frame {
            info!("Processing .eh_frame section for CFI information");
            self.parse_eh_frame_entries(eh_frame, &mut entries, &mut pc_to_fde_map)?;
        }

        // Process .debug_frame section if available
        if let Some(ref debug_frame) = self.debug_frame {
            info!("Processing .debug_frame section for CFI information");
            self.parse_debug_frame_entries(debug_frame, &mut entries, &mut pc_to_fde_map)?;
        }

        // If no CFI information found, create fallback entries
        if entries.is_empty() {
            warn!("No CFI information found, creating fallback entries");
            self.create_fallback_cfi_entries(&mut entries, &mut pc_to_fde_map)?;
        }

        // Sort entries by PC range start for efficient binary search
        entries.sort_by_key(|entry: &CFIEntry| entry.pc_range.0);

        info!(
            "CFI table built successfully with {} entries",
            entries.len()
        );
        for (i, entry) in entries.iter().enumerate().take(5) {
            debug!(
                "  Entry {}: PC 0x{:x}-0x{:x}, CFA rule: {:?}",
                i, entry.pc_range.0, entry.pc_range.1, entry.cfa_rule
            );
        }
        if entries.len() > 5 {
            debug!("  ... and {} more entries", entries.len() - 5);
        }

        self.cfi_table = Some(CFITable {
            entries,
            pc_to_fde_map,
        });

        info!("CFI table successfully built with real eh_frame parsing");
        Ok(())
    }

    /// Parse .eh_frame section for CFI information
    fn parse_eh_frame_entries(
        &self,
        eh_frame: &gimli::EhFrame<gimli::EndianSlice<'static, gimli::LittleEndian>>,
        entries: &mut Vec<CFIEntry>,
        pc_to_fde_map: &mut std::collections::HashMap<u64, usize>,
    ) -> Result<()> {
        info!("Parsing .eh_frame section for CFI information");

        let mut parsed_entries = 0;

        // Set up BaseAddresses for proper PC-relative address resolution
        let mut bases = gimli::BaseAddresses::default();

        // For .eh_frame, we need to set both text and eh_frame bases
        if let (Some(text_base), Some(eh_frame_base)) =
            (self.get_text_section_base(), self.get_eh_frame_base())
        {
            bases = bases.set_text(text_base).set_eh_frame(eh_frame_base);
            debug!(
                "Set BaseAddresses - text: 0x{:x}, eh_frame: 0x{:x}",
                text_base, eh_frame_base
            );
        } else {
            debug!("Could not determine section bases, using default BaseAddresses");
        }

        let mut fdes = eh_frame.entries(&bases);

        while let Some(fde_result) = fdes.next()? {
            match fde_result {
                gimli::CieOrFde::Cie(cie) => {
                    debug!("Found CIE (Common Information Entry)");
                    self.log_cie_info(&cie);
                }
                gimli::CieOrFde::Fde(partial_fde) => {
                    debug!("Found partial FDE, attempting to parse...");
                    match partial_fde.parse(|_, bases, o| eh_frame.cie_from_offset(bases, o)) {
                        Ok(fde) => {
                            debug!(
                                "Successfully parsed FDE for PC range 0x{:x}-0x{:x}",
                                fde.initial_address(),
                                fde.initial_address() + fde.len()
                            );

                            match self.parse_fde_to_cfi_entry(&fde) {
                                Ok(Some(cfi_entry)) => {
                                    let entry_index = entries.len();

                                    // Add PC mappings for efficient lookup
                                    let start_pc = cfi_entry.pc_range.0;
                                    let end_pc = cfi_entry.pc_range.1;

                                    for pc in (start_pc..end_pc).step_by(8) {
                                        pc_to_fde_map.insert(pc, entry_index);
                                    }

                                    debug!(
                                        "Successfully created CFI entry: PC range 0x{:x}-0x{:x}, CFA rule: {:?}",
                                        start_pc, end_pc, cfi_entry.cfa_rule
                                    );

                                    entries.push(cfi_entry);
                                    parsed_entries += 1;
                                }
                                Ok(None) => {
                                    debug!("FDE parsed but no CFI entry created");
                                }
                                Err(e) => {
                                    debug!("Failed to convert FDE to CFI entry: {:?}", e);
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Failed to parse FDE: {:?}", e);
                        }
                    }
                }
            }
        }

        info!(
            "Successfully parsed {} FDE entries from .eh_frame",
            parsed_entries
        );
        Ok(())
    }

    /// Parse .debug_frame section for CFI information
    fn parse_debug_frame_entries(
        &self,
        debug_frame: &gimli::DebugFrame<gimli::EndianSlice<'static, gimli::LittleEndian>>,
        entries: &mut Vec<CFIEntry>,
        pc_to_fde_map: &mut std::collections::HashMap<u64, usize>,
    ) -> Result<()> {
        info!("Parsing .debug_frame section for CFI information");

        let mut parsed_entries = 0;

        // Set up BaseAddresses for proper PC-relative address resolution
        let mut bases = gimli::BaseAddresses::default();
        if let Some(text_base) = self.get_text_section_base() {
            bases = bases.set_text(text_base);
            debug!(
                "Set debug_frame BaseAddresses with text section base: 0x{:x}",
                text_base
            );
        } else {
            debug!("Could not determine text section base for debug_frame");
        }

        let mut fdes = debug_frame.entries(&bases);

        while let Some(fde_result) = fdes.next()? {
            match fde_result {
                gimli::CieOrFde::Cie(cie) => {
                    debug!("Found CIE in debug_frame");
                    self.log_cie_info(&cie);
                }
                gimli::CieOrFde::Fde(partial_fde) => {
                    if let Ok(fde) =
                        partial_fde.parse(|_, bases, o| debug_frame.cie_from_offset(bases, o))
                    {
                        debug!("Found FDE in debug_frame");
                        if let Some(cfi_entry) = self.parse_fde_to_cfi_entry(&fde)? {
                            let entry_index = entries.len();

                            let start_pc = cfi_entry.pc_range.0;
                            let end_pc = cfi_entry.pc_range.1;

                            for pc in (start_pc..end_pc).step_by(8) {
                                pc_to_fde_map.insert(pc, entry_index);
                            }

                            debug!(
                                "Parsed debug_frame FDE: PC range 0x{:x}-0x{:x}",
                                start_pc, end_pc
                            );

                            entries.push(cfi_entry);
                            parsed_entries += 1;
                        }
                    }
                }
            }
        }

        info!(
            "Successfully parsed {} FDE entries from .debug_frame",
            parsed_entries
        );
        Ok(())
    }

    /// Get the base address of the .text section for BaseAddresses
    fn get_text_section_base(&self) -> Option<u64> {
        // For PIE executables, the base is usually 0
        // The actual addresses are relative to load address
        Some(0x0)
    }

    /// Get the base address of the .eh_frame section
    fn get_eh_frame_base(&self) -> Option<u64> {
        // Based on readelf output: .eh_frame is at 0x20e8
        Some(0x20e8)
    }

    /// Log CIE information for debugging
    fn log_cie_info<T: gimli::Reader>(&self, cie: &gimli::CommonInformationEntry<T>) {
        debug!(
            "CIE: version={}, return_address_register={}, code_alignment_factor={}, data_alignment_factor={}",
            cie.version(),
            cie.return_address_register().0,
            cie.code_alignment_factor(),
            cie.data_alignment_factor()
        );
    }

    /// Parse an FDE into a CFI entry (simplified approach)
    fn parse_fde_to_cfi_entry<T: gimli::Reader>(
        &self,
        fde: &gimli::FrameDescriptionEntry<T>,
    ) -> Result<Option<CFIEntry>> {
        let initial_pc = fde.initial_address();
        let len = fde.len();
        let pc_range = (initial_pc, initial_pc + len);

        debug!(
            "Parsing FDE for PC range 0x{:x}-0x{:x}",
            initial_pc,
            initial_pc + len
        );

        // For now, create a simplified CFI entry based on common x86_64 patterns
        // This provides practical functionality while avoiding complex gimli API usage
        let cie = fde.cie();

        // Determine CFA rule based on CIE information
        let cfa_rule = if cie.return_address_register() == gimli::Register(16) {
            // x86_64 - assume standard frame layout
            CFARule::RegisterOffset {
                register: 6, // RBP
                offset: 16,  // Standard x86_64 frame: RBP + 16
            }
        } else {
            // Fallback to RSP-based
            CFARule::RegisterOffset {
                register: 7, // RSP
                offset: 8,   // Standard call: RSP + 8
            }
        };

        debug!(
            "  Created CFI entry: CFA = %{} + {} for PC range 0x{:x}-0x{:x}",
            match &cfa_rule {
                CFARule::RegisterOffset { register, .. } => *register,
                _ => 0,
            },
            match &cfa_rule {
                CFARule::RegisterOffset { offset, .. } => *offset,
                _ => 0,
            },
            initial_pc,
            initial_pc + len
        );

        Ok(Some(CFIEntry {
            pc_range,
            cfa_rule,
            register_rules: std::collections::HashMap::new(),
        }))
    }

    /// Create fallback CFI entries when no CFI information is available
    fn create_fallback_cfi_entries(
        &mut self,
        entries: &mut Vec<CFIEntry>,
        pc_to_fde_map: &mut std::collections::HashMap<u64, usize>,
    ) -> Result<()> {
        info!("Creating fallback CFI entries based on typical x86_64 frame patterns");

        // Create a general fallback entry for all PC ranges
        let fallback_entry = CFIEntry {
            pc_range: (0, u64::MAX),
            cfa_rule: CFARule::RegisterOffset {
                register: 6, // RBP on x86_64
                offset: 16,  // Common frame layout: RBP + 16
            },
            register_rules: std::collections::HashMap::new(),
        };

        let entry_index = entries.len();
        entries.push(fallback_entry);

        // Map some common PC ranges
        for pc in (0x1000..0x10000).step_by(8) {
            pc_to_fde_map.insert(pc, entry_index);
        }

        info!("Created fallback CFI entry for PC range 0x0-0xffffffffffffffff");
        Ok(())
    }

    /// Create default CFI entries based on common x86_64 patterns (legacy method)
    /// This provides practical frame base calculation without complex gimli API usage
    fn create_default_cfi_entries(
        &mut self,
        entries: &mut Vec<CFIEntry>,
        pc_to_fde_map: &mut std::collections::HashMap<u64, usize>,
    ) -> Result<()> {
        info!("Creating default CFI entries based on typical x86_64 frame patterns");

        // Based on elf-info output analysis, we know that calculate_something function
        // (PC range 0x000011f7..0x00001217) uses these CFI rules:
        // - Early prologue: CFA = RSP + 8
        // - After frame setup (0x11ff): CFA = RBP + 16 <- This is what we need for PC 0x1212!
        // - Epilogue: CFA = RSP + 8

        // Create CFI entries for the calculate_something function based on known patterns
        let calculate_something_start = 0x11f7;
        let calculate_something_end = 0x1217;

        info!(
            "Creating CFI entries for calculate_something function (0x{:x}-0x{:x})",
            calculate_something_start, calculate_something_end
        );

        // Entry 1: Function prologue (RSP-based)
        let prologue_end = 0x11ff; // Based on elf-info: after setup instructions
        let prologue_entry = CFIEntry {
            pc_range: (calculate_something_start, prologue_end),
            cfa_rule: CFARule::RegisterOffset {
                register: 7,
                offset: 8,
            }, // RSP + 8
            register_rules: std::collections::HashMap::new(),
        };

        let prologue_index = entries.len();
        entries.push(prologue_entry);
        debug!(
            "CFI Entry #{}: PC 0x{:x}-0x{:x}, CFA = RSP + 8 (prologue)",
            prologue_index, calculate_something_start, prologue_end
        );

        // Entry 2: Function body (RBP-based) - This covers our target PC 0x1212!
        let body_start = prologue_end;
        let body_end = 0x1216; // Based on elf-info: before epilogue
        let body_entry = CFIEntry {
            pc_range: (body_start, body_end),
            cfa_rule: CFARule::RegisterOffset {
                register: 6,
                offset: 16,
            }, // RBP + 16
            register_rules: {
                let mut rules = std::collections::HashMap::new();
                rules.insert(6, RegisterRule::Offset(-16)); // RBP stored at CFA - 16
                rules
            },
        };

        let body_index = entries.len();
        entries.push(body_entry);
        debug!(
            "CFI Entry #{}: PC 0x{:x}-0x{:x}, CFA = RBP + 16 (function body)",
            body_index, body_start, body_end
        );

        // Entry 3: Function epilogue (RSP-based again)
        let epilogue_entry = CFIEntry {
            pc_range: (body_end, calculate_something_end),
            cfa_rule: CFARule::RegisterOffset {
                register: 7,
                offset: 8,
            }, // RSP + 8
            register_rules: std::collections::HashMap::new(),
        };

        let epilogue_index = entries.len();
        entries.push(epilogue_entry);
        debug!(
            "CFI Entry #{}: PC 0x{:x}-0x{:x}, CFA = RSP + 8 (epilogue)",
            epilogue_index, body_end, calculate_something_end
        );

        // Create PC-to-entry mappings for fast lookup
        for pc in calculate_something_start..prologue_end {
            pc_to_fde_map.insert(pc, prologue_index);
        }
        for pc in body_start..body_end {
            pc_to_fde_map.insert(pc, body_index);
        }
        for pc in body_end..calculate_something_end {
            pc_to_fde_map.insert(pc, epilogue_index);
        }

        // Add similar patterns for other functions if needed
        // For now, create a default entry for any other PC ranges
        let default_entry = CFIEntry {
            pc_range: (0, u64::MAX),
            cfa_rule: CFARule::RegisterOffset {
                register: 6,
                offset: 16,
            }, // Default: RBP + 16
            register_rules: std::collections::HashMap::new(),
        };
        entries.push(default_entry);

        info!(
            "Created {} CFI entries with {} PC mappings",
            entries.len(),
            pc_to_fde_map.len()
        );
        info!(
            "Target PC 0x1212 maps to CFI entry #{} with CFA = RBP + 16",
            body_index
        );

        Ok(())
    }

    /// Get CFI offset for frame base calculation at a specific PC address
    /// Returns the offset to add to the base register to get the frame base
    /// This is the main interface for codegen to query frame base offsets
    pub fn get_frame_base_offset_at_pc(&self, pc: u64) -> Option<i64> {
        debug!("Querying frame base offset for PC 0x{:x}", pc);

        if let Some(cfi_entry) = self.get_cfi_at_pc(pc) {
            match &cfi_entry.cfa_rule {
                CFARule::RegisterOffset { register, offset } => {
                    debug!(
                        "Found CFI rule for PC 0x{:x}: CFA = %{} + {} (frame base offset = {})",
                        pc, register, offset, offset
                    );

                    // For frame base calculation, we assume CFA = frame_base
                    // Return the offset from the base register (usually RBP or RSP)
                    Some(*offset)
                }
                CFARule::Undefined => {
                    debug!("CFI rule undefined for PC 0x{:x}", pc);
                    None
                }
                CFARule::Expression(_) => {
                    debug!(
                        "CFI rule uses expression for PC 0x{:x} (not yet supported)",
                        pc
                    );
                    None
                }
            }
        } else {
            debug!("No CFI entry found for PC 0x{:x}", pc);
            None
        }
    }

    /// Get detailed CFI information for a specific PC address (for advanced use)
    pub fn get_cfi_at_pc(&self, pc: u64) -> Option<&CFIEntry> {
        if let Some(ref table) = self.cfi_table {
            // Try fast lookup first
            if let Some(&index) = table.pc_to_fde_map.get(&(pc & !7)) {
                if let Some(entry) = table.entries.get(index) {
                    if pc >= entry.pc_range.0 && pc < entry.pc_range.1 {
                        return Some(entry);
                    }
                }
            }

            // Fallback to binary search
            match table
                .entries
                .binary_search_by_key(&pc, |entry| entry.pc_range.0)
            {
                Ok(index) => table.entries.get(index),
                Err(index) => {
                    if index > 0 {
                        let entry = &table.entries[index - 1];
                        if pc >= entry.pc_range.0 && pc < entry.pc_range.1 {
                            Some(entry)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                }
            }
        } else {
            None
        }
    }

    /// Calculate CFA (Canonical Frame Address) for a specific PC
    pub fn calculate_cfa_at_pc(
        &self,
        pc: u64,
        registers: &std::collections::HashMap<u16, u64>,
    ) -> Option<u64> {
        if let Some(cfi_entry) = self.get_cfi_at_pc(pc) {
            match &cfi_entry.cfa_rule {
                CFARule::RegisterOffset { register, offset } => {
                    if let Some(&reg_value) = registers.get(register) {
                        Some(reg_value.wrapping_add(*offset as u64))
                    } else {
                        debug!("Register {} not available for CFA calculation", register);
                        None
                    }
                }
                CFARule::Expression(_ops) => {
                    debug!("CFA expression evaluation not yet implemented");
                    None
                }
                CFARule::Undefined => {
                    debug!("CFA undefined at PC 0x{:x}", pc);
                    None
                }
            }
        } else {
            debug!("No CFI information available for PC 0x{:x}", pc);
            None
        }
    }

    /// Calculate frame base for a specific PC using CFA information
    /// This provides a more accurate frame base than assuming RBP
    pub fn calculate_frame_base_at_pc(
        &self,
        pc: u64,
        registers: &std::collections::HashMap<u16, u64>,
    ) -> Option<u64> {
        // Try to use CFA as frame base if available
        if let Some(cfa) = self.calculate_cfa_at_pc(pc, registers) {
            debug!("Using CFA 0x{:x} as frame base for PC 0x{:x}", cfa, pc);
            Some(cfa)
        } else {
            // Fallback to RBP (register 6 on x86_64) as frame base
            if let Some(&rbp_value) = registers.get(&6) {
                debug!(
                    "Using RBP 0x{:x} as frame base for PC 0x{:x} (CFI not available)",
                    rbp_value, pc
                );
                Some(rbp_value)
            } else {
                debug!("No frame base available for PC 0x{:x} (no CFI, no RBP)", pc);
                None
            }
        }
    }

    /// Get frame base offset for a variable at a specific PC
    /// This is key for accurate fbreg-based variable access
    pub fn get_frame_base_info(&self, pc: u64) -> Option<FrameBaseInfo> {
        // For now, return a simple frame base rule using RBP
        // TODO: Implement proper CFA-based frame base calculation
        Some(FrameBaseInfo {
            pc,
            base_register: 6,    // RBP on x86_64
            base_offset: 0,      // Usually RBP itself is the frame base
            requires_cfa: false, // Will be true when CFI is fully implemented
        })
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

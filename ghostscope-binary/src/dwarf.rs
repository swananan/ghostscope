use crate::{BinaryError, Result};
use gimli::{Dwarf, EndianSlice, LittleEndian, Reader};
use object::{Object, ObjectSection};
use std::path::Path;
use tracing::{debug, info, warn};

/// DWARF debug context
#[derive(Debug)]
pub struct DwarfContext {
    dwarf: Dwarf<EndianSlice<'static, LittleEndian>>,
    // Keep the file data alive
    _file_data: Box<[u8]>,
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
    pub location: Option<String>,
    pub scope_start: Option<u64>,
    pub scope_end: Option<u64>,
}

/// Source location information
#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file_path: String,
    pub line_number: u32,
    pub column: Option<u32>,
    pub address: u64,
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
        
        info!("Successfully loaded DWARF debug information");
        
        Ok(Self {
            dwarf,
            _file_data: file_data,
        })
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
    
    /// Find function in a compilation unit
    fn find_function_in_unit<R: Reader>(&self, unit: &gimli::Unit<R>, addr: u64) -> Option<FunctionInfo> {
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
    fn find_source_location_in_unit<R: Reader>(&self, unit: &gimli::Unit<R>, addr: u64) -> Option<SourceLocation> {
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
                    return self.create_source_location(header, &prev, addr);
                }
                break;
            }
            
            prev_row = Some(row.clone());
        }
        
        // Check the last row
        if let Some(row) = prev_row {
            let header = &unit.line_program.as_ref()?.header();
            return self.create_source_location(header, &row, addr);
        }
        
        None
    }
    
    /// Parse function entry from DWARF
    fn parse_function_entry<R: Reader>(&self, unit: &gimli::Unit<R>, entry: &gimli::DebuggingInformationEntry<R>, target_addr: u64) -> Option<FunctionInfo> {
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
                gimli::DW_AT_high_pc => {
                    match attr.value() {
                        gimli::AttributeValue::Addr(addr) => high_pc = Some(addr),
                        gimli::AttributeValue::Udata(size) => {
                            if let Some(low) = low_pc {
                                high_pc = Some(low + size);
                            }
                        }
                        _ => {}
                    }
                }
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
            file_path: None, // TODO: Extract from compilation unit
            line_number: None, // TODO: Get from line number info
            parameters: Vec::new(), // TODO: Parse parameters
            local_variables: Vec::new(), // TODO: Parse local variables
        })
    }
    
    /// Create source location from line program data
    fn create_source_location<R: Reader>(&self, header: &gimli::LineProgramHeader<R>, row: &gimli::LineRow, addr: u64) -> Option<SourceLocation> {
        let file = header.file(row.file_index())?;
        
        let file_path = "unknown".to_string(); // Simplified for now
        
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
}

/// Load DWARF sections from object file
fn load_dwarf_sections(object_file: &object::File) -> Result<Dwarf<EndianSlice<'static, LittleEndian>>> {
    let endian = LittleEndian;
    
    // Helper to load section data
    let load_section = |id: gimli::SectionId| -> Result<EndianSlice<'static, LittleEndian>> {
        let data = get_section_data(object_file, id.name())
            .unwrap_or_else(|| {
                debug!("Section {} not found, using empty data", id.name());
                &[]
            });
        
        // SAFETY: We're keeping the file data alive in DwarfContext
        let static_data = unsafe { 
            std::slice::from_raw_parts(data.as_ptr(), data.len())
        };
        
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
use crate::{BinaryError, Result};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use std::collections::HashMap;
use std::path::Path;
use tracing::{debug, info};

/// Represents a symbol in the binary
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub kind: SymbolType,
    pub is_global: bool,
    pub section_name: Option<String>,
    /// Section virtual address (for offset calculation)
    pub section_viraddr: Option<u64>,
    /// Section file offset (for offset calculation)
    pub section_file_offset: Option<u64>,
}

/// Types of symbols
#[derive(Debug, Clone, PartialEq)]
pub enum SymbolType {
    Function,
    Object,
    Section,
    File,
    Unknown,
}

impl From<SymbolKind> for SymbolType {
    fn from(kind: SymbolKind) -> Self {
        match kind {
            SymbolKind::Text => SymbolType::Function,
            SymbolKind::Data => SymbolType::Object,
            SymbolKind::Section => SymbolType::Section,
            SymbolKind::File => SymbolType::File,
            _ => SymbolType::Unknown,
        }
    }
}

/// Symbol table for efficient symbol lookups
#[derive(Debug)]
pub struct SymbolTable {
    symbols: Vec<Symbol>,
    name_index: HashMap<String, usize>,
    address_sorted: Vec<usize>, // Indices sorted by address
}

impl SymbolTable {
    /// Load symbol table from binary file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        info!("Loading symbol table from: {}", path.display());
        
        let file_data = std::fs::read(path)?;
        let object_file = object::File::parse(&*file_data)?;
        
        let mut symbols = Vec::new();
        let mut name_index = HashMap::new();
        
        // Parse dynamic symbols first
        for symbol in object_file.dynamic_symbols() {
            if let Some(sym) = parse_symbol(symbol, &object_file) {
                name_index.insert(sym.name.clone(), symbols.len());
                symbols.push(sym);
            }
        }
        
        // Then parse regular symbols
        for symbol in object_file.symbols() {
            if let Some(sym) = parse_symbol(symbol, &object_file) {
                // Avoid duplicates (prefer dynamic symbols)
                if !name_index.contains_key(&sym.name) {
                    name_index.insert(sym.name.clone(), symbols.len());
                    symbols.push(sym);
                }
            }
        }
        
        // Create address-sorted index
        let mut address_sorted: Vec<usize> = (0..symbols.len()).collect();
        address_sorted.sort_by(|&a, &b| symbols[a].address.cmp(&symbols[b].address));
        
        info!("Loaded {} symbols", symbols.len());
        debug!("Symbol types: functions: {}, objects: {}, others: {}", 
            symbols.iter().filter(|s| s.kind == SymbolType::Function).count(),
            symbols.iter().filter(|s| s.kind == SymbolType::Object).count(),
            symbols.iter().filter(|s| !matches!(s.kind, SymbolType::Function | SymbolType::Object)).count());
        
        Ok(SymbolTable {
            symbols,
            name_index,
            address_sorted,
        })
    }
    
    /// Find symbol by name
    pub fn find_by_name(&self, name: &str) -> Option<&Symbol> {
        self.name_index.get(name).map(|&idx| &self.symbols[idx])
    }
    
    /// Find symbol by exact address
    pub fn find_by_address(&self, addr: u64) -> Option<&Symbol> {
        self.symbols.iter().find(|sym| sym.address == addr)
    }
    
    /// Find the closest symbol at or before the given address
    pub fn find_closest_symbol(&self, addr: u64) -> Option<&Symbol> {
        if self.address_sorted.is_empty() {
            return None;
        }
        
        // Binary search for the largest address <= addr
        let mut left = 0;
        let mut right = self.address_sorted.len();
        
        while left < right {
            let mid = (left + right) / 2;
            let sym_addr = self.symbols[self.address_sorted[mid]].address;
            
            if sym_addr <= addr {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        
        if left > 0 {
            Some(&self.symbols[self.address_sorted[left - 1]])
        } else {
            None
        }
    }
    
    /// Find all symbols matching a pattern
    pub fn find_matching(&self, pattern: &str) -> Vec<&Symbol> {
        let pattern_lower = pattern.to_lowercase();
        self.symbols
            .iter()
            .filter(|sym| sym.name.to_lowercase().contains(&pattern_lower))
            .collect()
    }
    
    /// Get all function symbols
    pub fn get_functions(&self) -> Vec<&Symbol> {
        self.symbols
            .iter()
            .filter(|sym| sym.kind == SymbolType::Function)
            .collect()
    }
    
    /// Get all symbols
    pub fn get_all_symbols(&self) -> &[Symbol] {
        &self.symbols
    }
    
    /// Get symbol count
    pub fn len(&self) -> usize {
        self.symbols.len()
    }
    
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

/// Parse a symbol from object file
fn parse_symbol<'data, 'file>(
    symbol: object::Symbol<'data, 'file>,
    object_file: &object::File<'data>
) -> Option<Symbol> {
    let name = symbol.name().ok()?.to_string();
    
    // Skip empty names and some special symbols
    if name.is_empty() || name.starts_with('$') {
        return None;
    }
    
    let address = symbol.address();
    let size = symbol.size();
    let kind = SymbolType::from(symbol.kind());
    let is_global = symbol.is_global();
    
    // Get section information if available
    let (section_name, section_viraddr, section_file_offset) = match symbol.section() {
        object::SymbolSection::Section(section_index) => {
            if let Ok(section) = object_file.section_by_index(section_index) {
                let name = section.name().ok().map(|s| s.to_string());
                let viraddr = Some(section.address());
                let file_offset = Some(section.file_range().map_or(0, |(offset, _)| offset));
                (name, viraddr, file_offset)
            } else {
                (Some(format!("section_{}", section_index.0)), None, None)
            }
        }
        _ => (None, None, None),
    };
    
    Some(Symbol {
        name,
        address,
        size,
        kind,
        is_global,
        section_name,
        section_viraddr,
        section_file_offset,
    })
}

impl Symbol {
    /// Calculate the proper uprobe offset using the formula:
    /// uprobe_offset = symbol_offset - section_viraddr_offset + section_file_offset
    pub fn uprobe_offset(&self) -> Option<u64> {
        match (self.section_viraddr, self.section_file_offset) {
            (Some(viraddr), Some(file_offset)) => {
                // Formula: symbol_offset - section_viraddr_offset + section_file_offset
                if self.address >= viraddr {
                    Some(self.address - viraddr + file_offset)
                } else {
                    debug!("Symbol address 0x{:x} is less than section virtual address 0x{:x}", 
                           self.address, viraddr);
                    None
                }
            }
            _ => {
                debug!("Missing section information for symbol '{}': viraddr={:?}, file_offset={:?}", 
                       self.name, self.section_viraddr, self.section_file_offset);
                None
            }
        }
    }
}
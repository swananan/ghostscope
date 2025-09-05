# Improved Variable Storage and Lookup Design

## Current Problems

1. **Range-based organization**: Variables organized by AddressRange, ignoring function scopes
2. **Data redundancy**: Full Variable structs duplicated in EnhancedVariableLocation
3. **Poor scoping**: No proper lexical scope or variable shadowing handling
4. **Incorrect lookup**: Results include variables from wrong functions/scopes

## GDB-Inspired Solution

### 1. Hierarchical Scope-Based Storage

```rust
/// Variable information stored once, referenced by ID
#[derive(Debug, Clone)]
pub struct VariableInfo {
    pub id: VariableId,
    pub name: String,
    pub type_name: String,
    pub dwarf_type: Option<DwarfType>,
    pub location_expr: Option<LocationExpression>,
    pub is_parameter: bool,
    pub is_artificial: bool,
    pub size: Option<u64>,
}

/// Scope hierarchy (lexical scopes)
#[derive(Debug, Clone)]
pub struct Scope {
    pub id: ScopeId,
    pub parent_scope: Option<ScopeId>,
    pub scope_type: ScopeType,
    pub address_ranges: Vec<AddressRange>,
    pub variables: Vec<VariableRef>, // Reference to variables, not full data
    pub child_scopes: Vec<ScopeId>,
}

#[derive(Debug, Clone)]
pub enum ScopeType {
    CompilationUnit,
    Function { name: String, address: u64 },
    LexicalBlock { depth: usize },
    InlinedSubroutine { origin_func: String },
}

#[derive(Debug, Clone)]
pub struct VariableRef {
    pub variable_id: VariableId,
    pub address_ranges: Vec<AddressRange>, // Where this variable is visible
    pub location_at_ranges: Vec<(AddressRange, LocationExpression)>, // Location can change
}

/// New efficient variable storage
pub struct ScopedVariableMap {
    /// All variable information (deduplicated)
    variables: HashMap<VariableId, VariableInfo>,
    
    /// Hierarchical scopes
    scopes: HashMap<ScopeId, Scope>,
    
    /// Fast address-to-scopes lookup (sorted for binary search)
    address_to_scopes: Vec<AddressScopeEntry>,
    
    /// Cache for recent lookups
    lookup_cache: LruCache<u64, Vec<VariableResult>>,
    
    /// Root scopes (compilation units)
    root_scopes: Vec<ScopeId>,
}

#[derive(Debug, Clone)]
pub struct AddressScopeEntry {
    pub address: u64,
    pub active_scopes: Vec<ScopeId>, // All scopes active at this address
}

#[derive(Debug, Clone)]
pub struct VariableResult {
    pub variable_info: VariableInfo,
    pub location_at_address: LocationExpression,
    pub scope_depth: usize, // For shadowing resolution
    pub is_optimized_out: bool,
}
```

### 2. GDB-Style Variable Lookup Algorithm

```rust
impl ScopedVariableMap {
    /// Get variables at address with proper scoping and shadowing
    pub fn get_variables_at_address(&mut self, addr: u64) -> Vec<VariableResult> {
        // Check cache first
        if let Some(cached) = self.lookup_cache.get(&addr) {
            return cached.clone();
        }

        let result = self.lookup_variables_with_scoping(addr);
        self.lookup_cache.put(addr, result.clone());
        result
    }

    fn lookup_variables_with_scoping(&self, addr: u64) -> Vec<VariableResult> {
        // 1. Find all scopes active at this address
        let active_scopes = self.find_active_scopes_at_address(addr);
        
        // 2. Collect variables from all scopes, with depth information
        let mut variable_candidates = HashMap::new(); // name -> (depth, VariableResult)
        
        for (depth, scope_id) in active_scopes.iter().enumerate() {
            let scope = &self.scopes[scope_id];
            
            for var_ref in &scope.variables {
                // Check if variable is visible at this address
                if self.is_variable_visible_at_address(var_ref, addr) {
                    let var_info = &self.variables[&var_ref.variable_id];
                    let location = self.resolve_location_at_address(var_ref, addr);
                    
                    let result = VariableResult {
                        variable_info: var_info.clone(),
                        location_at_address: location.clone(),
                        scope_depth: depth,
                        is_optimized_out: matches!(location, LocationExpression::OptimizedOut),
                    };
                    
                    // Handle variable shadowing: inner scope wins
                    match variable_candidates.get(&var_info.name) {
                        Some((existing_depth, _)) if depth < *existing_depth => {
                            variable_candidates.insert(var_info.name.clone(), (depth, result));
                        }
                        None => {
                            variable_candidates.insert(var_info.name.clone(), (depth, result));
                        }
                        _ => {
                            // Keep existing (it's from a deeper/inner scope)
                        }
                    }
                }
            }
        }
        
        // 3. Extract final results (shadowing resolved)
        variable_candidates.into_values().map(|(_, result)| result).collect()
    }
    
    /// Find active scopes at address, ordered by depth (innermost first)
    fn find_active_scopes_at_address(&self, addr: u64) -> Vec<ScopeId> {
        // Binary search to find address entry
        let entry_idx = self.address_to_scopes.binary_search_by(|entry| {
            entry.address.cmp(&addr)
        }).unwrap_or_else(|idx| if idx > 0 { idx - 1 } else { 0 });
        
        if entry_idx < self.address_to_scopes.len() {
            let entry = &self.address_to_scopes[entry_idx];
            
            // Sort scopes by depth (innermost first) for proper shadowing
            let mut scopes = entry.active_scopes.clone();
            scopes.sort_by_key(|scope_id| {
                self.calculate_scope_depth(*scope_id)
            });
            
            scopes
        } else {
            Vec::new()
        }
    }
}
```

### 3. Benefits of This Approach

1. **Proper Scoping**: Variables are organized by lexical scopes, not just address ranges
2. **Deduplication**: Variable info stored once, referenced by ID
3. **Shadowing**: Correct handling of same-name variables in nested scopes
4. **Function-Aware**: Only variables from current function context are returned
5. **Efficient**: Binary search + caching for fast lookups
6. **GDB-Compatible**: Similar to GDB's symbol table organization

### 4. Migration Strategy

1. Build new ScopedVariableMap alongside existing VariableLocationMap
2. Update get_enhanced_variable_locations() to use new system
3. Add comprehensive tests comparing results with GDB
4. Remove old range-based system once validated

### 5. Key Improvements

- **Function Context**: Variables are grouped by function, preventing cross-function pollution
- **Lexical Scoping**: Proper handling of nested scopes (blocks, inlined functions)
- **Variable Shadowing**: Inner scope variables correctly hide outer ones
- **Memory Efficiency**: No duplicate variable storage
- **Performance**: O(log n) address lookup + cached results
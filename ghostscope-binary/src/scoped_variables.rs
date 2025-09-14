// Variable scope system with GDB-style lexical block hierarchy
// Provides efficient PC -> variable set lookup with proper scoping and shadowing

use crate::dwarf::{DwarfType, LocationExpression};
use crate::expression::{DwarfExpressionEvaluator, EvaluationContext, EvaluationResult};
use std::collections::{BTreeSet, HashMap, HashSet};
use tracing::{debug, error, warn};

pub(crate) type VariableId = u32;
pub(crate) type ScopeId = u32;

/// Address range for scope and variable visibility
#[derive(Debug, Clone, PartialEq)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

/// Variable information stored once, referenced by ID
#[derive(Debug, Clone)]
pub(crate) struct VariableInfo {
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
pub(crate) struct Scope {
    pub id: ScopeId,
    pub parent_scope: Option<ScopeId>,
    pub scope_type: ScopeType,
    pub address_ranges: Vec<AddressRange>,
    pub variables: Vec<VariableRef>,
    pub child_scopes: Vec<ScopeId>,
}

/// Types of scopes in the debug information
#[derive(Debug, Clone)]
pub(crate) enum ScopeType {
    CompilationUnit,
    Function { name: String, address: u64 },
    LexicalBlock { depth: usize },
    InlinedSubroutine { origin_func: String },
}

/// Variable reference within a scope with location information
#[derive(Debug, Clone)]
pub(crate) struct VariableRef {
    pub variable_id: VariableId,
    pub address_ranges: Vec<AddressRange>,
    pub location_at_ranges: Vec<(AddressRange, LocationExpression)>,
}

/// Address-to-scope mapping entry for fast lookup
#[derive(Debug, Clone)]
pub(crate) struct AddressScopeEntry {
    pub address: u64,
    pub active_scopes: Vec<ScopeId>,
}

/// Variable lookup result with scoping information
#[derive(Debug, Clone)]
pub(crate) struct VariableResult {
    pub variable_info: VariableInfo,
    pub location_at_address: LocationExpression,
    pub scope_depth: usize,
    pub is_optimized_out: bool,
    /// Enhanced evaluation result for LLVM codegen
    pub evaluation_result: Option<EvaluationResult>,
}

/// Efficient variable storage with proper scoping based on GDB design
#[derive(Debug)]
pub(crate) struct ScopedVariableMap {
    /// All variable information (deduplicated)
    variables: HashMap<VariableId, VariableInfo>,

    /// Hierarchical scopes
    scopes: HashMap<ScopeId, Scope>,

    /// Fast address-to-scopes lookup (sorted for binary search)
    address_to_scopes: Vec<AddressScopeEntry>,

    /// Cache for recent lookups
    lookup_cache: HashMap<u64, Vec<VariableResult>>,

    /// Map from abstract_origin offset (unit-relative) to variables created from it
    origin_to_variables: HashMap<u64, Vec<VariableId>>,

    /// Root scopes (compilation units)
    root_scopes: Vec<ScopeId>,

    /// Next available IDs
    next_variable_id: VariableId,
    next_scope_id: ScopeId,

    /// Expression evaluator for variable location evaluation
    expression_evaluator: DwarfExpressionEvaluator,
}

impl ScopedVariableMap {
    /// Create a new scoped variable map
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
            scopes: HashMap::new(),
            address_to_scopes: Vec::new(),
            lookup_cache: HashMap::new(),
            origin_to_variables: HashMap::new(),
            root_scopes: Vec::new(),
            next_variable_id: 1,
            next_scope_id: 1,
            expression_evaluator: DwarfExpressionEvaluator::new(),
        }
    }

    /// Get variables at address with CFI-aware DWARF expression evaluation

    /// Get variables at address with proper scoping and shadowing (main public API)
    pub fn get_variables_at_address(&mut self, addr: u64) -> Vec<VariableResult> {
        debug!(
            "ScopedVariableMap: Looking up variables at address 0x{:x}",
            addr
        );

        // Log current state for debugging
        debug!(
            "ScopedVariableMap: Current state - {} variables, {} scopes, {} address entries",
            self.variables.len(),
            self.scopes.len(),
            self.address_to_scopes.len()
        );

        // Check cache first
        if let Some(cached) = self.lookup_cache.get(&addr) {
            debug!(
                "ScopedVariableMap: Found {} cached variables at address 0x{:x}",
                cached.len(),
                addr
            );
            return cached.clone();
        }

        let result = self.lookup_variables_with_scoping(addr);
        debug!(
            "ScopedVariableMap: Found {} variables at address 0x{:x}",
            result.len(),
            addr
        );

        // If no results and we have scopes, debug the address lookup
        if result.is_empty() && !self.scopes.is_empty() {
            debug!("ScopedVariableMap: No variables found, debugging address lookup...");
            let active_scopes = self.find_active_scopes_at_address(addr);
            debug!(
                "ScopedVariableMap: Active scopes for 0x{:x}: {:?}",
                addr, active_scopes
            );

            // Log some address entries for debugging
            if !self.address_to_scopes.is_empty() {
                let first_entry = &self.address_to_scopes[0];
                let last_entry = &self.address_to_scopes[self.address_to_scopes.len() - 1];
                debug!(
                    "ScopedVariableMap: Address range coverage: 0x{:x} - 0x{:x}",
                    first_entry.address, last_entry.address
                );
            }
        }

        // Cache result (with size limit)
        if self.lookup_cache.len() > 1000 {
            self.lookup_cache.clear();
        }
        self.lookup_cache.insert(addr, result.clone());

        result
    }

    /// Core lookup algorithm with proper scoping and shadowing
    fn lookup_variables_with_scoping(&self, addr: u64) -> Vec<VariableResult> {
        // 1. Find all scopes active at this address
        let active_scopes = self.find_active_scopes_at_address(addr);
        debug!(
            "ScopedVariableMap: Found {} active scopes at address 0x{:x}: {:?}",
            active_scopes.len(),
            addr,
            active_scopes
        );

        // 2. Collect variables from all scopes, with depth information
        let mut variable_candidates: HashMap<String, (usize, VariableResult)> = HashMap::new();

        for (depth, scope_id) in active_scopes.iter().enumerate() {
            if let Some(scope) = self.scopes.get(scope_id) {
                debug!(
                    "ScopedVariableMap: Checking scope {:?} at depth {}, contains {} variables",
                    scope_id,
                    depth,
                    scope.variables.len()
                );
                for var_ref in &scope.variables {
                    // Check if variable is visible at this address
                    if self.is_variable_visible_at_address(var_ref, addr) {
                        if let Some(var_info) = self.variables.get(&var_ref.variable_id) {
                            debug!(
                                "ScopedVariableMap: Variable '{}' is visible at address 0x{:x}",
                                var_info.name, addr
                            );
                            let location = self.resolve_location_at_address(var_ref, addr);

                            // Expression evaluation is now done on-demand in DwarfContext
                            let evaluation_result = None;

                            let result = VariableResult {
                                variable_info: var_info.clone(),
                                location_at_address: location.clone(),
                                scope_depth: depth,
                                is_optimized_out: matches!(
                                    location,
                                    LocationExpression::OptimizedOut
                                ),
                                evaluation_result,
                            };

                            // Handle variable shadowing: inner scope (lower depth) wins
                            match variable_candidates.get(&var_info.name) {
                                Some((existing_depth, _)) if depth < *existing_depth => {
                                    variable_candidates
                                        .insert(var_info.name.clone(), (depth, result));
                                }
                                None => {
                                    variable_candidates
                                        .insert(var_info.name.clone(), (depth, result));
                                }
                                _ => {
                                    // Keep existing (it's from a deeper/inner scope)
                                }
                            }
                        }
                    }
                }
            }
        }

        // 3. Extract final results (shadowing resolved)
        let mut results: Vec<VariableResult> = variable_candidates
            .into_values()
            .map(|(_, result)| result)
            .collect();

        // Sort by scope depth for consistent ordering
        results.sort_by_key(|r| r.scope_depth);

        results
    }

    /// Core lookup algorithm with CFI-aware DWARF expression evaluation

    /// Find active scopes at address, ordered by depth (innermost first)
    fn find_active_scopes_at_address(&self, addr: u64) -> Vec<ScopeId> {
        // Binary search to find the appropriate address entry
        let entry_idx = match self
            .address_to_scopes
            .binary_search_by(|entry| entry.address.cmp(&addr))
        {
            Ok(idx) => idx,
            Err(idx) => {
                if idx > 0 {
                    idx - 1
                } else {
                    return Vec::new();
                }
            }
        };

        if entry_idx < self.address_to_scopes.len() {
            let entry = &self.address_to_scopes[entry_idx];

            // Sort scopes by depth (innermost first) for proper shadowing
            let mut scopes = entry.active_scopes.clone();
            scopes.sort_by_key(|scope_id| self.calculate_scope_depth(*scope_id));

            scopes
        } else {
            Vec::new()
        }
    }

    /// Calculate scope depth in the hierarchy (0 = root)
    fn calculate_scope_depth(&self, scope_id: ScopeId) -> usize {
        let mut depth = 0;
        let mut current_scope_id = Some(scope_id);
        let mut visited = HashSet::new();

        while let Some(id) = current_scope_id {
            // Prevent infinite loops due to circular references
            if visited.contains(&id) {
                warn!(
                    "Circular reference detected in scope hierarchy at scope {:?}",
                    id
                );
                break;
            }
            visited.insert(id);

            if let Some(scope) = self.scopes.get(&id) {
                current_scope_id = scope.parent_scope;
                // Prevent overflow with reasonable depth limit
                if depth >= 1000 {
                    warn!("Scope depth limit (1000) exceeded for scope {:?}", scope_id);
                    break;
                }
                depth += 1;
            } else {
                break;
            }
        }

        depth
    }

    /// Check if variable is visible at given address
    fn is_variable_visible_at_address(&self, var_ref: &VariableRef, addr: u64) -> bool {
        let visible = var_ref.address_ranges.iter().any(|range| {
            if range.start == range.end {
                // Handle point locations (e.g., [0x1157, 0x1157) for inlined function entry points)
                addr == range.start
            } else {
                // Handle regular ranges [start, end)
                addr >= range.start && addr < range.end
            }
        });

        if !visible {
            debug!(
                "ScopedVariableMap: Variable '{}' NOT visible at 0x{:x}. Address ranges: {:?}",
                var_ref.variable_id, addr, var_ref.address_ranges
            );
        } else {
            debug!(
                "ScopedVariableMap: Variable '{}' IS visible at 0x{:x}",
                var_ref.variable_id, addr
            );
        }

        visible
    }

    /// Resolve variable location at specific address
    fn resolve_location_at_address(&self, var_ref: &VariableRef, addr: u64) -> LocationExpression {
        // Find location expression for this address
        for (range, location_expr) in &var_ref.location_at_ranges {
            if addr >= range.start && addr < range.end {
                return location_expr.clone();
            }
        }

        // Fallback: use first available location or OptimizedOut
        var_ref
            .location_at_ranges
            .first()
            .map(|(_, expr)| expr.clone())
            .unwrap_or(LocationExpression::OptimizedOut)
    }

    /// Add a new variable to the map
    pub fn add_variable(
        &mut self,
        name: String,
        type_name: String,
        dwarf_type: Option<DwarfType>,
        location_expr: Option<LocationExpression>,
        is_parameter: bool,
        is_artificial: bool,
        size: Option<u64>,
    ) -> VariableId {
        let id = self.next_variable_id;
        self.next_variable_id += 1;

        let var_info = VariableInfo {
            id,
            name,
            type_name,
            dwarf_type,
            location_expr,
            is_parameter,
            is_artificial,
            size,
        };

        self.variables.insert(id, var_info);
        id
    }

    /// Add a new scope to the map
    pub fn add_scope(
        &mut self,
        parent_scope: Option<ScopeId>,
        scope_type: ScopeType,
        address_ranges: Vec<AddressRange>,
    ) -> ScopeId {
        let id = self.next_scope_id;
        self.next_scope_id += 1;

        let scope = Scope {
            id,
            parent_scope,
            scope_type,
            address_ranges,
            variables: Vec::new(),
            child_scopes: Vec::new(),
        };

        self.scopes.insert(id, scope);

        // Update parent's child list
        if let Some(parent_id) = parent_scope {
            if let Some(parent) = self.scopes.get_mut(&parent_id) {
                parent.child_scopes.push(id);
            }
        } else {
            // This is a root scope
            self.root_scopes.push(id);
        }

        id
    }

    /// Add variable reference to a scope
    pub fn add_variable_to_scope(
        &mut self,
        scope_id: ScopeId,
        variable_id: VariableId,
        address_ranges: Vec<AddressRange>,
        location_at_ranges: Vec<(AddressRange, LocationExpression)>,
    ) {
        if let Some(scope) = self.scopes.get_mut(&scope_id) {
            scope.variables.push(VariableRef {
                variable_id,
                address_ranges,
                location_at_ranges,
            });
        }
    }

    /// Register a mapping from abstract_origin offset to a variable id
    pub fn register_origin_mapping(&mut self, origin_offset: u64, variable_id: VariableId) {
        self.origin_to_variables
            .entry(origin_offset)
            .or_insert_with(Vec::new)
            .push(variable_id);
    }

    /// Find variable ids by abstract_origin offset (unit-relative offset value)
    pub fn find_variables_by_abstract_origin(&self, origin_offset: u64) -> Vec<VariableId> {
        self.origin_to_variables
            .get(&origin_offset)
            .cloned()
            .unwrap_or_default()
    }

    /// Build the address-to-scopes lookup table (call after all scopes are added)
    pub fn build_address_lookup(&mut self) {
        debug!("Building address-to-scopes lookup table...");

        let mut address_points = BTreeSet::new();

        // Collect all address points from all scopes
        for scope in self.scopes.values() {
            for range in &scope.address_ranges {
                address_points.insert(range.start);
                address_points.insert(range.end);
            }
        }

        self.address_to_scopes.clear();

        // For each address point, find active scopes
        for &addr in &address_points {
            let active_scopes = self.find_scopes_containing_address(addr);
            if !active_scopes.is_empty() {
                self.address_to_scopes.push(AddressScopeEntry {
                    address: addr,
                    active_scopes,
                });
            }
        }

        debug!(
            "Built {} address-to-scope entries",
            self.address_to_scopes.len()
        );
    }

    /// Find all scopes that contain the given address
    fn find_scopes_containing_address(&self, addr: u64) -> Vec<ScopeId> {
        let mut active_scopes = Vec::new();

        for scope in self.scopes.values() {
            if scope.address_ranges.iter().any(|range| {
                if range.start == range.end {
                    // Handle point locations (e.g., [0x1157, 0x1157) for inlined function entry points)
                    addr == range.start
                } else {
                    // Handle regular ranges [start, end)
                    addr >= range.start && addr < range.end
                }
            }) {
                active_scopes.push(scope.id);
            }
        }

        active_scopes
    }

    /// Get statistics about the scoped variable map
    pub fn get_statistics(&self) -> ScopedVariableMapStats {
        ScopedVariableMapStats {
            total_variables: self.variables.len(),
            total_scopes: self.scopes.len(),
            total_address_entries: self.address_to_scopes.len(),
            cache_size: self.lookup_cache.len(),
            root_scopes_count: self.root_scopes.len(),
        }
    }

    /// Get scope by ID (for DWARF parsing)
    pub fn get_scope(&self, scope_id: ScopeId) -> Option<&Scope> {
        self.scopes.get(&scope_id)
    }

    /// Find all addresses for functions with the given name
    pub fn find_function_addresses(&self, function_name: &str) -> Vec<u64> {
        let mut addresses = Vec::new();

        for scope in self.scopes.values() {
            match &scope.scope_type {
                // Handle regular (non-inlined) functions
                ScopeType::Function { name, address } => {
                    if name == function_name {
                        addresses.push(*address);
                    }
                }
                // Handle inlined functions
                ScopeType::InlinedSubroutine { origin_func } => {
                    if origin_func == function_name {
                        // For inlined functions, use the first address range start as the representative address
                        if let Some(first_range) = scope.address_ranges.first() {
                            addresses.push(first_range.start);
                        }
                    }
                }
                _ => {} // Ignore other scope types
            }
        }

        // Sort addresses for consistent ordering
        addresses.sort_unstable();
        addresses
    }

    /// Get mutable reference to the expression evaluator
    pub fn get_expression_evaluator_mut(&mut self) -> &mut DwarfExpressionEvaluator {
        &mut self.expression_evaluator
    }

    /// Get immutable variable info by id
    pub fn get_variable_info(&self, variable_id: VariableId) -> Option<&VariableInfo> {
        self.variables.get(&variable_id)
    }
}

/// Statistics about the scoped variable map
#[derive(Debug)]
pub(crate) struct ScopedVariableMapStats {
    pub total_variables: usize,
    pub total_scopes: usize,
    pub total_address_entries: usize,
    pub cache_size: usize,
    pub root_scopes_count: usize,
}

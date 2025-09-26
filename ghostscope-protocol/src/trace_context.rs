//! Trace context for managing strings, types, and variable names
//!
//! TraceContext is the upgraded version of StringTable that provides unified
//! management of all context information needed during tracing execution.

use crate::type_info::TypeInfo;
use serde::{Deserialize, Serialize};

/// Unified context for trace execution containing strings, types, and variable names
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    /// Format strings and constant strings
    pub strings: Vec<String>,

    /// Complete DWARF type information for perfect formatting
    pub types: Vec<TypeInfo>,

    /// Variable names for debugging and display
    pub variable_names: Vec<String>,
}

impl TraceContext {
    /// Create a new empty trace context
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            types: Vec::new(),
            variable_names: Vec::new(),
        }
    }

    /// Add a string to the context and return its index
    pub fn add_string(&mut self, s: String) -> u16 {
        // Check if string already exists to avoid duplicates
        if let Some(index) = self.strings.iter().position(|existing| existing == &s) {
            return index as u16;
        }

        let index = self.strings.len();
        if index > u16::MAX as usize {
            panic!("String table overflow: too many strings");
        }

        self.strings.push(s);
        index as u16
    }

    /// Add a type to the context and return its index
    pub fn add_type(&mut self, type_info: TypeInfo) -> u16 {
        // For now, don't deduplicate types as they can be complex to compare
        // TODO: Implement type deduplication for performance optimization
        let index = self.types.len();
        if index > u16::MAX as usize {
            panic!("Type table overflow: too many types");
        }

        // Debug: Log the type being added
        tracing::debug!("Adding type at index {}: {:#?}", index, type_info);

        self.types.push(type_info);
        index as u16
    }

    /// Add a variable name to the context and return its index
    pub fn add_variable_name(&mut self, name: String) -> u16 {
        // Check if variable name already exists to avoid duplicates
        if let Some(index) = self
            .variable_names
            .iter()
            .position(|existing| existing == &name)
        {
            return index as u16;
        }

        let index = self.variable_names.len();
        if index > u16::MAX as usize {
            panic!("Variable name table overflow: too many variable names");
        }

        self.variable_names.push(name);
        index as u16
    }

    /// Get a string by index
    pub fn get_string(&self, index: u16) -> Option<&str> {
        self.strings.get(index as usize).map(|s| s.as_str())
    }

    /// Get a type by index
    pub fn get_type(&self, index: u16) -> Option<&TypeInfo> {
        self.types.get(index as usize)
    }

    /// Get a variable name by index
    pub fn get_variable_name(&self, index: u16) -> Option<&str> {
        self.variable_names.get(index as usize).map(|s| s.as_str())
    }

    /// Get the number of strings in the context
    pub fn string_count(&self) -> usize {
        self.strings.len()
    }

    /// Get the number of types in the context
    pub fn type_count(&self) -> usize {
        self.types.len()
    }

    /// Get the number of variable names in the context
    pub fn variable_name_count(&self) -> usize {
        self.variable_names.len()
    }

    /// Clear all tables (useful for testing)
    pub fn clear(&mut self) {
        self.strings.clear();
        self.types.clear();
        self.variable_names.clear();
    }

    /// Get total memory usage estimate in bytes
    pub fn estimated_memory_usage(&self) -> usize {
        let strings_size: usize = self.strings.iter().map(|s| s.len()).sum();
        let variable_names_size: usize = self.variable_names.iter().map(|s| s.len()).sum();

        // Rough estimate: each TypeInfo is approximately 100 bytes on average
        // (this is a rough estimate since TypeInfo can vary significantly in size)
        let types_size = self.types.len() * 100;

        strings_size + variable_names_size + types_size
    }
}

impl Default for TraceContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_info::{StructMember, TypeInfo};

    #[test]
    fn test_trace_context_strings() {
        let mut ctx = TraceContext::new();

        let idx1 = ctx.add_string("Hello".to_string());
        let idx2 = ctx.add_string("World".to_string());
        let idx3 = ctx.add_string("Hello".to_string()); // Duplicate

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // Should return existing index

        assert_eq!(ctx.get_string(idx1), Some("Hello"));
        assert_eq!(ctx.get_string(idx2), Some("World"));
        assert_eq!(ctx.string_count(), 2);
    }

    #[test]
    fn test_trace_context_variable_names() {
        let mut ctx = TraceContext::new();

        let idx1 = ctx.add_variable_name("person".to_string());
        let idx2 = ctx.add_variable_name("name".to_string());
        let idx3 = ctx.add_variable_name("person".to_string()); // Duplicate

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // Should return existing index

        assert_eq!(ctx.get_variable_name(idx1), Some("person"));
        assert_eq!(ctx.get_variable_name(idx2), Some("name"));
        assert_eq!(ctx.variable_name_count(), 2);
    }

    #[test]
    fn test_trace_context_types() {
        let mut ctx = TraceContext::new();

        let type1 = TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };

        let type2 = TypeInfo::StructType {
            name: "Person".to_string(),
            size: 32,
            members: vec![StructMember {
                name: "name".to_string(),
                member_type: TypeInfo::BaseType {
                    name: "char".to_string(),
                    size: 1,
                    encoding: gimli::constants::DW_ATE_signed_char.0 as u16,
                },
                offset: 0,
                bit_offset: None,
                bit_size: None,
            }],
        };

        let idx1 = ctx.add_type(type1.clone());
        let idx2 = ctx.add_type(type2.clone());

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);

        assert_eq!(ctx.get_type(idx1), Some(&type1));
        assert_eq!(ctx.get_type(idx2), Some(&type2));
        assert_eq!(ctx.type_count(), 2);
    }

    #[test]
    fn test_trace_context_combined() {
        let mut ctx = TraceContext::new();

        let str_idx = ctx.add_string("format: {} = {}".to_string());
        let var_idx = ctx.add_variable_name("person.name".to_string());
        let type_idx = ctx.add_type(TypeInfo::BaseType {
            name: "char[32]".to_string(),
            size: 32,
            encoding: gimli::constants::DW_ATE_signed_char.0 as u16,
        });

        assert_eq!(str_idx, 0);
        assert_eq!(var_idx, 0);
        assert_eq!(type_idx, 0);

        // Each table is independent
        assert_eq!(ctx.string_count(), 1);
        assert_eq!(ctx.variable_name_count(), 1);
        assert_eq!(ctx.type_count(), 1);
    }

    #[test]
    fn test_trace_context_memory_usage() {
        let mut ctx = TraceContext::new();

        ctx.add_string("Hello World".to_string()); // 11 bytes
        ctx.add_variable_name("variable".to_string()); // 8 bytes
        ctx.add_type(TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        }); // ~100 bytes estimate

        let usage = ctx.estimated_memory_usage();
        assert!(usage >= 119); // At least the string sizes + type estimate
    }
}

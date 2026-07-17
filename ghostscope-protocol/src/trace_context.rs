//! Trace context for managing strings, types, and variable names
//!
//! TraceContext is the upgraded version of StringTable that provides unified
//! management of all context information needed during tracing execution.

use crate::type_info::TypeInfo;
use crate::ValuePresentation;
use serde::{Deserialize, Serialize};
use std::fmt;

static DWARF_VALUE_PRESENTATION: ValuePresentation = ValuePresentation::Dwarf;

/// Trace context table identifiers used in overflow errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceContextTable {
    Strings,
    Types,
    VariableNames,
}

impl fmt::Display for TraceContextTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Strings => write!(f, "string"),
            Self::Types => write!(f, "type"),
            Self::VariableNames => write!(f, "variable name"),
        }
    }
}

/// Error returned when a trace context table can no longer be indexed by u16.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceContextOverflow {
    table: TraceContextTable,
    attempted_index: usize,
}

impl TraceContextOverflow {
    fn new(table: TraceContextTable, attempted_index: usize) -> Self {
        Self {
            table,
            attempted_index,
        }
    }

    pub fn table(&self) -> TraceContextTable {
        self.table
    }

    pub fn attempted_index(&self) -> usize {
        self.attempted_index
    }
}

impl fmt::Display for TraceContextOverflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "trace context {} table overflow: index {} exceeds u16::MAX",
            self.table, self.attempted_index
        )
    }
}

impl std::error::Error for TraceContextOverflow {}

pub type TraceContextResult<T> = std::result::Result<T, TraceContextOverflow>;

/// Unified context for trace execution containing strings, types, and variable names
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceContext {
    /// Format strings and constant strings
    pub strings: Vec<String>,

    /// Complete DWARF type information for perfect formatting
    pub types: Vec<TypeInfo>,

    /// Semantic presentation associated with each type index. Older trace
    /// contexts omit this table and therefore use `Dwarf` for every type.
    #[serde(default)]
    pub value_presentations: Vec<ValuePresentation>,

    /// Variable names for debugging and display
    pub variable_names: Vec<String>,
}

impl TraceContext {
    /// Create a new empty trace context
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            types: Vec::new(),
            value_presentations: Vec::new(),
            variable_names: Vec::new(),
        }
    }

    /// Add a string to the context and return its index
    pub fn add_string(&mut self, s: String) -> TraceContextResult<u16> {
        // Check if string already exists to avoid duplicates
        if let Some(index) = self.strings.iter().position(|existing| existing == &s) {
            return Ok(index as u16);
        }

        let index = self.strings.len();
        if index > u16::MAX as usize {
            return Err(TraceContextOverflow::new(TraceContextTable::Strings, index));
        }

        self.strings.push(s);
        Ok(index as u16)
    }

    /// Add a type to the context and return its index
    pub fn add_type(&mut self, type_info: TypeInfo) -> TraceContextResult<u16> {
        self.add_type_with_presentation(type_info, ValuePresentation::Dwarf)
    }

    /// Add a type and its semantic presentation to the context.
    pub fn add_type_with_presentation(
        &mut self,
        type_info: TypeInfo,
        presentation: ValuePresentation,
    ) -> TraceContextResult<u16> {
        // For now, don't deduplicate types as they can be complex to compare
        // TODO: Implement type deduplication for performance optimization
        let index = self.types.len();
        if index > u16::MAX as usize {
            return Err(TraceContextOverflow::new(TraceContextTable::Types, index));
        }

        // Debug: Log the type being added
        tracing::debug!("Adding type at index {}: {:#?}", index, type_info);

        self.value_presentations
            .resize(index, ValuePresentation::Dwarf);
        self.types.push(type_info);
        self.value_presentations.push(presentation);
        Ok(index as u16)
    }

    /// Add a variable name to the context and return its index
    pub fn add_variable_name(&mut self, name: String) -> TraceContextResult<u16> {
        // Check if variable name already exists to avoid duplicates
        if let Some(index) = self
            .variable_names
            .iter()
            .position(|existing| existing == &name)
        {
            return Ok(index as u16);
        }

        let index = self.variable_names.len();
        if index > u16::MAX as usize {
            return Err(TraceContextOverflow::new(
                TraceContextTable::VariableNames,
                index,
            ));
        }

        self.variable_names.push(name);
        Ok(index as u16)
    }

    /// Get a string by index
    pub fn get_string(&self, index: u16) -> Option<&str> {
        self.strings.get(index as usize).map(|s| s.as_str())
    }

    /// Get a type by index
    pub fn get_type(&self, index: u16) -> Option<&TypeInfo> {
        self.types.get(index as usize)
    }

    /// Get the presentation for a type index, defaulting to physical DWARF
    /// formatting for contexts serialized before this table was introduced.
    pub fn get_value_presentation(&self, index: u16) -> &ValuePresentation {
        self.value_presentations
            .get(index as usize)
            .unwrap_or(&DWARF_VALUE_PRESENTATION)
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
        self.value_presentations.clear();
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

        let idx1 = ctx.add_string("Hello".to_string()).unwrap();
        let idx2 = ctx.add_string("World".to_string()).unwrap();
        let idx3 = ctx.add_string("Hello".to_string()).unwrap(); // Duplicate

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

        let idx1 = ctx.add_variable_name("person".to_string()).unwrap();
        let idx2 = ctx.add_variable_name("name".to_string()).unwrap();
        let idx3 = ctx.add_variable_name("person".to_string()).unwrap(); // Duplicate

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

        let idx1 = ctx.add_type(type1.clone()).unwrap();
        let idx2 = ctx.add_type(type2.clone()).unwrap();

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);

        assert_eq!(ctx.get_type(idx1), Some(&type1));
        assert_eq!(ctx.get_type(idx2), Some(&type2));
        assert_eq!(ctx.get_value_presentation(idx1), &ValuePresentation::Dwarf);
        assert_eq!(ctx.type_count(), 2);
    }

    #[test]
    fn test_trace_context_type_presentation() {
        let mut ctx = TraceContext::new();
        let type_info = TypeInfo::UnknownType {
            name: "&str".to_string(),
        };
        let index = ctx
            .add_type_with_presentation(type_info, ValuePresentation::Utf8String)
            .unwrap();

        assert_eq!(
            ctx.get_value_presentation(index),
            &ValuePresentation::Utf8String
        );
    }

    #[test]
    fn test_sequence_presentation_round_trips_with_element_type() {
        let mut ctx = TraceContext::new();
        let presentation = ValuePresentation::Sequence {
            element_type: Box::new(TypeInfo::BaseType {
                name: "i32".to_string(),
                size: 4,
                encoding: gimli::constants::DW_ATE_signed.0 as u16,
            }),
            element_stride: 4,
        };
        let index = ctx
            .add_type_with_presentation(
                TypeInfo::UnknownType {
                    name: "Vec<i32>".to_string(),
                },
                presentation.clone(),
            )
            .unwrap();

        let json = serde_json::to_string(&ctx).unwrap();
        let decoded: TraceContext = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.get_value_presentation(index), &presentation);
    }

    #[test]
    fn test_deserialized_legacy_context_defaults_to_dwarf_presentation() {
        let json = r#"{
            "strings": [],
            "types": [{"UnknownType": {"name": "legacy"}}],
            "variable_names": []
        }"#;
        let ctx: TraceContext = serde_json::from_str(json).unwrap();

        assert_eq!(ctx.get_value_presentation(0), &ValuePresentation::Dwarf);
    }

    #[test]
    fn test_appending_to_legacy_context_backfills_presentations() {
        let json = r#"{
            "strings": [],
            "types": [{"UnknownType": {"name": "legacy"}}],
            "variable_names": []
        }"#;
        let mut ctx: TraceContext = serde_json::from_str(json).unwrap();
        let new_index = ctx
            .add_type_with_presentation(
                TypeInfo::UnknownType {
                    name: "&str".to_string(),
                },
                ValuePresentation::Utf8String,
            )
            .unwrap();

        assert_eq!(new_index, 1);
        assert_eq!(ctx.value_presentations.len(), ctx.types.len());
        assert_eq!(ctx.get_value_presentation(0), &ValuePresentation::Dwarf);
        assert_eq!(
            ctx.get_value_presentation(new_index),
            &ValuePresentation::Utf8String
        );
    }

    #[test]
    fn test_trace_context_combined() {
        let mut ctx = TraceContext::new();

        let str_idx = ctx.add_string("format: {} = {}".to_string()).unwrap();
        let var_idx = ctx.add_variable_name("person.name".to_string()).unwrap();
        let type_idx = ctx
            .add_type(TypeInfo::BaseType {
                name: "char[32]".to_string(),
                size: 32,
                encoding: gimli::constants::DW_ATE_signed_char.0 as u16,
            })
            .unwrap();

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

        ctx.add_string("Hello World".to_string()).unwrap(); // 11 bytes
        ctx.add_variable_name("variable".to_string()).unwrap(); // 8 bytes
        ctx.add_type(TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        })
        .unwrap(); // ~100 bytes estimate

        let usage = ctx.estimated_memory_usage();
        assert!(usage >= 119); // At least the string sizes + type estimate
    }

    #[test]
    fn test_trace_context_reports_table_overflow() {
        let mut ctx = TraceContext::new();
        ctx.variable_names = (0..=u16::MAX).map(|i| format!("v{i}")).collect();

        let err = ctx
            .add_variable_name("overflow".to_string())
            .expect_err("variable name table should overflow");

        assert_eq!(err.table(), TraceContextTable::VariableNames);
        assert_eq!(err.attempted_index(), usize::from(u16::MAX) + 1);
    }
}

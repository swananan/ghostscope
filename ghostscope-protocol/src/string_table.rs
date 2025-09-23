use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// String table for optimizing transmission of repeated strings and variable names
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringTable {
    /// String constants (e.g., "hello world", "function entry")
    pub strings: Vec<String>,
    /// Variable names (e.g., "pid", "comm", "retval")
    pub variable_names: Vec<String>,

    // Internal maps for fast lookup (not serialized)
    #[serde(skip)]
    string_index_map: HashMap<String, u16>,
    #[serde(skip)]
    variable_index_map: HashMap<String, u16>,
}

impl StringTable {
    /// Create a new empty string table
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            variable_names: Vec::new(),
            string_index_map: HashMap::new(),
            variable_index_map: HashMap::new(),
        }
    }

    /// Add a string constant and return its index
    /// Returns existing index if string already exists (deduplication)
    pub fn add_string(&mut self, s: &str) -> u16 {
        if let Some(&index) = self.string_index_map.get(s) {
            return index;
        }

        let index = self.strings.len() as u16;
        if index == u16::MAX {
            panic!("Too many strings in string table (max: {})", u16::MAX);
        }

        self.strings.push(s.to_string());
        self.string_index_map.insert(s.to_string(), index);
        index
    }

    /// Add a variable name and return its index
    /// Returns existing index if variable name already exists (deduplication)
    pub fn add_variable_name(&mut self, name: &str) -> u16 {
        if let Some(&index) = self.variable_index_map.get(name) {
            return index;
        }

        let index = self.variable_names.len() as u16;
        if index == u16::MAX {
            panic!(
                "Too many variable names in string table (max: {})",
                u16::MAX
            );
        }

        self.variable_names.push(name.to_string());
        self.variable_index_map.insert(name.to_string(), index);
        index
    }

    /// Get string by index
    pub fn get_string(&self, index: u16) -> Option<&str> {
        self.strings.get(index as usize).map(|s| s.as_str())
    }

    /// Get variable name by index
    pub fn get_variable_name(&self, index: u16) -> Option<&str> {
        self.variable_names.get(index as usize).map(|s| s.as_str())
    }

    /// Get string index by content
    pub fn get_string_index(&self, s: &str) -> Option<u16> {
        self.string_index_map.get(s).copied()
    }

    /// Get variable name index by content
    pub fn get_variable_index(&self, name: &str) -> Option<u16> {
        self.variable_index_map.get(name).copied()
    }

    /// Rebuild internal maps after deserialization
    #[allow(dead_code)]
    pub(crate) fn rebuild_maps(&mut self) {
        self.string_index_map.clear();
        self.variable_index_map.clear();

        for (i, s) in self.strings.iter().enumerate() {
            self.string_index_map.insert(s.clone(), i as u16);
        }

        for (i, name) in self.variable_names.iter().enumerate() {
            self.variable_index_map.insert(name.clone(), i as u16);
        }
    }

    /// Get total number of strings
    pub fn string_count(&self) -> usize {
        self.strings.len()
    }

    /// Get total number of variable names
    pub fn variable_count(&self) -> usize {
        self.variable_names.len()
    }

    /// Calculate estimated memory usage for this string table
    #[allow(dead_code)]
    pub(crate) fn estimated_size(&self) -> usize {
        let strings_size: usize = self.strings.iter().map(|s| s.len()).sum();
        let variables_size: usize = self.variable_names.iter().map(|s| s.len()).sum();
        strings_size
            + variables_size
            + self.strings.len() * std::mem::size_of::<String>()
            + self.variable_names.len() * std::mem::size_of::<String>()
    }
}

impl Default for StringTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about string table usage
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct StringTableStats {
    pub total_strings: usize,
    pub total_variables: usize,
    pub estimated_memory: usize,
    pub deduplication_savings: usize, // How many duplicates were avoided
}

impl StringTable {
    /// Get usage statistics
    #[allow(dead_code)]
    pub(crate) fn get_stats(&self) -> StringTableStats {
        StringTableStats {
            total_strings: self.strings.len(),
            total_variables: self.variable_names.len(),
            estimated_memory: self.estimated_size(),
            deduplication_savings: 0, // TODO: track this during add operations
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_table_basic() {
        let mut table = StringTable::new();

        // Add strings
        let idx1 = table.add_string("hello");
        let idx2 = table.add_string("world");
        let idx3 = table.add_string("hello"); // duplicate

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // should reuse index

        assert_eq!(table.get_string(0), Some("hello"));
        assert_eq!(table.get_string(1), Some("world"));
        assert_eq!(table.string_count(), 2);
    }

    #[test]
    fn test_variable_names() {
        let mut table = StringTable::new();

        // Add variable names
        let idx1 = table.add_variable_name("pid");
        let idx2 = table.add_variable_name("comm");
        let idx3 = table.add_variable_name("pid"); // duplicate

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(idx3, 0); // should reuse index

        assert_eq!(table.get_variable_name(0), Some("pid"));
        assert_eq!(table.get_variable_name(1), Some("comm"));
        assert_eq!(table.variable_count(), 2);
    }

    #[test]
    fn test_serialization() {
        let mut table = StringTable::new();
        table.add_string("test");
        table.add_variable_name("var");

        // Serialize and deserialize
        let serialized = serde_json::to_string(&table).unwrap();
        let mut deserialized: StringTable = serde_json::from_str(&serialized).unwrap();

        // Rebuild maps
        deserialized.rebuild_maps();

        assert_eq!(deserialized.get_string(0), Some("test"));
        assert_eq!(deserialized.get_variable_name(0), Some("var"));
        assert_eq!(deserialized.get_string_index("test"), Some(0));
        assert_eq!(deserialized.get_variable_index("var"), Some(0));
    }
}
